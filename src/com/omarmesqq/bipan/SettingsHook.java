package com.omarmesqq.bipan;

import android.os.Bundle;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.lang.reflect.Field;
import android.content.Context;
import android.util.Log;

public class SettingsHook implements InvocationHandler {
    private final Object originalProvider;
    private static final String TAG = "Bipan";
    private static final String RANDOM_ANDROID_ID = generateRandomId();

    private static String generateRandomId() {
        java.security.SecureRandom random = new java.security.SecureRandom();
        byte[] bytes = new byte[8]; // 64 bits = 16 hex chars
        random.nextBytes(bytes);
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    public SettingsHook(Object originalProvider) {
        this.originalProvider = originalProvider;
    }

    @Override
    public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
        if ("call".equals(method.getName()) && args != null) {
            String callingMethod = null;
            String settingKey = null;

            for (int i = 0; i < args.length; i++) {
                if (args[i] instanceof String) {
                    String str = (String) args[i];
                    if (str.startsWith("GET_")) {
                        callingMethod = str;
                        if (i + 1 < args.length && args[i + 1] instanceof String) {
                            settingKey = (String) args[i + 1];
                        }
                        break;
                    }
                }
            }

            if (callingMethod != null && settingKey != null) {
                String fakeValue = null;
                if ("GET_global".equals(callingMethod)) {
                    switch (settingKey) {
                        case "adb_enabled":
                        case "development_settings_enabled":
                        case "wait_for_debugger": fakeValue = "0"; break;
                        case "boot_count": fakeValue = "43"; break;
                    }
                } else if ("GET_secure".equals(callingMethod) && "android_id".equals(settingKey)) {
                    fakeValue = RANDOM_ANDROID_ID;
                }

                if (fakeValue != null) {
                    Log.w(TAG, "Spoofed Java Settings field: " + settingKey + " -> " + fakeValue);
                    Bundle fakeResult = new Bundle();
                    fakeResult.putString("value", fakeValue);
                    return fakeResult;
                }
            }
        }
        return method.invoke(originalProvider, args);
    }

    private static void unseal() {
        try {
            // 1. Get the getDeclaredMethod from Class
            Method getDeclaredMethod = Class.class.getDeclaredMethod("getDeclaredMethod", String.class, Class[].class);
            Class<?> vmRuntimeClass = Class.forName("dalvik.system.VMRuntime");

            // 2. Get VMRuntime.getRuntime()
            // We use (Object) null to ensure the second parameter (Class[]) is treated as null, not as an Object[] wrapper
            Method getRuntimeMethod = (Method) getDeclaredMethod.invoke(vmRuntimeClass, "getRuntime", (Object) null);
            Object vmRuntime = getRuntimeMethod.invoke(null);

            // 3. Get VMRuntime.setHiddenApiExemptions(String[])
            // Note the nested array: we are passing an array that contains an array. This is critical.
            Method setExemptionsMethod = (Method) getDeclaredMethod.invoke(vmRuntimeClass, "setHiddenApiExemptions", (Object) new Class[]{String[].class});
            
            // 4. Trigger the bypass
            setExemptionsMethod.invoke(vmRuntime, (Object) new String[][]{new String[]{"L"}});
            
            Log.w(TAG, "VM Unsealed: Hidden API restrictions removed.");
        } catch (Throwable e) {
            // If the above fails, there is an alternative way for Android 15/16
            try {
                Method forName = Class.class.getDeclaredMethod("forName", String.class);
                Method getDeclaredMethod = Class.class.getDeclaredMethod("getDeclaredMethod", String.class, Class[].class);
                Class<?> vmRuntimeClass = (Class<?>) forName.invoke(null, "dalvik.system.VMRuntime");
                Method getRuntime = (Method) getDeclaredMethod.invoke(vmRuntimeClass, "getRuntime", (Object) null);
                Object vmRuntime = getRuntime.invoke(null);
                Method setHiddenApiExemptions = (Method) getDeclaredMethod.invoke(vmRuntimeClass, "setHiddenApiExemptions", (Object) new Class[]{String[].class});
                setHiddenApiExemptions.invoke(vmRuntime, new Object[]{new String[]{"L"}});
                Log.w(TAG, "VM Unsealed (Alt Method Success).");
            } catch (Throwable e2) {
                Log.e(TAG, "Fatal: Could not unseal VM", e2);
            }
        }
    }

    public static void install() {
        new Thread(() -> {
            // Step 1: Kill the API guards before doing any reflection
            unseal();

            try {
                Log.w(TAG, "SettingsHook: Waiting for Application context...");
                Object activityThread = null;
                Context appContext = null;

                for (int i = 0; i < 500; i++) {
                    Class<?> atClass = Class.forName("android.app.ActivityThread");
                    activityThread = atClass.getMethod("currentActivityThread").invoke(null);
                    if (activityThread != null) {
                        appContext = (Context) atClass.getMethod("getApplication").invoke(activityThread);
                        if (appContext != null) break;
                    }
                    Thread.sleep(20);
                }

                if (appContext == null) {
                    Log.e(TAG, "Failed to get Application context.");
                    return;
                }

                // Step 2: Warm up the Binder connection
                android.provider.Settings.Global.getString(appContext.getContentResolver(), "adb_enabled");
                android.provider.Settings.Secure.getString(appContext.getContentResolver(), "android_id");

                String[] targetClasses = {"android.provider.Settings$Global", "android.provider.Settings$Secure", "android.provider.Settings$System"};
                Class<?> iContentProviderClass = Class.forName("android.content.IContentProvider");

                for (String className : targetClasses) {
                    try {
                        Class<?> clazz = Class.forName(className);
                        Field sNameValueCacheField = clazz.getDeclaredField("sNameValueCache");
                        sNameValueCacheField.setAccessible(true);
                        Object cache = sNameValueCacheField.get(null);
                        if (cache == null) continue;

                        // Step 3: Purge cache (Now allowed because of unseal)
                        try {
                            Field mValuesField = cache.getClass().getDeclaredField("mValues");
                            mValuesField.setAccessible(true);
                            Object mValues = mValuesField.get(cache);
                            if (mValues != null) {
                                // ArrayMap implements Map, so we can cast to clear it
                                ((java.util.Map) mValues).clear();
                                Log.d(TAG, "Cache cleared for " + className);
                            }
                        } catch (Throwable e) {
                            Log.w(TAG, "Could not clear cache map for " + className);
                        }

                        Field mProviderHolderField = cache.getClass().getDeclaredField("mProviderHolder");
                        mProviderHolderField.setAccessible(true);
                        Object providerHolder = mProviderHolderField.get(cache);

                        Field mContentProviderField = providerHolder.getClass().getDeclaredField("mContentProvider");
                        mContentProviderField.setAccessible(true);
                        Object original = mContentProviderField.get(providerHolder);

                        if (original == null || Proxy.isProxyClass(original.getClass())) continue;

                        Object proxy = Proxy.newProxyInstance(
                            iContentProviderClass.getClassLoader(),
                            new Class[]{iContentProviderClass},
                            new SettingsHook(original)
                        );

                        mContentProviderField.set(providerHolder, proxy);
                        Log.w(TAG, "Successfully hijacked Binder for " + className);
                    } catch (Exception e) {
                        Log.e(TAG, "Failed hijacking class: " + className, e);
                    }
                }
            } catch (Exception e) {
                Log.e(TAG, "Async install fatal error", e);
            }
        }).start();
    }
}
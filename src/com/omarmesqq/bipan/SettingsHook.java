package com.omarmesqq.bipan;

import android.os.Bundle;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.lang.reflect.Field;
import android.content.Context;

public class SettingsHook implements InvocationHandler {
    private final Object originalProvider;

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
                    fakeValue = "a1b2c3d4e5f6g7h8";
                }

                if (fakeValue != null) {
                    android.util.Log.w("Bipan", "SPOOFED: " + settingKey + " -> " + fakeValue);
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
            // Fix the Double-Reflection Array Mismatch
            Method getDeclaredMethod = Class.class.getDeclaredMethod("getDeclaredMethod", String.class, Class[].class);
            Class<?> vmRuntimeClass = Class.forName("dalvik.system.VMRuntime");

            // Use (Class[]) null to explicitly tell the VM we are passing NO parameters for getRuntime()
            Method getRuntimeMethod = (Method) getDeclaredMethod.invoke(vmRuntimeClass, "getRuntime", (Class[]) null);
            Object vmRuntime = getRuntimeMethod.invoke(null);

            // Wrap the Class array in an Object array to prevent Method.invoke from flattening it
            Method setExemptionsMethod = (Method) getDeclaredMethod.invoke(vmRuntimeClass, "setHiddenApiExemptions", new Object[]{new Class[]{String[].class}});
            
            // Execute the bypass
            setExemptionsMethod.invoke(vmRuntime, new Object[]{new String[]{"L"}});
            android.util.Log.w("Bipan", "VM Unsealed: Hidden API restrictions removed.");
        } catch (Throwable e) {
            android.util.Log.e("Bipan", "Failed to unseal VM: " + e.getMessage());
        }
    }

    public static void install() {
        new Thread(() -> {
            // Step 1: Kill the API guards before doing any reflection
            unseal();

            try {
                android.util.Log.w("Bipan", "SettingsHook: Waiting for Application context...");
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
                    android.util.Log.e("Bipan", "Failed to get Application context.");
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
                                android.util.Log.d("Bipan", "Cache cleared for " + className);
                            }
                        } catch (Throwable e) {
                            android.util.Log.w("Bipan", "Could not clear cache map for " + className);
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
                        android.util.Log.w("Bipan", "Successfully hijacked Binder for " + className);
                    } catch (Exception e) {
                        android.util.Log.e("Bipan", "Failed hijacking class: " + className, e);
                    }
                }
            } catch (Exception e) {
                android.util.Log.e("Bipan", "Async install fatal error", e);
            }
        }).start();
    }
}
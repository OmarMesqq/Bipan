package com.omarmesqq.bipan.modules;

import android.content.Context;
import android.os.Bundle;
import android.util.Log;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.security.SecureRandom;
import java.util.Map;
import com.omarmesqq.bipan.BaseHook;
import android.provider.Settings.Secure;
import android.provider.Settings.Global;;

public class SettingsHook implements BaseHook, InvocationHandler {
  private static final String TAG = "BipanSettingsHook";
  private Object originalProvider;

  private static final String RANDOM_ANDROID_ID = generateRandomId();
  private static final String FAKE_BOOT_COUNT = "43";

  private static final Set<String> ALLOWLIST = new HashSet<>(
      Arrays.asList("com.spotify.music"));
  private static String currentPackageName = "unknown";

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

      if (settingKey != null) {
        if ("android_id".equals(settingKey)) {
          if (ALLOWLIST.contains(currentPackageName)) {
            Log.i(TAG, "Returning true SSAID for allowlisted app: " + currentPackageName);
            return method.invoke(originalProvider, args);
          } else {
            Log.w(TAG, currentPackageName + " is reading SSAID");
          }
        }
      }

      if (callingMethod != null && settingKey != null) {
        String fakeValue = null;
        if ("GET_global".equals(callingMethod)) {
          switch (settingKey) {
            case "adb_enabled":
            case "development_settings_enabled":
            case "wait_for_debugger":
              fakeValue = "0";
              break;
            case "boot_count":
              fakeValue = FAKE_BOOT_COUNT;
              break;
          }
        } else if ("GET_secure".equals(callingMethod)
            && "android_id".equals(settingKey)) {
          fakeValue = RANDOM_ANDROID_ID;
        }

        if (fakeValue != null) {
          Log.d(TAG, "Spoofed Settings field " + settingKey + ": " + fakeValue);
          Bundle fakeResult = new Bundle();
          fakeResult.putString("value", fakeValue);
          return fakeResult;
        }
      }
    }
    return method.invoke(originalProvider, args);
  }

  @Override
  public void install(Context context) throws Exception {
    currentPackageName = context.getPackageName();
    // Warm up the Binder connection
    Global.getString(context.getContentResolver(), "adb_enabled");
    Secure.getString(context.getContentResolver(), "android_id");

    String[] targetClasses = {
        "android.provider.Settings$Global",
        "android.provider.Settings$Secure",
        "android.provider.Settings$System"
    };

    Class<?> iContentProviderClass = Class.forName("android.content.IContentProvider");

    for (String className : targetClasses) {

      Class<?> clazz = Class.forName(className);
      Field sNameValueCacheField = clazz.getDeclaredField("sNameValueCache");
      sNameValueCacheField.setAccessible(true);
      Object cache = sNameValueCacheField.get(null);
      if (cache == null) {
        continue;
      }

      // Purge cache
      Field mValuesField = cache.getClass().getDeclaredField("mValues");
      mValuesField.setAccessible(true);
      Object mValues = mValuesField.get(cache);
      if (mValues != null) {
        // Apparently, ArrayMap implements Map, so we can cast to it
        ((Map<?, ?>) mValues).clear();
      } else {
        Log.w(TAG, "Failed to purge cache ache cleared for: " + className);
      }

      Field mProviderHolderField = cache.getClass().getDeclaredField("mProviderHolder");
      mProviderHolderField.setAccessible(true);
      Object providerHolder = mProviderHolderField.get(cache);

      Field mContentProviderField = providerHolder.getClass().getDeclaredField("mContentProvider");
      mContentProviderField.setAccessible(true);
      Object original = mContentProviderField.get(providerHolder);

      if (original == null || Proxy.isProxyClass(original.getClass())) {
        Log.w(TAG, "Original Content Provider field of " + className + " is null! Skipping...");
        continue;
      }

      this.originalProvider = original;

      Object proxy = Proxy.newProxyInstance(
          iContentProviderClass.getClassLoader(),
          new Class[] { iContentProviderClass },
          this);

      mContentProviderField.set(providerHolder, proxy);
      Log.d(TAG, "Hijacked Binder for " + className);
    }
  }

  private static String generateRandomId() {
    SecureRandom random = new SecureRandom();
    byte[] bytes = new byte[8]; // 64 bits = 16 hex chars
    random.nextBytes(bytes);
    StringBuilder sb = new StringBuilder();
    for (byte b : bytes) {
      sb.append(String.format("%02x", b));
    }
    return sb.toString();
  }
}

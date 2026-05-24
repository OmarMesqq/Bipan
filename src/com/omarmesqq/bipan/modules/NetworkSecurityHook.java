package com.omarmesqq.bipan.modules;

import android.content.Context;
import android.util.Log;
import com.omarmesqq.bipan.BaseHook;
import java.lang.reflect.Field;
import java.util.Collection;
import java.util.Map;

public class NetworkSecurityHook implements BaseHook {
  private static final String TAG = "BipanSecurityHook";

  @Override
  public void install(Context context) throws Exception {
    try {
      Log.d(TAG, "[*] Starting deep-inspection of NetworkSecurity architecture...");

      // 1. Locate the runtime active configuration instance
      Class<?> configConfigClass = Class.forName("android.security.net.config.ApplicationConfig");
      Object appConfig = configConfigClass.getMethod("getDefaultInstance").invoke(null);

      if (appConfig == null) {
        Log.e(TAG, "[-] ApplicationConfig.getDefaultInstance() returned null. Network config not initialized yet.");
        return;
      }

      // 2. Fetch the OS-level empty pin set rule to use as a replacement template
      Class<?> pinSetClass = Class.forName("android.security.net.config.PinSet");
      Field emptyPinSetField = pinSetClass.getDeclaredField("EMPTY_PINSET");
      emptyPinSetField.setAccessible(true);
      Object emptyPinSet = emptyPinSetField.get(null);
      Log.d(TAG, "[+] Successfully retrieved system EMPTY_PINSET instance.");

      // 3. Process the explicit Per-Domain Config Collection (mConfigs)
      Field configMapField = configConfigClass.getDeclaredField("mConfigs");
      configMapField.setAccessible(true);
      Object configsObject = configMapField.get(appConfig);

      if (configsObject != null) {
        Log.d(TAG, "[*] mConfigs runtime storage type: " + configsObject.getClass().getName());

        if (configsObject instanceof Collection) {
          Collection<?> configCollection = (Collection<?>) configsObject;
          Log.d(TAG, "[*] Processing " + configCollection.size() + " domain configuration blocks...");
          for (Object element : configCollection) {
            if (element == null)
              continue;

            // Critical Step: Android stores elements inside an ArraySet wrapped as a Pair
            // object
            Object targetedConfig = element;
            if (element.getClass().getName().equals("android.util.Pair")) {
              Field secondField = element.getClass().getDeclaredField("second");
              secondField.setAccessible(true);
              targetedConfig = secondField.get(element);
              Log.d(TAG, "[+] Unpacked NetworkSecurityConfig from android.util.Pair container.");
            }

            neuterConfigPins(targetedConfig, emptyPinSet);
          }
        } else if (configsObject instanceof Map) {
          Map<?, ?> configMap = (Map<?, ?>) configsObject;
          for (Map.Entry<?, ?> entry : configMap.entrySet()) {
            neuterConfigPins(entry.getKey(), emptyPinSet);
            neuterConfigPins(entry.getValue(), emptyPinSet);
          }
        }
      } else {
        Log.w(TAG, "[-] mConfigs field is empty/null.");
      }

      // 4. Process the Global Fallback Config (mDefaultConfig)
      try {
        Field defaultConfigField = configConfigClass.getDeclaredField("mDefaultConfig");
        defaultConfigField.setAccessible(true);
        Object defaultConfigObj = defaultConfigField.get(appConfig);
        if (defaultConfigObj != null) {
          Log.d(TAG, "[*] Found mDefaultConfig fallback block. Neutralizing...");
          neuterConfigPins(defaultConfigObj, emptyPinSet);
        }
      } catch (NoSuchFieldException e) {
        Log.w(TAG, "[-] mDefaultConfig field not found on this platform version.");
      }

      Log.i(TAG, "[+] NetworkSecurityTrustManager security mechanisms altered completely.");
    } catch (Throwable t) {
      Log.e(TAG, "[!] Core failure executing NetworkSecurity structural modification", t);
    }
  }

  /**
   * Directly reassigns the private final mPins field inside a target
   * NetworkSecurityConfig object
   */
  private void neuterConfigPins(Object configObj, Object emptyPinSet) {
    if (configObj == null)
      return;

    String objClassName = configObj.getClass().getName();
    // Prevent analyzing container types or mismatched elements passed during
    // unpacking loops
    if (!objClassName.contains("NetworkSecurityConfig")) {
      return;
    }

    try {
      Class<?> clazz = configObj.getClass();
      boolean fieldPatched = false;

      while (clazz != null && clazz != Object.class) {
        try {
          Field pinsField = clazz.getDeclaredField("mPins");
          pinsField.setAccessible(true);

          // Overwrite the final field reference in memory with the empty verification
          // profile
          pinsField.set(configObj, emptyPinSet);
          Log.i(TAG, "[███] SUCCESS: Overwrote mPins configuration to EMPTY_PINSET inside: " + clazz.getName());
          fieldPatched = true;
          break;
        } catch (NoSuchFieldException e) {
          clazz = clazz.getSuperclass();
        }
      }

      if (!fieldPatched) {
        Log.w(TAG, "[-] Could not locate mPins field layout inside object type: " + objClassName);
      }
    } catch (Throwable t) {
      Log.e(TAG, "[-] Error reassigning security field descriptor: " + t.getMessage(), t);
    }
  }
}
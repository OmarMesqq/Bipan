package com.omarmesqq.bipan;

import android.content.Context;
import android.util.Log;
import com.omarmesqq.bipan.modules.*;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;

public class BipanJava {
  private static final String TAG = "BipanJava";
  private static final int GET_APPLICATION_CONTEXT_MAX_RETRIES = 1000;
  private static final int GET_APPLICATION_CONTEXT_THREAD_SLEEP_TIME_MS = 5;

  /**
   * Entrypoint of Java-layer hooks called by Bipan in C++
   */
  public static void install() {
    new Thread(() -> {
      try {
        unseal();

        Context appContext = waitForContext();

        if (appContext != null) {
          loadModules(appContext);
        } else {
          Log.e(TAG, "Failed to get Application Context!");
        }
      } catch (Exception e) {
        Log.wtf(TAG, "[!] Fatal exception in install(): ", e);
      }
    }).start();
  }

  private static void loadModules(Context context) {
    List<BaseHook> modules = new ArrayList<>();

    modules.add(new SettingsHook());
    modules.add(new InstallerInfoHook());
    modules.add(new AntiScreenshotDetectionHook());
    modules.add(new AntiDiscoveryHook());
    modules.add(new NetworkSpoofingHook());

    for (BaseHook module : modules) {
      try {
        module.install(context);
        Log.i(TAG, "Module successfully loaded: " + module.getClass().getSimpleName());
      } catch (Exception e) {
        Log.e(TAG, "Failed to load module: " + module.getClass().getName(), e);
      }
    }
  }

  private static Context waitForContext() throws Exception {
    for (int i = 0; i < GET_APPLICATION_CONTEXT_MAX_RETRIES; i++) {

      Class<?> atClass = Class.forName("android.app.ActivityThread");
      Object activityThread = atClass.getMethod("currentActivityThread").invoke(null);

      if (activityThread != null) {
        Context ctx = (Context) atClass.getMethod("getApplication").invoke(activityThread);
        if (ctx != null) {
          return ctx;
        }
      }

      Thread.sleep(GET_APPLICATION_CONTEXT_THREAD_SLEEP_TIME_MS);
    }
    return null;
  }

  /**
   * Neuters hidden API restrictions in bleeding-edge Android versions
   * NOTE: should be called before install()
   */
  private static void unseal() {
    try {
      // 1. Get the getDeclaredMethod from Class
      Method getDeclaredMethod = Class.class.getDeclaredMethod(
          "getDeclaredMethod", String.class, Class[].class);
      Class<?> vmRuntimeClass = Class.forName("dalvik.system.VMRuntime");

      // 2. Get VMRuntime.getRuntime()
      // We use (Object) null to ensure the second parameter (Class[]) is
      // treated as null, not as an Object[] wrapper
      Method getRuntimeMethod = (Method) getDeclaredMethod.invoke(
          vmRuntimeClass, "getRuntime", (Object) null);
      Object vmRuntime = getRuntimeMethod.invoke(null);

      // 3. Get VMRuntime.setHiddenApiExemptions(String[])
      // Note the nested array: we are passing an array that contains an array.
      // This is critical.
      Method setExemptionsMethod = (Method) getDeclaredMethod.invoke(vmRuntimeClass,
          "setHiddenApiExemptions", (Object) new Class[] { String[].class });

      // 4. Trigger the bypass
      setExemptionsMethod.invoke(
          vmRuntime, (Object) new String[][] { new String[] { "L" } });

      Log.i(TAG, "ART VM unsealed (Legacy approach)");
    } catch (Throwable e) {
      try {
        Method forName = Class.class.getDeclaredMethod("forName", String.class);
        Method getDeclaredMethod = Class.class.getDeclaredMethod(
            "getDeclaredMethod", String.class, Class[].class);
        Class<?> vmRuntimeClass = (Class<?>) forName.invoke(null, "dalvik.system.VMRuntime");
        Method getRuntime = (Method) getDeclaredMethod.invoke(
            vmRuntimeClass, "getRuntime", (Object) null);
        Object vmRuntime = getRuntime.invoke(null);
        Method setHiddenApiExemptions = (Method) getDeclaredMethod.invoke(
            vmRuntimeClass, "setHiddenApiExemptions",
            (Object) new Class[] { String[].class });
        setHiddenApiExemptions.invoke(
            vmRuntime, new Object[] { new String[] { "L" } });
        Log.i(TAG, "ART VM unsealed (Modern approach)");
      } catch (Throwable e2) {
        Log.e(TAG, "Fatal: Could not unseal VM", e2);
      }
    }
  }
}

package b;

import android.content.Context;
import android.util.Log;
import b.modules.*;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import android.app.Instrumentation;
import android.os.Bundle;
import android.app.Application;
import java.lang.OutOfMemoryError;
import android.app.Activity;

/**
 * Entrypoint of BipanJava
 */
public class J {
  private static final String TAG = "BipanJava";
  private static final AtomicBoolean instrumentationHooked = new AtomicBoolean(false);

  // Spare GMS and Play Store from most hooks
  private static final Set<String> GLOBAL_ALLOW_LIST = new HashSet<>(Arrays.asList(
      "com.android.vending",
      "com.google.android.gms"));

  /**
   * hookInstrumentation:
   * Triggered at either clampGrowthLimit or clearGrowthLimit.
   * Blocks the start of the app's main thread
   * and **Java** code for module loading and singleton swapping
   */
  public static void h() throws Exception {
    if (!instrumentationHooked.compareAndSet(false, true)) {
      // both clampGrowthLimit and clearGrowthLimit may fire, only hook once
      return;
    }

    try {
      Class<?> atClz = Class.forName("android.app.ActivityThread");
      Object at = atClz.getMethod("currentActivityThread").invoke(null);
      if (at == null) {
        throw new Exception("hookInstrumentation: ActivityThread is null!");
      }

      Field mInstrField = atClz.getDeclaredField("mInstrumentation");
      mInstrField.setAccessible(true);
      final Object realInstr = mInstrField.get(at);
      if (realInstr == null) {
        throw new Exception("hookInstrumentation: mInstrumentation is null!");
      }

      Instrumentation hooked = new Instrumentation() {
        @Override
        public void onCreate(Bundle args) {
          try {
            Context ctx = (Context) Class.forName("android.app.ActivityThread").getMethod("currentApplication")
                .invoke(null);
            if (ctx == null) {
              throw new OutOfMemoryError(TAG + "[!] Context still null during Instrumentation.onCreate!");
            }
            loadModules(ctx);
          } catch (Exception e) {
            throw new OutOfMemoryError(TAG + " [!] [1] Instrumentation.onCreate failure: " + e.getMessage());
          }

          try {
            realInstr.getClass()
                .getMethod("onCreate", Bundle.class)
                .invoke(realInstr, args);
          } catch (Exception e) {
            throw new OutOfMemoryError(TAG + "[!] [2] Instrumentation.onCreate failure: " + e.getMessage());
          }
        }

        @Override
        public void callApplicationOnCreate(Application app) {
          // Hijack Application's ConnectivityManager
          if (NetworkSpoofingHook.s_cmProxy != null) {
            try {
              NetworkSpoofingHook.patchConnectivityManager(app);
            } catch (Exception e) {
              throw new OutOfMemoryError(
                  TAG + "[!] Instrumentation.callApplicationOnCreate exception: " + e.getMessage());
            }
          }
          try {
            realInstr.getClass()
                .getMethod("callApplicationOnCreate", Application.class)
                .invoke(realInstr, app);
          } catch (Exception e) {
            throw new OutOfMemoryError(
                TAG + "[!] Instrumentation.callApplicationOnCreate exception: " + e.getMessage());
          }
        }

        @Override
        public void callActivityOnCreate(Activity activity, Bundle icicle) {
          // Hijack Activity's PackageManager
          if (AntiAppInspectionHook.s_mPMField != null && AntiAppInspectionHook.s_pmProxy != null) {
            try {
              AntiAppInspectionHook.patchPackageManager(activity.getPackageManager());
            } catch (Exception e) {
              throw new OutOfMemoryError(
                  TAG + "[!] [1] Instrumentation.callActivityOnCreate exception: " + e.getMessage());
            }
          }

          // Hijack Activity's ConnectivityManager
          if (NetworkSpoofingHook.s_cmProxy != null) {
            try {
              NetworkSpoofingHook.patchConnectivityManager(activity);
            } catch (Exception e) {
              throw new OutOfMemoryError(
                  TAG + "[!] [2] Instrumentation.callActivityOnCreate exception: " + e.getMessage());
            }
          }

          try {
            realInstr.getClass()
                .getMethod("callActivityOnCreate",
                    Activity.class,
                    Bundle.class)
                .invoke(realInstr, activity, icicle);
          } catch (Exception e) {
            throw new OutOfMemoryError(
                TAG + "[!] [3] Instrumentation.callActivityOnCreate exception: " + e.getMessage());
            // super.callActivityOnCreate(activity, icicle);
          }
        }
      };

      Field mThreadField = Instrumentation.class.getDeclaredField("mThread");
      mThreadField.setAccessible(true);
      mThreadField.set(hooked, mThreadField.get(realInstr));

      // This should block before ContentProviders and onCreate
      mInstrField.set(at, hooked);
    } catch (Exception e) {
      Log.e(TAG, "hookInstrumentation failed: ", e);
      throw e;
    }
  }

  /**
   * `install`:
   * unseals ART VM at postAppSpecialize so modules access and modify
   * hidden/restricted APIs
   */
  public static void i() {
    try {
      unseal();
    } catch (Exception e) {
      throw new OutOfMemoryError(TAG + "install exception: " + e.getCause().toString());
    }
  }

  private static void loadModules(Context context) throws Exception {
    String packageName = context.getPackageName();
    List<BaseHook> modules = new ArrayList<>();

    if (GLOBAL_ALLOW_LIST.contains(packageName)) {
      modules.add(new AntiNetworkDiscoveryHook());
    } else {
      /**
       * Isolated processes (Services to be more precise) are quite restricted
       * and can't touch most system APIs, so just install modules for things it
       * CAN touch
       * 
       * https://developer.android.com/guide/topics/manifest/service-element#isolated
       */
      if (isIsolatedProcess()) {
        modules.add(new AntiAppInspectionHook());
        modules.add(new SystemPropertiesHook());
        modules.add(new DexLoaderMonitorHook());
      } else {
        // ---------------------------------------------
        /**
         * These two should be the first to load,
         * as they expose public methods that block
         * the app's main thread (for PM and CM hooking
         * both Application and Activity-wise)
         * 
         * TODO: refactor to undo this tight coupling
         */
        modules.add(new AntiAppInspectionHook());
        modules.add(new NetworkSpoofingHook());
        // ---------------------------------------------
        modules.add(new DexLoaderMonitorHook());
        modules.add(new SettingsHook());
        modules.add(new SystemPropertiesHook());
        modules.add(new AntiNetworkDiscoveryHook());
        modules.add(new TelephonyManagerHook());
        modules.add(new AntiScreenshotDetectionHook());
      }
    }

    for (BaseHook module : modules) {
      module.install(context);
    }
    Log.i(TAG, "All modules loaded successfully :)");
  }

  private static void unseal() throws Exception {
    try {
      Method getDeclaredMethod = Class.class.getDeclaredMethod(
          "getDeclaredMethod", String.class, Class[].class);
      Class<?> vmRuntimeClass = Class.forName("dalvik.system.VMRuntime");
      Method getRuntimeMethod = (Method) getDeclaredMethod.invoke(
          vmRuntimeClass, "getRuntime", (Object) null);
      Object vmRuntime = getRuntimeMethod.invoke(null);
      Method setExemptionsMethod = (Method) getDeclaredMethod.invoke(
          vmRuntimeClass, "setHiddenApiExemptions",
          (Object) new Class[] { String[].class });
      setExemptionsMethod.invoke(
          vmRuntime, (Object) new String[][] { new String[] { "L" } });
      Log.i(TAG, "ART VM unsealed (Legacy approach)");
    } catch (Throwable e) {
      try {
        Method forName = Class.class.getDeclaredMethod(
            "forName", String.class);
        Method getDeclaredMethod = Class.class.getDeclaredMethod(
            "getDeclaredMethod", String.class, Class[].class);
        Class<?> vmRuntimeClass = (Class<?>) forName.invoke(
            null, "dalvik.system.VMRuntime");
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
        throw e2;
      }
    }
  }

  private static boolean isIsolatedProcess() {
    try {
      Class<?> processClass = Class.forName("android.os.Process");
      Method isIsolated = processClass.getDeclaredMethod("isIsolated");
      boolean isolated = (boolean) isIsolated.invoke(null);
      if (isolated) {
        Class<?> atClz = Class.forName("android.app.ActivityThread");
        Method currentProcessName = atClz.getDeclaredMethod("currentProcessName");
        String processName = (String) currentProcessName.invoke(null);
        Log.w(TAG, "Isolated process detected: " + processName + " . Skipping most modules");
      }

      return isolated;
    } catch (Exception e) {
      Log.e(TAG, "isIsolatedProcess exception!", e);
      return false;
    }
  }
}
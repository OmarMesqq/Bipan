package com.omarmesqq.bipan;

import android.content.Context;
import android.util.Log;
import com.omarmesqq.bipan.modules.*;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;

public class BipanJava {
  private static final String TAG = "BipanJava";
  private static boolean isInitialized = false;

  /**
   * Phase 1: Early Zygote Entrypoint
   * Called directly in C++ via bootstrapJavaPayload() inside postAppSpecialize.
   * Only unseals the hidden APIs; does not look for Context yet.
   */
  public static void install() {
    try {
      unseal();
      Log.i(TAG, "Early injection phase complete. VM unsealed.");
    } catch (Exception e) {
      Log.wtf(TAG, "[!] Fatal exception in early install(): ", e);
    }
  }

  /**
   * Phase 2: Application Binding Entrypoint
   * Triggered synchronously from your C++ my_clampGrowthLimit JNI hook.
   */
  public static void initializeModules() {
    try {
      android.os.Handler handler = new android.os.Handler(android.os.Looper.getMainLooper());
      handler.post(() -> {
        try {
          // Check the guard inside the main looper execution block
          if (isInitialized) {
            return;
          }

          Class<?> atClass = Class.forName("android.app.ActivityThread");
          Object activityThread = atClass.getMethod("currentActivityThread").invoke(null);

          if (activityThread != null) {
            Context ctx = (Context) atClass.getMethod("getApplication").invoke(activityThread);
            if (ctx != null) {
              isInitialized = true;
              loadModules(ctx);
              Log.i(TAG, "All sandboxing modules successfully synchronized on the Main Thread!");
              return;
            }
          }
          Log.e(TAG, "Failed to resolve Context during deferred main looper execution!");
        } catch (Exception e) {
          Log.wtf(TAG, "Deferred module initialization failed: ", e);
        }
      });
    } catch (Exception e) {
      Log.wtf(TAG, "Failed to post initialization task to Main Looper: ", e);
    }
  }

  private static void loadModules(Context context) {
    List<BaseHook> modules = new ArrayList<>();

    modules.add(new SettingsHook());
    modules.add(new InstallerInfoHook());
    modules.add(new NetworkHook());
    modules.add(new ScreenCaptureHook());
    modules.add(new SecurityFlagHook());
    modules.add(new NsdHook());
    modules.add(new MediaRouterHook());
    modules.add(new WifiHook());
    modules.add(new ConnectivityHook());

    for (BaseHook module : modules) {
      try {
        module.install(context);
        Log.i(TAG, "Module successfully loaded: " + module.getClass().getSimpleName());
      } catch (Exception e) {
        Log.e(TAG, "Failed to load module: " + module.getClass().getName(), e);
      }
    }
  }

  /**
   * Neuters hidden API restrictions in bleeding-edge Android versions
   */
  private static void unseal() {
    try {
      Method getDeclaredMethod = Class.class.getDeclaredMethod(
          "getDeclaredMethod", String.class, Class[].class);
      Class<?> vmRuntimeClass = Class.forName("dalvik.system.VMRuntime");

      Method getRuntimeMethod = (Method) getDeclaredMethod.invoke(
          vmRuntimeClass, "getRuntime", (Object) null);

      // FIXED: Removed the redundant .getRuntimeMethod field reference
      Object vmRuntime = getRuntimeMethod.invoke(null);

      Method setExemptionsMethod = (Method) getDeclaredMethod.invoke(vmRuntimeClass,
          "setHiddenApiExemptions", (Object) new Class[] { String[].class });

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
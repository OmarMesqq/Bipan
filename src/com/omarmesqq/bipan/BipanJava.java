package com.omarmesqq.bipan;

import android.content.Context;
import android.util.Log;
import com.omarmesqq.bipan.modules.*;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicBoolean;
import android.app.Instrumentation;
import android.os.Bundle;
import android.app.Application;
import java.lang.OutOfMemoryError;

public class BipanJava {
  private static final String TAG = "BipanJava";

  private static final long WAIT_UNTIL_MODULES_READY_TIMEOUT_MS = 15000;

  private static final CountDownLatch modulesReady = new CountDownLatch(1);
  private static final AtomicBoolean instrumentationHooked = new AtomicBoolean(false);

  /**
   * Phase 2: called from C++ my_clampGrowthLimit / my_clearGrowthLimit.
   * At this point mInstrumentation is guaranteed set — it is assigned
   * in handleBindApplication just before clamp/clearGrowthLimit fires.
   * Hooks Instrumentation.onCreate() to block until modules are ready,
   * preventing Application.onCreate() from running with unhooked PM.
   */
  public static void hookInstrumentationNow() {
    if (!instrumentationHooked.compareAndSet(false, true)) {
      return; // both clamp and clear may fire — only hook once
    }

    try {
      Class<?> atClz = Class.forName("android.app.ActivityThread");
      Object at = atClz.getMethod("currentActivityThread").invoke(null);
      if (at == null) {
        throw new Exception("hookInstrumentationNow: ActivityThread is null!");
      }

      Field mInstrField = atClz.getDeclaredField("mInstrumentation");
      mInstrField.setAccessible(true);
      final Object realInstr = mInstrField.get(at);
      if (realInstr == null) {
        throw new Exception("hookInstrumentationNow: mInstrumentation is null!");
      }

      Instrumentation hooked = new Instrumentation() {
        @Override
        public void onCreate(Bundle args) {
          // Fires after mInitialApplication is set,
          // before installContentProviders and app.onCreate()
          try {
            boolean done = modulesReady.await(WAIT_UNTIL_MODULES_READY_TIMEOUT_MS,
                java.util.concurrent.TimeUnit.MILLISECONDS);
            if (!done) {
              throw new OutOfMemoryError("[!] BipanJava: Module loading timed out! Refusing to proceed!");
            } else {
              // Log.i(TAG, "Instrumentation.onCreate — modules ready");
            }
          } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
          }

          try {
            realInstr.getClass()
                .getMethod("onCreate", android.os.Bundle.class)
                .invoke(realInstr, args);
          } catch (Exception e) {
            Log.e(TAG, "[!] Failed to call original Instrumentation onCreate! Reason: " + e.getMessage());
          }
        }

        @Override
        public void callApplicationOnCreate(Application app) {
          try {
            realInstr.getClass()
                .getMethod("callApplicationOnCreate",
                    android.app.Application.class)
                .invoke(realInstr, app);
          } catch (Exception e) {
            Log.e(TAG, "Unknown exception captured at Instrumentation.callApplicationOnCreate: " + e);
            super.callApplicationOnCreate(app);
          }
        }

        @Override
        public void callActivityOnCreate(android.app.Activity activity, Bundle icicle) {
          // Patch the Activity's PackageManager before onCreate runs
          try {
            AntiAppInspectionHook.patchPackageManager(activity.getPackageManager());
          } catch (Exception ignored) {
          }
          try {
            realInstr.getClass()
                .getMethod("callActivityOnCreate",
                    android.app.Activity.class,
                    android.os.Bundle.class)
                .invoke(realInstr, activity, icicle);
          } catch (Exception e) {
            Log.e(TAG, "callActivityOnCreate failed: " + e.getMessage());
            super.callActivityOnCreate(activity, icicle);
          }
        }
      };

      Field mThreadField = android.app.Instrumentation.class
          .getDeclaredField("mThread");
      mThreadField.setAccessible(true);
      mThreadField.set(hooked, mThreadField.get(realInstr));

      mInstrField.set(at, hooked);
      // Log.i(TAG, "mInstrumentation hooked. This should block before
      // ContentProviders and onCreate.");
    } catch (Exception e) {
      Log.e(TAG, "hookInstrumentationNow failed: ", e);
    }
  }

  /**
   * Phase 1: spawns Bipan thread. Called from C++ bootstrapJavaPayload.
   * Polls mInitialApplication (set right after makeApplicationInner),
   * loads modules, then signals the latch so Instrumentation.onCreate unblocks.
   */
  public static void install() {
    new Thread(() -> {
      try {
        unseal();
        Context ctx = waitForContextDirect();
        loadModules(ctx);
      } catch (Exception e) {
        throw new OutOfMemoryError("[!] BipanJava.install: " + e);
      } finally {
        modulesReady.countDown();
      }
    }).start();
  }

  private static Context waitForContextDirect() throws Exception {
    Class<?> atClass = Class.forName("android.app.ActivityThread");
    Field mInitialApplicationField = atClass.getDeclaredField("mInitialApplication");
    mInitialApplicationField.setAccessible(true);
    Method currentActivityThread = atClass.getMethod("currentActivityThread");

    for (int i = 0; i < 200; i++) {
      try {
        Object at = currentActivityThread.invoke(null);
        if (at != null) {
          Object app = mInitialApplicationField.get(at);
          if (app instanceof Context) {
            return (Context) app;
          }
        }
      } catch (Exception ignored) {
        // Context may not be ready yet, keep going
      }
      Thread.sleep(5);
    }
    throw new OutOfMemoryError("[!] BipanJava: Couldn't get Context! Refusing to proceed!");
  }

  private static void loadModules(Context context) throws Exception {
    spoofOsVersion();

    List<BaseHook> modules = new ArrayList<>();

    modules.add(new AntiAppInspectionHook());
    modules.add(new SettingsHook());
    modules.add(new AntiScreenshotDetectionHook());
    modules.add(new AntiNetworkDiscoveryHook());
    modules.add(new NetworkSpoofingHook());
    modules.add(new TelephonyManagerHook());
    modules.add(new MemoryInfoHook());

    for (BaseHook module : modules) {
      try {
        module.install(context);
        Log.i(TAG, "Module successfully loaded: " + module.getClass().getSimpleName());
      } catch (Exception e) {
        Log.e(TAG, "Failed to load module: " + module.getClass().getName(), e);
        throw e;
      }
    }
  }

  private static void unseal() {
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
      }
    }
  }

  /**
   * https://cs.android.com/android/platform/superproject/+/android-latest-release:libcore/ojluni/src/main/java/java/lang/System.java;l=1799?q=java.lang.System&ss=android%2Fplatform%2Fsuperproject
   */
  private static void spoofOsVersion() {
    try {
      // System.java overrides setProperty to ignore "protected" props
      Class<?> systemClass = Class.forName("java.lang.System");
      Field unchangeablePropsField = systemClass.getDeclaredField("unchangeableProps");

      // `unchangeableProps` is a static field in current AOSP, so we can just put()
      unchangeablePropsField.setAccessible(true);
      Properties unchangeableProps = (Properties) unchangeablePropsField.get(null);

      // Bypasses PropertiesWithNonOverrideableDefaults "protections"
      unchangeableProps.put("os.version", "6.6.56-android16-11-g8a3e2b1c4d5f");
    } catch (Exception e) {
      Log.wtf(TAG, "[!] Failed to spoof os.version: " + e);
    }
  }
}
package com.omarmesqq.bipan;

import android.content.Context;
import android.util.Log;
import com.omarmesqq.bipan.modules.*;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicBoolean;
import android.app.Instrumentation;
import android.os.Bundle;
import android.app.Application;

/**
 * TODO: not satisfied. polling feels hacky, there should
 * be a way to get Application Context right away
 */
public class BipanJava {
  private static final String TAG = "BipanJava";
  private static final int GET_APPLICATION_CONTEXT_MAX_RETRIES = 1000;
  private static final int GET_APPLICATION_CONTEXT_THREAD_SLEEP_TIME_MS = 1;

  private static final CountDownLatch modulesReady = new CountDownLatch(1);
  private static final AtomicBoolean instrumentationHooked = new AtomicBoolean(false);

  private static final long WAIT_UNTIL_MODULES_READY_TIMEOUT_MS = 15000;


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
        Log.e(TAG, "hookInstrumentationNow: ActivityThread is null");
        return;
      }

      Field mInstrField = atClz.getDeclaredField("mInstrumentation");
      mInstrField.setAccessible(true);
      final Object realInstr = mInstrField.get(at);
      if (realInstr == null) {
        Log.e(TAG, "hookInstrumentationNow: mInstrumentation is null");
        return;
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
              Log.e(TAG, "[!] Module loading timed out! Proceeding anyway");
            } else {
              // Log.i(TAG, "Instrumentation.onCreate — modules ready");
            }
          } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
          } catch (Exception e) {
            Log.e(TAG, "Unknown exception captured at Instrumentation.onCreate: " + e);
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
      };

      Field mThreadField = android.app.Instrumentation.class
          .getDeclaredField("mThread");
      mThreadField.setAccessible(true);
      mThreadField.set(hooked, mThreadField.get(realInstr));

      mInstrField.set(at, hooked);
      // Log.i(TAG, "mInstrumentation hooked. This should block before ContentProviders and onCreate.");
    } catch (Exception e) {
      Log.e(TAG, "hookInstrumentationNow failed: ", e);
    }
  }

  /**
   * Phase 3: spawns Bipan thread. Called from C++ bootstrapJavaPayload.
   * Polls mInitialApplication (set right after makeApplicationInner),
   * loads modules, then signals the latch so Instrumentation.onCreate unblocks.
   */
  public static void install() {
    new Thread(() -> {
      try {
        unseal();
        Context ctx = waitForContextDirect();
        if (ctx != null) {
          loadModules(ctx);
        } else {
          Log.e(TAG, "Failed to get Application Context!");
        }
      } catch (Exception e) {
        Log.wtf(TAG, "[!] Fatal exception in install(): ", e);
      } finally {
        modulesReady.countDown();
      }
    }).start();
  }

  private static Context waitForContextDirect() throws Exception {
    Class<?> atClass = Class.forName("android.app.ActivityThread");
    Field mInitialApplicationField = atClass.getDeclaredField("mInitialApplication");
    mInitialApplicationField.setAccessible(true);

    for (int i = 0; i < GET_APPLICATION_CONTEXT_MAX_RETRIES; i++) {
      Object at = atClass.getMethod("currentActivityThread").invoke(null);
      if (at != null) {
        Object app = mInitialApplicationField.get(at);
        if (app instanceof Context) {
          return (Context) app;
        }
        app = atClass.getMethod("getApplication").invoke(at);
        if (app instanceof Context) {
          return (Context) app;
        }
      }
      Thread.sleep(GET_APPLICATION_CONTEXT_THREAD_SLEEP_TIME_MS);
    }
    return null;
  }

  private static void loadModules(Context context) {
    List<BaseHook> modules = new ArrayList<>();

    modules.add(new AntiAppSweepingHook());
    modules.add(new SettingsHook());
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

  /**
   * TODO: maybe reseal if possible?
   */
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
}
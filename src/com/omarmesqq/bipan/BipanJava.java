package com.omarmesqq.bipan;

import android.content.Context;
import android.util.Log;
import com.omarmesqq.bipan.modules.*;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import android.app.Instrumentation;
import android.os.Bundle;
import android.app.Application;
import java.lang.OutOfMemoryError;
import android.app.Activity;

public class BipanJava {
  private static final String TAG = "BipanJava";

  private static final AtomicBoolean instrumentationHooked = new AtomicBoolean(false);

  // Spare microG from most hooks as its harmless (i guess)
  private static final Set<String> GLOBAL_ALLOW_LIST = new HashSet<>(Arrays.asList(
      "com.android.vending",
      "com.google.android.gms"));

  public static void hookInstrumentationNow() throws Exception {
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
          try {
            Context ctx = (Context) Class.forName("android.app.ActivityThread").getMethod("currentApplication")
                .invoke(null);
            if (ctx == null) {
              throw new OutOfMemoryError(TAG + "[!] Context still null during Instrumentation.onCreate!");
            }
            loadModules(ctx);
          } catch (Exception e) {
            throw new OutOfMemoryError(TAG + "[!] [1] Instrumentation.onCreate failure: " + e.getMessage());
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
          // Patch the Activity's PackageManager if app is in blocklist
          if (AntiAppInspectionHook.s_mPMField != null && AntiAppInspectionHook.s_pmProxy != null) {
            try {
              AntiAppInspectionHook.patchPackageManager(activity.getPackageManager());
            } catch (Exception e) {
              throw new OutOfMemoryError(
                  TAG + "[!] [1] Instrumentation.callActivityOnCreate exception: " + e.getMessage());
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
                TAG + "[!] [2] Instrumentation.callActivityOnCreate exception: " + e.getMessage());
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
      Log.e(TAG, "hookInstrumentationNow failed: ", e);
      throw e;
    }
  }

  public static void install() {
    try {
      unseal();
    } catch (Exception e) {
      throw new OutOfMemoryError(TAG + "install exception: " + e.getMessage());
    }
  }

  private static void loadModules(Context context) throws Exception {
    spoofOsVersion();
    String packageName = context.getPackageName();
    List<BaseHook> modules = new ArrayList<>();

    if (GLOBAL_ALLOW_LIST.contains(packageName)) {
      modules.add(new AntiNetworkDiscoveryHook());
    } else {
      // has to be the first to load!
      modules.add(new AntiAppInspectionHook());

      modules.add(new SettingsHook());
      modules.add(new AntiScreenshotDetectionHook());
      modules.add(new AntiNetworkDiscoveryHook());
      modules.add(new NetworkSpoofingHook());
      modules.add(new TelephonyManagerHook());
      modules.add(new MemoryInfoHook());
    }

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

  /**
   * https://cs.android.com/android/platform/superproject/+/android-latest-release:libcore/ojluni/src/main/java/java/lang/System.java;l=1799?q=java.lang.System&ss=android%2Fplatform%2Fsuperproject
   */
  private static void spoofOsVersion() throws Exception {
    // System.java overrides setProperty to ignore "protected" props
    Class<?> systemClass = Class.forName("java.lang.System");
    Field unchangeablePropsField = systemClass.getDeclaredField("unchangeableProps");

    // `unchangeableProps` is a static field in current AOSP, so we can just put()
    unchangeablePropsField.setAccessible(true);
    Properties unchangeableProps = (Properties) unchangeablePropsField.get(null);

    // Bypasses PropertiesWithNonOverrideableDefaults "protections"
    unchangeableProps.put("os.version", "6.6.56-android16-11-g8a3e2b1c4d5f");
  }
}
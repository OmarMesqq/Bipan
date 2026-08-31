package b;

import android.content.Context;
import android.content.pm.PackageManager;
import android.net.ConnectivityManager;
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
import java.util.regex.Pattern;

/**
 * Entrypoint of BipanJava
 */
public class J {
  private static final String TAG = "BipanJava";
  private static final AtomicBoolean instrumentationHooked = new AtomicBoolean(false);

  // ConnectivtyManager
  public static volatile Object s_cmProxy = null;

  // Package Manager
  public static volatile Field s_mPMField = null;
  public static volatile Object s_pmProxy = null;
  public static volatile Field s_mUseField = null;
  public static volatile Field s_mCacheField = null;
  public static volatile Field s_mDisabledField = null;

  // Spare GMS and Play Store from most hooks
  private static final Set<String> GLOBAL_ALLOW_LIST = new HashSet<>(Arrays.asList(
      "com.android.vending",
      "com.google.android.gms"));

  /**
   * `hookInstrumentation`:
   * Triggered at either clampGrowthLimit or clearGrowthLimit.
   * Blocks the start of the app's main thread
   * and **Java** code for module loading and singleton swapping
   */
  public static void h() throws Exception {
    if (!instrumentationHooked.compareAndSet(false, true)) {
      // both clampGrowthLimit and clearGrowthLimit may fire, only hook once
      Log.w(TAG, "hookInstrumentation: race condition in instrumentationHooked flag");
      return;
    }

    try {
      Class<?> atClz = Class.forName("android.app.ActivityThread");
      Object at = atClz.getMethod("currentActivityThread").invoke(null);
      if (at == null) {
        throw cleanThrowable(new Exception("hookInstrumentation: ActivityThread is null!"));
      }

      Field mInstrField = atClz.getDeclaredField("mInstrumentation");
      mInstrField.setAccessible(true);
      final Object realInstr = mInstrField.get(at);
      if (realInstr == null) {
        throw cleanThrowable(new Exception("hookInstrumentation: mInstrumentation is null!"));
      }

      Instrumentation hooked = new Instrumentation() {
        @Override
        public void onCreate(Bundle args) {
          try {
            Context ctx = (Context) Class.forName("android.app.ActivityThread")
                .getMethod("currentApplication")
                .invoke(null);

            if (ctx == null) {
              throw cleanThrowable(
                  new OutOfMemoryError(TAG + " [!] Context still null during Instrumentation.onCreate!"));
            }
            loadModules(ctx);
          } catch (Throwable e) {
            throw cleanThrowable(new OutOfMemoryError(TAG + " Instrumentation.onCreate e: " + e.getCause()));
          }

          try {
            realInstr.getClass()
                .getMethod("onCreate", Bundle.class)
                .invoke(realInstr, args);
          } catch (Exception e) {
            throw cleanThrowable(new OutOfMemoryError(TAG + " Instrumentation.onCreate e: " + e.getCause()));
          }
        }

        @Override
        public void callApplicationOnCreate(Application app) {
          // Hijack Application's ConnectivityManager
          if (s_cmProxy != null) {
            try {
              patchConnectivityManager(app);
            } catch (Throwable e) {
              throw cleanThrowable(new OutOfMemoryError(TAG + " callApplicationOnCreate e: " + e.getCause()));
            }
          }

          // Hijack Application's ContextResolver for GSF
          try {
            GsfIdSpoofHook.reInject();
            // Log.d(TAG, "callApplicationOnCreate: reInjected GSF spoof in Application");
          } catch (Exception e) {
            throw cleanThrowable(new OutOfMemoryError(TAG + " callApplicationOnCreate e: " + e.getCause()));
          }

          try {
            realInstr.getClass()
                .getMethod("callApplicationOnCreate", Application.class)
                .invoke(realInstr, app);
          } catch (Exception e) {
            throw cleanThrowable(new OutOfMemoryError(TAG + " callApplicationOnCreate e: " + e.getCause()));
          }
        }

        @Override
        public void callActivityOnCreate(Activity activity, Bundle icicle) {
          // Hijack Activity's PackageManager
          if (s_mPMField != null && s_pmProxy != null) {
            try {
              patchPackageManager(activity.getPackageManager());
            } catch (Throwable e) {
              throw cleanThrowable(new OutOfMemoryError(TAG + " callActivityOnCreate e: " + e.getCause()));
            }
          }

          // Hijack Activity's ContextResolver for GSF
          try {
            GsfIdSpoofHook.reInject();
            // Log.d(TAG, "callActivityOnCreate: reInjected GSF spoof in Activity");
          } catch (Exception e) {
            throw cleanThrowable(new OutOfMemoryError(TAG + " callActivityOnCreate e: " + e.getCause()));
          }

          // Hijack Activity's ConnectivityManager
          if (s_cmProxy != null) {
            try {
              patchConnectivityManager(activity);
            } catch (Throwable e) {
              throw cleanThrowable(new OutOfMemoryError(TAG + "callActivityOnCreate e: " + e.getCause()));
            }
          }

          try {
            realInstr.getClass()
                .getMethod("callActivityOnCreate",
                    Activity.class,
                    Bundle.class)
                .invoke(realInstr, activity, icicle);
          } catch (Exception e) {
            throw cleanThrowable(new OutOfMemoryError(TAG + " callActivityOnCreate e: " + e.getCause()));
          }
        }

        @Override
        public void callActivityOnResume(Activity activity) {
          // Also hijack Application's Context's `cr` for GSF, once again
          try {
            GsfIdSpoofHook.reInject();
          } catch (Exception e) {
            throw cleanThrowable(new OutOfMemoryError(TAG + " callActivityOnResume: " + e));
          }

          try {
            realInstr.getClass()
                .getMethod("callActivityOnResume", Activity.class)
                .invoke(realInstr, activity);
          } catch (Exception e) {
            throw cleanThrowable(new OutOfMemoryError(TAG + " callActivityOnResume: " + e));
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
      throw cleanThrowable(e);
    }
  }

  /**
   * `install`:
   * unseals ART VM at postAppSpecialize so modules access and modify
   * hidden/restricted APIs
   */
  public static void i() throws Throwable {
    unseal();
  }

  private static void loadModules(Context context) throws Throwable {
    String packageName = context.getPackageName();
    List<BaseHook> modules = new ArrayList<>();

    if (GLOBAL_ALLOW_LIST.contains(packageName)) {
      modules.add(new AntiNetworkDiscoveryHook());
      modules.add(new SystemPropertiesHook());
    } else {
      /**
       * Isolated processes (Services to be more precise) are quite restricted
       * and can't touch most system APIs, so just install modules for things they
       * CAN touch
       * 
       * https://developer.android.com/guide/topics/manifest/service-element#isolated
       */
      if (isIsolatedProcess()) {
        modules.add(new AntiAppInspectionHook());
        modules.add(new SystemPropertiesHook());
        modules.add(new GsfIdSpoofHook());
      } else {
        modules.add(new AntiAppInspectionHook());
        modules.add(new NetworkSpoofingHook());
        modules.add(new SettingsHook());
        modules.add(new SystemPropertiesHook());
        modules.add(new AntiNetworkDiscoveryHook());
        modules.add(new TelephonyManagerHook());
        modules.add(new AntiScreenshotDetectionHook());
        modules.add(new GsfIdSpoofHook());
      }
    }

    for (BaseHook module : modules) {
      module.install(context);
    }
    Log.i(TAG, "All modules loaded successfully :)");
  }

  private static void patchConnectivityManager(Context context) throws Throwable {
    if (s_cmProxy == null) {
      throw cleanThrowable(new Exception(TAG + "s_cmProxy is null"));
    }
    ConnectivityManager cm = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
    Class<?> cmClass = ConnectivityManager.class;
    Class<?> iConnClz = Class.forName("android.net.IConnectivityManager");
    for (Field f : cmClass.getDeclaredFields()) {
      if (iConnClz.isAssignableFrom(f.getType())) {
        f.setAccessible(true);
        f.set(cm, s_cmProxy);
      }
    }
  }

  private static void patchPackageManager(PackageManager pm) throws Throwable {
    if (pm == null || s_pmProxy == null || s_mPMField == null) {
      throw cleanThrowable(new Exception(TAG + "PM fields are null"));
    }
    s_mPMField.set(pm, s_pmProxy);
    if (s_mUseField != null) {
      s_mUseField.setBoolean(pm, false);
    }
    if (s_mCacheField != null && s_mDisabledField != null) {
      Object pic = s_mCacheField.get(pm);
      if (pic != null) {
        s_mDisabledField.setBoolean(pic, true);
      }
    }
  }

  public static <T extends Throwable> T cleanThrowable(T tr) {
    if (tr == null) {
      return null;
    }

    List<Pattern> noiseClassPatterns = List.of(
        Pattern.compile("^java\\.lang\\.reflect\\..*"),
        Pattern.compile("^\\$Proxy\\d+$"));

    List<Pattern> noiseFilePatterns = List.of(
        Pattern.compile("^SourceFile$"),
        Pattern.compile("^Unknown Source$"));

    clean_stack_trace_recursive(tr, noiseClassPatterns, noiseFilePatterns, new HashSet<>());
    return tr;
  }

  private static void clean_stack_trace_recursive(
      Throwable tr,
      List<Pattern> noiseClassPatterns,
      List<Pattern> noiseFilePatterns,
      Set<Throwable> seen) {
    if (tr == null || !seen.add(tr)) {
      return; // avoid infinite loops on cyclic causes
    }

    StackTraceElement[] original = tr.getStackTrace();
    List<StackTraceElement> filtered = new ArrayList<>(original.length);

    for (StackTraceElement element : original) {
      String className = element.getClassName();
      String fileName = element.getFileName();

      boolean isNoise = noiseClassPatterns.stream().anyMatch(p -> p.matcher(className).matches())
          || (fileName != null
              && noiseFilePatterns.stream().anyMatch(p -> p.matcher(fileName).matches()));

      if (!isNoise) {
        filtered.add(element);
      }
    }

    if (filtered.isEmpty() && original.length > 0) {
      filtered.add(original[0]);
    }

    tr.setStackTrace(filtered.toArray(new StackTraceElement[0]));

    clean_stack_trace_recursive(tr.getCause(), noiseClassPatterns, noiseFilePatterns, seen);
    for (Throwable suppressed : tr.getSuppressed()) {
      clean_stack_trace_recursive(suppressed, noiseClassPatterns, noiseFilePatterns, seen);
    }
  }

  private static void unseal() throws Throwable {
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
        throw cleanThrowable(e2);
      }
    }
  }

  private static boolean isIsolatedProcess() throws Throwable {
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
      throw cleanThrowable(new OutOfMemoryError());
    }
  }
}
package com.omarmesqq.bipan.modules;

import android.content.Context;
import android.content.pm.PackageInstaller;
import android.util.Log;
import com.omarmesqq.bipan.BaseHook;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * Single IPackageManager proxy:
 * - Installer spoofing: getInstallerPackageName + getInstallSourceInfo
 * - Total blindness: all enumeration APIs return empty / NameNotFoundException
 *
 * Caller sees a device with zero installed apps.
 * Replaces both InstallerInfoHook and AntiDiscoveryHook.
 */
public class AntiAppSweepingHook implements BaseHook, InvocationHandler {

  private static final String TAG = "BipanAntiAppSweeping";

  private Object originalPM;
  private String selfPackageName = "unknown";

  private static final Set<String> TRUSTED_PACKAGES = new HashSet<>(Arrays.asList(
      "com.android.vending",
      "com.google.android.gms",
      "com.android.webview"));

  private Object emptyParceledListSlice() throws Exception {
    Class<?> sliceClass = Class.forName("android.content.pm.ParceledListSlice");
    Method emptyList = sliceClass.getMethod("emptyList");
    return emptyList.invoke(null);
  }

  @Override
  public void install(Context context) throws Exception {
    this.selfPackageName = context.getPackageName();

    Class<?> activityThreadClz = Class.forName("android.app.ActivityThread");
    Method getPM = activityThreadClz.getDeclaredMethod("getPackageManager");
    getPM.setAccessible(true);

    // Unwrap through any existing proxy chain to get real IPackageManager
    Object maybePM = getPM.invoke(null);
    this.originalPM = unwrapProxy(maybePM);

    Object proxy = Proxy.newProxyInstance(
        context.getClassLoader(),
        new Class[] { Class.forName("android.content.pm.IPackageManager") },
        this);

    // Replace in ActivityThread
    Field sPMField = activityThreadClz.getDeclaredField("sPackageManager");
    sPMField.setAccessible(true);
    sPMField.set(null, proxy);

    // Replace mPM in ALL ApplicationPackageManager instances via
    // ActivityThread.mPackages
    replaceAllPackageManagerWrappers(activityThreadClz, proxy);

    Log.i(TAG, "AntiAppSweepingHook installed");
  }

  private Object unwrapProxy(Object obj) {
    if (!Proxy.isProxyClass(obj.getClass())) {
      return obj;
    }
    try {
      Class<?> smClz = Class.forName("android.os.ServiceManager");
      Method getService = smClz.getDeclaredMethod("getService", String.class);
      android.os.IBinder binder = (android.os.IBinder) getService.invoke(null, "package");
      Class<?> stubClz = Class.forName("android.content.pm.IPackageManager$Stub");
      Method asInterface = stubClz.getDeclaredMethod("asInterface", android.os.IBinder.class);
      return asInterface.invoke(null, binder);
    } catch (Exception e) {
      Log.e(TAG, "unwrapProxy failed, using wrapped PM: " + e.getMessage());
      return obj;
    }
  }

  private void replaceAllPackageManagerWrappers(Class<?> activityThreadClz, Object proxy)
      throws Exception {
    Class<?> appPMClz = Class.forName("android.app.ApplicationPackageManager");
    Field mPMField = appPMClz.getDeclaredField("mPM");
    mPMField.setAccessible(true);

    try {
      // Get the actual ActivityThread instance, not null
      Method currentAT = activityThreadClz.getMethod("currentActivityThread");
      Object activityThread = currentAT.invoke(null);
      if (activityThread == null) {
        Log.w(TAG, "currentActivityThread() returned null");
        return;
      }

      Field mPackagesField = activityThreadClz.getDeclaredField("mPackages");
      mPackagesField.setAccessible(true);
      // instance, shouldn't be null
      Object mPackages = mPackagesField.get(activityThread);
      if (mPackages instanceof java.util.Map) {
        for (Object val : ((java.util.Map<?, ?>) mPackages).values()) {
          Object loadedApk = null;
          if (val instanceof java.lang.ref.WeakReference) {
            loadedApk = ((java.lang.ref.WeakReference<?>) val).get();
          }
          if (loadedApk == null) {
            continue;
          }
          try {
            Field mPackageManagerField = loadedApk.getClass()
                .getDeclaredField("mPackageManager");
            mPackageManagerField.setAccessible(true);
            Object pmWrapper = mPackageManagerField.get(loadedApk);
            if (pmWrapper != null) {
              mPMField.set(pmWrapper, proxy);
              Log.d(TAG, "Replaced mPM in LoadedApk wrapper");
            }
          } catch (NoSuchFieldException ignored) {
          }
        }
      }
    } catch (Exception e) {
      Log.w(TAG, "mPackages walk failed: " + e.getMessage());
    }
  }

  @Override
  public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
    switch (method.getName()) {

      // ---- Installer spoofing (unchanged) ----

      case "getInstallerPackageName": {
        String targetPkg = (args != null && args.length > 0 && args[0] instanceof String)
            ? (String) args[0]
            : "unknown";
        Log.w(TAG, "[Legacy] installer read for: " + targetPkg +
            (targetPkg.equals(selfPackageName) ? " (Self)" : " (External Scan)"));
        return "com.android.vending";
      }

      case "getInstallSourceInfo": {
        String targetPkg = (args != null && args.length > 0 && args[0] instanceof String)
            ? (String) args[0]
            : "unknown";
        Log.w(TAG, "[Modern] install source read for: " + targetPkg +
            (targetPkg.equals(selfPackageName) ? " (Self)" : " (External Scan)"));
        return createFakeInstallSourceInfo();
      }

      // ---- Total blindness ----

      case "queryIntentActivities": {
        Log.w(TAG, "Blinded: queryIntentActivities");
        return emptyParceledListSlice();
      }

      case "getInstalledApplications": {
        Log.w(TAG, "Blinded: getInstalledApplications");
        return emptyParceledListSlice();
      }

      case "getInstalledPackages": {
        Log.w(TAG, "Blinded: getInstalledPackages");
        return emptyParceledListSlice();
      }

      // API 1 overload: (String packageName, int flags)
      case "getPackageInfo":
        // API 33 overload: (String packageName, PackageInfoFlags flags)
      case "getPackageInfoWithFlags": {
        String pkg = (args != null && args.length > 0 && args[0] instanceof String)
            ? (String) args[0]
            : null;

        if (selfPackageName.equals(pkg) || TRUSTED_PACKAGES.contains(pkg)) {
          Log.d(TAG, "Allowing getPackageInfo for trusted pkg: " + pkg);
          return method.invoke(originalPM, args);
        }

        Log.w(TAG, "Blinded: " + method.getName() + " for: " + pkg);
        return null;
      }

      default: {
        Object result = method.invoke(originalPM, args);
        final String stackTrace = Log.getStackTraceString(new Throwable());
        Log.e(TAG, "Allowing app PM sweeping method: " + method.getName() + " Stacktrace:\n" + stackTrace);
        return result;
      }
    }
  }

  // ---- Installer helpers (unchanged from InstallerInfoHook) ----

  private Object createFakeInstallSourceInfo() throws Exception {
    Class<?> infoClz = Class.forName("android.content.pm.InstallSourceInfo");

    Field unsafeField = Class.forName("sun.misc.Unsafe").getDeclaredField("theUnsafe");
    unsafeField.setAccessible(true);
    Object unsafe = unsafeField.get(null);
    Method allocateInstance = unsafe.getClass().getMethod("allocateInstance", Class.class);

    Object info = allocateInstance.invoke(unsafe, infoClz);

    setHiddenField(info, "mInitiatingPackageName", "com.android.vending");
    setHiddenField(info, "mInstallingPackageName", "com.android.vending");
    setHiddenField(info, "mUpdateOwnerPackageName", "com.android.vending");
    setHiddenField(info, "mOriginatingPackageName", null);
    setHiddenField(info, "mPackageSource", PackageInstaller.PACKAGE_SOURCE_STORE);

    return info;
  }

  private void setHiddenField(Object obj, String name, Object value) {
    try {
      Field field = obj.getClass().getDeclaredField(name);
      field.setAccessible(true);
      field.set(obj, value);
    } catch (Exception e) {
      Log.e(TAG, "failed to set field: " + name);
    }
  }
}
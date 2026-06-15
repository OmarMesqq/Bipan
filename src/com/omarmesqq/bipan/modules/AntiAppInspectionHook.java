package com.omarmesqq.bipan.modules;

import android.content.Context;
import android.content.pm.PackageInstaller;
import android.os.IBinder;
import android.util.Log;
import com.omarmesqq.bipan.BaseHook;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import android.content.Intent;
import android.content.pm.PackageManager;

/**
 * Single IPackageManager proxy:
 * - Installer spoofing: getInstallerPackageName + getInstallSourceInfo
 * - Total blindness: all enumeration APIs return empty / NameNotFoundException
 *
 * Caller sees a device with zero installed apps.
 * Replaces both InstallerInfoHook and AntiDiscoveryHook.
 */
public class AntiAppInspectionHook implements BaseHook, InvocationHandler {
  private static final String TAG = "BipanAntiAppInspectionHook";

  private Object originalPM;
  private String selfPackageName = "unknown";

  private static final Set<String> ALLOW_LIST = new HashSet<>(Arrays.asList(
      "com.android.vending",
      "com.google.android.gms"));

  private Object emptyParceledListSlice() throws Exception {
    Class<?> sliceClass = Class.forName("android.content.pm.ParceledListSlice");
    Method emptyList = sliceClass.getMethod("emptyList");
    return emptyList.invoke(null);
  }

  private static final Set<String> TRUSTED_PACKAGES = new HashSet<>(Arrays.asList(
      "com.android.vending",
      "com.google.android.gms",
      "com.android.webview"));

  @Override
  public void install(Context context) throws Exception {
    this.selfPackageName = context.getPackageName();
    if (ALLOW_LIST.contains(selfPackageName)) {
      return;
    }

    Class<?> serviceManager = Class.forName("android.os.ServiceManager");
    Method getService = serviceManager.getDeclaredMethod("getService", String.class);
    Field sCacheField = serviceManager.getDeclaredField("sCache");
    sCacheField.setAccessible(true);

    @SuppressWarnings("unchecked")
    Map<String, IBinder> cache = (Map<String, IBinder>) sCacheField.get(null);

    IBinder realPackageManagerBinder = (IBinder) getService.invoke(null, "package");
    if (realPackageManagerBinder == null) {
      throw new Exception(TAG + " Package Manager service ('package') not found!");
    }

    // Get real IPackageManager via Stub.asInterface
    Class<?> stubClz = Class.forName("android.content.pm.IPackageManager$Stub");
    Method asInterface = stubClz.getDeclaredMethod("asInterface", IBinder.class);
    this.originalPM = asInterface.invoke(null, realPackageManagerBinder);

    // Create IPackageManager proxy
    Class<?> iPMClz = Class.forName("android.content.pm.IPackageManager");
    Object pmProxy = Proxy.newProxyInstance(
        iPMClz.getClassLoader(),
        new Class[] { iPMClz },
        this);

    // Wrap in an IBinder proxy that returns our pmProxy on queryLocalInterface
    IBinder pmProxyBinder = (IBinder) Proxy.newProxyInstance(
        IBinder.class.getClassLoader(),
        new Class[] { IBinder.class },
        (p, method, args) -> {
          if ("queryLocalInterface".equals(method.getName())) {
            return pmProxy;
          }
          return method.invoke(realPackageManagerBinder, args);
        });

    cache.put("package", pmProxyBinder);

    // Replace mPM directly on the context's ApplicationPackageManager
    try {
      Class<?> apmClass = Class.forName("android.app.ApplicationPackageManager");
      Field mPMField = apmClass.getDeclaredField("mPM");
      mPMField.setAccessible(true);

      // We replace the `mPM` from `ApplicationPackageManager` on the context passed
      // to install()
      PackageManager pm = context.getPackageManager();
      mPMField.set(pm, pmProxy);

      // Walk through ContextImpl chain to replace any possible instances in it too
      Context base = context;
      while (base != null) {
        try {
          Field mPMWrapperField = base.getClass().getDeclaredField("mPackageManager");
          mPMWrapperField.setAccessible(true);
          Object wrapper = mPMWrapperField.get(base);
          if (wrapper != null) {
            mPMField.set(wrapper, pmProxy);
            // Log.d(TAG, "Replaced mPM in ContextImpl: " + base.getClass().getName());
          }
        } catch (NoSuchFieldException ignored) {
        }
        try {
          Field mBaseField = base.getClass().getDeclaredField("mBase");
          mBaseField.setAccessible(true);
          base = (Context) mBaseField.get(base);
        } catch (Exception e) {
          break;
        }
      }
    } catch (Exception e) {
      Log.e(TAG, "Failed to replace mPM directly: " + e.getMessage());
    }

    try {
      // Replace `sPackageManager` of `ActivityThread` as well
      Class<?> atClz = Class.forName("android.app.ActivityThread");
      Field sPMField = atClz.getDeclaredField("sPackageManager");
      sPMField.setAccessible(true);
      sPMField.set(null, pmProxy);
    } catch (Exception e) {
      Log.e(TAG, "Failed to replace sPackageManager: " + e.getMessage());
    }
  }

  @Override
  public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
    switch (method.getName()) {
      // Installer spoofing
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

      case "queryIntentActivities": {
        if (args != null && args.length > 0 && args[0] instanceof Intent) {
          Intent intent = (Intent) args[0];

          // Allow self-targeted queries (component or package matches self)
          boolean isSelfQuery = false;
          if (intent.getComponent() != null && selfPackageName.equals(intent.getComponent().getPackageName())) {
            isSelfQuery = true;
          }
          if (intent.getPackage() != null && selfPackageName.equals(intent.getPackage())) {
            isSelfQuery = true;
          }

          if (isSelfQuery) {
            return method.invoke(originalPM, args);
          }

          Log.w(TAG, "Blinded: queryIntentActivities");
        }
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

      case "getPackageInfo": {
        String pkg = (args != null && args.length > 0 && args[0] instanceof String)
            ? (String) args[0]
            : null;

        if (selfPackageName.equals(pkg) || TRUSTED_PACKAGES.contains(pkg)) {
          // Log.i(TAG, "Allowing getPackageInfo for: " + pkg);
          return method.invoke(originalPM, args);
        }

        Log.w(TAG, "Blinded: " + method.getName() + " for: " + pkg);
        return null;
      }

      case "getApplicationInfo": {
        String pkg = (args != null && args.length > 0 && args[0] instanceof String)
            ? (String) args[0]
            : null;

        if (selfPackageName.equals(pkg) || TRUSTED_PACKAGES.contains(pkg)) {
          // Log.i(TAG, "Allowing getApplicationInfo for: " + pkg);
          return method.invoke(originalPM, args);
        }

        Log.w(TAG, "Blinded: getApplicationInfo for: " + pkg);
        return null;
      }

      case "getActivityInfo": {
        // Signature: getActivityInfo(ComponentName component, long flags, int userId)
        // args[0] is ComponentName — extract package name from it
        String pkg = null;
        if (args != null && args.length > 0 && args[0] != null) {
          // ComponentName is a public class, getPackageName() is accessible
          try {
            pkg = (String) args[0].getClass()
                .getMethod("getPackageName")
                .invoke(args[0]);
          } catch (Exception e) {
            Log.e(TAG, "getActivityInfo: failed to extract package from ComponentName");
          }
        }

        if (selfPackageName.equals(pkg) || TRUSTED_PACKAGES.contains(pkg)) {
          return method.invoke(originalPM, args);
        }

        Log.w(TAG, "Blinded: getActivityInfo for pkg=" + pkg);
        return null;
      }
      case "getPackageArchiveInfo": {
        Log.w(TAG, "Blinded: getPackageArchiveInfo");
        return emptyParceledListSlice();
      }
      case "getPackagesHoldingPermissions": {
        Log.w(TAG, "Blinded: getPackagesHoldingPermissions");
        return emptyParceledListSlice();
      }
      case "getPreferredPackages": {
        Log.w(TAG, "Blinded: getPreferredPackages");
        return emptyParceledListSlice();
      }
      case "getPreferredActivities": {
        Log.w(TAG, "Blinded: getPreferredActivities");
        return emptyParceledListSlice();
      }
      case "getProperty": {
        Log.w(TAG, "Blinded: getProperty");
        return emptyParceledListSlice();
      }
      case "queryIntentActivityOptions": {
        Log.w(TAG, "Blinded: queryIntentActivityOptions");
        return emptyParceledListSlice();
      }
      case "resolveActivity": {
        if (args != null && args.length > 0 && args[0] instanceof Intent) {
          Intent intent = (Intent) args[0];
          boolean isSelf = (intent.getComponent() != null
              && selfPackageName.equals(intent.getComponent().getPackageName()))
              || selfPackageName.equals(intent.getPackage());
          if (isSelf) {
            return method.invoke(originalPM, args);
          }
        }
        Log.w(TAG, "Blinded: resolveActivity");
        return null; // ResolveInfo, NOT ParceledListSlice
      }
      case "getTargetSdkVersion": {
        Log.w(TAG, "Blinded: getTargetSdkVersion");
        return 36;
      }

      case "hasSystemFeature": {
        Log.w(TAG, "Blinded: hasSystemFeature");
        if (args != null && args.length > 0 && args[0] instanceof Intent) {
          Intent intent = (Intent) args[0];
          dumpIntent(intent);
        }
        return false;
      }

      case "getSystemAvailableFeatures": {
        Log.w(TAG, "Blinded: getSystemAvailableFeatures");
        return null;
      }

      default: {
        Object result = method.invoke(originalPM, args);
        // final String stackTrace = Log.getStackTraceString(new Throwable());
        // Log.i(TAG, "Allowing app Package Manager method: " + method.getName() + "
        // Stacktrace:\n" + stackTrace);
        Log.i(TAG, "Allowing app Package Manager method: " + method.getName());
        return result;
      }
    }
  }

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

  private void dumpIntent(Intent intent) {
    String intentInfo = "\naction=" + intent.getAction()
        + " data=" + intent.getDataString()
        + " pkg=" + intent.getPackage()
        + " component=" + intent.getComponent()
        + " categories=" + intent.getCategories();
    Log.d(TAG, "intentInfo:" + intentInfo);
  }
}
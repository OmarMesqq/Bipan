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
import android.content.pm.FeatureInfo;
import java.util.ArrayList;
import java.util.List;

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

  private Object emptyParceledListSlice() throws Exception {
    Class<?> sliceClass = Class.forName("android.content.pm.ParceledListSlice");
    Method emptyList = sliceClass.getMethod("emptyList");
    return emptyList.invoke(null);
  }

  private static final Set<String> TRUSTED_PACKAGES = new HashSet<>(Arrays.asList(
      "com.android.vending",
      "com.google.android.gms",
      "com.android.webview"));

  private static final Set<String> FEATURE_STRIP_LIST = new HashSet<>(Arrays.asList(
      "org.lineageos.livedisplay",
      "org.lineageos.profiles",
      "org.lineageos.hardware",
      "org.lineageos.globalactions",
      "org.lineageos.trust",
      "org.lineageos.health",
      "org.lineageos.android",
      "org.lineageos.settings",

      "android.hardware.nfc",
      "android.hardware.nfc.any",
      "android.hardware.nfc.hce",
      "android.hardware.nfc.hcef",
      "android.hardware.nfc.uicc",
      "android.hardware.nfc.ese",

      "android.hardware.bluetooth_le",
      "android.software.autofill",
      "android.software.app_widgets",
      "android.software.live_wallpaper",
      "android.software.midi",
      "android.software.picture_in_picture",
      "android.software.freeform_window_management",
      "android.software.window_magnification",
      "android.hardware.screen.landscape",
      "android.software.print",
      "android.hardware.sensor.stepcounter",
      "android.hardware.sensor.stepdetector",
      "android.software.controls",

      "android.hardware.usb.accessory",
      "android.hardware.usb.host",

      "android.software.managed_users",

      "android.software.sip",
      "android.software.sip.voip",
      "android.hardware.telephony.ims",

      "android.hardware.wifi.direct",
      "android.hardware.wifi.passpoint",

      "android.software.companion_device_setup",

      "android.software.telecom",

      "android.hardware.sensor.hifi_sensors",
      "android.hardware.camera.ar"));

  private static final Set<String> FEATURE_ADD_LIST = new HashSet<>(Arrays.asList(
      "android.software.verified_boot",
      "android.software.device_id_attestation",
      "android.hardware.hardware_keystore",
      "android.hardware.keystore.app_attest_key"
    ));

  public static volatile Object s_pmProxy = null;
  public static volatile Field s_mPMField = null;
  private static volatile Field s_mUseField = null;
  private static volatile Field s_mCacheField = null;
  private static volatile Field s_mDisabledField = null;

  @Override
  public void install(Context context) throws Exception {
    this.selfPackageName = context.getPackageName();

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
      Class<?> apmClass = Class.forName("android.app.ApplicationPackageManager");
      PackageManager pm = context.getPackageManager();

      // Disable the cache flag on ApplicationPackageManager
      Field mUseField = apmClass.getDeclaredField("mUseSystemFeaturesCache");
      mUseField.setAccessible(true);
      mUseField.setBoolean(pm, false);

      Field mCacheField = apmClass.getDeclaredField("mHasSystemFeatureCache");
      mCacheField.setAccessible(true);
      Object pic = mCacheField.get(pm);
      if (pic == null) {
        throw new Exception(TAG + "ApplicationPackageManager.get(mHasSystemFeatureCache) returned null!");
      }

      Class<?> picClass = Class.forName("android.app.PropertyInvalidatedCache");

      // Set mDisabled=true — bypasses cache, forces recompute() on every query()
      Field mDisabledField = picClass.getDeclaredField("mDisabled");
      mDisabledField.setAccessible(true);
      mDisabledField.setBoolean(pic, true);

      // Also disable globally for this process via disableForCurrentProcess()
      Method disableMethod = picClass.getMethod("disableForCurrentProcess");
      disableMethod.invoke(pic);

      if (!mDisabledField.getBoolean(pic)) {
        throw new Exception(TAG + "Couldn't set PIC's mDisabled flag to false!");
      }
    } catch (Exception e) {
      throw new Exception(TAG + "Could not disable feature cache: " + e.getMessage());
    }

    try {
      Class<?> atClz = Class.forName("android.app.ActivityThread");
      Method currentAt = atClz.getMethod("currentActivityThread");
      Object at = currentAt.invoke(null);
      if (at != null) {
        Method getApp = atClz.getMethod("getApplication");
        Object app = getApp.invoke(at);
        if (app instanceof Context) {
          Context appCtx = (Context) app;
          // Hijack Application's PackageManager
          Class<?> apmClass = Class.forName("android.app.ApplicationPackageManager");
          Field mPMField = apmClass.getDeclaredField("mPM");
          mPMField.setAccessible(true);
          PackageManager appPm = appCtx.getPackageManager();
          mPMField.set(appPm, pmProxy);

          // Also disable its feature cache
          Field mUseField = apmClass.getDeclaredField("mUseSystemFeaturesCache");
          mUseField.setAccessible(true);
          mUseField.setBoolean(appPm, false);

          Field mCacheField = apmClass.getDeclaredField("mHasSystemFeatureCache");
          mCacheField.setAccessible(true);
          Object pic = mCacheField.get(appPm);
          if (pic == null) {
            throw new Exception(TAG + "ApplicationPackageManager.get(mHasSystemFeatureCache) returned null!");
          }

          // Disable Application's Package Manager cache
          Class<?> picClass = Class.forName("android.app.PropertyInvalidatedCache");
          Field mDisabledField = picClass.getDeclaredField("mDisabled");
          mDisabledField.setAccessible(true);
          mDisabledField.setBoolean(pic, true);
        }
      }
    } catch (Exception e) {
      Log.e(TAG, "Could not patch Application PM: " + e.getMessage());
    }

    // Store fields statically for Activity-time patching via BipanJava
    try {
      Class<?> apmClass2 = Class.forName("android.app.ApplicationPackageManager");
      Class<?> picClass2 = Class.forName("android.app.PropertyInvalidatedCache");
      s_pmProxy = pmProxy;
      s_mPMField = apmClass2.getDeclaredField("mPM");
      s_mPMField.setAccessible(true);
      s_mUseField = apmClass2.getDeclaredField("mUseSystemFeaturesCache");
      s_mUseField.setAccessible(true);
      s_mCacheField = apmClass2.getDeclaredField("mHasSystemFeatureCache");
      s_mCacheField.setAccessible(true);
      s_mDisabledField = picClass2.getDeclaredField("mDisabled");
      s_mDisabledField.setAccessible(true);
    } catch (Exception e) {
      Log.e(TAG, "Failed to store static PM fields: " + e.getMessage());
    }

    try {
      Class<?> atClz = Class.forName("android.app.ActivityThread");
      Field sPMField = atClz.getDeclaredField("sPackageManager");
      sPMField.setAccessible(true);
      sPMField.set(null, pmProxy);
    } catch (Exception e) {
      Log.e(TAG, "Failed to replace sPackageManager: " + e.getMessage());
    }
  }

  public static void patchPackageManager(PackageManager pm) throws Exception {
    if (pm == null || s_pmProxy == null || s_mPMField == null) {
      throw new Exception(TAG + "'pm', 's_pmProxy', and/or 's_mPMField' are null");
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

  @Override
  public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
    switch (method.getName()) {
      // Installer spoofing
      case "getInstallerPackageName": {
        String targetPkg = (args != null && args.length > 0 && args[0] instanceof String)
            ? (String) args[0]
            : "unknown";
        Log.i(TAG, "Spoofed Legacy installer read for: " + targetPkg +
            (targetPkg.equals(selfPackageName) ? " (Self)" : " (External Scan)"));
        return "com.android.vending";
      }

      case "getInstallSourceInfo": {
        String targetPkg = (args != null && args.length > 0 && args[0] instanceof String)
            ? (String) args[0]
            : "unknown";
        Log.i(TAG, "Spoofed Modern install source read for: " + targetPkg +
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

          Log.i(TAG, "Blinded: queryIntentActivities");
        }
        return emptyParceledListSlice();
      }

      case "getInstalledApplications": {
        Log.i(TAG, "Blinded: getInstalledApplications");
        return emptyParceledListSlice();
      }

      case "getInstalledPackages": {
        Log.i(TAG, "Blinded: getInstalledPackages");
        return emptyParceledListSlice();
      }

      case "getPackageInfo": {
        String pkg = (args != null && args.length > 0 && args[0] instanceof String)
            ? (String) args[0]
            : null;

        if (selfPackageName.equals(pkg) || TRUSTED_PACKAGES.contains(pkg)) {
          return method.invoke(originalPM, args);
        }

        Log.i(TAG, "Blinded getPackageInfo for: " + pkg);
        return null;
      }

      case "getApplicationInfo": {
        String pkg = (args != null && args.length > 0 && args[0] instanceof String)
            ? (String) args[0]
            : null;

        if (selfPackageName.equals(pkg) || TRUSTED_PACKAGES.contains(pkg)) {
          return method.invoke(originalPM, args);
        }

        Log.i(TAG, "Blinded: getApplicationInfo for: " + pkg);
        return null;
      }

      case "getActivityInfo": {
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

        Log.i(TAG, "Blinded: getActivityInfo for: " + pkg);
        return null;
      }
      case "getPackageArchiveInfo": {
        Log.i(TAG, "Blinded: getPackageArchiveInfo");
        return emptyParceledListSlice();
      }
      case "getPackagesHoldingPermissions": {
        Log.i(TAG, "Blinded: getPackagesHoldingPermissions");
        return emptyParceledListSlice();
      }
      case "getPreferredPackages": {
        Log.i(TAG, "Blinded: getPreferredPackages");
        return emptyParceledListSlice();
      }
      case "getPreferredActivities": {
        Log.i(TAG, "Blinded: getPreferredActivities");
        return emptyParceledListSlice();
      }
      case "getProperty": {
        Log.i(TAG, "Blinded: getProperty");
        return emptyParceledListSlice();
      }
      case "queryIntentActivityOptions": {
        Log.i(TAG, "Blinded: queryIntentActivityOptions");
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
        Log.i(TAG, "Blinded: resolveActivity");
        return null;
      }
      case "getTargetSdkVersion": {
        Log.i(TAG, "Blinded: getTargetSdkVersion");
        return 36;
      }

      case "hasSystemFeature": {
        String feature = (args != null && args.length > 0 && args[0] instanceof String)
            ? (String) args[0]
            : null;

        if (feature != null && FEATURE_STRIP_LIST.contains(feature)) {
          Log.i(TAG, "hasSystemFeature: Trimmed system feature: " + feature);
          return false;
        }

        if (feature != null && FEATURE_ADD_LIST.contains(feature)) {
          Log.i(TAG, "hasSystemFeature: Added system feature: " + feature);
          return true;
        }

        return method.invoke(originalPM, args);
      }

      case "getSystemAvailableFeatures": {
        try {
          Object result = method.invoke(originalPM, args);
          if (result == null) {
            return null;
          }

          Class<?> sliceClass = Class.forName("android.content.pm.ParceledListSlice");
          Method getList = sliceClass.getMethod("getList");
          @SuppressWarnings("unchecked")
          List<FeatureInfo> realFeatures = (List<FeatureInfo>) getList.invoke(result);

          if (realFeatures == null) {
            return result;
          }

          List<FeatureInfo> filtered = new ArrayList<>();
          for (FeatureInfo fi : realFeatures) {
            if (fi.name != null && FEATURE_STRIP_LIST.contains(fi.name)) {
              continue;
            }
            filtered.add(fi);
          }

          for (String feat : FEATURE_ADD_LIST) {
            FeatureInfo fi = new FeatureInfo();

            // reflect on fresh instance to set the name, which is what matters i guess...
            Field nameField = FeatureInfo.class.getDeclaredField("name");
            nameField.setAccessible(true);
            nameField.set(fi, feat);

            filtered.add(fi);
          }

          Log.i(TAG, "Filtered getSystemAvailableFeatures");
          return sliceClass
              .getConstructor(List.class)
              .newInstance(filtered);

        } catch (Exception e) {
          Log.e(TAG, "getSystemAvailableFeatures filter failed", e);
          return null;
        }
      }

      case "notifyPackagesReplacedReceived": {
        if (args != null && args.length > 0 && args[0] instanceof String[]) {
          String[] packages = (String[]) args[0];
          for (String pkg : packages) {
            Log.d(TAG, "notifyPackagesReplacedReceived (neutered): " + pkg);
          }
        }
        return null;
      }

      case "isSafeMode": {
        return false;
      }

      case "setComponentEnabledSetting": {
        if (args != null && args.length >= 3) {
          Object componentName = args[0];
          int newState = (int) args[1];
          int flags = (int) args[2];

          String stateStr;
          switch (newState) {
            case PackageManager.COMPONENT_ENABLED_STATE_DEFAULT:
              stateStr = "DEFAULT";
              break;
            case PackageManager.COMPONENT_ENABLED_STATE_ENABLED:
              stateStr = "ENABLED";
              break;
            case PackageManager.COMPONENT_ENABLED_STATE_DISABLED:
              stateStr = "DISABLED";
              break;
            case PackageManager.COMPONENT_ENABLED_STATE_DISABLED_USER:
              stateStr = "DISABLED_USER";
              break;
            case PackageManager.COMPONENT_ENABLED_STATE_DISABLED_UNTIL_USED:
              stateStr = "DISABLED_UNTIL_USED";
              break;
            default:
              stateStr = String.valueOf(newState);
          }

          Log.d(TAG, "setComponentEnabledSetting: component=" + componentName
              + " newState=" + stateStr
              + " flags=" + flags);
        }
        return method.invoke(originalPM, args);
      }

      case "queryIntentServices": {
        if (args != null && args.length > 0 && args[0] instanceof Intent) {
          Intent intent = (Intent) args[0];
          String action = intent.getAction();
          if ("com.facebook.usdid.CROSS_SIGN_SERVICE".equals(action)) {
            Log.i(TAG, "Blinded: queryIntentServices USDID cross-sign service");
            return emptyParceledListSlice();
          }
          Log.d(TAG, "queryIntentServices: intent: " + dumpIntent(intent));
        }
        return method.invoke(originalPM, args);
      }

      case "queryIntentReceivers": {
        if (args != null && args.length > 0 && args[0] instanceof Intent) {
          Intent intent = (Intent) args[0];
          String action = intent.getAction();

          if ("android.intent.action.BOOT_COMPLETED".equals(action)) {
            Log.i(TAG, "Blinded: queryIntentReceivers BOOT_COMPLETED");
            return emptyParceledListSlice();
          }
          if ("android.intent.action.BADGE_COUNT_UPDATE".equals(action)) {
            Log.i(TAG, "Blinded: queryIntentReceivers badge count receiver enumeration");
            return emptyParceledListSlice();
          }
          Log.d(TAG, "queryIntentReceivers: intent: " + dumpIntent(intent));
        }
        return method.invoke(originalPM, args);
      }

      case "getPropertyAsUser": {
        if (args != null && args.length > 0) {
          String className;
          if (args[2] == null) {
            className = "null";
          } else {
            className = (String) args[2];
          }
          Log.d("TAG", "getPropertyAsUser: propertyName " + args[0] + " package: " + args[1] + " className: "
              + className + " UID: " + args[3]);
        }
        return method.invoke(originalPM, args);
      }

      case "resolveContentProvider": {
        if (args != null && args.length > 0 && args[0] instanceof String) {
          Log.d("TAG", "resolveContentProvider: authority " + args[0] + " flags: " + args[1]);
        }
        return method.invoke(originalPM, args);
      }

      case "queryIntentContentProviders": {
        if (args != null && args.length > 0) {
          Log.d("TAG", "queryIntentContentProviders: intent " + dumpIntent((Intent) args[0]) + " flags: " + args[1]);
        }
        return method.invoke(originalPM, args);
      }

      default: {
        Object result = method.invoke(originalPM, args);
        Log.w(TAG, "Allowing PM method: " + method.getName());
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

  private String dumpIntent(Intent intent) {
    String intentInfo = "\naction=" + intent.getAction()
        + " data=" + intent.getDataString()
        + " pkg=" + intent.getPackage()
        + " component=" + intent.getComponent()
        + " categories=" + intent.getCategories();
    return intentInfo;
  }
}
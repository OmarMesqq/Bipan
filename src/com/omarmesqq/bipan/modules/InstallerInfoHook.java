package com.omarmesqq.bipan.modules;

import android.content.Context;
import android.util.Log;
import com.omarmesqq.bipan.BaseHook;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import android.content.pm.PackageInstaller;

/**
 * Spoofs app installer and initiating, updating, owner package
 * in newer Android APIs.
 */
public class InstallerInfoHook implements BaseHook, InvocationHandler {
  private static final String TAG = "BipanInstallerHook";
  private Object originalPM;
  private String selfPackageName = "unknown";

  @Override
  public void install(Context context) throws Exception {
    this.selfPackageName = context.getPackageName();

    Class<?> activityThreadClz = Class.forName("android.app.ActivityThread");
    Method getPM = activityThreadClz.getDeclaredMethod("getPackageManager");
    getPM.setAccessible(true);
    this.originalPM = getPM.invoke(null);

    Object proxy = Proxy.newProxyInstance(
        context.getClassLoader(),
        new Class[] { Class.forName("android.content.pm.IPackageManager") },
        this);

    // Replace our proxy in the ActivityThread singleton
    Field sPMField = activityThreadClz.getDeclaredField("sPackageManager");
    sPMField.setAccessible(true);
    sPMField.set(null, proxy);

    // Also replace it in ApplicationPackageManager (the wrapper used by
    // context.getPackageManager())
    Object pmWrapper = context.getPackageManager();
    Field mPMField = pmWrapper.getClass().getDeclaredField("mPM");
    mPMField.setAccessible(true);
    mPMField.set(pmWrapper, proxy);
  }

  @Override
  public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
    String targetPkg = (args != null && args.length > 0 && args[0] instanceof String)
        ? (String) args[0]
        : "unknown";

    if (method.getName().equals("getInstallerPackageName")) {
      Log.w(TAG, "[Legacy] App is reading installer for: " + targetPkg +
          (targetPkg.equals(selfPackageName) ? " (Self)" : " (External Scan)"));
      return "com.android.vending";
    }

    if (method.getName().equals("getInstallSourceInfo")) {
      Log.w(TAG, "[Modern] App is reading install source info for: " + targetPkg +
          (targetPkg.equals(selfPackageName) ? " (Self)" : " (External Scan)"));
      return createFakeInstallSourceInfo();
    }

    return method.invoke(originalPM, args);
  }

  private Object createFakeInstallSourceInfo() throws Exception {
    Class<?> infoClz = Class.forName("android.content.pm.InstallSourceInfo");

    // Create an Unsafe generic Object
    Field unsafeField = Class.forName("sun.misc.Unsafe").getDeclaredField("theUnsafe");
    unsafeField.setAccessible(true);
    Object unsafe = unsafeField.get(null);
    Method allocateInstance = unsafe.getClass().getMethod("allocateInstance", Class.class);

    // Allocate it without calling constructor
    Object info = allocateInstance.invoke(unsafe, infoClz);

    // Set expected internal fields directly
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
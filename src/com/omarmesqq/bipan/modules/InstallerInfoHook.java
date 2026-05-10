package com.omarmesqq.bipan.modules;

import android.content.Context;
import android.util.Log;

import com.omarmesqq.bipan.BaseHook;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;

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

    // Replace in ActivityThread singleton
    Field sPMField = activityThreadClz.getDeclaredField("sPackageManager");
    sPMField.setAccessible(true);
    sPMField.set(null, proxy);

    // Also replace in ApplicationPackageManager (the wrapper used by
    // context.getPackageManager())
    Object pmWrapper = context.getPackageManager();
    Field mPMField = pmWrapper.getClass().getDeclaredField("mPM");
    mPMField.setAccessible(true);
    mPMField.set(pmWrapper, proxy);
  }

  @Override
  public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
    // Most PackageManager methods take the target package name as the first
    // argument
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

    // 1. Get the Unsafe instance
    Field unsafeField = Class.forName("sun.misc.Unsafe").getDeclaredField("theUnsafe");
    unsafeField.setAccessible(true);
    Object unsafe = unsafeField.get(null);
    Method allocateInstance = unsafe.getClass().getMethod("allocateInstance", Class.class);

    // 2. Allocate the object WITHOUT calling a constructor
    Object info = allocateInstance.invoke(unsafe, infoClz);

    // 3. Set the internal fields directly
    // These are the core fields present since Android 11
    setHiddenField(info, "mInitiatingPackageName", "com.android.vending");
    setHiddenField(info, "mInstallingPackageName", "com.android.vending");
    setHiddenField(info, "mOriginatingPackageName", null);

    // 4. Handle version-specific fields (Android 13/14)
    // Using try-catch inside setHiddenField ensures we don't crash on older
    // versions
    setHiddenField(info, "mPackageSource", 2); // 2 = PACKAGE_SOURCE_STORE
    setHiddenField(info, "mUpdateOwnerPackageName", "com.android.vending");

    return info;
  }

  private void setHiddenField(Object obj, String name, Object value) {
    try {
      Field field = obj.getClass().getDeclaredField(name);
      field.setAccessible(true);
      field.set(obj, value);
    } catch (Exception e) {
      // Field might not exist on this specific ROM/Version, skip silently
    }
  }
}
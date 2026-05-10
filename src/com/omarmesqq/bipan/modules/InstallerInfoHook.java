package com.omarmesqq.bipan.modules;

import android.content.Context;
import com.omarmesqq.bipan.BaseHook;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;

public class InstallerInfoHook implements BaseHook, InvocationHandler {
  private Object originalPM;

  @Override
  public void install(Context context) throws Exception {
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
    // 1. Spoof getInstallerPackageName (Legacy API)
    if (method.getName().equals("getInstallerPackageName")) {
      return "com.android.vending";
    }

    // 2. Spoof getInstallSourceInfo (Modern API)
    if (method.getName().equals("getInstallSourceInfo")) {
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
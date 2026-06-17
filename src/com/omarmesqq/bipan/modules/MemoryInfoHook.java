package com.omarmesqq.bipan.modules;

import android.app.ActivityManager;
import android.content.Context;
import android.util.Log;
import com.omarmesqq.bipan.BaseHook;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.lang.reflect.InvocationHandler;
import android.os.IBinder;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class MemoryInfoHook implements BaseHook, InvocationHandler {
  private static final String TAG = "BipanMemoryInfoHook";

  // Target profile: ~3.7GB total, ~252MB available, ~146MB threshold
  private static final long FAKE_TOTAL_MEM = 3901140L * 1024L; // ~3.7 GB in bytes
  private static final long FAKE_AVAIL_MEM = 258600L * 1024L; // ~252 MB in bytes
  private static final long FAKE_THRESHOLD = 150000L * 1024L; // ~146 MB in bytes
  private static final boolean FAKE_LOW_MEMORY = false;

  private Object originalIActivityManager;

  private static final Set<String> ALLOW_LIST = new HashSet<>(Arrays.asList(
      "com.android.vending",
      "com.google.android.gms"));

  @Override
  public void install(Context context) throws Exception {
    String packageName = context.getPackageName();
    if (ALLOW_LIST.contains(packageName)) {
      return;
    }
    Class<?> serviceManager = Class.forName("android.os.ServiceManager");
    Method getService = serviceManager.getDeclaredMethod("getService", String.class);

    IBinder realBinder = (IBinder) getService.invoke(null, "activity");
    if (realBinder == null) {
      throw new Exception(TAG + ": Could not get 'activity' binder");
    }

    // Get IActivityManager via ActivityManager.getService() shortcut
    Class<?> iamClass = Class.forName("android.app.IActivityManager");
    Class<?> stubClass = Class.forName("android.app.IActivityManager$Stub");
    Method asInterface = stubClass.getDeclaredMethod("asInterface", IBinder.class);
    originalIActivityManager = asInterface.invoke(null, realBinder);

    Object proxy = Proxy.newProxyInstance(
        iamClass.getClassLoader(),
        new Class[] { iamClass },
        this);

    IBinder proxyBinder = (IBinder) Proxy.newProxyInstance(
        IBinder.class.getClassLoader(),
        new Class[] { IBinder.class },
        (p, method, args) -> {
          if ("queryLocalInterface".equals(method.getName()))
            return proxy;
          return method.invoke(realBinder, args);
        });

    // Inject into ServiceManager cache
    Field sCacheField = serviceManager.getDeclaredField("sCache");
    sCacheField.setAccessible(true);
    @SuppressWarnings("unchecked")
    Map<String, IBinder> cache = (Map<String, IBinder>) sCacheField.get(null);
    cache.put("activity", proxyBinder);

    // Also replace the cached singleton in ActivityManager itself
    replaceActivityManagerSingleton(proxy);

    Log.i(TAG, "MemoryInfo hook installed");
  }

  private void replaceActivityManagerSingleton(Object proxy) {
    try {
      // ActivityManager caches IActivityManager in a static singleton
      Class<?> amClass = Class.forName("android.app.ActivityManager");
      Field sServiceField = amClass.getDeclaredField("IActivityManagerSingleton");
      sServiceField.setAccessible(true);
      Object singleton = sServiceField.get(null);

      // Singleton<IActivityManager> — replace the cached instance
      Class<?> singletonClass = Class.forName("android.util.Singleton");
      Field mInstanceField = singletonClass.getDeclaredField("mInstance");
      mInstanceField.setAccessible(true);
      mInstanceField.set(singleton, proxy);

      Log.d(TAG, "Replaced IActivityManager singleton");
    } catch (Exception e) {
      Log.w(TAG, "Could not replace AM singleton (non-fatal): " + e.getMessage());
    }
  }

  @Override
  public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
    if ("getMemoryInfo".equals(method.getName())) {
      // Let the real call populate the MemoryInfo object first
      Object result = method.invoke(originalIActivityManager, args);

      // args[0] is the ActivityManager.MemoryInfo object passed by reference
      if (args != null && args.length > 0
          && args[0] instanceof ActivityManager.MemoryInfo) {
        patchMemoryInfo((ActivityManager.MemoryInfo) args[0]);
      }
      return result;
    }

    try {
      return method.invoke(originalIActivityManager, args);
    } catch (Exception e) {
      Log.w(TAG, "AM passthrough failed for " + method.getName()
          + ": " + e.getMessage());
      return null;
    }
  }

  private void patchMemoryInfo(ActivityManager.MemoryInfo info) {
    try {
      setLongField(info, "totalMem", FAKE_TOTAL_MEM);
      setLongField(info, "availMem", FAKE_AVAIL_MEM);
      setLongField(info, "threshold", FAKE_THRESHOLD);
      setBoolField(info, "lowMemory", FAKE_LOW_MEMORY);
    } catch (Exception e) {
      Log.e(TAG, "Failed to patch MemoryInfo: ", e);
    }
  }

  private void setLongField(Object obj, String name, long value) throws Exception {
    Field f = obj.getClass().getDeclaredField(name);
    f.setAccessible(true);
    f.setLong(obj, value);
  }

  private void setBoolField(Object obj, String name, boolean value) throws Exception {
    Field f = obj.getClass().getDeclaredField(name);
    f.setAccessible(true);
    f.setBoolean(obj, value);
  }
}
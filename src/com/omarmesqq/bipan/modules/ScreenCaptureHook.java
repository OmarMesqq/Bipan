package com.omarmesqq.bipan.modules;

import android.content.Context;
import android.os.IBinder;
import android.util.Log;
import com.omarmesqq.bipan.BaseHook;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.Map;
import java.lang.reflect.Field;

public class ScreenCaptureHook implements BaseHook, InvocationHandler {
  private static final String TAG = "BipanScreenCaptureHook";
  private Object originalService;

  @Override
  public void install(Context context) throws Exception {
    Class<?> serviceManager = Class.forName("android.os.ServiceManager");
    Method getService = serviceManager.getDeclaredMethod("getService", String.class);

    IBinder realBinder = (IBinder) getService.invoke(null, "activity_task");
    if (realBinder == null) {
      realBinder = (IBinder) getService.invoke(null, "activity");
    }

    final IBinder finalRealBinder = realBinder;

    Class<?> iInterface = Class.forName("android.app.IActivityTaskManager");
    Class<?> stubClz = Class.forName("android.app.IActivityTaskManager$Stub");
    Method asInterface = stubClz.getDeclaredMethod("asInterface", IBinder.class);
    this.originalService = asInterface.invoke(null, finalRealBinder);

    // Create our custom proxy
    Object proxy = Proxy.newProxyInstance(
        iInterface.getClassLoader(),
        new Class[] { iInterface },
        this);

    // 1. Maintain your ServiceManager cache spoofing for future requests
    Field sCacheField = serviceManager.getDeclaredField("sCache");
    sCacheField.setAccessible(true);
    @SuppressWarnings("unchecked")
    Map<String, IBinder> cache = (Map<String, IBinder>) sCacheField.get(null);

    IBinder proxyBinder = (IBinder) Proxy.newProxyInstance(
        IBinder.class.getClassLoader(),
        new Class[] { IBinder.class },
        (p, method, args) -> {
          if ("queryLocalInterface".equals(method.getName())) {
            return proxy;
          }
          return method.invoke(finalRealBinder, args);
        });
    cache.put("activity_task", proxyBinder);

    // 2. THE CRITICAL FIX: Direct Singleton Overwrite
    // Forcefully replace the service instance even if the Main thread already
    // cached it.
    try {
      Class<?> atmClz = Class.forName("android.app.ActivityTaskManager");
      Field singletonField = atmClz.getDeclaredField("IActivityTaskManagerSingleton");
      singletonField.setAccessible(true);
      Object singletonInstance = singletonField.get(null);

      Class<?> singletonClz = Class.forName("android.util.Singleton");
      Field mInstanceField = singletonClz.getDeclaredField("mInstance");
      mInstanceField.setAccessible(true);

      // Overwrite the field directly with our proxy object
      mInstanceField.set(singletonInstance, proxy);
    } catch (Throwable t) {
      Log.e(TAG, "Failed to forcefully patch ActivityTaskManager cache singleton", t);
    }
  }

  @Override
  public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
    String methodName = method.getName();

    if (methodName.contains("Screenshot") || methodName.contains("ScreenCapture")) {
      Log.w(TAG, "Blocked screenshot-related system notification: " + methodName);
      return null;
    }

    return method.invoke(originalService, args);
  }
}
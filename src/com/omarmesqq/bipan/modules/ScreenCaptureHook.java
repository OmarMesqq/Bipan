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

    // final reference for the lambda
    final IBinder finalRealBinder = realBinder;

    Class<?> iInterface = Class.forName("android.app.IActivityTaskManager");
    Class<?> stubClz = Class.forName("android.app.IActivityTaskManager$Stub");
    Method asInterface = stubClz.getDeclaredMethod("asInterface", IBinder.class);
    this.originalService = asInterface.invoke(null, finalRealBinder);

    // Proxy the service
    Object proxy = Proxy.newProxyInstance(
        iInterface.getClassLoader(),
        new Class[] { iInterface },
        this);

    // Replace in ServiceManager cache
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
    Log.d(TAG, "Hijacked ActivityTaskManager Binder");
  }

  @Override
  public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
    String methodName = method.getName();

    // Heuristic for common method names related to screenshot capture
    if (methodName.contains("Screenshot") || methodName.contains("ScreenCapture")) {
      Log.w(TAG, "Blocked screenshot-related system notification: " + methodName);
      return null; // Swallow the event, not letting app know about it
    }

    return method.invoke(originalService, args);
  }
}
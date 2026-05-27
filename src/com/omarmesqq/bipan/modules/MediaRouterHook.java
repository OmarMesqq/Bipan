package com.omarmesqq.bipan.modules;

import android.content.Context;
import android.os.IBinder;
import android.util.Log;
import com.omarmesqq.bipan.BaseHook;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.Map;

public class MediaRouterHook implements BaseHook, InvocationHandler {
  private static final String TAG = "BipanMediaRouterHook";
  private Object originalMediaRouterService;

  @Override
  public void install(Context context) throws Exception {
    Class<?> serviceManager = Class.forName("android.os.ServiceManager");
    Method getService = serviceManager.getDeclaredMethod("getService", String.class);

    IBinder realBinder = (IBinder) getService.invoke(null, "media_router");
    if (realBinder == null) {
      Log.e(TAG, "Media Router service ('media_router') not found!");
      return;
    }

    Class<?> iMediaRouterClz = Class.forName("android.media.IMediaRouterService");
    Class<?> stubClz = Class.forName("android.media.IMediaRouterService$Stub");
    Method asInterface = stubClz.getDeclaredMethod("asInterface", IBinder.class);

    this.originalMediaRouterService = asInterface.invoke(null, realBinder);

    Object proxy = Proxy.newProxyInstance(
        iMediaRouterClz.getClassLoader(),
        new Class[] { iMediaRouterClz },
        this);

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
          return method.invoke(realBinder, args);
        });

    cache.put("media_router", proxyBinder);
    Log.d(TAG, "Successfully hijacked IMediaRouterService Binder via media_router cache.");
  }

  @Override
  public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
    String methodName = method.getName();

    if (methodName.equals("registerClientAsUser") ||
        methodName.equals("registerClientGroupId") ||
        methodName.equals("requestSetVolume") ||
        methodName.equals("requestUpdateVolume") ||
        methodName.contains("setDiscoveryRequest") ||
        methodName.equals("registerRouter2") ||
        methodName.equals("setRouteListingPreference") ||
        methodName.equals("setRouteListingPreference")) {

      Log.w(TAG, "Neutering MediaRouter method call: " + methodName);

      Class<?> returnType = method.getReturnType();
      if (returnType == void.class) {
        return null;
      } else if (returnType == boolean.class) {
        return false;
      } else if (returnType == int.class || returnType == long.class) {
        return 0;
      }
      return null;
    } else {
      Log.i(TAG, "Allowing MediaRouter call: " + methodName);
    }

    return method.invoke(originalMediaRouterService, args);
  }
}
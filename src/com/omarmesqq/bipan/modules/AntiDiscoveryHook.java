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

/**
 * Prevents apps from discovering LAN devices using mDNS (and possibly
 * SSDP/UPnP and similar methods). The approach is two-fold:
 * 
 * - Intercept MediaRouter
 * 
 * - Intercept NSD Service
 */
public class AntiDiscoveryHook implements BaseHook {
  private static final String TAG = "BipanAntiDiscoveryHook";

  @Override
  public void install(Context context) throws Exception {
    // Common ServiceManager setup
    Class<?> serviceManager = Class.forName("android.os.ServiceManager");
    Method getService = serviceManager.getDeclaredMethod("getService", String.class);
    Field sCacheField = serviceManager.getDeclaredField("sCache");
    sCacheField.setAccessible(true);

    @SuppressWarnings("unchecked")
    Map<String, IBinder> cache = (Map<String, IBinder>) sCacheField.get(null);

    // MediaRouter Hook
    setupMediaRouter(getService, cache);

    // NSD Hook
    setupNsd(getService, cache);
  }

  private void setupMediaRouter(Method getService, Map<String, IBinder> cache) throws Exception {
    IBinder realMediaRouterBinder = (IBinder) getService.invoke(null, "media_router");
    if (realMediaRouterBinder == null) {
      throw new Exception(TAG + " Media Router service ('media_router') not found!");
    }

    Class<?> iMediaRouterClz = Class.forName("android.media.IMediaRouterService");
    Class<?> stubClz = Class.forName("android.media.IMediaRouterService$Stub");
    Method asInterface = stubClz.getDeclaredMethod("asInterface", IBinder.class);
    final Object originalMediaRouterService = asInterface.invoke(null, realMediaRouterBinder);

    InvocationHandler mediaRouterHandler = (proxy, method, args) -> {
      String methodName = method.getName();
      if (methodName.equals("registerClientAsUser") ||
          methodName.equals("registerClientGroupId") ||
          methodName.equals("requestSetVolume") ||
          methodName.equals("requestUpdateVolume") ||
          methodName.contains("setDiscoveryRequest") ||
          methodName.equals("registerRouter2") ||
          methodName.equals("setRouteListingPreference")) {

        Log.w(TAG, "Neutering MediaRouter method call: " + methodName);

        Class<?> returnType = method.getReturnType();
        if (returnType == void.class) {
          return null;
        }
        if (returnType == boolean.class) {
          return false;
        }
        if (returnType == int.class || returnType == long.class) {
          return 0;
        }
        return null;
      }
      return method.invoke(originalMediaRouterService, args);
    };

    Object mediaRouterProxy = Proxy.newProxyInstance(
        iMediaRouterClz.getClassLoader(),
        new Class[] { iMediaRouterClz },
        mediaRouterHandler);

    IBinder mediaRouterProxyBinder = (IBinder) Proxy.newProxyInstance(
        IBinder.class.getClassLoader(),
        new Class[] { IBinder.class },
        (p, method, args) -> "queryLocalInterface".equals(method.getName()) ? mediaRouterProxy
            : method.invoke(realMediaRouterBinder, args));

    cache.put("media_router", mediaRouterProxyBinder);
  }

  private void setupNsd(Method getService, Map<String, IBinder> cache) throws Exception {
    IBinder realNsdBinder = (IBinder) getService.invoke(null, "servicediscovery");
    if (realNsdBinder == null) {
      throw new Exception(TAG + " Network Service Discovery service 'servicediscovery' not found!");
    }

    Class<?> iNsdManagerClz = Class.forName("android.net.nsd.INsdManager");
    Class<?> stubClz = Class.forName("android.net.nsd.INsdManager$Stub");
    Method asInterface = stubClz.getDeclaredMethod("asInterface", IBinder.class);
    final Object originalNsdService = asInterface.invoke(null, realNsdBinder);

    InvocationHandler nsdHandler = (proxy, method, args) -> {
      String methodName = method.getName();

      if ("connect".equals(methodName)) {
        Object originalConnector = method.invoke(originalNsdService, args);
        if (originalConnector != null) {
          Class<?> connectorClz = Class.forName("android.net.connectivity.android.net.nsd.INsdServiceConnector");

          // NSD calls a second instance: 'INsdServiceConnector', so create a proxy for it
          return Proxy.newProxyInstance(
              connectorClz.getClassLoader(),
              new Class[] { connectorClz },
              (cProxy, cMethod, cArgs) -> {
                String cMethodName = cMethod.getName();
                if (cMethodName.contains("discoverServices") ||
                    cMethodName.contains("registerService") ||
                    cMethodName.contains("resolveService")) {

                  Log.w(TAG, "Neutering NSD method call: " + cMethodName);

                  Class<?> returnType = cMethod.getReturnType();
                  if (returnType == void.class)
                    return null;
                  if (returnType == boolean.class)
                    return true;
                  if (returnType == int.class || returnType == long.class)
                    return 0;
                  return null;
                }
                return cMethod.invoke(originalConnector, cArgs);
              });
        }
        return null;
      }
      return method.invoke(originalNsdService, args);
    };

    Object nsdProxy = Proxy.newProxyInstance(
        iNsdManagerClz.getClassLoader(),
        new Class[] { iNsdManagerClz },
        nsdHandler);

    IBinder nsdProxyBinder = (IBinder) Proxy.newProxyInstance(
        IBinder.class.getClassLoader(),
        new Class[] { IBinder.class },
        (p, method, args) -> "queryLocalInterface".equals(method.getName()) ? nsdProxy
            : method.invoke(realNsdBinder, args));

    cache.put("servicediscovery", nsdProxyBinder);
  }
}
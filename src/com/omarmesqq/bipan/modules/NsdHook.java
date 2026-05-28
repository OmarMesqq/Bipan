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

public class NsdHook implements BaseHook, InvocationHandler {
  private static final String TAG = "BipanNsdHook";
  private Object originalNsdService;

  @Override
  public void install(Context context) throws Exception {
    Class<?> serviceManager = Class.forName("android.os.ServiceManager");
    Method getService = serviceManager.getDeclaredMethod("getService", String.class);

    // NSD service is registered with the "servicediscovery" Binder name
    IBinder realBinder = (IBinder) getService.invoke(null, "servicediscovery");
    if (realBinder == null) {
      Log.e(TAG, "Network Service Discovery service 'servicediscovery' not found!");
      return;
    }

    Class<?> iNsdManagerClz = Class.forName("android.net.nsd.INsdManager");
    Class<?> stubClz = Class.forName("android.net.nsd.INsdManager$Stub");
    Method asInterface = stubClz.getDeclaredMethod("asInterface", IBinder.class);

    this.originalNsdService = asInterface.invoke(null, realBinder);

    Object proxy = Proxy.newProxyInstance(
        iNsdManagerClz.getClassLoader(),
        new Class[] { iNsdManagerClz },
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

    cache.put("servicediscovery", proxyBinder);
  }

  @Override
  public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
    String methodName = method.getName();
    Log.d(TAG, "NSD Manager call: " + methodName);

    // We allow the connection but proxy the returned connector
    if (methodName.equals("connect")) {
      Object originalConnector = method.invoke(originalNsdService, args);

      if (originalConnector != null) {
        Log.d(TAG, "App requested .connect() to NSD Manager. Wrapping INsdServiceConnector in a secondary proxy.");

        Class<?> connectorClz = Class.forName("android.net.connectivity.android.net.nsd.INsdServiceConnector");

        return Proxy.newProxyInstance(
            connectorClz.getClassLoader(),
            new Class[] { connectorClz },
            new ConnectorProxy(originalConnector));
      }
      return null; // Fallback if system fails naturally
    }

    return method.invoke(originalNsdService, args);
  }

  /**
   * Inner class to handle the secondary proxy for INsdServiceConnector
   */
  private static class ConnectorProxy implements InvocationHandler {
    private final Object realConnector;

    public ConnectorProxy(Object realConnector) {
      this.realConnector = realConnector;
    }

    @Override
    public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
      String methodName = method.getName();

      if (methodName.contains("discoverServices") ||
          methodName.contains("registerService") ||
          methodName.contains("resolveService")) {

        Log.w(TAG, "Neutering NSD method call: " + methodName);

        Class<?> returnType = method.getReturnType();
        if (returnType == void.class) {
          return null;
        } else if (returnType == boolean.class) {
          return true;
        } else if (returnType == int.class || returnType == long.class) {
          return 0;
        }
        return null;
      } else {
        Log.d(TAG, "Allowing NSD method call: " + methodName);
      }

      return method.invoke(realConnector, args);
    }
  }
}
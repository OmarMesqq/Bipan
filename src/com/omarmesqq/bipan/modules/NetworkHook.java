package com.omarmesqq.bipan.modules;

import android.content.Context;
import android.net.NetworkCapabilities;
import android.os.IBinder;
import android.util.Log;
import com.omarmesqq.bipan.BaseHook;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;

public class NetworkHook implements BaseHook, InvocationHandler {
  private static final String TAG = "BipanNetworkHook";
  private Object originalConnectivityService;

  @Override
  public void install(Context context) throws Exception {
    Class<?> serviceManager = Class.forName("android.os.ServiceManager");
    Method getService = serviceManager.getDeclaredMethod("getService", String.class);
    IBinder realBinder = (IBinder) getService.invoke(null, "connectivity");

    Class<?> iConnectivityManagerClz = Class.forName("android.net.IConnectivityManager");
    Class<?> stubClz = Class.forName("android.net.IConnectivityManager$Stub");
    Method asInterface = stubClz.getDeclaredMethod("asInterface", IBinder.class);

    this.originalConnectivityService = asInterface.invoke(null, realBinder);

    Object proxy = Proxy.newProxyInstance(
        iConnectivityManagerClz.getClassLoader(),
        new Class[] { iConnectivityManagerClz },
        this);

    java.lang.reflect.Field sCacheField = serviceManager.getDeclaredField("sCache");
    sCacheField.setAccessible(true);
    @SuppressWarnings("unchecked")
    java.util.Map<String, IBinder> cache = (java.util.Map<String, IBinder>) sCacheField.get(null);

    IBinder proxyBinder = (IBinder) Proxy.newProxyInstance(
        IBinder.class.getClassLoader(),
        new Class[] { IBinder.class },
        (p, method, args) -> {
          if ("queryLocalInterface".equals(method.getName())) {
            return proxy;
          }
          return method.invoke(realBinder, args);
        });

    cache.put("connectivity", proxyBinder);
    Log.d(TAG, "Hijacked ConnectivityService Binder");
  }

  @Override
  public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
    Object result = method.invoke(originalConnectivityService, args);

    if (result instanceof NetworkCapabilities) {
      applySpoof((NetworkCapabilities) result);
    }

    return result;
  }

  private void applySpoof(NetworkCapabilities caps) {
    try {
      // Access the hidden methods via reflection
      Method removeTransport = NetworkCapabilities.class.getDeclaredMethod("removeTransportType", int.class);
      removeTransport.setAccessible(true);
      removeTransport.invoke(caps, NetworkCapabilities.TRANSPORT_VPN);

      Method addCap = NetworkCapabilities.class.getDeclaredMethod("addCapability", int.class);
      addCap.setAccessible(true);
      addCap.invoke(caps, NetworkCapabilities.NET_CAPABILITY_NOT_VPN);

      Log.d(TAG, "Successfully spoofed NetworkCapabilities object");
    } catch (Exception e) {
      Log.e(TAG, "Failed to spoof NetworkCapabilities via reflection", e);
    }
  }
}
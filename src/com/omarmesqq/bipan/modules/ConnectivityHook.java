package com.omarmesqq.bipan.modules;

import android.content.Context;
import android.net.LinkProperties;
import android.net.LinkAddress;
import android.os.IBinder;
import android.util.Log;
import com.omarmesqq.bipan.BaseHook;
import java.lang.reflect.*;
import java.net.InetAddress;
import java.util.Map;

public class ConnectivityHook implements BaseHook, InvocationHandler {
  private static final String TAG = "BipanConnHook";
  private Object originalConnService;

  @Override
  public void install(Context context) throws Exception {
    Class<?> serviceManager = Class.forName("android.os.ServiceManager");
    Method getService = serviceManager.getDeclaredMethod("getService", String.class);
    IBinder realBinder = (IBinder) getService.invoke(null, "connectivity");

    if (realBinder == null) {
      Log.e(TAG, "Connectivity service not found.");
      return;
    }

    Class<?> iConnManagerClz = Class.forName("android.net.IConnectivityManager");
    Method asInterface = Class.forName("android.net.IConnectivityManager$Stub").getDeclaredMethod("asInterface",
        IBinder.class);
    this.originalConnService = asInterface.invoke(null, realBinder);

    Object proxy = Proxy.newProxyInstance(
        iConnManagerClz.getClassLoader(),
        new Class[] { iConnManagerClz },
        this);

    Field sCacheField = serviceManager.getDeclaredField("sCache");
    sCacheField.setAccessible(true);
    @SuppressWarnings("unchecked")
    Map<String, IBinder> cache = (Map<String, IBinder>) sCacheField.get(null);

    IBinder proxyBinder = (IBinder) Proxy.newProxyInstance(
        IBinder.class.getClassLoader(),
        new Class[] { IBinder.class },
        (p, method, args) -> {
          if ("queryLocalInterface".equals(method.getName()))
            return proxy;
          return method.invoke(realBinder, args);
        });

    cache.put("connectivity", proxyBinder);
    Log.d(TAG, "Successfully hijacked ConnectivityManager Binder");
  }

  @Override
  public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
    Object result = method.invoke(originalConnService, args);

    if (method.getName().equals("getLinkProperties") && result instanceof LinkProperties) {
      spoofLinkProperties((LinkProperties) result);
    }
    return result;
  }

  private void spoofLinkProperties(LinkProperties lp) {
    try {
      // 1. Get the list directly
      Field field = LinkProperties.class.getDeclaredField("mLinkAddresses");
      field.setAccessible(true);
      @SuppressWarnings("unchecked")
      java.util.ArrayList<LinkAddress> list = (java.util.ArrayList<LinkAddress>) field.get(lp);

      // 2. Clear the real list
      list.clear();

      // 3. Create the fake address using reflection to bypass "undefined" constructor
      InetAddress fakeIp = InetAddress.getByName("192.168.1.128");

      // Look for the constructor: LinkAddress(InetAddress, int)
      // Note: We use getDeclaredConstructor() to find it even if it's hidden
      Constructor<LinkAddress> ctor = LinkAddress.class.getDeclaredConstructor(InetAddress.class, int.class);
      ctor.setAccessible(true);
      LinkAddress fakeAddr = ctor.newInstance(fakeIp, 24);

      // 4. Add to the list
      list.add(fakeAddr);

      Log.d(TAG, "Successfully injected fake IP into mLinkAddresses via reflection");
    } catch (Exception e) {
      Log.e(TAG, "Failed to spoof LinkProperties", e);
    }
  }

  // private void logLinkPropertiesFields(LinkProperties lp) {
  //   Log.d(TAG, "--- Introspecting LinkProperties Fields ---");
  //   for (Field field : lp.getClass().getDeclaredFields()) {
  //     field.setAccessible(true);
  //     try {
  //       Log.d(TAG, "Field: " + field.getName() + " | Type: " + field.getType().getName());
  //     } catch (Exception e) {
  //     }
  //   }
  //   Log.d(TAG, "------------------------------------");
  // }
}
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
      Field field = LinkProperties.class.getDeclaredField("mLinkAddresses");
      field.setAccessible(true);

      @SuppressWarnings("unchecked")
      java.util.ArrayList<LinkAddress> list = (java.util.ArrayList<LinkAddress>) field.get(lp);

      list.clear();

      InetAddress fakeIp = InetAddress.getByName("192.168.1.128");

      // Use `getDeclaredConstructor` to look for the potentially hidden constructor:
      // LinkAddress(InetAddress, int)
      Constructor<LinkAddress> ctor = LinkAddress.class.getDeclaredConstructor(InetAddress.class, int.class);
      ctor.setAccessible(true);
      LinkAddress fakeAddr = ctor.newInstance(fakeIp, 24);

      list.add(fakeAddr);
    } catch (Exception e) {
      Log.e(TAG, "Failed to spoof LinkProperties", e);
    }
  }
}
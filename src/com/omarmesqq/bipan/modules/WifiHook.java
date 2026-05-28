package com.omarmesqq.bipan.modules;

import android.content.Context;
import android.net.wifi.WifiInfo;
import android.os.IBinder;
import android.util.Log;
import com.omarmesqq.bipan.BaseHook;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.Map;
import java.net.InetAddress;

public class WifiHook implements BaseHook, InvocationHandler {
  private static final String TAG = "BipanWifiHook";
  private Object originalWifiService;

  @Override
  public void install(Context context) throws Exception {
    // logWifiInfoFields();
    Class<?> serviceManager = Class.forName("android.os.ServiceManager");
    Method getService = serviceManager.getDeclaredMethod("getService", String.class);
    IBinder realBinder = (IBinder) getService.invoke(null, "wifi");

    if (realBinder == null) {
      Log.e(TAG, "Wifi service not found.");
      return;
    }

    Class<?> iWifiManagerClz = Class.forName("android.net.wifi.IWifiManager");
    Class<?> stubClz = Class.forName("android.net.wifi.IWifiManager$Stub");
    Method asInterface = stubClz.getDeclaredMethod("asInterface", IBinder.class);

    this.originalWifiService = asInterface.invoke(null, realBinder);

    Object proxy = Proxy.newProxyInstance(
        iWifiManagerClz.getClassLoader(),
        new Class[] { iWifiManagerClz },
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

    cache.put("wifi", proxyBinder);
  }

  @Override
  public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
    Object result = method.invoke(originalWifiService, args);

    if (method.getName().equals("getConnectionInfo") && result instanceof WifiInfo) {
      spoofWifiInfo((WifiInfo) result);
    }

    return result;
  }

  private void spoofWifiInfo(WifiInfo info) {
    try {
      InetAddress fakeIp = InetAddress.getByAddress(new byte[] { (byte) 192, (byte) 168, 1, (byte) 128 });
      setField(info, "mIpAddress", fakeIp);

      setField(info, "mLinkSpeed", 53);

      Log.d(TAG, "Successfully patched WifiInfo instance fields in-place");
    } catch (Exception e) {
      Log.e(TAG, "In-place patch failed", e);
    }
  }

  private void setField(Object obj, String name, Object value) {
    try {
      Field f = obj.getClass().getDeclaredField(name);
      f.setAccessible(true);
      f.set(obj, value);
      Log.d(TAG, "Field patched: " + name);
    } catch (NoSuchFieldException e) {
      Log.w(TAG, "Field not found: " + name);
    } catch (Exception e) {
      Log.e(TAG, "Failed to patch field: " + name, e);
    }
  }

  // private void logWifiInfoFields() {
  // Log.d(TAG, "--- Introspecting WifiInfo Fields ---");
  // Field[] fields = WifiInfo.class.getDeclaredFields();
  // for (Field field : fields) {
  // field.setAccessible(true);
  // Log.d(TAG, "Field Name: " + field.getName() + " | Type: " +
  // field.getType().getName());
  // }
  // Log.d(TAG, "------------------------------------");
  // }
}
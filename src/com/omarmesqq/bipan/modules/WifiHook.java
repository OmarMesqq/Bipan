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
    Log.d(TAG, "Successfully hijacked WifiManager Binder");
  }

  @Override
  public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
    // Execute the real call to maintain system state
    Object result = method.invoke(originalWifiService, args);

    // Intercept result if it's a WifiInfo request
    if (method.getName().equals("getConnectionInfo") && result instanceof WifiInfo) {
      return createSpoofedWifiInfo();
    }

    return result;
  }

  private WifiInfo createSpoofedWifiInfo() {
    try {
      // Instantiate a fresh WifiInfo object
      // WifiInfo has a hidden constructor, we use reflection to instantiate
      WifiInfo spoofedInfo = WifiInfo.class.newInstance();

      // Inject spoofed values
      setField(spoofedInfo, "mBSSID", "02:00:00:00:00:00");
      setField(spoofedInfo, "mSSID", "Unknown");

      // Handle IP Address (try InetAddress first for modern APIs, fallback to int)
      try {
        byte[] ipBytes = new byte[] { (byte) 192, (byte) 168, 1, (byte) 128 };
        InetAddress fakeInetAddress = InetAddress.getByAddress(ipBytes);
        setField(spoofedInfo, "mInetAddress", fakeInetAddress);
      } catch (Exception e) {
        // Fallback for older versions/APIs
        setField(spoofedInfo, "mIpAddress", 0x8001A8C0);
      }

      return spoofedInfo;
    } catch (Exception e) {
      Log.e(TAG, "Failed to create spoofed WifiInfo", e);
      return null;
    }
  }

  private void setField(Object obj, String fieldName, Object value) {
    try {
      Field field = WifiInfo.class.getDeclaredField(fieldName);
      field.setAccessible(true);
      field.set(obj, value);
    } catch (Exception e) {
      Log.w(TAG, "Field " + fieldName + " not found, skipping.");
    }
  }
}
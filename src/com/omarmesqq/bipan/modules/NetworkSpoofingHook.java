package com.omarmesqq.bipan.modules;

import android.content.Context;
import android.net.LinkAddress;
import android.net.LinkProperties;
import android.net.NetworkCapabilities;
import android.net.wifi.WifiInfo;
import android.os.Bundle;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.os.Message;
import android.os.Messenger;
import android.util.Log;
import com.omarmesqq.bipan.BaseHook;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.net.InetAddress;
import java.util.Map;
import java.util.ArrayList;

/**
 * An almost-too-complex hook for some networking related services in Android:
 * - Trims VPN flag from NetworkCapabilities
 * - Hardcodes a fake IPv4 local address
 * - Hardcodes 53Mbps as link speed
 * - Hardcodes `VALIDATED` for connections i.e. not behind captive portal
 * 
 */
public class NetworkSpoofingHook implements BaseHook {
  private static final String TAG = "BipanNetworkSpoofingHook";

  /**
   * Non-system apps can't use the `LOCAL_MAC_ADDRESS` permission,
   * so this is the default returned by AOSP.
   * 
   * https://cs.android.com/android/platform/superproject/+/android-latest-release:packages/modules/Wifi/framework/java/android/net/wifi/WifiInfo.java;l=100
   */
  public static final String DEFAULT_MAC_ADDRESS = "02:00:00:00:00:00";

  /**
   * Returned when the "if there is no network currently connected
   * or if the caller has insufficient permissions to access the SSID"
   * 
   * https://cs.android.com/android/platform/superproject/+/android-latest-release:packages/modules/Wifi/framework/java/android/net/wifi/WifiManager.java;l=1985
   */
  public static final String UNKNOWN_SSID = "<unknown ssid>";

  @Override
  public void install(Context context) throws Exception {
    // Common ServiceManager setup
    Class<?> serviceManager = Class.forName("android.os.ServiceManager");
    Method getService = serviceManager.getDeclaredMethod("getService", String.class);
    Field sCacheField = serviceManager.getDeclaredField("sCache");
    sCacheField.setAccessible(true);

    @SuppressWarnings("unchecked")
    Map<String, IBinder> cache = (Map<String, IBinder>) sCacheField.get(null);

    setupConnectivitySpoofing(getService, cache);
    setupWifiSpoofing(getService, cache);
  }

  private void setupConnectivitySpoofing(Method getService, Map<String, IBinder> cache) throws Exception {
    IBinder realBinder = (IBinder) getService.invoke(null, "connectivity");
    if (realBinder == null) {
      throw new Exception(TAG + " Connectivity service ('connectivity') not found!");
    }

    Class<?> iConnManagerClz = Class.forName("android.net.IConnectivityManager");
    Class<?> stubClz = Class.forName("android.net.IConnectivityManager$Stub");
    Method asInterface = stubClz.getDeclaredMethod("asInterface", IBinder.class);
    final Object originalConnService = asInterface.invoke(null, realBinder);

    // InvocationHandler for async callbacks
    InvocationHandler connHandler = (proxy, method, args) -> {
      if (args != null) {
        for (int i = 0; i < args.length; i++) {
          if (args[i] instanceof Messenger) {
            final Messenger originalMessenger = (Messenger) args[i];
            Handler interceptorHandler = new Handler(Looper.getMainLooper()) {
              @Override
              public void handleMessage(Message msg) {
                Message safeCopy = Message.obtain(msg);
                patchAsyncMessage(safeCopy);
                try {
                  originalMessenger.send(safeCopy);
                } catch (Exception e) {
                  Log.e(TAG, "Failed to forward callback message", e);
                }
              }
            };
            args[i] = new Messenger(interceptorHandler);
          }
        }
      }

      Object result = method.invoke(originalConnService, args);

      // synchronous returns
      if (result instanceof NetworkCapabilities) {
        applyVpnSpoof((NetworkCapabilities) result);
      } else if (result != null && result.getClass().isArray()
          && result.getClass().getComponentType() == NetworkCapabilities.class) {
        NetworkCapabilities[] capsArray = (NetworkCapabilities[]) result;
        for (NetworkCapabilities caps : capsArray) {
          applyVpnSpoof(caps);
        }
      } else if ("getLinkProperties".equals(method.getName()) && result instanceof LinkProperties) {
        spoofLinkProperties((LinkProperties) result);
      }

      return result;
    };

    Object proxy = Proxy.newProxyInstance(iConnManagerClz.getClassLoader(), new Class[] { iConnManagerClz },
        connHandler);
    IBinder proxyBinder = (IBinder) Proxy.newProxyInstance(
        IBinder.class.getClassLoader(),
        new Class[] { IBinder.class },
        (p, method, args) -> "queryLocalInterface".equals(method.getName()) ? proxy : method.invoke(realBinder, args));

    cache.put("connectivity", proxyBinder);
  }

  private void setupWifiSpoofing(Method getService, Map<String, IBinder> cache) throws Exception {
    IBinder realBinder = (IBinder) getService.invoke(null, "wifi");
    if (realBinder == null) {
      throw new Exception(TAG + " Wifi service ('wifi') not found!");
    }

    Class<?> iWifiManagerClz = Class.forName("android.net.wifi.IWifiManager");
    Class<?> stubClz = Class.forName("android.net.wifi.IWifiManager$Stub");
    Method asInterface = stubClz.getDeclaredMethod("asInterface", IBinder.class);
    final Object originalWifiService = asInterface.invoke(null, realBinder);

    InvocationHandler wifiHandler = (proxy, method, args) -> {
      Object result = method.invoke(originalWifiService, args);
      if ("getConnectionInfo".equals(method.getName()) && result instanceof WifiInfo) {
        spoofWifiInfo((WifiInfo) result);
      }
      return result;
    };

    Object proxy = Proxy.newProxyInstance(iWifiManagerClz.getClassLoader(), new Class[] { iWifiManagerClz },
        wifiHandler);
    IBinder proxyBinder = (IBinder) Proxy.newProxyInstance(
        IBinder.class.getClassLoader(),
        new Class[] { IBinder.class },
        (p, method, args) -> "queryLocalInterface".equals(method.getName()) ? proxy : method.invoke(realBinder, args));

    cache.put("wifi", proxyBinder);
  }

  private void patchAsyncMessage(Message msg) {
    if (msg == null) {
      return;
    }

    if (msg.obj instanceof NetworkCapabilities) {
      applyVpnSpoof((NetworkCapabilities) msg.obj);
    } else if (msg.obj != null) {
      try {
        for (Field f : msg.obj.getClass().getDeclaredFields()) {
          if (NetworkCapabilities.class.isAssignableFrom(f.getType())) {
            f.setAccessible(true);
            NetworkCapabilities nc = (NetworkCapabilities) f.get(msg.obj);
            if (nc != null) {
              applyVpnSpoof(nc);
            }
          }
        }
      } catch (Throwable t) {
        Log.e(TAG, "Failed to apply direct async NetworkCapabilities spoof!");
      }
    }

    Bundle data = msg.getData();
    if (data != null) {
      try {
        data.setClassLoader(NetworkCapabilities.class.getClassLoader());
        for (String key : data.keySet()) {
          @SuppressWarnings("deprecation")
          Object val = data.get(key);

          if (val instanceof NetworkCapabilities) {
            applyVpnSpoof((NetworkCapabilities) val);
            data.putParcelable(key, (NetworkCapabilities) val);
          }
        }
      } catch (Throwable t) {
        Log.e(TAG, "Failed to apply Bundle-wrapped async NetworkCapabilities spoof!");
      }
    }
  }

  private void applyVpnSpoof(NetworkCapabilities caps) {
    if (caps == null) {
      return;
    }

    try {
      // Remove `VPN` transport from object
      Method removeTransport = NetworkCapabilities.class.getDeclaredMethod("removeTransportType", int.class);
      removeTransport.setAccessible(true);
      removeTransport.invoke(caps, NetworkCapabilities.TRANSPORT_VPN);

      // Tell app we don't have a VPN and Internet is VALIDATED i.e. not behind
      // captive portal
      Method addCap = NetworkCapabilities.class.getDeclaredMethod("addCapability", int.class);
      addCap.setAccessible(true);
      addCap.invoke(caps, NetworkCapabilities.NET_CAPABILITY_NOT_VPN);
      addCap.invoke(caps, NetworkCapabilities.NET_CAPABILITY_VALIDATED);

      // Trim `TransportInfo`
      Field transportInfoField = NetworkCapabilities.class
          .getDeclaredField("mTransportInfo");
      transportInfoField.setAccessible(true);
      transportInfoField.set(caps, null);

      // Spoof bandwidth to realistic mid-range WiFi values
      Field upBwField = NetworkCapabilities.class
          .getDeclaredField("mLinkUpBandwidthKbps");
      upBwField.setAccessible(true);
      upBwField.setInt(caps, 53000); // 53 Mbps up

      Field downBwField = NetworkCapabilities.class
          .getDeclaredField("mLinkDownBandwidthKbps");
      downBwField.setAccessible(true);
      downBwField.setInt(caps, 52000); // 52 Mbps down

    } catch (Exception e) {
      Log.e(TAG, "Failed to spoof NetworkCapabilities via reflection", e);
    }
  }

  private void spoofLinkProperties(LinkProperties lp) {
    try {
      Field field = LinkProperties.class.getDeclaredField("mLinkAddresses");
      field.setAccessible(true);

      @SuppressWarnings("unchecked")
      ArrayList<LinkAddress> list = (ArrayList<LinkAddress>) field.get(lp);
      list.clear();

      InetAddress fakeIp = InetAddress.getByName("192.168.1.128");
      Constructor<LinkAddress> ctor = LinkAddress.class.getDeclaredConstructor(InetAddress.class, int.class);
      ctor.setAccessible(true);
      list.add(ctor.newInstance(fakeIp, 24));
    } catch (Exception e) {
      Log.e(TAG, "Failed to spoof LinkProperties", e);
    }
  }

  private void spoofWifiInfo(WifiInfo info) {
    try {
      InetAddress fakeIp = InetAddress.getByAddress(new byte[] { (byte) 192, (byte) 168, 1, (byte) 128 });
      
      setField(info, "mIpAddress", fakeIp);
      setField(info, "mLinkSpeed", 53); // Mbps
      setField(info, "mWifiSsid", UNKNOWN_SSID);
      setField(info, "mBSSID", DEFAULT_MAC_ADDRESS);
      
    } catch (Exception e) {
      Log.e(TAG, "In-place patch failed: ", e);
    }
  }

  private void setField(Object obj, String name, Object value) {
    try {
      Field f = obj.getClass().getDeclaredField(name);
      f.setAccessible(true);
      f.set(obj, value);
    } catch (Exception e) {
      Log.e(TAG, "Failed to patch field: " + name);
    }
  }
}
package com.omarmesqq.bipan.modules;

import android.content.Context;
import android.net.LinkAddress;
import android.net.LinkProperties;
import android.net.Network;
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
import android.net.ConnectivityManager;
import android.net.ConnectivityManager.NetworkCallback;

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
  private static final String DEFAULT_MAC_ADDRESS = "02:00:00:00:00:00";

  /**
   * Returned when the "if there is no network currently connected
   * or if the caller has insufficient permissions to access the SSID"
   * 
   * https://cs.android.com/android/platform/superproject/+/android-latest-release:packages/modules/Wifi/framework/java/android/net/wifi/WifiManager.java;l=1985
   */
  private static final String UNKNOWN_SSID = "<unknown ssid>";

  private static final String CELLULAR_IFACE_NAME = "rmnet0";
  private static final String WIFI_IFACE_NAME = "wlan0";
  private static final String FAKE_IP = "10.111.222.1";

  private static Boolean isCurrentNetworkMetered = null;

  @Override
  public void install(Context context) throws Exception {
    ConnectivityManager cm = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
    isCurrentNetworkMetered = cm.isActiveNetworkMetered();

    NetworkCallback nc = new NetworkCallback() {
      @Override
      public void onCapabilitiesChanged(Network network, NetworkCapabilities networkCapabilities) {
        int[] caps = networkCapabilities.getCapabilities();
        Log.w(TAG, "ConnectivityManager.onCapabilitiesChanged");
        for (int cap : caps) {
          if (cap == NetworkCapabilities.NET_CAPABILITY_NOT_METERED) {
            isCurrentNetworkMetered = true;
            break;
          }
        }
      }
    };
    try {
      cm.registerDefaultNetworkCallback(nc);
    } catch (RuntimeException re) {
      Log.e(TAG, "Failed register CM callback. App has too many callbacks registered:" + re.getMessage());
    } catch (Exception e) {
      Log.e(TAG, "Failed register CM callback. Unknown cause:" + e.getCause() + " Message: " + e.getMessage());
    }

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
      ArrayList<InetAddress> dnsServers = new ArrayList<>();
      dnsServers.add(InetAddress.getByName("8.8.8.8"));
      dnsServers.add(InetAddress.getByName("8.8.4.4"));

      // Default to cellular
      if (isCurrentNetworkMetered == null || isCurrentNetworkMetered == true) {
        Field field = LinkProperties.class.getDeclaredField("mLinkAddresses");
        field.setAccessible(true);

        @SuppressWarnings("unchecked")
        ArrayList<LinkAddress> list = (ArrayList<LinkAddress>) field.get(lp);
        list.clear();

        // Use a plausible cellular IP range
        InetAddress fakeIp = InetAddress.getByName(FAKE_IP);
        Constructor<LinkAddress> ctor = LinkAddress.class.getDeclaredConstructor(InetAddress.class, int.class);
        ctor.setAccessible(true);
        list.add(ctor.newInstance(fakeIp, 24));

        Field routesField = LinkProperties.class.getDeclaredField("mRoutes");
        routesField.setAccessible(true);

        @SuppressWarnings("unchecked")
        ArrayList<Object> routes = (ArrayList<Object>) routesField.get(lp);
        routes.clear();

        Class<?> routeInfoClass = Class.forName("android.net.RouteInfo");
        Class<?> ipPrefixClass = Class.forName("android.net.IpPrefix");

        // IpPrefix(InetAddress address, int prefixLength)
        Constructor<?> ipPrefixCtor = ipPrefixClass.getDeclaredConstructor(InetAddress.class, int.class);
        ipPrefixCtor.setAccessible(true);

        // RouteInfo(IpPrefix destination, InetAddress gateway, String iface)
        Constructor<?> routeCtor = routeInfoClass.getDeclaredConstructor(ipPrefixClass, InetAddress.class,
            String.class);
        routeCtor.setAccessible(true);

        InetAddress subnetAddr = InetAddress.getByName("10.111.222.0");
        InetAddress gatewayAddr = InetAddress.getByName(FAKE_IP);
        InetAddress anyAddr = InetAddress.getByName("0.0.0.0");

        // Subnet route: 10.111.222.0/24 directly connected
        Object subnetPrefix = ipPrefixCtor.newInstance(subnetAddr, 24);
        routes.add(routeCtor.newInstance(subnetPrefix, null, CELLULAR_IFACE_NAME));

        // Default route: 0.0.0.0/0 via gateway
        Object defaultPrefix = ipPrefixCtor.newInstance(anyAddr, 0);
        routes.add(routeCtor.newInstance(defaultPrefix, gatewayAddr, CELLULAR_IFACE_NAME));

        lp.setMtu(1500);
        lp.setDhcpServerAddress(null);
        lp.setDnsServers(dnsServers);
        return;
      }

      Field field = LinkProperties.class.getDeclaredField("mLinkAddresses");
      field.setAccessible(true);

      @SuppressWarnings("unchecked")
      ArrayList<LinkAddress> list = (ArrayList<LinkAddress>) field.get(lp);
      list.clear();

      InetAddress fakeIp = InetAddress.getByName(FAKE_IP);
      Constructor<LinkAddress> ctor = LinkAddress.class.getDeclaredConstructor(InetAddress.class, int.class);
      ctor.setAccessible(true);
      list.add(ctor.newInstance(fakeIp, 24));

      Field routesField = LinkProperties.class.getDeclaredField("mRoutes");
      routesField.setAccessible(true);

      @SuppressWarnings("unchecked")
      ArrayList<Object> routes = (ArrayList<Object>) routesField.get(lp);
      routes.clear();

      Class<?> routeInfoClass = Class.forName("android.net.RouteInfo");
      Class<?> ipPrefixClass = Class.forName("android.net.IpPrefix");

      // IpPrefix(InetAddress address, int prefixLength)
      Constructor<?> ipPrefixCtor = ipPrefixClass.getDeclaredConstructor(InetAddress.class, int.class);
      ipPrefixCtor.setAccessible(true);

      // RouteInfo(IpPrefix destination, InetAddress gateway, String iface)
      Constructor<?> routeCtor = routeInfoClass.getDeclaredConstructor(ipPrefixClass, InetAddress.class, String.class);
      routeCtor.setAccessible(true);

      InetAddress subnetAddr = InetAddress.getByName("10.111.222.0");
      InetAddress gatewayAddr = InetAddress.getByName(FAKE_IP);
      InetAddress anyAddr = InetAddress.getByName("0.0.0.0");

      // Subnet route: 10.111.222.0/24 directly connected
      Object subnetPrefix = ipPrefixCtor.newInstance(subnetAddr, 24);
      routes.add(routeCtor.newInstance(subnetPrefix, null, WIFI_IFACE_NAME));

      // Default route: 0.0.0.0/0 via gateway
      Object defaultPrefix = ipPrefixCtor.newInstance(anyAddr, 0);
      routes.add(routeCtor.newInstance(defaultPrefix, gatewayAddr, WIFI_IFACE_NAME));

      lp.setInterfaceName(WIFI_IFACE_NAME);
      lp.setMtu(1500);
      lp.setDhcpServerAddress(null);

      lp.setDnsServers(dnsServers);
    } catch (Exception e) {
      Log.e(TAG, "Failed to spoof LinkProperties: ", e);
    }
  }

  private void spoofWifiInfo(WifiInfo info) {
    try {
      // Check if WiFi is actually connected
      Field networkIdField = info.getClass().getDeclaredField("mNetworkId");
      networkIdField.setAccessible(true);
      int networkId = (int) networkIdField.get(info);

      // We're on cellular
      if (networkId == -1) {
        InetAddress zeroIp = InetAddress.getByAddress(new byte[] { 0, 0, 0, 0 });
        setField(info, "mIpAddress", zeroIp);
        setField(info, "mLinkSpeed", -1);
        setField(info, "mBSSID", null);
        setField(info, "mMaxSupportedRxLinkSpeed", 0);
        setField(info, "mMaxSupportedTxLinkSpeed", 0);
        setField(info, "mTxLinkSpeed", -1);
        setField(info, "mRxLinkSpeed", -1);
        spoofSsid(info);
        return;
      }

      InetAddress fakeIp = InetAddress.getByAddress(new byte[] { (byte) 10, (byte) 111, (byte) 222, (byte) 1 });

      setField(info, "mIpAddress", fakeIp);
      setField(info, "mLinkSpeed", 53); // Mbps
      setField(info, "mNetworkId", 4);
      setField(info, "mBSSID", DEFAULT_MAC_ADDRESS);
      setField(info, "mMaxSupportedRxLinkSpeed", 62);
      setField(info, "mMaxSupportedTxLinkSpeed", 60);
      setField(info, "mTxLinkSpeed", 54);
      setField(info, "mRxLinkSpeed", 54);
      spoofSsid(info);

    } catch (Exception e) {
      Log.e(TAG, "In-place patch failed: ", e);
    }
  }

  private void spoofSsid(WifiInfo info) {
    try {
      Class<?> wifiSsidClass = Class.forName("android.net.wifi.WifiSsid");

      Method fromUtf8Text = wifiSsidClass.getDeclaredMethod("fromUtf8Text", CharSequence.class);
      fromUtf8Text.setAccessible(true);
      Object fakeSsid = fromUtf8Text.invoke(null, UNKNOWN_SSID);

      setField(info, "mWifiSsid", fakeSsid);
    } catch (Exception e) {
      Log.e(TAG, "Failed to spoof mWifiSsid: ", e);
    }
  }

  private void setField(Object obj, String name, Object value) {
    try {
      Field f = obj.getClass().getDeclaredField(name);
      f.setAccessible(true);
      f.set(obj, value);
    } catch (Exception e) {
      Log.e(TAG, "Failed to patch field: " + name + ". Exception: " + new Throwable(e));
    }
  }
}
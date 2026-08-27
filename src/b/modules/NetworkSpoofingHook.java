package b.modules;

import android.content.Context;
import android.net.LinkAddress;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkInfo;
import android.net.wifi.WifiInfo;
import android.os.Bundle;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.os.Message;
import android.os.Messenger;
import android.util.Log;
import b.BaseHook;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.net.InetAddress;
import java.util.Map;
import java.util.ArrayList;
import b.J;

/**
 * An almost-too-complex hook for some networking related services in Android:
 * - Trims VPN flag from NetworkCapabilities
 * - Hardcodes a fake IPv4 local address
 * - Hardcodes `VALIDATED` for connections i.e. not behind captive portal
 */
public class NetworkSpoofingHook implements BaseHook {
  private static final String TAG = "BipanJavaNetwork";

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

  private static Object cmProxy;
  private static Object wifiProxy;

  private static String selfPackageName;

  @Override
  public void install(Context context) throws Exception {
    selfPackageName = context.getPackageName();

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

  @SuppressWarnings("deprecation")
  private void setupConnectivitySpoofing(Method getService, Map<String, IBinder> cache) throws Exception {
    IBinder realBinder = (IBinder) getService.invoke(null, "connectivity");
    if (realBinder == null) {
      throw new Exception(TAG + " Connectivity service ('connectivity') not found!");
    }

    Class<?> iConnManagerClz = Class.forName("android.net.IConnectivityManager");
    Class<?> stubClz = Class.forName("android.net.IConnectivityManager$Stub");
    Method asInterface = stubClz.getDeclaredMethod("asInterface", IBinder.class);
    final Object originalConnService = asInterface.invoke(null, realBinder);

    InvocationHandler connHandler = (proxy, method, args) -> {
      if (args != null) {
        for (int i = 0; i < args.length; i++) {
          // for async callbacks
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
                  Log.e(TAG, "Failed to forward message", e);
                  throw new OutOfMemoryError();
                }
              }
            };
            args[i] = new Messenger(interceptorHandler);
          }
        }
      }

      // synchronous returns
      Object result;
      try {
        result = method.invoke(originalConnService, args);
      } catch (InvocationTargetException e) {
        Throwable cause = e.getCause() != null ? e.getCause() : e;
        Log.w(TAG, "connHandler: InvocationTargetException: Underlying call to " + method.getName()
            + " failed. Cause's msg: " + cause.getMessage());
        throw cause;
      }

      if ("getNetworkCapabilities".equals(method.getName())) {
        // Log.i(TAG, "Neutered getNetworkCapabilities");
        NetworkCapabilities nc = (NetworkCapabilities) result;
        applyVpnSpoof(nc);
      } else if ("getLinkProperties".equals(method.getName()) && result instanceof LinkProperties) {
        try {
          spoofLinkProperties((LinkProperties) result);
        } catch (SecurityException e) {
          Log.w(TAG, "connHandler: SecurityException during LinkProperties spoof");
          throw new OutOfMemoryError();
        } catch (Exception e) {
          Log.e(TAG, "connHandler: unknown exception. Aborting!", e);
          throw new OutOfMemoryError();
        }
      } else if ("getAllNetworks".equals(method.getName())) {
        // Log.i(TAG, "Neutered getAllNetworks");
        return new Network[0];
      } else if ("getAllNetworkInfo".equals(method.getName())) {
        // Log.i(TAG, "Neutered getAllNetworkInfo");
        return new NetworkInfo[0];
      } else if ("getBoundNetworkForProcess".equals(method.getName())) {
        // Log.i(TAG, "Neutered getBoundNetworkForProcess");
        return new NetworkInfo(0, 0, "DUMMY", "");
      } else if ("getActiveNetworkInfo".equals(method.getName())) {
        if (result != null) {
          NetworkInfo ni = (NetworkInfo) result;
          ni.setDetailedState(
              NetworkInfo.DetailedState.CONNECTED,
              null, // reason
              null // extraInfo
          );

          // If VPN, we abort
          if ("VPN".equals(ni.getTypeName())) {
            throw new OutOfMemoryError();
          }
          return ni;
        }
      }

      return result;
    };

    cmProxy = Proxy.newProxyInstance(iConnManagerClz.getClassLoader(), new Class[] { iConnManagerClz },
        connHandler);
    IBinder proxyBinder = (IBinder) Proxy.newProxyInstance(
        IBinder.class.getClassLoader(),
        new Class[] { IBinder.class },
        (p, method, args) -> "queryLocalInterface".equals(method.getName()) ? cmProxy
            : method.invoke(realBinder, args));

    cache.put("connectivity", proxyBinder);
    J.scmp = cmProxy;
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
      Object result;
      try {
        result = method.invoke(originalWifiService, args);
      } catch (InvocationTargetException e) {
        Throwable cause = e.getCause() != null ? e.getCause() : e;
        Log.d(TAG, "wifiHandler: " + method.getName() + " call failed", cause);
        throw cause;
      }

      if ("getConnectionInfo".equals(method.getName()) && result instanceof WifiInfo) {
        spoofWifiInfo((WifiInfo) result);
      }
      return result;
    };

    wifiProxy = Proxy.newProxyInstance(iWifiManagerClz.getClassLoader(), new Class[] { iWifiManagerClz },
        wifiHandler);
    IBinder proxyBinder = (IBinder) Proxy.newProxyInstance(
        IBinder.class.getClassLoader(),
        new Class[] { IBinder.class },
        (p, method, args) -> "queryLocalInterface".equals(method.getName()) ? wifiProxy
            : method.invoke(realBinder, args));

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
        Log.e(TAG, "Failed to patch async message [1]", t);
        throw new OutOfMemoryError();
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
        Log.e(TAG, "Failed to patch async message [1]", t);
        throw new OutOfMemoryError();
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

      // Tell app we don't have a VPN and Internet is `VALIDATED`
      // i.e. not behind a captive portal
      Method addCap = NetworkCapabilities.class.getDeclaredMethod("addCapability", int.class);
      addCap.setAccessible(true);
      addCap.invoke(caps, NetworkCapabilities.NET_CAPABILITY_NOT_VPN);
      addCap.invoke(caps, NetworkCapabilities.NET_CAPABILITY_VALIDATED);

      // Trim `TransportInfo`
      Field transportInfoField = NetworkCapabilities.class
          .getDeclaredField("mTransportInfo");
      transportInfoField.setAccessible(true);
      transportInfoField.set(caps, null);

    } catch (Exception e) {
      Log.e(TAG, "Failed to apply VPN spoof", e);
      throw new OutOfMemoryError();
    }
  }

  private void spoofLinkProperties(LinkProperties lp) throws Throwable {
    try {
      ArrayList<InetAddress> dnsServers = new ArrayList<>();
      dnsServers.add(InetAddress.getByName("1.1.1.1"));
      dnsServers.add(InetAddress.getByName("1.0.0.1"));

      String currentIface = lp.getInterfaceName();

      // We are on mobile
      if (currentIface.contains("rmnet")) {
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

        lp.setInterfaceName(CELLULAR_IFACE_NAME);
        lp.setMtu(1500);
        lp.setDhcpServerAddress(null);
        lp.setDnsServers(dnsServers);
        spoofPrivateDnsInLp(lp);

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
      spoofPrivateDnsInLp(lp);

    } catch (InvocationTargetException e) {
      throw e.getCause() != null ? e.getCause() : e;
    } catch (Exception e) {
      Log.e(TAG, "Failed to spoof LinkProperties", e);
      throw new OutOfMemoryError();
    }
  }

  private void spoofWifiInfo(WifiInfo info) {
    try {
      // Check if WiFi is actually connected
      Field networkIdField = info.getClass().getDeclaredField("mNetworkId");
      networkIdField.setAccessible(true);
      int networkId = (int) networkIdField.get(info);

      // No permission, not connected or we are on mobile
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
      setField(info, "mNetworkId", 4);
      setField(info, "mBSSID", DEFAULT_MAC_ADDRESS);
      spoofSsid(info);
    } catch (Exception e) {
      Log.e(TAG, "spoofWifiInfo: Unknown exception", e);
      throw new OutOfMemoryError();
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
      Log.e(TAG, "spoofSsid: Unknown exception: ", e);
      throw new OutOfMemoryError();
    }
  }

  private void setField(Object obj, String name, Object value) {
    try {
      Field f = obj.getClass().getDeclaredField(name);
      f.setAccessible(true);
      f.set(obj, value);
    } catch (NoSuchFieldException e) {
      Log.e(TAG, "setField(" + name + ") - NoSuchFieldException. Message: " + e.getMessage());
    } catch (Exception e) {
      Log.e(TAG, "setField(" + name + "). Unknown exception: ", e);
      throw new OutOfMemoryError();
    }
  }

  private void spoofPrivateDnsInLp(LinkProperties lp) {
    try {
      Method setUsePrivateDns = LinkProperties.class.getMethod("setUsePrivateDns", boolean.class);
      setUsePrivateDns.invoke(lp, false);

      Method setPrivateDnsServerName = LinkProperties.class.getMethod(
          "setPrivateDnsServerName", String.class);
      setPrivateDnsServerName.invoke(lp, new Object[] { null });
    } catch (NoSuchMethodException | IllegalAccessException | InvocationTargetException e) {
      Log.e(TAG, "Failed to spoof private DNS: ", e);
      throw new OutOfMemoryError();
    }
  }
}

package com.omarmesqq.bipan.modules;

import android.content.Context;
import android.net.NetworkCapabilities;
import android.os.Bundle;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.os.Message;
import android.os.Messenger;
import android.util.Log;
import com.omarmesqq.bipan.BaseHook;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.Map;

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

    cache.put("connectivity", proxyBinder);
  }

  @Override
  public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {

    // 1. Intercept Asynchronous IPC Callbacks
    if (args != null) {
      for (int i = 0; i < args.length; i++) {
        if (args[i] instanceof Messenger) {
          final Messenger originalMessenger = (Messenger) args[i];

          // Create a middle-man handler on the main thread
          Handler interceptorHandler = new Handler(Looper.getMainLooper()) {
            @Override
            public void handleMessage(Message msg) {

              // Clone the message to avoid "This message is already in use" exception
              Message safeCopy = Message.obtain(msg);

              patchAsyncMessage(safeCopy);
              try {
                // Forward the safe, patched copy to the app's real callback
                originalMessenger.send(safeCopy);
              } catch (Exception e) {
                Log.e(TAG, "Failed to forward callback message", e);
              }
            }
          };

          // Replace the app's messenger with our middle-man before passing to the OS
          args[i] = new Messenger(interceptorHandler);
          Log.d(TAG, "Intercepted NetworkCallback Messenger in: " + method.getName());
        }
      }
    }

    // 2. Execute original method
    Object result = method.invoke(originalConnectivityService, args);

    // 3. Intercept Synchronous Returns
    if (result instanceof NetworkCapabilities) {
      applySpoof((NetworkCapabilities) result);
    } else if (result != null && result.getClass().isArray()
        && result.getClass().getComponentType() == NetworkCapabilities.class) {
      NetworkCapabilities[] capsArray = (NetworkCapabilities[]) result;
      for (NetworkCapabilities caps : capsArray) {
        applySpoof(caps);
      }
    }

    return result;
  }

  /**
   * Digs through the IPC Message payload to find and modify NetworkCapabilities
   */
  private void patchAsyncMessage(Message msg) {
    if (msg == null) {
      return;
    }

    // Scenario A: NetworkCapabilities is passed directly in the object
    if (msg.obj instanceof NetworkCapabilities) {
      applySpoof((NetworkCapabilities) msg.obj);
    } else if (msg.obj != null) {
      // B: It's wrapped in an internal OS class (like CallbackInfo)
      try {
        for (Field f : msg.obj.getClass().getDeclaredFields()) {
          if (NetworkCapabilities.class.isAssignableFrom(f.getType())) {
            f.setAccessible(true);
            NetworkCapabilities nc = (NetworkCapabilities) f.get(msg.obj);
            if (nc != null) {
              applySpoof(nc);
            }
          }
        }
      } catch (Throwable t) {
        // swallow
      }
    }

    // C: ConnectivityManager packages the objects inside the Message's Bundle data
    Bundle data = msg.getData();
    if (data != null) {
      try {
        data.setClassLoader(NetworkCapabilities.class.getClassLoader());
        for (String key : data.keySet()) {
          Object val = data.get(key);
          if (val instanceof NetworkCapabilities) {
            applySpoof((NetworkCapabilities) val);
            // Put the spoofed object back into the bundle
            data.putParcelable(key, (NetworkCapabilities) val);
          }
        }
      } catch (Throwable t) {
        // swallow
      }
    }
  }

  private void applySpoof(NetworkCapabilities caps) {
    if (caps == null) {
      return;
    }
    try {
      Method removeTransport = NetworkCapabilities.class.getDeclaredMethod("removeTransportType", int.class);
      removeTransport.setAccessible(true);
      removeTransport.invoke(caps, 4); // NetworkCapabilities.TRANSPORT_VPN

      Method addCap = NetworkCapabilities.class.getDeclaredMethod("addCapability", int.class);
      addCap.setAccessible(true);

      addCap.invoke(caps, 15); // NetworkCapabilities.NET_CAPABILITY_NOT_VPN
      // Not behind captive portal
      addCap.invoke(caps, 16); // NetworkCapabilities.NET_CAPABILITY_VALIDATED

    } catch (Exception e) {
      Log.e(TAG, "Failed to spoof NetworkCapabilities via reflection: ", e);
    }
  }
}
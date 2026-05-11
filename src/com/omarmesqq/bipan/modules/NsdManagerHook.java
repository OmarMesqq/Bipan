package com.omarmesqq.bipan.modules;

import android.content.Context;
import android.os.IBinder;
import android.os.Message;
import android.os.Messenger;
import android.util.Log;

import com.omarmesqq.bipan.BaseHook;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.Map;

public class NsdManagerHook implements BaseHook {
  private static final String TAG = "BipanNsdManagerHook";

  @Override
  public void install(Context context) throws Exception {
    try {
      Class<?> serviceManagerClass = Class.forName("android.os.ServiceManager");

      // 1. Warm up the cache and get original IBinder for NSD
      Method getServiceMethod = serviceManagerClass.getDeclaredMethod("getService", String.class);
      IBinder originalNsdBinder = (IBinder) getServiceMethod.invoke(null, Context.NSD_SERVICE);

      if (originalNsdBinder == null) {
        Log.w(TAG, "INSTALL FAILED: NSD Service not found.");
        return;
      }

      // 2. Create Binder Proxy for NSD
      IBinder nsdBinderProxy = (IBinder) Proxy.newProxyInstance(
          context.getClassLoader(),
          new Class[] { IBinder.class },
          new NsdBinderProxyHandler(originalNsdBinder, context.getClassLoader()));

      // 3. Inject into ServiceManager cache
      Field sCacheField = serviceManagerClass.getDeclaredField("sCache");
      sCacheField.setAccessible(true);
      @SuppressWarnings("unchecked")
      Map<String, IBinder> sCache = (Map<String, IBinder>) sCacheField.get(null);

      if (sCache != null) {
        sCache.put(Context.NSD_SERVICE, nsdBinderProxy);
        Log.i(TAG, "NsdManager Binder hijacked successfully. Waiting for IPC...");
      } else {
        Log.e(TAG, "sCache is null!");
      }
    } catch (Exception e) {
      Log.e(TAG, "Exception during NsdManagerHook install", e);
      throw e;
    }
  }

  // --- Level 1: Handler for NSD IBinder ---
  private static class NsdBinderProxyHandler implements InvocationHandler {
    private final IBinder originalBinder;
    private final ClassLoader classLoader;
    private Object iNsdManagerProxy;

    public NsdBinderProxyHandler(IBinder originalBinder, ClassLoader classLoader) {
      this.originalBinder = originalBinder;
      this.classLoader = classLoader;
    }

    @Override
    public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
      if ("queryLocalInterface".equals(method.getName())) {
        Log.d(TAG, "[L1] queryLocalInterface intercepted.");
        if (iNsdManagerProxy == null) {
          try {
            Class<?> iNsdManagerClass = Class.forName("android.net.nsd.INsdManager");
            Class<?> stubClass = Class.forName("android.net.nsd.INsdManager$Stub");
            Method asInterfaceMethod = stubClass.getDeclaredMethod("asInterface", IBinder.class);
            Object originalINsdManager = asInterfaceMethod.invoke(null, originalBinder);

            if (originalINsdManager != null) {
              iNsdManagerProxy = Proxy.newProxyInstance(
                  classLoader,
                  new Class[] { iNsdManagerClass },
                  new INsdManagerProxyHandler(originalINsdManager, classLoader));
              Log.d(TAG, "[L1] Successfully created INsdManagerProxy");
            } else {
              Log.e(TAG, "originalINsdManager is null!");
            }
          } catch (Exception e) {
            Log.e(TAG, "[L1] Exception setting up INsdManagerProxy", e);
          }
        } else {
          Log.e(TAG, "iNsdManagerProxy is null!");
        }
        return iNsdManagerProxy != null ? iNsdManagerProxy : method.invoke(originalBinder, args);
      } else {
        Log.e(TAG, "Another method is being queried: " + method.getName());
      }
      return method.invoke(originalBinder, args);
    }
  }

  // --- Level 2: Handler for INsdManager ---
  private static class INsdManagerProxyHandler implements InvocationHandler {
    private final Object originalINsdManager;
    private final ClassLoader classLoader;

    public INsdManagerProxyHandler(Object originalINsdManager, ClassLoader classLoader) {
      this.originalINsdManager = originalINsdManager;
      this.classLoader = classLoader;
    }

    @Override
    public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
      String methodName = method.getName();

      // Failsafe for direct discovery calls on INsdManager
      if (methodName.toLowerCase().contains("discover") || methodName.toLowerCase().contains("resolve")) {
        Log.e(TAG, "[L2] Blocked direct NSD action: " + methodName);
        return getDefaultReturnValue(method.getReturnType());
      }

      // Legacy Android (API < 33) support
      if ("getMessenger".equals(methodName)) {
        Log.d(TAG, "[L2] getMessenger intercepted (Legacy Android).");
        Messenger realMessenger = (Messenger) method.invoke(originalINsdManager, args);
        if (realMessenger != null && realMessenger.getBinder() != null) {
          IBinder messengerBinderProxy = (IBinder) Proxy.newProxyInstance(
              classLoader,
              new Class[] { IBinder.class },
              new MessengerBinderProxyHandler(realMessenger.getBinder(), classLoader));
          return new Messenger(messengerBinderProxy);
        } else {
          Log.e(TAG, "[L2] realMessenger and its binder are null!");
        }
      }

      Log.d(TAG, "[L2] Forwarding INsdManager method: " + methodName);
      Object result = method.invoke(originalINsdManager, args);

      // Modern Android (API 33+): connect() returns INsdServiceConnector
      if (result != null && "connect".equals(methodName)) {
        Log.d(TAG, "[L2] connect() returned: " + result.getClass().getName() + ". Proxying the connector!");
        Class<?>[] interfaces = result.getClass().getInterfaces();

        if (interfaces != null && interfaces.length > 0) {
          return Proxy.newProxyInstance(
              classLoader,
              interfaces,
              new INsdConnectorProxyHandler(result));
        } else {
          Log.w(TAG, "[L2] Return object has no interfaces. Cannot proxy.");
        }
      } else {
        Log.e(TAG, "Modern API: result is null and/or another method is queried: " + methodName);
      }

      return result;
    }
  }

  // --- Level 3: Handler for Modern INsdServiceConnector (Android 13/14+) ---
  private static class INsdConnectorProxyHandler implements InvocationHandler {
    private final Object originalConnector;

    public INsdConnectorProxyHandler(Object originalConnector) {
      this.originalConnector = originalConnector;
    }

    @Override
    public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
      String methodName = method.getName();

      // Catch the actual discovery payload on the connector
      if (methodName.toLowerCase().contains("discover") || methodName.toLowerCase().contains("resolve")) {
        Log.e(TAG, "[L3-Connector] BLOCKED Modern NSD action: " + methodName);
        return getDefaultReturnValue(method.getReturnType());
      }

      Log.d(TAG, "[L3-Connector] Forwarding method: " + methodName);
      return method.invoke(originalConnector, args);
    }
  }

  // Helper to safely swallow method calls
  private static Object getDefaultReturnValue(Class<?> returnType) {
    if (returnType == boolean.class)
      return false;
    if (returnType == int.class)
      return 0;
    if (returnType == long.class)
      return 0L;
    if (returnType == float.class || returnType == double.class)
      return 0.0;
    return null;
  }

  // --- Level 3 (Legacy): Handler for IMessenger IBinder ---
  private static class MessengerBinderProxyHandler implements InvocationHandler {
    private final IBinder originalBinder;
    private final ClassLoader classLoader;
    private Object iMessengerProxy;

    public MessengerBinderProxyHandler(IBinder originalBinder, ClassLoader classLoader) {
      this.originalBinder = originalBinder;
      this.classLoader = classLoader;
    }

    @Override
    public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
      if ("queryLocalInterface".equals(method.getName())) {
        if (iMessengerProxy == null) {
          Class<?> iMessengerClass = Class.forName("android.os.IMessenger");
          Class<?> stubClass = Class.forName("android.os.IMessenger$Stub");
          Method asInterfaceMethod = stubClass.getDeclaredMethod("asInterface", IBinder.class);
          Object originalIMessenger = asInterfaceMethod.invoke(null, originalBinder);

          if (originalIMessenger != null) {
            iMessengerProxy = Proxy.newProxyInstance(
                classLoader,
                new Class[] { iMessengerClass },
                new IMessengerProxyHandler(originalIMessenger));
          } else {
            Log.e(TAG, ".invoke(): originalIMessenger is null");
          }
        } else {
          Log.e(TAG, ".invoke(): iMessengerProxy is NOT null");
        }
        return iMessengerProxy != null ? iMessengerProxy : method.invoke(originalBinder, args);
      } else {
        Log.e(TAG, ".invoke() another method is queried: " + method.getName());
      }
      return method.invoke(originalBinder, args);
    }
  }

  // --- Level 4 (Legacy): Handler for IMessenger ---
  private static class IMessengerProxyHandler implements InvocationHandler {
    private final Object originalIMessenger;
    private static final int DISCOVER_SERVICES = 393217;
    private static final int DISCOVER_SERVICES_FAILED = 393219;
    private static final int RESOLVE_SERVICE = 393234;
    private static final int RESOLVE_SERVICE_FAILED = 393235;

    public IMessengerProxyHandler(Object originalIMessenger) {
      this.originalIMessenger = originalIMessenger;
    }

    @Override
    public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
      if ("send".equals(method.getName()) && args != null && args.length > 0 && args[0] instanceof Message) {
        Message msg = (Message) args[0];

        if (msg.what == DISCOVER_SERVICES || msg.what == RESOLVE_SERVICE) {
          String action = (msg.what == DISCOVER_SERVICES) ? "DISCOVER_SERVICES" : "RESOLVE_SERVICE";
          Log.e(TAG, "[L4-Legacy] Blocked System Server IPC: " + action);

          if (msg.replyTo != null) {
            try {
              Message reply = Message.obtain();
              reply.what = (msg.what == DISCOVER_SERVICES) ? DISCOVER_SERVICES_FAILED : RESOLVE_SERVICE_FAILED;
              reply.arg1 = 0;
              msg.replyTo.send(reply);
            } catch (Exception e) {
              Log.e(TAG, "[L4-Legacy] Failed to send fake reply", e);
            }
          } else {
            Log.e(TAG, "msg.replyTo is NULL!");
          }
          return null;
        } else {
          Log.e(TAG, "msg.what is something else: " + msg.what);
        }
      } else {
        Log.e(TAG, ".invoke(): another method is being called: " + method.getName());
      }
      return method.invoke(originalIMessenger, args);
    }
  }
}
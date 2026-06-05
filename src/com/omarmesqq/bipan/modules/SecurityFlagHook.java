package com.omarmesqq.bipan.modules;

import android.content.Context;
import android.os.IBinder;
import android.util.Log;
import android.view.WindowManager;
import com.omarmesqq.bipan.BaseHook;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.Map;

public class SecurityFlagHook implements BaseHook {
  private static final String TAG = "BipanSecurityFlagHook";

  @Override
  public void install(Context context) throws Exception {
    ClassLoader appClassLoader = context.getClassLoader();

    try {
      Class<?> serviceManager = Class.forName("android.os.ServiceManager");
      Method getService = serviceManager.getDeclaredMethod("getService", String.class);

      final IBinder realWindowBinder = (IBinder) getService.invoke(null, "window");
      if (realWindowBinder == null) {
        Log.e(TAG, "Failed to acquire real native WindowBinder handle!");
        return;
      }

      Class<?> iWindowManagerClz = Class.forName("android.view.IWindowManager");
      Class<?> stubClz = Class.forName("android.view.IWindowManager$Stub");
      Method asInterface = stubClz.getDeclaredMethod("asInterface", IBinder.class);
      final Object realWindowManager = asInterface.invoke(null, realWindowBinder);

      // 1. Create a Global Proxy over the IWindowManager system service
      Object windowManagerProxy = Proxy.newProxyInstance(
          appClassLoader,
          new Class[] { iWindowManagerClz },
          (proxy, method, args) -> {
            Object result = method.invoke(realWindowManager, args);

            // Intercept the openSession operation where layout controllers are handed to
            // the app
            if ("openSession".equals(method.getName()) && result != null) {
              Class<?> iWindowSessionClz = Class.forName("android.view.IWindowSession");
              final Object realSession = result;

              // 2. Cascade down and proxy the private IWindowSession instance
              return Proxy.newProxyInstance(
                  appClassLoader,
                  new Class[] { iWindowSessionClz },
                  (sProxy, sMethod, sArgs) -> {
                    // Catch every operational phase where windows are registered or altered
                    if (sArgs != null && ("addToDisplay".equals(sMethod.getName()) ||
                        "addToDisplayAsUser".equals(sMethod.getName()) ||
                        "relayout".equals(sMethod.getName()) ||
                        "relayoutAsync".equals(sMethod.getName()))) {

                      // Scan the layout arguments for Window parameters
                      for (Object arg : sArgs) {
                        if (arg instanceof WindowManager.LayoutParams) {
                          WindowManager.LayoutParams lp = (WindowManager.LayoutParams) arg;

                          // If FLAG_SECURE is requested, forcefully clear it from the composition matrix
                          if ((lp.flags & WindowManager.LayoutParams.FLAG_SECURE) != 0) {
                            lp.flags &= ~WindowManager.LayoutParams.FLAG_SECURE;
                            Log.d(TAG, "Globally stripped FLAG_SECURE from low-level LayoutParams composition matrix!");
                          }
                        }
                      }
                    }
                    // FIXED: Replaced the typo with the correct native reflective call
                    return sMethod.invoke(realSession, sArgs);
                  });
            }
            return result;
          });

      // 3. Force-inject our window controller back into the local ServiceManager
      // instance cache
      Field sCacheField = serviceManager.getDeclaredField("sCache");
      sCacheField.setAccessible(true);
      @SuppressWarnings("unchecked")
      Map<String, IBinder> cache = (Map<String, IBinder>) sCacheField.get(null);

      IBinder windowProxyBinder = (IBinder) Proxy.newProxyInstance(
          appClassLoader,
          new Class[] { IBinder.class },
          (p, method, args) -> "queryLocalInterface".equals(method.getName()) ? windowManagerProxy
              : method.invoke(realWindowBinder, args));

      cache.put("window", windowProxyBinder);
      Log.i(TAG, "Low-level Global Window Compositor Hook installed successfully.");
    } catch (Throwable t) {
      Log.e(TAG, "Failed to initialize low-level global window composition hooks", t);
    }
  }
}
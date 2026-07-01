package b.modules;

import android.content.Context;
import android.os.IBinder;
import android.util.Log;
import android.view.WindowManager;
import b.BaseHook;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.Map;
import java.lang.reflect.InvocationHandler;

/**
 * Prevents app from detecting and/or blocking when you take screenshot.
 * Two approaches are used here:
 * 
 * - Stripping `FLAG_SECURE` from Activities
 * - Neutering `registerScreenCaptureObserver` introduced in modern Android APIs
 * 
 * The native C++ implementation which `ENOENT`s paths with the word
 * `Screenshot`
 * is also important for "smarter" apps which attempt to detect a new .png in
 * these folders.
 * Perhaps these rely ultimately on `inotify`, but for now this suffices.
 */
public class AntiScreenshotDetectionHook implements BaseHook, InvocationHandler {
  private static final String TAG = "BipanAntiScreenshotDetectionHook";
  private Object originalService;

  @Override
  public void install(Context context) throws Exception {
    // Common
    Class<?> serviceManager = Class.forName("android.os.ServiceManager");
    Method getService = serviceManager.getDeclaredMethod("getService", String.class);
    Field sCacheField = serviceManager.getDeclaredField("sCache");
    sCacheField.setAccessible(true);

    @SuppressWarnings("unchecked")
    Map<String, IBinder> cache = (Map<String, IBinder>) sCacheField.get(null);

    // FLAG_SECURE
    ClassLoader appClassLoader = context.getClassLoader();
    final IBinder realWindowBinder = (IBinder) getService.invoke(null, "window");
    if (realWindowBinder == null) {
      throw new Exception(TAG + "Failed to acquire real native WindowBinder handle!");
    }

    Class<?> iWindowManagerClz = Class.forName("android.view.IWindowManager");
    Class<?> iWindowManagerClzStubClz = Class.forName("android.view.IWindowManager$Stub");
    Method iWindowManagerClzStubClzAsInterface = iWindowManagerClzStubClz.getDeclaredMethod("asInterface",
        IBinder.class);
    final Object realWindowManager = iWindowManagerClzStubClzAsInterface.invoke(null, realWindowBinder);

    // global proxy of the IWindowManager system service
    Object windowManagerProxy = Proxy.newProxyInstance(
        appClassLoader,
        new Class[] { iWindowManagerClz },
        (proxy, method, args) -> {
          if ("registerScreenRecordingCallback".equals(method.getName())) {
            Log.i(TAG, "Blocked screen-recording registration: " + method.getName());
            return false;
          }

          Object result = method.invoke(realWindowManager, args);

          // Intercept the openSession operation where layout controllers are handed to
          // the app
          if ("openSession".equals(method.getName()) && result != null) {
            Class<?> iWindowSessionClz = Class.forName("android.view.IWindowSession");
            final Object realSession = result;

            // Cascade down and proxy the private IWindowSession instance
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

                        // If FLAG_SECURE is requested, clear it from the composition matrix
                        if ((lp.flags & WindowManager.LayoutParams.FLAG_SECURE) != 0) {
                          lp.flags &= ~WindowManager.LayoutParams.FLAG_SECURE;
                        }
                      }
                    }
                  }
                  return sMethod.invoke(realSession, sArgs);
                });
          }

          return result;
        });

    IBinder windowProxyBinder = (IBinder) Proxy.newProxyInstance(
        appClassLoader,
        new Class[] { IBinder.class },
        (p, method, args) -> "queryLocalInterface".equals(method.getName()) ? windowManagerProxy
            : method.invoke(realWindowBinder, args));

    cache.put("window", windowProxyBinder);

    // Screenshot
    IBinder realActivityTaskBinder = (IBinder) getService.invoke(null, "activity_task");
    if (realActivityTaskBinder == null) {
      Log.w(TAG, "realActivityTaskBinder is null, attempting fallback...");
      realActivityTaskBinder = (IBinder) getService.invoke(null, "activity");
    }

    final IBinder finalRealBinder = realActivityTaskBinder;
    if (finalRealBinder == null) {
      throw new Exception(TAG + "Failed to acquire real ActivityTask Binder handle!");
    }

    Class<?> iInterface = Class.forName("android.app.IActivityTaskManager");
    Class<?> stubClz = Class.forName("android.app.IActivityTaskManager$Stub");
    Method asInterface = stubClz.getDeclaredMethod("asInterface", IBinder.class);
    this.originalService = asInterface.invoke(null, finalRealBinder);

    Object proxy = Proxy.newProxyInstance(
        iInterface.getClassLoader(),
        new Class[] { iInterface },
        this);

    IBinder proxyBinder = (IBinder) Proxy.newProxyInstance(
        IBinder.class.getClassLoader(),
        new Class[] { IBinder.class },
        (p, method, args) -> {
          if ("queryLocalInterface".equals(method.getName())) {
            return proxy;
          }
          return method.invoke(finalRealBinder, args);
        });
    cache.put("activity_task", proxyBinder);

    // overwrite the ActivityTaskManager singleton even if the Main thread cached it
    Class<?> atmClz = Class.forName("android.app.ActivityTaskManager");
    Field singletonField = atmClz.getDeclaredField("IActivityTaskManagerSingleton");
    singletonField.setAccessible(true);
    Object singletonInstance = singletonField.get(null);

    Class<?> singletonClz = Class.forName("android.util.Singleton");
    Field mInstanceField = singletonClz.getDeclaredField("mInstance");
    mInstanceField.setAccessible(true);

    mInstanceField.set(singletonInstance, proxy);
  }

  @Override
  public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
    String methodName = method.getName();

    if (methodName.equals("registerScreenCaptureObserver")) {
      Log.i(TAG, "Blocked screenshot detection method: " + methodName);
      return null;
    }

    return method.invoke(originalService, args);
  }
}

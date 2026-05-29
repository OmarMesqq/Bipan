package com.omarmesqq.bipan.modules;

import android.content.Context;
import android.graphics.Point;
import android.util.DisplayMetrics;
import android.util.Log;

import com.omarmesqq.bipan.BaseHook;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;

public class DisplayMetricsHook implements BaseHook, InvocationHandler {
  private static final String TAG = "BipanDisplayHook";
  private Object originalWM;

  private static final int PIXEL8_WIDTH = 1344;
  private static final int PIXEL8_HEIGHT = 2992;
  private static final float PIXEL8_DENSITY = 3.5f;
  private static final int PIXEL8_DENSITY_DPI = 560; // Standard DENSITY_XHIGH baseline scale
  private static final float PIXEL8_XDPI = 489.654f; // Calibrated hardware panel subpixel pitch
  private static final float PIXEL8_YDPI = 488.912f;

  @Override
  public void install(Context context) throws Exception {
    if (context.getResources() != null) {
      mutateDisplayMetrics(context.getResources().getDisplayMetrics());
    }
    mutateDisplayMetrics(android.content.res.Resources.getSystem().getDisplayMetrics());

    // 2. Fetch the native WindowManager system service interface reference
    Class<?> serviceManagerClz = Class.forName("android.os.ServiceManager");
    Method getServiceMethod = serviceManagerClz.getMethod("getService", String.class);
    Object rawWindowBinder = getServiceMethod.invoke(null, "window");

    if (rawWindowBinder == null) {
      Log.e(TAG, "Abort: Root WindowManager service binder endpoint is unreachable.");
      return;
    }

    Class<?> iWindowManagerInterface = Class.forName("android.view.IWindowManager");
    Class<?> iWindowManagerStubClz = Class.forName("android.view.IWindowManager$Stub");
    Method asInterfaceMethod = iWindowManagerStubClz.getMethod("asInterface", android.os.IBinder.class);
    this.originalWM = asInterfaceMethod.invoke(null, rawWindowBinder);

    if (this.originalWM == null) {
      Log.e(TAG, "Abort: Instantiated IWindowManager system interface is null.");
      return;
    }

    // 3. Build our dynamic proxy wrapper over the Window Manager interface layout
    Object proxy = Proxy.newProxyInstance(
        context.getClassLoader(),
        new Class[] { iWindowManagerInterface },
        this);

    // 4. Inject our proxy into the global WindowManagerGlobal tracker engine
    // singleton cache
    Class<?> windowManagerGlobalClz = Class.forName("android.view.WindowManagerGlobal");
    Field sWindowManagerServiceField = windowManagerGlobalClz.getDeclaredField("sWindowManagerService");
    sWindowManagerServiceField.setAccessible(true);
    sWindowManagerServiceField.set(null, proxy);

    Log.w(TAG, "=== [DISPLAY ISOLATION SUCCESS] Pixel 8 Pro hardware sandbox is stabilized! ===");
  }

  @Override
  public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
    String methodName = method.getName();

    // Catch low-level queries that Meta's fingerprinting libraries use to deduce
    // actual screen geometry
    if ("getDisplayBaseDisplayMetrics".equals(methodName) && args != null && args.length > 1) {
      Object outMetrics = args[1]; // Out parameter structure containing the display density fields
      if (outMetrics instanceof DisplayMetrics) {
        Log.w(TAG,
            "=== [METRICS INTERCEPT] Injecting Pixel 8 Pro structural footprint into getDisplayBaseDisplayMetrics ===");
        mutateDisplayMetrics((DisplayMetrics) outMetrics);
        return null;
      }
    }

    Object result = method.invoke(originalWM, args);

    // Intercept hardware coordinate point transformations
    if (result instanceof Point) {
      Point pt = (Point) result;
      if ("getInitialDisplaySize".equals(methodName) || "getBaseDisplaySize".equals(methodName)) {
        Log.w(TAG, "=== [METRICS INTERCEPT] Enforcing hardware resolution properties over: " + methodName);
        pt.x = PIXEL8_WIDTH;
        pt.y = PIXEL8_HEIGHT;
      }
    }

    return result;
  }

  private void mutateDisplayMetrics(DisplayMetrics metrics) {
    if (metrics == null)
      return;
    metrics.widthPixels = PIXEL8_WIDTH;
    metrics.heightPixels = PIXEL8_HEIGHT;
    metrics.density = PIXEL8_DENSITY;
    metrics.densityDpi = PIXEL8_DENSITY_DPI;
    metrics.scaledDensity = PIXEL8_DENSITY;
    metrics.xdpi = PIXEL8_XDPI;
    metrics.ydpi = PIXEL8_YDPI;
  }
}
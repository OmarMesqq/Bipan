package com.omarmesqq.bipan.modules;

import android.content.Context;
import android.content.Intent;
import android.os.BatteryManager;
import android.util.Log;

import com.omarmesqq.bipan.BaseHook;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;

public class BatteryHook implements BaseHook, InvocationHandler {
  private static final String TAG = "BipanBatteryHook";
  private Object originalAM;

  // Fake Telemetry Profile (Fakes a clean, unplugged battery discharging state)
  private static final int FAKE_BATTERY_LEVEL = 78;
  private static final int FAKE_BATTERY_SCALE = 100;
  private static final int FAKE_BATTERY_STATUS = BatteryManager.BATTERY_STATUS_DISCHARGING;
  private static final int FAKE_BATTERY_PLUGGED = 0; // 0 = NOT plugged into USB or AC outlets
  private static final int FAKE_BATTERY_TEMPERATURE = 240; // 24.0°C standard calibration
  private static final int FAKE_BATTERY_VOLTAGE = 3800; // 3.8V typical cell runtime profile

  @Override
  public void install(Context context) throws Exception {
    // 1. Resolve the interface and global system proxy framework structures
    Class<?> activityManagerNativeClz = Class.forName("android.app.ActivityManagerNative");
    Method getDefaultMethod = activityManagerNativeClz.getMethod("getDefault");
    getDefaultMethod.setAccessible(true);
    this.originalAM = getDefaultMethod.invoke(null);

    if (this.originalAM == null) {
      Log.e(TAG, "Abort: Root ActivityManager framework instance is unreachable.");
      return;
    }

    // 2. Generate the dynamic proxy wrapper using the exact target system interface
    Object proxy = Proxy.newProxyInstance(
        context.getClassLoader(),
        new Class[] { Class.forName("android.app.IActivityManager") },
        this);

    // 3. Inject our proxy back into the global framework singletons
    try {
      // Route 1: Target the standard modern singleton tracker field
      Class<?> activityManagerClz = Class.forName("android.app.ActivityManager");
      Field singletonField = activityManagerClz.getDeclaredField("IActivityManagerSingleton");
      singletonField.setAccessible(true);
      Object singletonInstance = singletonField.get(null);

      if (singletonInstance != null) {
        Class<?> singletonClass = Class.forName("android.util.Singleton");
        Field mInstanceField = singletonClass.getDeclaredField("mInstance");
        mInstanceField.setAccessible(true);
        mInstanceField.set(singletonInstance, proxy);
        Log.i(TAG, "Successfully bound proxy inside ActivityManager.IActivityManagerSingleton!");
      }
    } catch (Exception e) {
      Log.d(TAG, "Skipping modern singleton path assignment (older/custom ROM variance).");
    }

    try {
      // Route 2: Target legacy/custom framework locations for backward compatibility
      Field gDefaultField = activityManagerNativeClz.getDeclaredField("gDefault");
      gDefaultField.setAccessible(true);
      Object singletonInstance = gDefaultField.get(null);

      if (singletonInstance != null) {
        Class<?> singletonClass = Class.forName("android.util.Singleton");
        Field mInstanceField = singletonClass.getDeclaredField("mInstance");
        mInstanceField.setAccessible(true);
        mInstanceField.set(singletonInstance, proxy);
        Log.i(TAG, "Successfully bound proxy inside ActivityManagerNative.gDefault!");
      }
    } catch (Exception e) {
      Log.d(TAG, "Skipping legacy fallback path assignment.");
    }
  }

  @Override
  public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
    // Intercept the application's underlying registration call to the system server
    Object result = method.invoke(originalAM, args);

    if ("registerReceiver".equals(method.getName()) && result instanceof Intent) {
      Intent intent = (Intent) result;
      if (Intent.ACTION_BATTERY_CHANGED.equals(intent.getAction())) {

        // Rewrite the intent metrics inside the returning broadcast bundle
        intent.putExtra("level", FAKE_BATTERY_LEVEL);
        intent.putExtra("scale", FAKE_BATTERY_SCALE);
        intent.putExtra("status", FAKE_BATTERY_STATUS);
        intent.putExtra("plugged", FAKE_BATTERY_PLUGGED); // Neutralizes "usb_adb" tracking calculations
        intent.putExtra("present", true);
        intent.putExtra("temperature", FAKE_BATTERY_TEMPERATURE);
        intent.putExtra("voltage", FAKE_BATTERY_VOLTAGE);
      }
    }

    // Modern Android versions may package intent registries into wrapped structures
    // inside Bundles or custom return items
    if ("registerReceiverWithFeature".equals(method.getName()) && result instanceof Intent) {
      Intent intent = (Intent) result;
      if (Intent.ACTION_BATTERY_CHANGED.equals(intent.getAction())) {
        intent.putExtra("level", FAKE_BATTERY_LEVEL);
        intent.putExtra("scale", FAKE_BATTERY_SCALE);
        intent.putExtra("status", FAKE_BATTERY_STATUS);
        intent.putExtra("plugged", FAKE_BATTERY_PLUGGED);
        intent.putExtra("present", true);
        intent.putExtra("temperature", FAKE_BATTERY_TEMPERATURE);
        intent.putExtra("voltage", FAKE_BATTERY_VOLTAGE);
      }
    }

    return result;
  }
}
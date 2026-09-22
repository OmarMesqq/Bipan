package b.modules;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.util.Log;
import b.BaseHook;

public class BroadcastReceiverHook implements BaseHook {
  private static final String TAG = "BipanJavaBroadcastRec";
  private static final Set<String> ALLOWLIST = new HashSet<>(Arrays.asList(
      "com.aurora.store"));

  @Override
  public void install(Context context) throws Exception {
    if (ALLOWLIST.contains(context.getPackageName())) {
      return;
    }
    hookBroadcastRegistration(context);
  }

  private void hookBroadcastRegistration(Context context) throws Exception {
    // Get the real IActivityManager
    Class<?> amClz = Class.forName("android.app.ActivityManager");
    Method getService = amClz.getDeclaredMethod("getService");
    Object realAm = getService.invoke(null);

    Class<?> iAmClz = Class.forName("android.app.IActivityManager");

    InvocationHandler amHandler = (proxy, method, args) -> {
      String methodName = method.getName();

      if (methodName.startsWith("registerReceiver")) {
        IntentFilter filter = null;
        for (Object arg : args) {
          if (arg instanceof IntentFilter) {
            filter = (IntentFilter) arg;
            break;
          }
        }

        if (filter != null && shouldBlockFilter(filter)) {
          Log.i(TAG, "Blocked registerReceiver for filter: " + dumpFilter(filter));
          return null;
        }
      }
      return method.invoke(realAm, args);
    };

    Object amProxy = Proxy.newProxyInstance(
        iAmClz.getClassLoader(),
        new Class[] { iAmClz },
        amHandler);

    // Replace the singleton that ActivityManager holds
    Field iActivityManagerSingleton = amClz.getDeclaredField("IActivityManagerSingleton");
    iActivityManagerSingleton.setAccessible(true);
    Object singleton = iActivityManagerSingleton.get(null);

    // Get a Singleton (android.util.Singleton<T>) for setting AM's proxy
    Field mInstance = singleton.getClass().getSuperclass().getDeclaredField("mInstance");
    mInstance.setAccessible(true);
    mInstance.set(singleton, amProxy);
  }

  private boolean shouldBlockFilter(IntentFilter filter) {
    if (filter.countDataSchemes() > 0) {
      Iterator<String> schemes = filter.schemesIterator();
      if (schemes != null) {
        while (schemes.hasNext()) {
          if ("package".equals(schemes.next())) {
            return true;
          }
        }
      }
    }

    Iterator<String> actions = filter.actionsIterator();
    while (actions != null && actions.hasNext()) {
      String action = actions.next();
      if (action == null) {
        continue;
      }
      if ( // Package stuff
      action.equals(Intent.ACTION_PACKAGE_ADDED) ||
          action.equals(Intent.ACTION_PACKAGE_CHANGED) ||
          action.equals(Intent.ACTION_PACKAGE_REMOVED) ||
          action.equals(Intent.ACTION_PACKAGE_RESTARTED) ||
          action.equals(Intent.ACTION_PACKAGE_DATA_CLEARED) ||
          action.equals(Intent.ACTION_PACKAGE_FIRST_LAUNCH) ||
          action.equals(Intent.ACTION_PACKAGE_FULLY_REMOVED) ||
          action.equals(Intent.ACTION_PACKAGE_NEEDS_VERIFICATION) ||
          action.equals(Intent.ACTION_PACKAGE_REPLACED) ||
          action.equals(Intent.ACTION_PACKAGE_UNSTOPPED) ||
          action.equals(Intent.ACTION_PACKAGES_SUSPENDED) ||
          action.equals(Intent.ACTION_PACKAGES_UNSUSPENDED) ||
          action.equals(Intent.ACTION_PACKAGE_VERIFIED) ||
          action.startsWith("android.intent.action.PACKAGE_") ||
          action.equals(Intent.ACTION_ALL_APPS) ||
          action.equals(Intent.ACTION_UID_REMOVED) ||

          // Device lifecycle
          action.equals(Intent.ACTION_LOCKED_BOOT_COMPLETED) ||
          action.equals(Intent.ACTION_BOOT_COMPLETED) ||
          action.equals(Intent.ACTION_REBOOT) ||
          action.equals(Intent.ACTION_SHUTDOWN) ||
          action.equals(Intent.ACTION_USER_UNLOCKED) ||
          action.equals(Intent.ACTION_USER_PRESENT) ||
          action.equals(Intent.ACTION_USER_INITIALIZE) ||

          // Additional profiles
          action.equals(Intent.ACTION_MANAGED_PROFILE_ADDED) ||
          action.equals(Intent.ACTION_MANAGED_PROFILE_REMOVED) ||
          action.equals(Intent.ACTION_MANAGED_PROFILE_AVAILABLE) ||
          action.equals(Intent.ACTION_MANAGED_PROFILE_UNAVAILABLE) ||
          action.equals(Intent.ACTION_MANAGED_PROFILE_UNLOCKED) ||
          action.equals(Intent.ACTION_PROFILE_ACCESSIBLE) ||

          // Why should an app know this?
          action.equals(Intent.ACTION_QUICK_CLOCK) ||
          // Error propagation
          action.equals(Intent.ACTION_MEDIA_BAD_REMOVAL) ||
          action.equals(Intent.ACTION_APP_ERROR) ||
          // System stuff
          action.equals(Intent.ACTION_DREAMING_STARTED) ||
          action.equals(Intent.ACTION_DREAMING_STOPPED) ||
          action.equals(Intent.ACTION_CARRIER_SETUP) ||
          // Battery saving
          action.equals(Intent.ACTION_TIME_TICK)) {
        return true;
      }
    }
    return false;
  }

  private String dumpFilter(IntentFilter filter) {
    StringBuilder sb = new StringBuilder("actions=[");
    Iterator<String> actions = filter.actionsIterator();

    if (actions != null) {
      while (actions.hasNext()) {
        sb.append(actions.next()).append(',');
      }
    }

    sb.append("] schemes=[");
    Iterator<String> schemes = filter.schemesIterator();
    if (schemes != null) {
      while (schemes.hasNext()) {
        sb.append(schemes.next()).append(',');
      }
    }

    sb.append(']');
    return sb.toString();
  }
}

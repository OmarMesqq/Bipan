package b.modules;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.Iterator;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.util.Log;
import b.BaseHook;

public class BroadcastReceiverHook implements BaseHook {
  private static final String TAG = "BipanJavaBroadcastRec";

  @Override
  public void install(Context context) throws Exception {
    hookBroadcastRegistration(context);
  }

  private void hookBroadcastRegistration(Context context) throws Exception {
    // 1. Obtain the real IActivityManager
    Class<?> amClz = Class.forName("android.app.ActivityManager");
    Method getService = amClz.getDeclaredMethod("getService");
    Object realAm = getService.invoke(null); // IActivityManager

    Class<?> iAmClz = Class.forName("android.app.IActivityManager");

    InvocationHandler amHandler = (proxy, method, args) -> {
      String name = method.getName();

      if (name.startsWith("registerReceiver")) {
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

    // 2. Replace the singleton that ActivityManager holds
    Field iActivityManagerSingleton = amClz.getDeclaredField("IActivityManagerSingleton");
    iActivityManagerSingleton.setAccessible(true);
    Object singleton = iActivityManagerSingleton.get(null);

    // Singleton is a android.util.Singleton<T>
    Field mInstance = singleton.getClass().getSuperclass().getDeclaredField("mInstance");
    mInstance.setAccessible(true);
    mInstance.set(singleton, amProxy);

    Log.i(TAG, "IActivityManager proxy installed for broadcast filtering");
  }

  private boolean shouldBlockFilter(IntentFilter filter) {
    Iterator<String> actions = filter.actionsIterator();
    while (actions != null && actions.hasNext()) {
      String action = actions.next();
      if (action == null) {
        continue;
      }
      if (action.equals(Intent.ACTION_PACKAGE_ADDED) ||
          action.equals(Intent.ACTION_PACKAGE_REMOVED) ||
          action.equals(Intent.ACTION_PACKAGE_CHANGED) ||
          action.equals(Intent.ACTION_PACKAGE_REPLACED) ||
          action.equals(Intent.ACTION_MY_PACKAGE_REPLACED) ||
          action.equals(Intent.ACTION_PACKAGE_DATA_CLEARED) ||
          action.equals(Intent.ACTION_PACKAGE_FULLY_REMOVED) ||
          action.equals(Intent.ACTION_PACKAGE_NEEDS_VERIFICATION) ||
          action.equals(Intent.ACTION_PACKAGE_VERIFIED) ||
          action.startsWith("android.intent.action.PACKAGE_")) {
        return true;
      }
    }
    return false;
  }

  private String dumpFilter(IntentFilter filter) {
    StringBuilder sb = new StringBuilder();
    Iterator<String> actions = filter.actionsIterator();
    while (actions != null && actions.hasNext()) {
      sb.append(actions.next()).append(' ');
    }
    return sb.toString().trim();
  }
}

package b.modules;

import android.content.ContentProviderClient;
import android.content.ContentResolver;
import android.content.Context;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.Bundle;
import android.os.IBinder;
import android.os.IInterface;
import android.util.Log;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.Random;
import b.BaseHook;
import java.lang.reflect.InvocationTargetException;

public class GsfIdSpoofHook implements BaseHook {
  private static final String TAG = "BipanJavaGsf";
  private static final String GSF_AUTHORITY = "com.google.android.gsf.gservices";
  private static final String GSF_KEY = "android_id";

  private static final String SPOOFED_ID;
  static {
    long id = new Random().nextLong();
    if (id < 0) {
      id = -id;
    }
    SPOOFED_ID = Long.toString(id);
  }

  /** Kept so J can re-apply the map injection on Application / Activity. */
  public static volatile Object sGsfProxy = null;

  @Override
  public void install(Context context) throws Exception {
    ContentResolver resolver = context.getContentResolver();
    if (resolver == null) {
      Log.e(TAG, "ContentResolver is null");
      return;
    }

    // Keep the client open so the provider stays in ActivityThread.mProviderMap
    ContentProviderClient client = resolver.acquireUnstableContentProviderClient(GSF_AUTHORITY);
    if (client == null) {
      Log.e(TAG, "Could not acquire GSF ContentProviderClient");
      return;
    }

    Object realProvider = extractIContentProvider(client);
    if (realProvider == null) {
      Log.e(TAG, "Failed to extract IContentProvider");
      client.close();
      return;
    }

    Class<?> iface = Class.forName("android.content.IContentProvider");
    final IBinder realBinder = ((IInterface) realProvider).asBinder();

    Object proxy = Proxy.newProxyInstance(
        iface.getClassLoader(),
        new Class<?>[] { iface },
        new InvocationHandler() {
          @Override
          public Object invoke(Object p, Method method, Object[] args)
              throws Throwable {
            String name = method.getName();

            // Keep Binder identity so the system does not drop us
            if ("asBinder".equals(name)) {
              return realBinder;
            }

            if ("query".equals(name)) {
              Cursor spoofed = trySpoof(args);
              if (spoofed != null) {
                return spoofed;
              }
            }

            try {
              return method.invoke(realProvider, args);
            } catch (InvocationTargetException e) {
              Log.e(TAG,
                  "install().newProxyInstance.InvocationHandler.invoke() got InvocationTargetException:", e);

              Throwable cause = e.getCause() != null ? e.getCause() : e;

              Log.e(TAG,
                  "install().newProxyInstance.InvocationHandler.invoke() InvocationTargetException cause:", cause);
              throw cause;
            } catch (Exception e) {
              Log.e(TAG,
                  "install().newProxyInstance.InvocationHandler.invoke() Exception:", e);
              throw e;
            }
          }
        });

    sGsfProxy = proxy;
    injectProviderProxy(proxy);

    // Do NOT close the client – keeps the map entry alive
    // (small intentional leak for the lifetime of the process)

    Log.i(TAG, "GSF ID spoof installed, id=" +
        Long.toHexString(Long.parseLong(SPOOFED_ID)));
  }

  private static Cursor trySpoof(Object[] args) {
    if (args == null) {
      return null;
    }

    Uri uri = null;
    String[] selectionArgs = null;

    for (Object arg : args) {
      if (arg instanceof Uri) {
        uri = (Uri) arg;
      } else if (arg instanceof String[]) {
        selectionArgs = (String[]) arg;
      } else if (arg instanceof Bundle) {
        selectionArgs = ((Bundle) arg).getStringArray(
            ContentResolver.QUERY_ARG_SQL_SELECTION_ARGS);
      }
    }

    if (uri == null || !GSF_AUTHORITY.equals(uri.getAuthority())) {
      return null;
    }

    boolean wants = false;
    if (selectionArgs != null) {
      for (String s : selectionArgs) {
        if (GSF_KEY.equals(s)) {
          wants = true;
          break;
        }
      }
    }
    if (!wants && GSF_KEY.equals(uri.getLastPathSegment())) {
      wants = true;
    }
    if (!wants) {
      return null;
    }

    MatrixCursor c = new MatrixCursor(new String[] { "key", "value" });
    c.addRow(new Object[] { GSF_KEY, SPOOFED_ID });
    Log.d(TAG, "Spoofed GSF android_id → " +
        Long.toHexString(Long.parseLong(SPOOFED_ID)));
    return c;
  }

  /**
   * Public so J can call it from callApplicationOnCreate / callActivityOnCreate.
   */
  public static void reInject() {
    if (sGsfProxy != null) {
      try {
        injectProviderProxy(sGsfProxy);
      } catch (Throwable t) {
        Log.e(TAG, "reInject failed", t);
      }
    }
  }

  private static void injectProviderProxy(Object proxy) throws Exception {
    Object activityThread = getActivityThread();
    if (activityThread == null) {
      Log.e(TAG, "ActivityThread is null");
      return;
    }

    Field mapField = findField(activityThread.getClass(), "mProviderMap");
    if (mapField == null) {
      Log.e(TAG, "injectProviderProxy: mProviderMap not found");
      return;
    }
    mapField.setAccessible(true);
    Object providerMap = mapField.get(activityThread);
    if (providerMap == null) {
      Log.e(TAG, "injectProviderProxy: providerMap is null");
      return;
    }

    Method sizeMethod = providerMap.getClass().getMethod("size");
    Method keyAtMethod = providerMap.getClass().getMethod("keyAt", int.class);
    Method valueAtMethod = providerMap.getClass().getMethod("valueAt", int.class);

    int size = (Integer) sizeMethod.invoke(providerMap);
    for (int i = 0; i < size; i++) {
      Object key = keyAtMethod.invoke(providerMap, i);
      Object record = valueAtMethod.invoke(providerMap, i);
      if (key == null || record == null) {
        continue;
      }

      String auth = extractAuthority(key);
      if (auth == null || !GSF_AUTHORITY.equals(auth)) {
        continue;
      }

      Field providerField = findField(record.getClass(), "mProvider");
      if (providerField != null) {
        providerField.setAccessible(true);
        Object old = providerField.get(record);
        providerField.set(record, proxy);
        Log.i(TAG, "Replaced IContentProvider for " + auth +
            " (old=" + (old != null ? old.getClass().getName() : "null") + ")");
      }
    }
  }

  private static Object extractIContentProvider(ContentProviderClient client)
      throws Exception {
    Field f = findField(ContentProviderClient.class, "mContentProvider", "mProvider");
    if (f == null) {
      return null;
    }

    f.setAccessible(true);
    Object provider = f.get(client);

    Class<?> iface = Class.forName("android.content.IContentProvider");
    if (provider != null && iface.isInstance(provider)) {
      return provider;
    }
    if (provider != null) {
      Field bf = findField(provider.getClass(), "mRemote", "mProvider");
      if (bf != null) {
        bf.setAccessible(true);
        Object remote = bf.get(provider);
        if (remote != null && iface.isInstance(remote)) {
          return remote;
        }
      }
    }
    return null;
  }

  private static Object getActivityThread() throws Exception {
    try {
      Class<?> atClass = Class.forName("android.app.ActivityThread");
      Method current = atClass.getDeclaredMethod("currentActivityThread");
      current.setAccessible(true);
      Object at = current.invoke(null);
      if (at != null) {
        return at;
      } else {
        Log.e(TAG, "getActivityThread: currentActivityThread is null");
      }
    } catch (Throwable ignored) {
      Log.e(TAG, "getActivityThread: Throwable [1]:", ignored);
    }
    try {
      Class<?> atClass = Class.forName("android.app.ActivityThread");
      Field f = atClass.getDeclaredField("sCurrentActivityThread");
      f.setAccessible(true);
      return f.get(null);
    } catch (Throwable ignored) {
      Log.e(TAG, "getActivityThread: Throwable [2]:", ignored);
    }
    return null;
  }

  private static String extractAuthority(Object providerKey) {
    for (String name : new String[] { "authority", "mAuthority" }) {
      Field f = findField(providerKey.getClass(), name);
      if (f == null) {
        continue;
      }
      try {
        f.setAccessible(true);
        Object v = f.get(providerKey);
        if (v instanceof String)
          return (String) v;
      } catch (Throwable ignored) {
        Log.e(TAG, "extractAuthority: Throwable:", ignored);
      }
    }
    return null;
  }

  private static Field findField(Class<?> clazz, String... names) {
    for (String name : names) {
      Class<?> c = clazz;
      while (c != null && c != Object.class) {
        try {
          return c.getDeclaredField(name);
        } catch (NoSuchFieldException ignored) {
          Log.e(TAG, "findField: NoSuchFieldException:", ignored);
        } catch (Exception e) {
          Log.e(TAG, "findField: Exception:", e);
        }
        c = c.getSuperclass();
      }
    }
    return null;
  }
}
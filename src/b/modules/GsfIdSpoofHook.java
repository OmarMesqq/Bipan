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
import java.util.Map;
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
      // Log.d(TAG, "ContentResolver is null");
      return;
    }

    // Keep the client open so the provider stays in ActivityThread.mProviderMap
    ContentProviderClient client = resolver.acquireUnstableContentProviderClient(GSF_AUTHORITY);
    if (client == null) {
      // Log.d(TAG, "Could not acquire GSF ContentProviderClient");
      return;
    }

    Object realProvider = extractIContentProvider(client);
    if (realProvider == null) {
      // Log.d(TAG, "Failed to extract IContentProvider");
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
              Throwable cause = e.getCause() != null ? e.getCause() : e;
              Log.e(TAG, "install().InvocationHandler got InvocationTargetException. Cause:", cause);
              throw cause;
            } catch (Exception e) {
              Log.e(TAG, "install().InvocationHandler got unknown Exception:", e);
              throw e;
            }
          }
        });

    sGsfProxy = proxy;
    injectProviderProxy(proxy);
    patchActivityManagerSingleton(); // primary
    installActivityManagerProxy();

    // Log.d(TAG, "GSF ID spoof installed, id=" +
    // Long.toHexString(Long.parseLong(SPOOFED_ID)));
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

    Log.i(TAG, "Spoofed GSF android_id → " + Long.toHexString(Long.parseLong(SPOOFED_ID)));
    return c;
  }

  public static void reInject() {
    if (sGsfProxy == null) {
      return;
    }
    try {
      if (!injectProviderProxy(sGsfProxy)) {
        // Entry gone or replaced with a real proxy – force a new acquire
        forceAcquireAndInject();
      }
    } catch (Throwable t) {
      Log.e(TAG, "reInject failed", t);
    }
  }

  private static boolean injectProviderProxy(Object proxy) throws Exception {
    Object activityThread = getActivityThread();
    if (activityThread == null) {
      // Log.d(TAG, "ActivityThread is null");
      return false;
    }

    Field mapField = findField(activityThread.getClass(), "mProviderMap");
    if (mapField == null) {
      return false;
    }
    mapField.setAccessible(true);
    Object providerMap = mapField.get(activityThread);
    if (providerMap == null) {
      return false;
    }

    Method sizeMethod = providerMap.getClass().getMethod("size");
    Method keyAtMethod = providerMap.getClass().getMethod("keyAt", int.class);
    Method valueAtMethod = providerMap.getClass().getMethod("valueAt", int.class);

    boolean found = false;
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
      if (providerField == null) {
        continue;
      }
      providerField.setAccessible(true);

      Object old = providerField.get(record);
      if (old != proxy) {
        providerField.set(record, proxy);
        // Log.d(TAG, "Replaced IContentProvider for " + auth + " (old=" + (old != null
        // ? old.getClass().getName() : "null") + ")");
      }
      found = true;
    }
    return found;
  }

  private static void forceAcquireAndInject() {
    try {
      Object at = getActivityThread();
      if (at == null) {
        return;
      }
      Method getApp = at.getClass().getMethod("getApplication");
      Object app = getApp.invoke(at);
      if (!(app instanceof Context)) {
        return;
      }

      ContentResolver cr = ((Context) app).getContentResolver();
      ContentProviderClient client = cr.acquireUnstableContentProviderClient(GSF_AUTHORITY);
      if (client == null) {
        return;
      }

      injectProviderProxy(sGsfProxy);
      // Log.d(TAG, "forceAcquireAndInject: re-acquired GSF provider");
    } catch (Throwable t) {
      Log.e(TAG, "forceAcquireAndInject failed", t);
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
      }
    } catch (Throwable ignored) {
    }
    try {
      Class<?> atClass = Class.forName("android.app.ActivityThread");
      Field f = atClass.getDeclaredField("sCurrentActivityThread");
      f.setAccessible(true);
      return f.get(null);
    } catch (Throwable ignored) {
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
        if (v instanceof String) {
          return (String) v;
        }
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
          //
        } catch (Exception e) {
          Log.e(TAG, "findField: Exception:", e);
        }
        c = c.getSuperclass();
      }
    }
    return null;
  }

  private static void installActivityManagerProxy() throws Exception {
    Class<?> sm = Class.forName("android.os.ServiceManager");
    Method getService = sm.getDeclaredMethod("getService", String.class);
    Field sCacheField = sm.getDeclaredField("sCache");
    sCacheField.setAccessible(true);
    @SuppressWarnings("unchecked")
    Map<String, IBinder> cache = (Map<String, IBinder>) sCacheField.get(null);

    // "activity" is the classic name; some builds also use activity_task
    for (String svcName : new String[] { "activity", "activity_task" }) {
      IBinder realBinder = (IBinder) getService.invoke(null, svcName);
      if (realBinder == null) {
        continue;
      }

      // Resolve IActivityManager / IActivityTaskManager
      String stubName = svcName.equals("activity")
          ? "android.app.IActivityManager$Stub"
          : "android.app.IActivityTaskManager$Stub";
      String ifaceName = svcName.equals("activity")
          ? "android.app.IActivityManager"
          : "android.app.IActivityTaskManager";

      Class<?> stubClz = Class.forName(stubName);
      Method asInterface = stubClz.getDeclaredMethod("asInterface", IBinder.class);
      final Object original = asInterface.invoke(null, realBinder);
      Class<?> iface = Class.forName(ifaceName);

      Object amProxy = Proxy.newProxyInstance(
          iface.getClassLoader(),
          new Class<?>[] { iface },
          (proxy, method, args) -> {
            Object result = method.invoke(original, args);

            // Wrap any ContentProviderHolder that is for GSF
            if (result != null && isGetContentProvider(method.getName())) {
              wrapHolderIfGsf(result);
            }
            return result;
          });

      IBinder proxyBinder = (IBinder) Proxy.newProxyInstance(
          IBinder.class.getClassLoader(),
          new Class<?>[] { IBinder.class },
          (p, method, args) -> {
            if ("queryLocalInterface".equals(method.getName())) {
              return amProxy;
            }
            return method.invoke(realBinder, args);
          });

      cache.put(svcName, proxyBinder);
      // Log.d(TAG, "Installed IActivityManager proxy on service: " + svcName);
    }
  }

  private static boolean isGetContentProvider(String name) {
    return "getContentProvider".equals(name)
        || "getContentProviderExternal".equals(name)
        || "getContentProviderExternalUnchecked".equals(name);
  }

  private static void wrapHolderIfGsf(Object holder) {
    try {
      // ContentProviderHolder.info.authority or .provider
      Field infoField = findField(holder.getClass(), "info");
      if (infoField != null) {
        infoField.setAccessible(true);
        Object info = infoField.get(holder); // ProviderInfo
        if (info != null) {
          Field authField = findField(info.getClass(), "authority");
          if (authField != null) {
            authField.setAccessible(true);
            Object auth = authField.get(info);
            if (auth instanceof String && !((String) auth).contains(GSF_AUTHORITY)) {
              return; // not GSF
            }
          }
        }
      }

      Field providerField = findField(holder.getClass(), "provider");
      if (providerField == null) {
        return;
      }
      providerField.setAccessible(true);
      Object current = providerField.get(holder);
      if (current == null || current == sGsfProxy) {
        return;
      }
      if (sGsfProxy != null) {
        providerField.set(holder, sGsfProxy);
        // Log.d(TAG, "Wrapped ContentProviderHolder.provider with GSF proxy");
      }
    } catch (Throwable t) {
      Log.e(TAG, "wrapHolderIfGsf failed", t);
    }
  }

  private static void patchActivityManagerSingleton() throws Exception {
    // ActivityManager.IActivityManagerSingleton (API 26+)
    Class<?> amClass = Class.forName("android.app.ActivityManager");
    Field singletonField = amClass.getDeclaredField("IActivityManagerSingleton");
    singletonField.setAccessible(true);
    Object singleton = singletonField.get(null);
    if (singleton == null) {
      // Log.d(TAG, "IActivityManagerSingleton is null");
      return;
    }

    // android.util.Singleton<T> → mInstance
    Field mInstanceField = findField(singleton.getClass(), "mInstance");
    if (mInstanceField == null) {
      // some builds: field is on superclass
      mInstanceField = findField(singleton.getClass().getSuperclass(), "mInstance");
    }
    if (mInstanceField == null) {
      // Log.d(TAG, "Singleton.mInstance not found");
      return;
    }
    mInstanceField.setAccessible(true);

    Object realAm = mInstanceField.get(singleton);
    if (realAm == null) {
      // force create
      Method get = singleton.getClass().getMethod("get");
      realAm = get.invoke(singleton);
    }
    if (realAm == null) {
      // Log.d(TAG, "Could not obtain IActivityManager instance");
      return;
    }
    if (Proxy.isProxyClass(realAm.getClass())) {
      // Log.d(TAG, "IActivityManager already proxied");
      return;
    }

    Class<?> iface = Class.forName("android.app.IActivityManager");
    final Object original = realAm;

    Object amProxy = Proxy.newProxyInstance(
        iface.getClassLoader(),
        new Class<?>[] { iface },
        (proxy, method, args) -> {
          Object result = method.invoke(original, args);
          if (result != null && isGetContentProvider(method.getName())) {
            wrapHolderIfGsf(result);
          }
          return result;
        });

    mInstanceField.set(singleton, amProxy);
    // Log.d(TAG, "Patched ActivityManager.IActivityManagerSingleton");
  }
}
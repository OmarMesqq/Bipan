package b.modules;

import android.content.Context;
import android.os.IBinder;
import android.telephony.ServiceState;
import android.telephony.TelephonyManager;
import android.util.Log;
import b.BaseHook;
import b.J;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.lang.reflect.UndeclaredThrowableException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.Map;
import java.util.ArrayList;
import java.lang.reflect.Constructor;
import android.Manifest;

public class TelephonyManagerHook implements BaseHook, InvocationHandler {
  private static final String TAG = "BipanJavaTelephony";

  private Object originalITelephony;
  private TelephonyManager realTm;

  private static boolean hasFineLocationPerm = false;

  private static final String CARRIER_NAME = "Vivo";
  private static final int CARRIER_ID = 530;
  private static final String MCCMNC_TUPLE = "72406";
  private static final String SIM_ISO_COUNTRY_CODE = "br";

  private static String pkgName = "";

  private static final Set<String> ALLOWLIST = new HashSet<>(Arrays.asList(
      "com.whatsapp"));

  private Object createEmptyCellIdentity() throws Throwable {
    Class<?> cellIdentityGsmClass = Class.forName("android.telephony.CellIdentityGsm");

    for (Constructor<?> ctor : cellIdentityGsmClass.getDeclaredConstructors()) {
      ctor.setAccessible(true);
      Class<?>[] params = ctor.getParameterTypes();

      if (params.length == 0) {
        return ctor.newInstance();
      } else if (params.length == 4
          && params[0] == int.class && params[1] == int.class
          && params[2] == int.class && params[3] == int.class) {
        return ctor.newInstance(
            Integer.MAX_VALUE, Integer.MAX_VALUE,
            Integer.MAX_VALUE, Integer.MAX_VALUE);
      } else {
        Log.e(TAG, "createEmptyCellIdentity: exhausted ctor params length possibilities");
        throw J.cleanThrowable(new OutOfMemoryError());
      }
    }
    Log.e(TAG, "createEmptyCellIdentity: no ctors found!");
    throw J.cleanThrowable(new OutOfMemoryError());
  }

  @Override
  public void install(Context context) throws Exception {
    pkgName = context.getPackageName();

    realTm = (TelephonyManager) context.getSystemService(Context.TELEPHONY_SERVICE);

    Class<?> serviceManager = Class.forName("android.os.ServiceManager");
    Method getService = serviceManager.getDeclaredMethod("getService", String.class);

    IBinder realPhoneBinder = (IBinder) getService.invoke(null, "phone");
    if (realPhoneBinder == null) {
      throw new Exception(TAG + "Could not get 'phone' service binder");
    }

    hasFineLocationPerm = J.hasPermission(context, Manifest.permission.ACCESS_FINE_LOCATION);

    Class<?> iTelephonyStub = Class.forName("com.android.internal.telephony.ITelephony$Stub");
    Method asInterface = iTelephonyStub.getDeclaredMethod("asInterface", IBinder.class);
    originalITelephony = asInterface.invoke(null, realPhoneBinder);

    // // TODO: put `invoke` separate
    Class<?> iTelephonyClass = Class.forName("com.android.internal.telephony.ITelephony");
    Object proxy = Proxy.newProxyInstance(
        iTelephonyClass.getClassLoader(),
        new Class[] { iTelephonyClass },
        this);

    IBinder proxyBinder = (IBinder) Proxy.newProxyInstance(
        IBinder.class.getClassLoader(),
        new Class[] { IBinder.class },
        (p, method, args) -> {
          if ("queryLocalInterface".equals(method.getName()))
            return proxy;
          return method.invoke(realPhoneBinder, args);
        });

    Field sCacheField = serviceManager.getDeclaredField("sCache");
    sCacheField.setAccessible(true);

    @SuppressWarnings("unchecked")
    Map<String, IBinder> cache = (Map<String, IBinder>) sCacheField.get(null);
    cache.put("phone", proxyBinder);

    replaceBinderInTelephonyManager(realTm, proxyBinder);
  }

  private void replaceBinderInTelephonyManager(TelephonyManager tm, IBinder proxyBinder) throws Exception {
    for (Field f : tm.getClass().getDeclaredFields()) {
      if (IBinder.class.isAssignableFrom(f.getType())) {
        f.setAccessible(true);
        f.set(tm, proxyBinder);
      }
    }
  }

  @Override
  public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
    try {
      String methodName = method.getName();
      switch (methodName) {
        case "getNetworkOperatorName":
        case "getNetworkOperatorNameForDisplay":
        case "getSimOperatorName":
        case "getSimOperatorNameForPhone":
        case "getSimOperatorNameForSubscription":
        case "getSubscriptionCarrierName": {
          if (ALLOWLIST.contains(pkgName)) {
            return method.invoke(originalITelephony, args);
          }
          Log.i(TAG, "Neutered " + methodName);
          return CARRIER_NAME;
        }

        case "getNetworkCountryIso":
        case "getNetworkCountryIsoForPhone":
        case "getSimCountryIso":
        case "getSimCountryIsoForPhone":
        case "getSimCountryIsoForSubscription": {
          if (ALLOWLIST.contains(pkgName)) {
            return method.invoke(originalITelephony, args);
          }
          Log.i(TAG, "Neutered " + methodName);
          return SIM_ISO_COUNTRY_CODE;
        }

        case "getSimOperator":
        case "getSimOperatorNumeric":
        case "getSimOperatorForSubscription": {
          if (ALLOWLIST.contains(pkgName)) {
            return method.invoke(originalITelephony, args);
          }
          Log.i(TAG, "Neutered " + methodName);
          return MCCMNC_TUPLE;
        }

        case "getAllCellInfo": {
          if (hasFineLocationPerm) {
            Log.i(TAG, "Neutered getAllCellInfo");
            return new ArrayList<>();
          }
          return method.invoke(originalITelephony, args);
        }

        case "getCellLocation": {
          if (hasFineLocationPerm) {
            Log.i(TAG, "Neutered getCellLocation");
            return createEmptyCellIdentity();
          }
          return method.invoke(originalITelephony, args);
        }

        case "getServiceState":
        case "getServiceStateForSlot": {
          if (ALLOWLIST.contains(pkgName)) {
            return method.invoke(originalITelephony, args);
          }
          Log.i(TAG, "Neutered " + methodName);
          return new ServiceState();
        }

        case "getCarrierPrivilegeStatus": {
          Log.i(TAG, "Neutered getCarrierPrivilegeStatus");
          return 0; // CARRIER_PRIVILEGE_STATUS_NO_ACCESS
        }

        case "getSimCarrierId":
        case "getSimSpecificCarrierId":
        case "getSubscriptionCarrierId":
        case "getSubscriptionSpecificCarrierId": {
          if (ALLOWLIST.contains(pkgName)) {
            return method.invoke(originalITelephony, args);
          }
          Log.i(TAG, "Neutered " + methodName);
          return CARRIER_ID;
        }

        case "getDeviceId":
        case "getDeviceIdWithFeature": {
          Log.i(TAG, "Neutered " + methodName);
          return null;
        }

        case "getMmsUserAgent":
        case "getMmsUAProfUrl": {
          Log.i(TAG, "Neutered " + methodName);
          return "";
        }

        case "getCarrierIdFromMccMnc": {
          if (ALLOWLIST.contains(pkgName)) {
            return method.invoke(originalITelephony, args);
          }
          String mccmnc = (args != null && args.length > 1 && args[1] instanceof String)
              ? (String) args[1]
              : "";
          Log.i(TAG, "Neutered getCarrierIdFromMccMnc mccmnc=" + mccmnc);
          if (MCCMNC_TUPLE.equals(mccmnc)) {
            return CARRIER_ID;
          }
          return TelephonyManager.UNKNOWN_CARRIER_ID;
        }

        default: {
          // Log.w(TAG, "Allowing TM method: " + method.getName());
          return method.invoke(originalITelephony, args);
        }
      }
    } catch (InvocationTargetException e) {
      Throwable cause = e.getCause() != null ? e.getCause() : e;
      Log.e(TAG, "invoke InvocationTargetException: cause:", cause);
      throw J.cleanThrowable(cause);
    } catch (UndeclaredThrowableException e) {
      Throwable cause = e.getCause() != null ? e.getCause() : e;
      Log.e(TAG, "invoke UndeclaredThrowableException: cause:", cause);
      throw J.cleanThrowable(cause);
    } catch (Exception e) {
      Log.e(TAG, "Exception: ", e);
      throw J.cleanThrowable(new OutOfMemoryError());
    }
  }
}
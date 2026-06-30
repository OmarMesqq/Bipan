package b.modules;

import android.content.Context;
import android.os.IBinder;
import android.telephony.ServiceState;
import android.telephony.TelephonyManager;
import android.util.Log;
import b.BaseHook;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.Map;
import java.util.ArrayList;
import java.lang.reflect.Constructor;

public class TelephonyManagerHook implements BaseHook, InvocationHandler {
  private static final String TAG = "BipanTelephonyHook";

  private Object originalITelephony;
  private TelephonyManager realTm;

  private static final String CARRIER_NAME = "Vivo";
  private static final int CARRIER_ID = 530;
  private static final String MCCMNC_TUPLE = "72406";
  private static final String SIM_ISO_COUNTRY_CODE = "br";
  private static final int MODEM_COUNT = 1;

  private static final Set<String> ALLOW_LIST = new HashSet<>(Arrays.asList(
      "com.whatsapp",
      "com.instagram.android"));

  private Object createEmptyCellIdentity() throws Exception {
    try {
      Class<?> cellIdentityGsmClass = Class.forName("android.telephony.CellIdentityGsm");

      for (Constructor<?> ctor : cellIdentityGsmClass.getDeclaredConstructors()) {
        ctor.setAccessible(true);
        Class<?>[] params = ctor.getParameterTypes();
        try {
          if (params.length == 0) {
            return ctor.newInstance();
          } else if (params.length == 4
              && params[0] == int.class && params[1] == int.class
              && params[2] == int.class && params[3] == int.class) {
            return ctor.newInstance(
                Integer.MAX_VALUE, Integer.MAX_VALUE,
                Integer.MAX_VALUE, Integer.MAX_VALUE);
          }
        } catch (Exception ignored) {
        }
      }
    } catch (Exception e) {
      Log.e(TAG, "Exception while creating an empty CellIdentity: " + e.getMessage() + ". Will return 'null'!");
    }
    return null;
  }

  @Override
  public void install(Context context) throws Exception {
    if (ALLOW_LIST.contains(context.getPackageName())) {
      return;
    }

    realTm = (TelephonyManager) context.getSystemService(Context.TELEPHONY_SERVICE);

    Class<?> serviceManager = Class.forName("android.os.ServiceManager");
    Method getService = serviceManager.getDeclaredMethod("getService", String.class);

    IBinder realPhoneBinder = (IBinder) getService.invoke(null, "phone");
    if (realPhoneBinder == null) {
      throw new Exception(TAG + "Could not get 'phone' service binder");
    }

    Class<?> iTelephonyStub = Class.forName("com.android.internal.telephony.ITelephony$Stub");
    Method asInterface = iTelephonyStub.getDeclaredMethod("asInterface", IBinder.class);
    originalITelephony = asInterface.invoke(null, realPhoneBinder);

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
    switch (method.getName()) {

      case "getNetworkOperatorName":
      case "getNetworkOperatorNameForDisplay":
      case "getSimOperatorName":
      case "getSimOperatorNameForPhone":
      case "getSimOperatorNameForSubscription":
      case "getSubscriptionCarrierName":
        Log.i(TAG, "Neutered " + method.getName());
        return CARRIER_NAME;

      case "getNetworkCountryIso":
      case "getNetworkCountryIsoForPhone":
      case "getSimCountryIso":
      case "getSimCountryIsoForPhone":
      case "getSimCountryIsoForSubscription":
        Log.i(TAG, "Neutered " + method.getName());
        return SIM_ISO_COUNTRY_CODE;

      case "getSimOperator":
      case "getSimOperatorNumeric":
      case "getSimOperatorForSubscription":
        Log.i(TAG, "Neutered " + method.getName());
        return MCCMNC_TUPLE;

      case "getPhoneCount":
      case "getActiveModemCount":
      case "getSupportedModemCount":
        Log.i(TAG, "Neutered " + method.getName());
        return MODEM_COUNT;

      case "isMultiSimEnabled":
        Log.i(TAG, "Neutered " + method.getName());
        return false;

      case "isMultiSimSupported":
        Log.i(TAG, "Neutered " + method.getName());
        return TelephonyManager.MULTISIM_NOT_SUPPORTED_BY_HARDWARE;

      case "getAllCellInfo":
        Log.i(TAG, "Neutered " + method.getName());
        return new ArrayList<>();

      case "getCellLocation":
        Log.i(TAG, "Neutered " + method.getName());
        return createEmptyCellIdentity();

      case "getServiceState":
      case "getServiceStateForSlot": {
        Log.i(TAG, "Neutered " + method.getName());
        return new ServiceState(); 
      }
      
      case "getVisualVoicemailPackageName":
        Log.i(TAG, "Neutered " + method.getName());
        return "com.google.android.dialer";

      case "getCarrierPrivilegeStatus":
        Class<?> tm = Class.forName("android.telephony.TelephonyManager");
        Field carrierPrivilegeStatusNoAccessField = tm.getDeclaredField("CARRIER_PRIVILEGE_STATUS_NO_ACCESS");
        carrierPrivilegeStatusNoAccessField.setAccessible(true);
        int CARRIER_PRIVILEGE_STATUS_NO_ACCESS = (int) carrierPrivilegeStatusNoAccessField.get(null);

        Log.i(TAG, "Neutered " + method.getName());
        return CARRIER_PRIVILEGE_STATUS_NO_ACCESS;

      case "getSimCarrierId":
      case "getSimSpecificCarrierId":
      case "getSubscriptionCarrierId":
      case "getSubscriptionSpecificCarrierId":
        Log.i(TAG, "Neutered " + method.getName());
        return CARRIER_ID;

      /**
       * If app doesn't have `READ_PHONE_STATE`, returns null.
       * However if we don't intercept a system throws `SecurityException`, thus
       * we need to return early here as to not "confuse" the Proxy
       * and make it return `UndeclaredThrowableException` which most apps don't
       * handle
       * 
       * https://cs.android.com/android/platform/superproject/+/android-latest-release:packages/services/Telephony/src/com/android/phone/PhoneInterfaceManager.java;l=8049
       */
      case "getDeviceId":
      case "getDeviceIdWithFeature":
        Log.i(TAG, "Neutered " + method.getName());
        return null;

      case "getMmsUserAgent":
      case "getMmsUAProfUrl": {
        return "";
      }

      case "hasIccCardUsingSlotIndex": {
        int slotIndex = (args != null && args.length > 0) ? (int) args[0] : -1;
        Log.i(TAG, "Neutered hasIccCardUsingSlotIndex slot=" + slotIndex);
        return slotIndex == 0; // single SIM, slot 0 only
      }
      case "getDataNetworkTypeForSubscriber": {
        Log.i(TAG, "Neutered getDataNetworkTypeForSubscriber");
        return TelephonyManager.NETWORK_TYPE_LTE;
      }
      case "getSimStateForSlotIndex": {
        int slotIndex = (args != null && args.length > 0) ? (int) args[0] : -1;
        Log.i(TAG, "Neutered getSimStateForSlotIndex slot=" + slotIndex);
        if (slotIndex == 0) {
          return TelephonyManager.SIM_STATE_READY;
        }
        return TelephonyManager.SIM_STATE_UNKNOWN;
      }

      case "getCarrierIdFromMccMnc": {
        String mccmnc = (args != null && args.length > 1 && args[1] instanceof String)
            ? (String) args[1]
            : "";
        Log.i(TAG, "Neutered getCarrierIdFromMccMnc mccmnc=" + mccmnc);
        if (MCCMNC_TUPLE.equals(mccmnc)) {
          return CARRIER_ID;
        }
        return TelephonyManager.UNKNOWN_CARRIER_ID;
      }

      default:
        Log.w(TAG, "Allowing Telephony method through: " + method.getName());
        return method.invoke(originalITelephony, args);
    }
  }
}
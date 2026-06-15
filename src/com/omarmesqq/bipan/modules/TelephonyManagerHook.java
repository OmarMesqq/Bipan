package com.omarmesqq.bipan.modules;

import android.content.Context;
import android.os.IBinder;
import android.telephony.TelephonyManager;
import android.util.Log;
import com.omarmesqq.bipan.BaseHook;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.Map;

public class TelephonyManagerHook implements BaseHook, InvocationHandler {
  private static final String TAG = "BipanTelephonyHook";

  private Object originalITelephony;
  private TelephonyManager realTm;

  private static final int CARRIER_ID = 530;

  private static final String SPOOF_OPERATOR_NAME = "Vivo";
  private static final String SPOOF_OPERATOR_NUMERIC = "72423";
  private static final String SPOOF_COUNTRY_ISO = "br";
  private static final String SPOOF_SIM_OPERATOR_NAME = "Vivo";
  private static final String SPOOF_SIM_OPERATOR = "72423";
  private static final String SPOOF_SIM_COUNTRY_ISO = "br";
  // maybe unnecessary
  private static final String SPOOF_DEVICE_SOFTWARE_VER = "06";
  private static final int SPOOF_PHONE_TYPE = TelephonyManager.PHONE_TYPE_GSM;
  private static final int SPOOF_PHONE_COUNT = 1;
  private static final int SPOOF_ACTIVE_MODEM_COUNT = 1;
  private static final int SPOOF_NETWORK_TYPE = TelephonyManager.NETWORK_TYPE_LTE;
  private static final int SPOOF_DATA_NETWORK_TYPE = TelephonyManager.NETWORK_TYPE_LTE;

  private static final Set<String> ALLOW_LIST = new HashSet<>(Arrays.asList(
      "com.android.vending",
      "com.google.android.gms",
      "com.spotify.music",
      "com.whatsapp",
      "com.instagram.android"));

  private Object emptyParceledListSlice() throws Exception {
    Class<?> sliceClass = Class.forName("android.content.pm.ParceledListSlice");
    Method emptyList = sliceClass.getMethod("emptyList");
    return emptyList.invoke(null);
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

    Log.i(TAG, "TelephonyManager hook installed");
  }

  private void replaceBinderInTelephonyManager(TelephonyManager tm, IBinder proxyBinder) {
    // TelephonyManager caches an IPhoneStateListener or ITelephony ref directly
    // Walk declared fields to find the binder field
    for (Field f : tm.getClass().getDeclaredFields()) {
      if (IBinder.class.isAssignableFrom(f.getType())) {
        f.setAccessible(true);
        try {
          f.set(tm, proxyBinder);
          Log.d(TAG, "Replaced binder field: " + f.getName());
        } catch (Exception e) {
          Log.w(TAG, "Could not replace field " + f.getName() + ": " + e.getMessage());
        }
      }
    }
  }



  @Override
  public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
    switch (method.getName()) {

      // Network operator — what shows in status bar
      case "getNetworkOperatorName":
      case "getNetworkOperatorNameForDisplay":
        Log.w(TAG, "Spoofed: " + method.getName());
        return SPOOF_OPERATOR_NAME;

      case "getNetworkCountryIso":
      case "getNetworkCountryIsoForPhone":
        Log.w(TAG, "Spoofed: getNetworkCountryIso");
        return SPOOF_COUNTRY_ISO;

      // SIM operator
      case "getSimOperatorName":
      case "getSimOperatorNameForPhone":
      case "getSimOperatorNameForSubscription":
        Log.w(TAG, "Spoofed: getSimOperatorName");
        return SPOOF_SIM_OPERATOR_NAME;

      case "getSimOperator":
      case "getSimOperatorNumeric":
      case "getSimOperatorForSubscription":
        Log.w(TAG, "Spoofed: getSimOperator");
        return SPOOF_OPERATOR_NUMERIC;

      case "getSimCountryIso":
      case "getSimCountryIsoForPhone":
      case "getSimCountryIsoForSubscription":
        Log.w(TAG, "Spoofed: getSimCountryIso");
        return SPOOF_SIM_COUNTRY_ISO;

      // Phone/modem count — critical for dual SIM detection
      case "getPhoneCount":
      case "getActiveModemCount":
      case "getSupportedModemCount":
        Log.w(TAG, "Spoofed: " + method.getName() + " → 1");
        return SPOOF_PHONE_COUNT;

      case "getPhoneType":
      case "getPhoneTypeForSlot":
        return SPOOF_PHONE_TYPE;

      // Network type
      case "getNetworkType":
      case "getNetworkTypeForSubscriber":
      case "getDataNetworkType":
      case "getDataNetworkTypeForSubscriber":
      case "getVoiceNetworkType":
      case "getVoiceNetworkTypeForSubscriber":
        return SPOOF_NETWORK_TYPE;

      // SIM state — LOADED = SIM present and ready
      case "getSimState":
      case "getSimStateForSlotIndex":
        // TelephonyManager.SIM_STATE_READY = 5
        return 5;

      // SIM slot count
      case "getPhoneCapability":
        // Fall through to real — we handle slot count via sysprop
        return method.invoke(originalITelephony, args);

      // Signal that we're not dual SIM
      case "isMultiSimEnabled":
        Log.w(TAG, "Spoofed: isMultiSimEnabled → false");
        return false;

      // Device software version (visible in About Phone)
      case "getDeviceSoftwareVersion":
      case "getDeviceSoftwareVersionForSubscriber":
        return SPOOF_DEVICE_SOFTWARE_VER;

      // Emergency number list
      case "getEmergencyNumberList":
      case "getEmergencyNumberListForSubscriber":
        return method.invoke(originalITelephony, args);

      case "isMultiSimSupported":
        Log.i(TAG, "Neutered " + method.getName());
        return TelephonyManager.MULTISIM_NOT_SUPPORTED_BY_HARDWARE;

      case "getAllCellInfo":
      case "getCellLocation":
        Log.i(TAG, "Neutered " + method.getName());
        return null;

      // case "getServiceState":
      // case "getServiceStateForSlot":
      // Log.i(TAG, "Neutered " + method.getName());
      // return emptyParceledListSlice();

      case "getVisualVoicemailPackageName":
        Log.i(TAG, "Neutered " + method.getName());
        return "com.google.android.dialer";

      case "hasCarrierPrivileges":
        Log.i(TAG, "Neutered " + method.getName());
        return false;

      case "getSimCarrierId":
      case "getSimSpecificCarrierId":
        Log.i(TAG, "Neutered " + method.getName());
        return CARRIER_ID;

      // Everything else passes through
      default:
        Log.i(TAG, "Allowing Telephony method through: " + method.getName());
        try {
          return method.invoke(originalITelephony, args);
        } catch (Exception e) {
          Log.w(TAG, "ITelephony passthrough failed for " + method.getName() + ": " + e.getMessage());
          return null;
        }
    }
  }
}
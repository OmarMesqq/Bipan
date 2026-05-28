package com.omarmesqq.bipan.modules;

import android.content.Context;
import android.util.Log;

import com.omarmesqq.bipan.BaseHook;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;
import javax.net.ssl.X509TrustManager;

public class SslPinningHook implements BaseHook {
  private static final String TAG = "BipanJava-SslPinning";

  @Override
  public void install(Context context) throws Exception {
    bypassAndroidNetworkSecurityConfig(context);
  }

  private void bypassAndroidNetworkSecurityConfig(Context context) {
    try {
      Class<?> applicationConfigClass = Class.forName("android.security.net.config.ApplicationConfig");

      // 1. Force platform initialization routines organically
      Method getDefaultMethod = applicationConfigClass.getMethod("getDefaultInstance");
      Object applicationConfigInstance = getDefaultMethod.invoke(null);

      if (applicationConfigInstance == null) {
        Log.w(TAG, "ApplicationConfig instance was null. Bootstrapping network provider engine...");
        Class<?> providerClass = Class.forName("android.security.net.config.NetworkSecurityConfigProvider");
        Method installMethod = providerClass.getMethod("install", Context.class);
        installMethod.invoke(null, context);
        applicationConfigInstance = getDefaultMethod.invoke(null);
      }

      if (applicationConfigInstance == null) {
        Log.e(TAG, "Critical: ApplicationConfig instance could not be resolved.");
        return;
      }

      // 2. Extract the working TrustManager straight from the initialized platform
      // singleton
      Field mTrustManagerField = applicationConfigClass.getDeclaredField("mTrustManager");
      mTrustManagerField.setAccessible(true);
      X509TrustManager originalTM = (X509TrustManager) mTrustManagerField.get(applicationConfigInstance);

      if (originalTM == null) {
        Log.e(TAG, "Critical: Original OS TrustManager was null inside ApplicationConfig.");
        return;
      }

      // 3. CRASH INSURANCE: Check if we already patched it to prevent loops
      if (originalTM instanceof BipanTrustManagerWrapper) {
        Log.w(TAG, "TrustManager is already wrapped by Bipan. Skipping.");
        return;
      }

      // 4. Instantiate our static, compiled wrapper that native code cannot reject
      BipanTrustManagerWrapper safeWrapper = new BipanTrustManagerWrapper(originalTM);

      // 5. HOT SWAP: Inject our concrete object instance back into the system
      // property config location
      mTrustManagerField.set(applicationConfigInstance, safeWrapper);

      Log.i(TAG, "Successfully injected concrete static wrapper over ApplicationConfig.mTrustManager!");

    } catch (Exception e) {
      Log.e(TAG, "Critical failure configuring NetworkSecurityTrustManager bypass", e);
    }
  }

  /**
   * Concrete implementation of the extended hidden Android TrustManager layout.
   * This class physically defines every possible variant check signature, making
   * it
   * impossible for Facebook's Tigon or X509TrustManagerExtensions to reject it.
   */
  public static class BipanTrustManagerWrapper implements X509TrustManager {
    private final X509TrustManager delegate;
    private Method checkServerTrusted3ArgMethod;

    public BipanTrustManagerWrapper(X509TrustManager original) {
      this.delegate = original;
      try {
        // Cache the extended 3-argument check method via reflection from the original
        // platform class
        checkServerTrusted3ArgMethod = original.getClass().getMethod(
            "checkServerTrusted", X509Certificate[].class, String.class, String.class);
        checkServerTrusted3ArgMethod.setAccessible(true);
      } catch (NoSuchMethodException e) {
        Log.w(TAG, "Extended 3-argument checkServerTrusted method not found on delegate class.");
      }
    }

    // Required 3-argument hidden endpoint tracked by X509TrustManagerExtensions
    @SuppressWarnings("unused")
    public List<X509Certificate> checkServerTrusted(X509Certificate[] chain, String authType, String host)
        throws CertificateException {
      Log.w(TAG, "Intercepted 3-arg checkServerTrusted(chain, authType, \"" + host + "\")");
      try {
        if (checkServerTrusted3ArgMethod != null) {
          return (List<X509Certificate>) checkServerTrusted3ArgMethod.invoke(delegate, chain, authType, host);
        } else {
          delegate.checkServerTrusted(chain, authType);
          return java.util.Arrays.asList(chain);
        }
      } catch (Exception ite) {
        Throwable cause = ite instanceof java.lang.reflect.InvocationTargetException ? ite.getCause() : ite;
        if (cause != null && cause.getMessage() != null && cause.getMessage().contains("Pin verification failed")) {
          Log.e(TAG, "Muted Pin verification failure for host: " + host);
          return java.util.Arrays.asList(chain); // Safe return bypassing exception pipeline
        }
        if (cause instanceof CertificateException)
          throw (CertificateException) cause;
        throw new CertificateException(cause);
      }
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
      delegate.checkClientTrusted(chain, authType);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
      Log.w(TAG, "Intercepted standard 2-arg checkServerTrusted()");
      try {
        delegate.checkServerTrusted(chain, authType);
      } catch (CertificateException e) {
        if (e.getMessage() != null && e.getMessage().contains("Pin verification failed")) {
          Log.e(TAG, "Muted 2-arg active Pin verification failure!");
          return;
        }
        throw e;
      }
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
      return delegate.getAcceptedIssuers();
    }
  }
}

/**
 * 
 * logClassFields("android.security.net.config.NetworkSecurityTrustManager");
 * logClassFields("android.security.net.config.ApplicationConfig");
 * logClassFields("javax.net.ssl.X509TrustManager");
 * 
 * 
 * 
 * private void logClassFields(String className) {
 * try {
 * Log.d(TAG, "--- Introspecting Fields for: " + className + " ---");
 * Class<?> clazz = Class.forName(className);
 * Field[] fields = clazz.getDeclaredFields();
 * 
 * for (Field field : fields) {
 * field.setAccessible(true);
 * Log.d(TAG, " Field: [" + field.getName() + "] | Type: " +
 * field.getType().getName());
 * }
 * } catch (ClassNotFoundException e) {
 * Log.e(TAG, " Failed introspection: Class " + className + " not found on this
 * runtime platform.");
 * } catch (Exception e) {
 * Log.e(TAG, " Error introspecting fields for " + className, e);
 * }
 * Log.d(TAG, "--------------------------------------------------------");
 * }
 */
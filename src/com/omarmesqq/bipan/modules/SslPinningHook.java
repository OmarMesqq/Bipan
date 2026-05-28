package com.omarmesqq.bipan.modules;

import android.content.Context;
import android.util.Log;

import com.omarmesqq.bipan.BaseHook;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;
import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.TrustManagerFactorySpi;
import javax.net.ssl.X509TrustManager;

public class SslPinningHook implements BaseHook {
  private static final String TAG = "BipanJava-SslPinning";

  @Override
  public void install(Context context) throws Exception {
    bypassAndroidNetworkSecurityConfig(context);
    bypassObfuscatedTrustManagers(context);
  }

  private void bypassAndroidNetworkSecurityConfig(Context context) {
    try {
      Class<?> applicationConfigClass = Class.forName("android.security.net.config.ApplicationConfig");

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

      Field mTrustManagerField = applicationConfigClass.getDeclaredField("mTrustManager");
      mTrustManagerField.setAccessible(true);
      X509TrustManager originalTM = (X509TrustManager) mTrustManagerField.get(applicationConfigInstance);

      if (originalTM == null) {
        Log.e(TAG, "Critical: Original OS TrustManager was null inside ApplicationConfig.");
        return;
      }

      if (originalTM instanceof BipanTrustManagerWrapper) {
        Log.w(TAG, "TrustManager is already wrapped by Bipan. Skipping.");
        return;
      }

      BipanTrustManagerWrapper safeWrapper = new BipanTrustManagerWrapper(originalTM);
      mTrustManagerField.set(applicationConfigInstance, safeWrapper);
      Log.i(TAG, "Successfully injected concrete static wrapper over ApplicationConfig.mTrustManager!");

    } catch (Exception e) {
      Log.e(TAG, "Critical failure configuring NetworkSecurityTrustManager bypass", e);
    }
  }

  /**
   * Targets custom engine configurations (like Msys/X.IQr) that instantiate
   * their own standalone TrustManagerFactory pipelines.
   */
  private void bypassObfuscatedTrustManagers(Context context) {
    try {
      // 1. Force a baseline factory instantiation to trigger the framework's internal
      // provider cache population
      TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());

      // 2. Fetch the platform's primary crypto security provider context
      Provider provider = Security.getProvider("AndroidOpenSSL");
      if (provider == null) {
        provider = Security.getProvider("Conscrypt");
      }

      if (provider != null) {
        // 3. Locate the service class definition managing factory requests
        String key = "TrustManagerFactory." + TrustManagerFactory.getDefaultAlgorithm();
        String tmfSpiClassName = provider.getProperty(key);

        if (tmfSpiClassName != null) {
          // 4. Overwrite the Provider engine structure to distribute our custom BipanSPI
          // factory globally
          Provider.Service customService = new Provider.Service(
              provider,
              "TrustManagerFactory",
              TrustManagerFactory.getDefaultAlgorithm(),
              BipanTrustManagerFactorySpi.class.getName(),
              null,
              null) {
            @Override
            public Object newInstance(Object constructorParameter) {
              return new BipanTrustManagerFactorySpi();
            }
          };

          // Inject our service back into the cryptographic tracking runtime
          Method putServiceMethod = Provider.class.getDeclaredMethod("putService", Provider.Service.class);
          putServiceMethod.setAccessible(true);
          putServiceMethod.invoke(provider, customService);

          Log.i(TAG, "=== [GLOBAL SUCCESS] Overrode standard TrustManagerFactory SPI layout engine! ===");
        }
      }
    } catch (Exception e) {
      Log.e(TAG, "Failed overriding custom application trust infrastructure", e);
    }
  }

  /**
   * Custom Factory SPI implementation. Forces any custom instantiation loop
   * to fetch a TrustManager chain wrapped inside our validation interceptor.
   */
  public static class BipanTrustManagerFactorySpi extends TrustManagerFactorySpi {
    private X509TrustManager nativeTrustManager;

    public BipanTrustManagerFactorySpi() {
      try {
        // Build a baseline factory to extract clean native components
        TrustManagerFactory factory = TrustManagerFactory.getInstance("PKIX");
        factory.init((java.security.KeyStore) null);
        for (TrustManager tm : factory.getTrustManagers()) {
          if (tm instanceof X509TrustManager) {
            this.nativeTrustManager = (X509TrustManager) tm;
            break;
          }
        }
      } catch (Exception ignored) {
      }
    }

    @Override
    protected void engineInit(java.security.KeyStore keyStore) {
      // No-op to avoid breaking local configurations
    }

    // FIXED: Removed the erroneous engineInit(TrustManagerFactorySpi) overload

    @Override
    protected void engineInit(ManagerFactoryParameters managerFactoryParameters) {
      // No-op
    }

    @Override
    protected TrustManager[] engineGetTrustManagers() {
      if (nativeTrustManager != null) {
        return new TrustManager[] { new BipanTrustManagerWrapper(nativeTrustManager) };
      }
      return new TrustManager[0];
    }
  }

  /**
   * Universal TrustManager Interceptor layout.
   */
  public static class BipanTrustManagerWrapper implements X509TrustManager {
    private final X509TrustManager delegate;
    private Method checkServerTrusted3ArgMethod;

    public BipanTrustManagerWrapper(X509TrustManager original) {
      this.delegate = original;
      try {
        checkServerTrusted3ArgMethod = original.getClass().getMethod(
            "checkServerTrusted", X509Certificate[].class, String.class, String.class);
        checkServerTrusted3ArgMethod.setAccessible(true);
      } catch (NoSuchMethodException e) {
        Log.d(TAG, "Extended 3-argument checkServerTrusted method not found on delegate class.");
      }
    }

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
        // Catch all variations of Path/Pin exceptions thrown by any underlying
        // TrustManager
        if (cause != null && cause.getMessage() != null &&
            (cause.getMessage().contains("Pin verification failed") || cause.getMessage().contains("trust anchors"))) {
          Log.e(TAG, "Neutralized verification failure for host target: " + host);
          return java.util.Arrays.asList(chain);
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
        if (e.getMessage() != null &&
            (e.getMessage().contains("Pin verification failed") || e.getMessage().contains("trust anchors"))) {
          Log.e(TAG, "Neutralized 2-arg active verification error!");
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
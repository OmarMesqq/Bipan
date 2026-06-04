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
import java.util.Arrays;
import java.util.List;
import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.TrustManagerFactorySpi;
import javax.net.ssl.X509TrustManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLContextSpi;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;

public class SslPinningHook implements BaseHook {
  private static final String TAG = "BipanJava-SslPinning";
  private static final List<String> TARGET_APPS = Arrays.asList(
      "com.whatsapp");

  @Override
  public void install(Context context) throws Exception {
    String currentPackage = context.getPackageName();
    if (currentPackage == null || !TARGET_APPS.contains(currentPackage)) {
      return;
    }

    forceDowngradeToTls12();
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
      TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());

      Provider provider = Security.getProvider("AndroidOpenSSL");
      if (provider == null) {
        provider = Security.getProvider("Conscrypt");
      }

      if (provider != null) {
        String key = "TrustManagerFactory." + TrustManagerFactory.getDefaultAlgorithm();
        String tmfSpiClassName = provider.getProperty(key);

        if (tmfSpiClassName != null) {
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

  private void forceDowngradeToTls12() {
    try {
      SSLContext defaultContext = SSLContext.getDefault();
      SSLContext tlsContext = SSLContext.getInstance("TLS");

      Field contextSpiField = SSLContext.class.getDeclaredField("contextSpi");
      contextSpiField.setAccessible(true);

      final SSLContextSpi originalSpi = (SSLContextSpi) contextSpiField.get(tlsContext);

      if (originalSpi != null) {
        final Method engineInitMethod = SSLContextSpi.class.getDeclaredMethod("engineInit",
            javax.net.ssl.KeyManager[].class, TrustManager[].class, java.security.SecureRandom.class);
        final Method engineGetSocketFactoryMethod = SSLContextSpi.class.getDeclaredMethod("engineGetSocketFactory");
        final Method engineGetServerSocketFactoryMethod = SSLContextSpi.class
            .getDeclaredMethod("engineGetServerSocketFactory");
        final Method engineCreateSSLEngineMethod = SSLContextSpi.class.getDeclaredMethod("engineCreateSSLEngine");
        final Method engineCreateSSLEngineWithHostMethod = SSLContextSpi.class
            .getDeclaredMethod("engineCreateSSLEngine", String.class, int.class);
        final Method engineGetServerSessionContextMethod = SSLContextSpi.class
            .getDeclaredMethod("engineGetServerSessionContext");
        final Method engineGetClientSessionContextMethod = SSLContextSpi.class
            .getDeclaredMethod("engineGetClientSessionContext");

        engineInitMethod.setAccessible(true);
        engineGetSocketFactoryMethod.setAccessible(true);
        engineGetServerSocketFactoryMethod.setAccessible(true);
        engineCreateSSLEngineMethod.setAccessible(true);
        engineCreateSSLEngineWithHostMethod.setAccessible(true);
        engineGetServerSessionContextMethod.setAccessible(true);
        engineGetClientSessionContextMethod.setAccessible(true);

        // STABILIZED: Resolve baseline trust manager using generic default runtime
        // lookups
        X509TrustManager systemTm = null;
        try {
          TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
          tmf.init((java.security.KeyStore) null);
          for (TrustManager tm : tmf.getTrustManagers()) {
            if (tm instanceof X509TrustManager) {
              systemTm = (X509TrustManager) tm;
              break;
            }
          }
        } catch (Exception e) {
          Log.e(TAG, "Failed to retrieve system default trust manager reference", e);
        }

        final X509TrustManager finalSystemTm = systemTm;

        // Force contextual pre-initialization using our wrapped bypass structure
        try {
          if (finalSystemTm != null) {
            TrustManager[] preInitTms = new TrustManager[] { new BipanTrustManagerWrapper(finalSystemTm) };
            engineInitMethod.invoke(originalSpi, null, preInitTms, null);
          } else {
            engineInitMethod.invoke(originalSpi, null, null, null);
          }
        } catch (Exception ignored) {
        }

        SSLSocketFactory nativeFactory = (SSLSocketFactory) engineGetSocketFactoryMethod.invoke(originalSpi);
        final BipanSSLSocketFactory fallbackFactory = new BipanSSLSocketFactory(nativeFactory);

        SSLContextSpi customSpi = new SSLContextSpi() {
          @Override
          protected void engineInit(javax.net.ssl.KeyManager[] km, TrustManager[] tm, java.security.SecureRandom sr)
              throws java.security.KeyManagementException {
            try {
              TrustManager[] wrappedTms = tm;
              if (tm != null) {
                wrappedTms = new TrustManager[tm.length];
                for (int i = 0; i < tm.length; i++) {
                  if (tm[i] instanceof X509TrustManager && !(tm[i] instanceof BipanTrustManagerWrapper)) {
                    wrappedTms[i] = new BipanTrustManagerWrapper((X509TrustManager) tm[i]);
                  } else {
                    wrappedTms[i] = tm[i];
                  }
                }
              } else if (finalSystemTm != null) {
                wrappedTms = new TrustManager[] { new BipanTrustManagerWrapper(finalSystemTm) };
              }
              engineInitMethod.invoke(originalSpi, km, wrappedTms, sr);
            } catch (Exception e) {
              throw new java.security.KeyManagementException(e);
            }
          }

          @Override
          protected SSLSocketFactory engineGetSocketFactory() {
            return fallbackFactory;
          }

          @Override
          protected SSLServerSocketFactory engineGetServerSocketFactory() {
            try {
              return (SSLServerSocketFactory) engineGetServerSocketFactoryMethod.invoke(originalSpi);
            } catch (Exception e) {
              return null;
            }
          }

          @Override
          protected SSLEngine engineCreateSSLEngine() {
            try {
              SSLEngine engine = (SSLEngine) engineCreateSSLEngineMethod.invoke(originalSpi);
              if (engine != null)
                engine.setEnabledProtocols(new String[] { "TLSv1.2" });
              return engine;
            } catch (Exception e) {
              return null;
            }
          }

          @Override
          protected SSLEngine engineCreateSSLEngine(String host, int port) {
            try {
              SSLEngine engine = (SSLEngine) engineCreateSSLEngineWithHostMethod.invoke(originalSpi, host, port);
              if (engine != null)
                engine.setEnabledProtocols(new String[] { "TLSv1.2" });
              return engine;
            } catch (Exception e) {
              return null;
            }
          }

          @Override
          protected javax.net.ssl.SSLSessionContext engineGetServerSessionContext() {
            try {
              return (javax.net.ssl.SSLSessionContext) engineGetServerSessionContextMethod.invoke(originalSpi);
            } catch (Exception e) {
              return null;
            }
          }

          @Override
          protected javax.net.ssl.SSLSessionContext engineGetClientSessionContext() {
            try {
              return (javax.net.ssl.SSLSessionContext) engineGetClientSessionContextMethod.invoke(originalSpi);
            } catch (Exception e) {
              return null;
            }
          }
        };

        contextSpiField.set(tlsContext, customSpi);
        contextSpiField.set(defaultContext, customSpi);

        Log.w(TAG,
            "=== [TLS 1.2 INJECTION SUCCESS] Stabilized active SSLContext parameters with full trust hooks! ===");
      }
    } catch (Exception e) {
      Log.e(TAG, "Failed to apply direct field injection patch setup", e);
    }
  }

  public static class BipanTrustManagerFactorySpi extends TrustManagerFactorySpi {
    private X509TrustManager nativeTrustManager;

    public BipanTrustManagerFactorySpi() {
      try {
        TrustManagerFactory factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
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
    }

    @Override
    protected void engineInit(ManagerFactoryParameters managerFactoryParameters) {
    }

    @Override
    protected TrustManager[] engineGetTrustManagers() {
      if (nativeTrustManager != null) {
        return new TrustManager[] { new BipanTrustManagerWrapper(nativeTrustManager) };
      }
      return new TrustManager[0];
    }
  }

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

    @SuppressWarnings("unchecked")
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

  public static class BipanSSLSocketFactory extends SSLSocketFactory {
    private final SSLSocketFactory delegateFactory;

    public BipanSSLSocketFactory(SSLSocketFactory original) {
      this.delegateFactory = original;
    }

    private Socket forceTls12(Socket socket) {
      if (socket instanceof SSLSocket) {
        SSLSocket sslSocket = (SSLSocket) socket;
        sslSocket.setEnabledProtocols(new String[] { "TLSv1.2" });
        Log.d(TAG, "Successfully stripped TLSv1.3 parameter matrix from outbound socket.");
      }
      return socket;
    }

    @Override
    public String[] getDefaultCipherSuites() {
      return delegateFactory.getDefaultCipherSuites();
    }

    @Override
    public String[] getSupportedCipherSuites() {
      return delegateFactory.getSupportedCipherSuites();
    }

    @Override
    public Socket createSocket(Socket s, String host, int port, boolean autoClose) throws IOException {
      return forceTls12(delegateFactory.createSocket(s, host, port, autoClose));
    }

    @Override
    public Socket createSocket() throws IOException {
      return forceTls12(delegateFactory.createSocket());
    }

    @Override
    public Socket createSocket(String host, int port) throws IOException {
      return forceTls12(delegateFactory.createSocket(host, port));
    }

    @Override
    public Socket createSocket(String host, int port, InetAddress localHost, int localPort) throws IOException {
      return forceTls12(delegateFactory.createSocket(host, port, localHost, localPort));
    }

    @Override
    public Socket createSocket(InetAddress host, int port) throws IOException {
      return forceTls12(delegateFactory.createSocket(host, port));
    }

    @Override
    public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort)
        throws IOException {
      return forceTls12(delegateFactory.createSocket(address, port, localAddress, localPort));
    }
  }
}
package com.omarmesqq.bipan.modules;

import android.content.Context;
import android.util.Log;
import com.omarmesqq.bipan.BaseHook;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import javax.net.ssl.KeyManager;
import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLContextSpi;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactorySpi;
import javax.net.ssl.X509TrustManager;

public class MsysProviderHook implements BaseHook {
  private static final String TAG = "BipanMsysProvider";

  @Override
  public void install(Context context) throws Exception {
    try {
      Log.d(TAG, "[*] Preparing comprehensive Security Provider Hijack Engine...");

      BipanSecurityProvider proxyProvider = new BipanSecurityProvider();

      // Force our wrapper into Position 1 to catch all cryptographic allocation
      // requests
      Security.insertProviderAt(proxyProvider, 1);
      Log.i(TAG, "[███] SUCCESS: Position 1 hijacked. Contexts and TrustFactories rerouted.");

    } catch (Throwable t) {
      Log.e(TAG, "[-] Failed to install global Security Provider hooks", t);
    }
  }

  public static final class BipanSecurityProvider extends Provider {
    public BipanSecurityProvider() {
      super("BipanProxyProvider", 1.0, "Bipan MitM Trust-All Wrapper Provider");

      // 1. Map global SSL Context paths
      String ctxSpi = BipanSSLContextSpi.class.getName();
      put("SSLContext.TLS", ctxSpi);
      put("SSLContext.TLSv1", ctxSpi);
      put("SSLContext.TLSv1.1", ctxSpi);
      put("SSLContext.TLSv1.2", ctxSpi);
      put("SSLContext.TLSv1.3", ctxSpi);
      put("SSLContext.Default", ctxSpi);

      // 2. NEW: Map global Trust Manager validation hooks
      String tmfSpi = BipanTrustManagerFactorySpi.class.getName();
      put("TrustManagerFactory.PKIX", tmfSpi);
      put("TrustManagerFactory.X509", tmfSpi);
    }
  }

  /**
   * Intercepts all validation factory allocations globally across the process
   * space
   */
  public static final class BipanTrustManagerFactorySpi extends TrustManagerFactorySpi {
    @Override
    protected void engineInit(KeyStore ks) throws KeyStoreException {
      Log.d(TAG, "[#] TrustManagerFactory intercepted via engineInit(KeyStore)");
    }

    @Override
    protected void engineInit(ManagerFactoryParameters spec) throws InvalidAlgorithmParameterException {
      Log.d(TAG, "[#] TrustManagerFactory intercepted via engineInit(ManagerFactoryParameters)");
    }

    @Override
    protected TrustManager[] engineGetTrustManagers() {
      Log.w(TAG, "[███] TARGET HIT: Swapping internal verification engine parameters for Trust-All profile.");

      return new TrustManager[] {
          new X509TrustManager() {
            @Override
            public X509Certificate[] getAcceptedIssuers() {
              return new X509Certificate[0];
            }

            @Override
            public void checkClientTrusted(X509Certificate[] certs, String authType) {
            }

            @Override
            public void checkServerTrusted(X509Certificate[] certs, String authType) {
              Log.d(TAG, "[+] Custom Trust-All wrapper neutralizing leaf signature evaluation.");
            }
          }
      };
    }
  }

  public static final class BipanSSLContextSpi extends SSLContextSpi {
    private final SSLContext underlyingRealContext;

    public BipanSSLContextSpi() {
      try {
        // Explicitly isolate Conscrypt provider backend to prevent recursion loops
        this.underlyingRealContext = SSLContext.getInstance("TLS", "Conscrypt");
      } catch (Exception e) {
        throw new RuntimeException("Fallback context mapping failure", e);
      }
    }

    @Override
    protected void engineInit(KeyManager[] km, TrustManager[] tm, SecureRandom sr) throws KeyManagementException {
      Log.w(TAG, "[#] SSLContext intercepted. Substituting trust-all profile structures.");

      TrustManager[] trustAllCerts = new TrustManager[] {
          new X509TrustManager() {
            @Override
            public X509Certificate[] getAcceptedIssuers() {
              return new X509Certificate[0];
            }

            @Override
            public void checkClientTrusted(X509Certificate[] certs, String authType) {
            }

            @Override
            public void checkServerTrusted(X509Certificate[] certs, String authType) {
            }
          }
      };
      underlyingRealContext.init(km, trustAllCerts, sr);
    }

    @Override
    protected SSLSocketFactory engineGetSocketFactory() {
      return underlyingRealContext.getSocketFactory();
    }

    @Override
    protected SSLServerSocketFactory engineGetServerSocketFactory() {
      return underlyingRealContext.getServerSocketFactory();
    }

    @Override
    protected SSLEngine engineCreateSSLEngine() {
      return underlyingRealContext.createSSLEngine();
    }

    @Override
    protected SSLEngine engineCreateSSLEngine(String host, int port) {
      return underlyingRealContext.createSSLEngine(host, port);
    }

    @Override
    protected javax.net.ssl.SSLSessionContext engineGetClientSessionContext() {
      return underlyingRealContext.getClientSessionContext();
    }

    @Override
    protected javax.net.ssl.SSLSessionContext engineGetServerSessionContext() {
      return underlyingRealContext.getServerSessionContext();
    }
  }
}
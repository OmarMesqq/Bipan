package com.omarmesqq.bipan.modules;

import android.content.Context;
import android.util.Log;
import com.omarmesqq.bipan.BaseHook;
import java.lang.reflect.Method;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

public class MsysTrustHook implements BaseHook {
  private static final String TAG = "BipanMsysHook";

  @Override
  public void install(Context context) throws Exception {
    try {
      Log.d(TAG, "[*] Intercepting global SSLContext providers...");

      // 1. Define a completely blank TrustManager that accepts everything
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
              // Do nothing: accept all proxy cert chains blindly
            }
          }
      };

      // 2. Reflect directly into standard SSLContext initialization method
      Class<?> sslContextClass = SSLContext.class;
      Method initMethod = sslContextClass.getMethod("init",
          KeyManager[].class,
          TrustManager[].class,
          SecureRandom.class);

      // 3. Since this is a fileless dex, hook the method structure
      // If using dynamic hooks, replace the execution parameters:
      Log.d(TAG, "[+] Target method resolved: " + initMethod.toString());

      // Note: Because you are working inside an InMemoryDexClassLoader environment,
      // you can use standard reflection overrides or bridge to Dobby if you track
      // the JNI art method pointer, but a pure Java hook framework (like standard
      // method replacement or dynamic proxying where applicable) is ideal.

      // If you want to force default factories across the board via reflection:
      SSLContext customContext = SSLContext.getInstance("TLS");
      initMethod.invoke(customContext, null, trustAllCerts, new SecureRandom());
      SSLContext.setDefault(customContext);
      Log.i(TAG, "[███] SUCCESS: Default SSLContext overridden with Trust-All profile.");

    } catch (Throwable t) {
      Log.e(TAG, "[-] Failed to inject transparent SSL context proxy", t);
    }
  }
}
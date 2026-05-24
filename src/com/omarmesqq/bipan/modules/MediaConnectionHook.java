package com.omarmesqq.bipan.modules;

import android.content.Context;
import android.util.Log;
import com.omarmesqq.bipan.BaseHook;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLStreamHandler;
import java.net.URLStreamHandlerFactory;
import java.util.List;
import java.util.Map;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSocketFactory;

public class MediaConnectionHook implements BaseHook {
  private static final String TAG = "BipanMediaHook";

  @Override
  public void install(Context context) throws Exception {
    try {
      Log.d(TAG, "[*] Executing comprehensive stream and factory overrides...");

      // 1. Resolve basic baseline factory profile
      SSLSocketFactory systemFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
      TlsDowngradeSocketFactory customizedFallback = new TlsDowngradeSocketFactory(systemFactory);

      // 2. Smash class-level defaults to catch implicit inheritance paths
      HttpsURLConnection.setDefaultSSLSocketFactory(customizedFallback);
      Log.i(TAG, "[███] SUCCESS: Neutralized HttpsURLConnection global class factory.");

      // 3. Keep URL stream factory interception active for instance isolation defense
      Field factoryField = URL.class.getDeclaredField("factory");
      factoryField.setAccessible(true);
      final URLStreamHandlerFactory originalFactory = (URLStreamHandlerFactory) factoryField.get(null);

      URLStreamHandlerFactory proxyFactory = new URLStreamHandlerFactory() {
        @Override
        public URLStreamHandler createURLStreamHandler(String protocol) {
          if ("https".equalsIgnoreCase(protocol)) {
            final URLStreamHandler originalHandler;
            if (originalFactory != null) {
              originalHandler = originalFactory.createURLStreamHandler(protocol);
            } else {
              try {
                Method method = URL.class.getDeclaredMethod("getURLStreamHandler", String.class);
                method.setAccessible(true);
                originalHandler = (URLStreamHandler) method.invoke(null, protocol);
              } catch (Exception e) {
                return null;
              }
            }

            return new URLStreamHandler() {
              @Override
              protected URLConnection openConnection(URL u) throws java.io.IOException {
                Method openMethod;
                try {
                  openMethod = URLStreamHandler.class.getDeclaredMethod("openConnection", URL.class);
                  openMethod.setAccessible(true);
                  URLConnection conn = (URLConnection) openMethod.invoke(originalHandler, u);

                  if (conn instanceof HttpsURLConnection) {
                    return new BipanHttpsURLConnectionWrapper((HttpsURLConnection) conn, customizedFallback);
                  }
                  return conn;
                } catch (Exception e) {
                  throw new java.io.IOException("Bipan stream pipeline redirection failure", e);
                }
              }
            };
          }
          return originalFactory != null ? originalFactory.createURLStreamHandler(protocol) : null;
        }
      };

      factoryField.set(null, null);
      URL.setURLStreamHandlerFactory(proxyFactory);
      Log.i(TAG, "[███] SUCCESS: URL Stream Handler Factory verified globally.");

    } catch (Throwable t) {
      Log.e(TAG, "[-] Fatal disruption installing stream configuration layers", t);
    }
  }

  private static class BipanHttpsURLConnectionWrapper extends HttpsURLConnection {
    private final HttpsURLConnection delegate;

    public BipanHttpsURLConnectionWrapper(HttpsURLConnection delegate, SSLSocketFactory forcedFactory) {
      super(delegate.getURL());
      this.delegate = delegate;
      delegate.setSSLSocketFactory(forcedFactory);
    }

    @Override
    public void setSSLSocketFactory(SSLSocketFactory sf) {
      Log.w(TAG, "[#] BLOCKED: Prevented runtime instance factory override request.");
    }

    @Override public SSLSocketFactory getSSLSocketFactory() { return delegate.getSSLSocketFactory(); }
    @Override public String getCipherSuite() { return delegate.getCipherSuite(); }
    @Override public java.security.cert.Certificate[] getLocalCertificates() { return delegate.getLocalCertificates(); }
    @Override public java.security.cert.Certificate[] getServerCertificates() throws javax.net.ssl.SSLPeerUnverifiedException { return delegate.getServerCertificates(); }
    @Override public void connect() throws java.io.IOException { delegate.connect(); }
    @Override public void disconnect() { delegate.disconnect(); }
    @Override public boolean usingProxy() { return delegate.usingProxy(); }
    @Override public InputStream getInputStream() throws java.io.IOException { return delegate.getInputStream(); }
    @Override public OutputStream getOutputStream() throws java.io.IOException { return delegate.getOutputStream(); }
    @Override public int getResponseCode() throws java.io.IOException { return delegate.getResponseCode(); }
    @Override public String getResponseMessage() throws java.io.IOException { return delegate.getResponseMessage(); }
    @Override public String getHeaderField(String name) { return delegate.getHeaderField(name); }
    @Override public String getHeaderField(int n) { return delegate.getHeaderField(n); }
    @Override public String getHeaderFieldKey(int n) { return delegate.getHeaderFieldKey(n); }
    @Override public Map<String, List<String>> getHeaderFields() { return delegate.getHeaderFields(); }
    @Override public void setRequestProperty(String key, String value) { delegate.setRequestProperty(key, value); }
    @Override public String getRequestProperty(String key) { return delegate.getRequestProperty(key); }
    @Override public Map<String, List<String>> getRequestProperties() { return delegate.getRequestProperties(); }
    @Override public void setDoInput(boolean doinput) { delegate.setDoInput(doinput); }
    @Override public void setDoOutput(boolean dooutput) { delegate.setDoOutput(dooutput); }
    @Override public void setHostnameVerifier(HostnameVerifier v) { delegate.setHostnameVerifier(v); }
    @Override public HostnameVerifier getHostnameVerifier() { return delegate.getHostnameVerifier(); }
  }

  private static class TlsDowngradeSocketFactory extends SSLSocketFactory {
    private final SSLSocketFactory base;
    private final String[] forcedProtocols = new String[] { "TLSv1.2" };

    public TlsDowngradeSocketFactory(SSLSocketFactory base) {
      this.base = base;
    }

    private java.net.Socket configureSocket(java.net.Socket socket) {
      if (socket instanceof javax.net.ssl.SSLSocket) {
        javax.net.ssl.SSLSocket sslSocket = (javax.net.ssl.SSLSocket) socket;
        sslSocket.setEnabledProtocols(forcedProtocols);
        Log.d(TAG, "[███] SOCKET ENFORCED: Protocol downgraded to TLSv1.2 for signature alignment.");
      }
      return socket;
    }

    @Override public String[] getDefaultCipherSuites() { return base.getDefaultCipherSuites(); }
    @Override public String[] getSupportedCipherSuites() { return base.getSupportedCipherSuites(); }

    @Override public java.net.Socket createSocket(java.net.Socket s, String host, int port, boolean autoClose) throws java.io.IOException { return configureSocket(base.createSocket(s, host, port, autoClose)); }
    @Override public java.net.Socket createSocket() throws java.io.IOException { return configureSocket(base.createSocket()); }
    @Override public java.net.Socket createSocket(String host, int port) throws java.io.IOException { return configureSocket(base.createSocket(host, port)); }
    @Override public java.net.Socket createSocket(String host, int port, java.net.InetAddress localHost, int localPort) throws java.io.IOException { return configureSocket(base.createSocket(host, port, localHost, localPort)); }
    @Override public java.net.Socket createSocket(java.net.InetAddress host, int port) throws java.io.IOException { return configureSocket(base.createSocket(host, port)); }
    @Override public java.net.Socket createSocket(java.net.InetAddress address, int port, java.net.InetAddress localAddress, int localPort) throws java.io.IOException { return configureSocket(base.createSocket(address, port, localAddress, localPort)); }
  }
}
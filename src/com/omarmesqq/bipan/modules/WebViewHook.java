package com.omarmesqq.bipan.modules;

import android.util.Log;
import com.omarmesqq.bipan.BaseHook;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;

public class WebViewHook implements BaseHook {
  private static final String TAG = "BipanWebViewHook";

  @Override
  public void install(android.content.Context context) throws Exception {
    try {
      Class<?> factoryClass = Class.forName("android.webkit.WebViewFactory");

      // 1. Force the WebView provider to load so sProviderInstance is initialized
      Method getProviderMethod = factoryClass.getDeclaredMethod("getProvider");
      getProviderMethod.setAccessible(true);
      Object originalFactoryProvider = getProviderMethod.invoke(null);

      if (originalFactoryProvider == null) {
        Log.e(TAG, "Could not initialize WebViewFactoryProvider");
        return;
      }

      // 2. Proxy the WebViewFactoryProvider (the factory that creates WebViews)
      Object factoryProxy = Proxy.newProxyInstance(
          context.getClassLoader(),
          new Class[] { Class.forName("android.webkit.WebViewFactoryProvider") },
          new FactoryProviderHandler(originalFactoryProvider));

      // 3. Inject our proxy back into the static singleton
      Field providerField = factoryClass.getDeclaredField("sProviderInstance");
      providerField.setAccessible(true);
      providerField.set(null, factoryProxy);

      Log.i(TAG, "WebView Factory hijacked successfully. Monitoring all future WebViews.");
    } catch (Exception e) {
      Log.e(TAG, "Failed to hijack WebViewFactory", e);
    }
  }

  // This intercepts the creation of the WebView internal engine
  private static class FactoryProviderHandler implements InvocationHandler {
    private final Object originalFactory;

    public FactoryProviderHandler(Object originalFactory) {
      this.originalFactory = originalFactory;
    }

    @Override
    public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
      Object result = method.invoke(originalFactory, args);

      // When the factory creates a WebViewProvider, we wrap it!
      if (method.getName().equals("createWebView") && result != null) {
        Log.d(TAG, "A new WebView instance was just created. Injecting Proxy...");

        // 1. DYNAMIC INTERFACE DISCOVERY
        // Instead of just WebViewProvider, we take EVERY interface the original
        // implements
        Class<?>[] interfaces = result.getClass().getInterfaces();

        WebViewProviderHandler handler = new WebViewProviderHandler(result);
        Object proxyInstance = Proxy.newProxyInstance(
            result.getClass().getClassLoader(),
            interfaces, // Now includes ViewDelegate, ScrollDelegate, etc.
            handler);

        handler.setProxy(proxyInstance);
        return proxyInstance;
      }
      return result;
    }
  }

  private static class WebViewProviderHandler implements InvocationHandler {
    private final Object originalProvider;
    private Object proxyInstance; // Reference to the proxy itself

    public WebViewProviderHandler(Object originalProvider) {
      this.originalProvider = originalProvider;
    }

    // We need this to set the proxy reference after creation
    public void setProxy(Object proxy) {
      this.proxyInstance = proxy;
    }

    @Override
    public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
      String methodName = method.getName();

      // 1. LOGGING (Squelch the noisy delegates for a bit to see the real calls)
      // if (!methodName.contains("Delegate")) {
      //   Log.v(TAG, "Method called: " + methodName + " (args: " + (args != null ? args.length : 0) + ")");
      // }

      // 2. JS DETECTION (Use your improved case-insensitive logic)
      if (methodName.toLowerCase().contains("javascript")) {
        if (args != null && args.length > 0 && args[0] instanceof String) {
          Log.w(TAG, "🚨 [JS DETECTED] Method: " + methodName + " | Script: " + args[0]);
        }
      }

      // 3. URL LOADING
      if (methodName.equals("loadUrl") && args != null) {
        String url = (args[0] instanceof String) ? (String) args[0] : "unknown";
        Log.d(TAG, "App is loading URL: " + url);
      }

      // 4. THE FIX: Execute the method
      Object result;
      try {
        result = method.invoke(originalProvider, args);
      } catch (java.lang.reflect.InvocationTargetException e) {
        throw e.getCause(); // Pass through real exceptions
      }

      // 5. IDENTITY MANAGEMENT: If the original object returns itself, return the
      // proxy
      // This prevents the WebView from "escaping" the proxy during init/delegation
      if (result == originalProvider) {
        return proxyInstance;
      }

      return result;
    }
  }
}
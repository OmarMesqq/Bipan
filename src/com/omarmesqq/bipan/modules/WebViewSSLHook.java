package com.omarmesqq.bipan.modules;

import android.content.Context;
import android.net.http.SslError;
import android.util.Log;
import android.webkit.SslErrorHandler;
import android.webkit.WebView;
import com.omarmesqq.bipan.BaseHook;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;

public class WebViewSSLHook implements BaseHook {
  private static final String TAG = "BipanWebViewSSL";

  @Override
  public void install(Context context) throws Exception {
    Class<?> factoryClass = Class.forName("android.webkit.WebViewFactory");
    Method getProviderMethod = factoryClass.getDeclaredMethod("getProvider");
    getProviderMethod.setAccessible(true);
    Object factory = getProviderMethod.invoke(null);

    if (factory == null) {
      Log.w(TAG, "WebViewFactory.getProvider() returned null — WebView not loaded yet");
      return;
    }

    hookWebViewFactory(factory, factoryClass);
    Log.i(TAG, "WebViewSSLHook installed");
  }

  private void hookWebViewFactory(Object factory, Class<?> factoryClass)
      throws Exception {
    Class<?> providerClass = Class.forName(
        "android.webkit.WebViewFactoryProvider");

    Object proxy = Proxy.newProxyInstance(
        providerClass.getClassLoader(),
        new Class[] { providerClass },
        (p, method, args) -> {
          Object result = method.invoke(factory, args);
          if ("createWebView".equals(method.getName()) && result != null) {
            interceptWebViewProvider(result);
          }
          return result;
        });

    // Find and replace sProviderInstance
    Field sProviderField = null;
    for (Field f : factoryClass.getDeclaredFields()) {
      if (f.getType().equals(providerClass)) {
        sProviderField = f;
        break;
      }
    }
    if (sProviderField == null) {
      sProviderField = factoryClass.getDeclaredField("sProviderInstance");
    }
    sProviderField.setAccessible(true);
    sProviderField.set(null, proxy);
    Log.d(TAG, "sProviderInstance replaced with proxy");
  }

  private void interceptWebViewProvider(Object provider) {
    try {
      Field clientField = null;
      Class<?> clz = provider.getClass();
      while (clz != null && clientField == null) {
        try {
          clientField = clz.getDeclaredField("mWebViewClient");
        } catch (NoSuchFieldException ignored) {
          clz = clz.getSuperclass();
        }
      }

      if (clientField != null) {
        clientField.setAccessible(true);
        android.webkit.WebViewClient existing = (android.webkit.WebViewClient) clientField.get(provider);
        clientField.set(provider, wrapClient(
            existing != null
                ? existing
                : new android.webkit.WebViewClient()));
        Log.d(TAG, "Wrapped WebViewClient on: "
            + provider.getClass().getSimpleName());
      } else {
        Log.w(TAG, "mWebViewClient not found on "
            + provider.getClass().getName());
      }
    } catch (Exception e) {
      Log.e(TAG, "interceptWebViewProvider failed: " + e.getMessage());
    }
  }

  private static android.webkit.WebViewClient wrapClient(
      android.webkit.WebViewClient original) {
    return new android.webkit.WebViewClient() {
      @Override
      public void onReceivedSslError(
          WebView view,
          SslErrorHandler handler,
          SslError error) {
        Log.w(TAG, "SSL error bypassed: error="
            + error.getPrimaryError()
            + " url=" + error.getUrl());
        handler.proceed();
      }

      @Override
      public boolean shouldOverrideUrlLoading(
          WebView view,
          android.webkit.WebResourceRequest request) {
        return original.shouldOverrideUrlLoading(view, request);
      }

      @Override
      public void onPageStarted(WebView view,
          String url, android.graphics.Bitmap favicon) {
        original.onPageStarted(view, url, favicon);
      }

      @Override
      public void onPageFinished(WebView view, String url) {
        original.onPageFinished(view, url);
      }

      @Override
      public void onReceivedError(WebView view,
          android.webkit.WebResourceRequest request,
          android.webkit.WebResourceError error) {
        original.onReceivedError(view, request, error);
      }
    };
  }
}
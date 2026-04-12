package com.omarmesqq.grunfeld.utils

import android.net.http.SslError
import android.util.Log
import android.webkit.ConsoleMessage
import android.webkit.JavascriptInterface
import android.webkit.WebChromeClient
import android.webkit.WebSettings.MIXED_CONTENT_NEVER_ALLOW
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.compose.runtime.MutableState
import android.webkit.CookieManager
import android.webkit.SslErrorHandler
import android.webkit.WebStorage
import com.omarmesqq.grunfeld.BuildConfig

private const val TAG = "WebViewUtils"
private const val BRIDGE_NAME = "GrunfeldBridge"

object WebViewUtils {
    fun configureSettings(
        webView: WebView,
        canGoBack: MutableState<Boolean>,
        isLoading: MutableState<Boolean>,
        urlText: MutableState<String>
    ) {
        val cookieManager = CookieManager.getInstance()
        cookieManager.setAcceptCookie(true)
        cookieManager.setAcceptThirdPartyCookies(webView, false)

        webView.setBackgroundColor(android.graphics.Color.TRANSPARENT)
        webView.setLayerType(android.view.View.LAYER_TYPE_HARDWARE, null)

        webView.settings.apply {
            javaScriptEnabled = true
            domStorageEnabled = false
            javaScriptCanOpenWindowsAutomatically = false
            safeBrowsingEnabled = false
            allowFileAccess = false
            allowContentAccess  = false
            builtInZoomControls = false
            displayZoomControls = false
            setGeolocationEnabled(false)
            setSupportZoom(false)
            mixedContentMode = MIXED_CONTENT_NEVER_ALLOW
        }

        webView.webViewClient = object : WebViewClient() {
            override fun doUpdateVisitedHistory(view: WebView?, url: String?, isReload: Boolean) {
                super.doUpdateVisitedHistory(view, url, isReload)
                canGoBack.value = view?.canGoBack() ?: false
                url?.let { urlText.value = it }
            }
            override fun onPageStarted(view: WebView?, url: String?, favicon: android.graphics.Bitmap?) {
                super.onPageStarted(view, url, favicon)
                isLoading.value = true
                if (url != null) {
                    urlText.value = url
                }
            }
            override fun onPageFinished(view: WebView?, url: String?) {
                super.onPageFinished(view, url)
                isLoading.value = false
            }
            override fun onReceivedSslError(
                view: WebView?,
                handler: SslErrorHandler?,
                error: SslError?
            ) {
                if (BuildConfig.DEBUG) {
                    handler?.proceed()
                } else {
                    super.onReceivedSslError(view, handler, error)
                }
            }
        }

        webView.webChromeClient = object : WebChromeClient() {
            override fun onConsoleMessage(consoleMessage: ConsoleMessage?): Boolean {
                if (consoleMessage?.messageLevel() == ConsoleMessage.MessageLevel.ERROR) {
                    Log.e(TAG, "JS Console: ${consoleMessage.message()}")
                }
                return super.onConsoleMessage(consoleMessage)
            }
        }

        // webView.addJavascriptInterface(WebNativeBridge(), BRIDGE_NAME)
    }

    fun fullCleanup(webView: WebView?) {
        val cookieManager = CookieManager.getInstance()
        cookieManager.removeAllCookies { }
        WebStorage.getInstance().deleteAllData()
        webView?.apply {
            clearCache(true)
            clearHistory()
            clearFormData()
        }
    }


    /**
     * Example of Native -> Web
     */
    fun injectCustomJs(webView: WebView) {
        val js = """
            (function() {
                document.body.style.backgroundColor = 'pink';
                console.log("Injected JS from native!");
            })();
        """.trimIndent()

        webView.evaluateJavascript(js, null)
    }

    /**
     * Contains methods for
     * Web -> Native
     */
    class WebNativeBridge {
        @JavascriptInterface
        fun showLog(message: String) {
            //TODO
        }
    }
}

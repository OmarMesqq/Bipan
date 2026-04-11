package com.omarmesqq.grunfeld.utils

import android.util.Log
import android.webkit.ConsoleMessage
import android.webkit.JavascriptInterface
import android.webkit.WebChromeClient
import android.webkit.WebSettings.MIXED_CONTENT_NEVER_ALLOW
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.Toast
import androidx.compose.runtime.MutableState
import android.webkit.CookieManager
import android.webkit.WebStorage


object WebViewUtils {
    fun configureSettings(webView: WebView, canGoBack: MutableState<Boolean>) {
        val cookieManager = CookieManager.getInstance()
        cookieManager.setAcceptCookie(true)
        cookieManager.setAcceptThirdPartyCookies(webView, false)

        webView.settings.apply {
            javaScriptEnabled = true
            domStorageEnabled = true
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
            }
        }

        webView.webChromeClient = object : WebChromeClient() {
            override fun onConsoleMessage(consoleMessage: ConsoleMessage?): Boolean {
                if (consoleMessage?.messageLevel() == ConsoleMessage.MessageLevel.ERROR) {
                    Toast.makeText(webView.context, "JS Console: ${consoleMessage.message()}", Toast.LENGTH_SHORT).show()
                }
                return super.onConsoleMessage(consoleMessage)
            }
        }

        // Add a JavaScript Interface (bridge)
        // This allows JS on the webpage to call Kotlin code
        webView.addJavascriptInterface(WebAppInterface(), "AndroidBridge")
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
     * Inject custom CSS or JS after a page loads
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
     * The actual Bridge class
     */
    class WebAppInterface {
        @JavascriptInterface
        fun showLog(message: String) {
            Log.d("WebViewJS", "Message from Web: $message")
        }
    }
}

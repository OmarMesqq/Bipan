package com.omarmesqq.grunfeld.utils

import android.webkit.JavascriptInterface
import android.webkit.WebView
import android.util.Log

object WebViewUtils {
    fun configureSettings(webView: WebView) {
        webView.settings.apply {
            javaScriptEnabled = true
            domStorageEnabled = true
            allowFileAccess = false
            builtInZoomControls = false
            displayZoomControls = false
            setGeolocationEnabled(false)
        }

        // Add a JavaScript Interface (The Bridge)
        // This allows JS on the webpage to call Kotlin code
        webView.addJavascriptInterface(WebAppInterface(), "AndroidBridge")
    }

    /**
     * Inject custom CSS or JS after a page loads
     */
    fun injectCustomJs(webView: WebView) {
        val js = """
            (function() {
                document.body.style.backgroundColor = 'pink';
                console.log("JS Injected successfully");
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

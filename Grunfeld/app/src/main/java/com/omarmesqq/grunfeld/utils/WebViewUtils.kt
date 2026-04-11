package com.omarmesqq.grunfeld.utils

import android.webkit.ConsoleMessage
import android.webkit.JavascriptInterface
import android.webkit.WebChromeClient
import android.webkit.WebSettings.MIXED_CONTENT_NEVER_ALLOW
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.compose.runtime.MutableState
import android.webkit.CookieManager
import android.webkit.WebStorage
import com.omarmesqq.grunfeld.utils.UIUtils.showToastAndLog


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
                url?.let { urlText.value = it }
            }
            override fun onPageStarted(view: WebView?, url: String?, favicon: android.graphics.Bitmap?) {
                super.onPageStarted(view, url, favicon)
                isLoading.value = true // Show spinner
                if (url != null) urlText.value = url // Update bar to show real URL
            }
            override fun onPageFinished(view: WebView?, url: String?) {
                super.onPageFinished(view, url)
                isLoading.value = false // Hide spinner
            }
        }

        webView.webChromeClient = object : WebChromeClient() {
            override fun onConsoleMessage(consoleMessage: ConsoleMessage?): Boolean {
                if (consoleMessage?.messageLevel() == ConsoleMessage.MessageLevel.ERROR) {
                    showToastAndLog(webView.context, "JS Console: ${consoleMessage.message()}")
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
            //TODO
        }
    }
}

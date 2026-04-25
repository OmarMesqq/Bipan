package com.omarmesqq.grunfeld.utils

import android.net.http.SslError
import android.webkit.ConsoleMessage
import android.webkit.CookieManager
import android.webkit.SslErrorHandler
import android.webkit.WebChromeClient
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import android.webkit.WebSettings.MIXED_CONTENT_NEVER_ALLOW
import android.webkit.WebStorage
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.compose.runtime.MutableState
import com.omarmesqq.grunfeld.BuildConfig
import com.omarmesqq.grunfeld.utils.Avocado.avocadoLog

private const val TAG = "WebViewUtils"

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

                if (url != null && url.contains("deviceinfo.me")) {
                    view?.let {
                        detectAllDeviceInfoProps(it)
                    }
                }
            }
            override fun shouldInterceptRequest(
                view: WebView?,
                request: WebResourceRequest?
            ): WebResourceResponse? {
                if (view == null || request == null) {
                    return null
                }

                val url = request.url?.toString() ?: ""
                val path = request.url?.path?.lowercase() ?: ""

                if (path.contains("favicon") || path.contains("apple-touch-icon")) {
                    avocadoLog(AVOCADO_LOG_LEVEL.AVOCADO_DEBUG, TAG, "Neutering favicon/icon fetch: ${request.url}")
                    return WebResourceResponse("image/png", "UTF-8", null)
                }

                // Stop Cookie Consent banner
                if (url.contains("cookieconsent-js.js")) {
                    return WebResourceResponse("text/plain", "utf-8", null)
                }
                return null
            }
            override fun onReceivedSslError(
                view: WebView?,
                handler: SslErrorHandler?,
                error: SslError?
            ) {
                if (BuildConfig.DEBUG) {
                    avocadoLog(AVOCADO_LOG_LEVEL.AVOCADO_ERROR, TAG, "onReceivedSslError: $error")
                     handler?.proceed()
                } else {
                    super.onReceivedSslError(view, handler, error)
                }
            }
        }

        webView.webChromeClient = object : WebChromeClient() {
            override fun onConsoleMessage(consoleMessage: ConsoleMessage?): Boolean {
                avocadoLog(AVOCADO_LOG_LEVEL.AVOCADO_DEBUG, TAG, "JS Console: ${consoleMessage?.message()}")
                return super.onConsoleMessage(consoleMessage)
            }
        }
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


    private fun detectAllDeviceInfoProps(webView: WebView) {
        val js = """
    (function() {
        // rrhdi: Detect all button
        // vfofc: Device Motion (Live) button
        // ittay: Device Orientation (Live) button
        
        var idsToClick = ['rrhdi', 'ittay', 'vfofc'];
        var targetToScroll = null;

        idsToClick.forEach(function(id) {
            var el = document.getElementById(id);
            if (el) {
                el.click();
                if (id === 'ittay' || id === 'vfofc') {
                    targetToScroll = el;
                }
            }
        });

        // Wait for a while to allow DOM to reload
        if (targetToScroll) {
            setTimeout(function() {
                targetToScroll.scrollIntoView({ 
                    behavior: 'smooth', 
                    block: 'center' 
                });
            }, 2500);
        }
    })();
    """.trimIndent()

        webView.evaluateJavascript(js) { result ->
            avocadoLog(AVOCADO_LOG_LEVEL.AVOCADO_DEBUG, TAG, "detectAllDeviceInfoProps injection worked. Res: $result")
        }
    }
}

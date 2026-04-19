package com.omarmesqq.grunfeld.utils

import android.net.http.SslError
import android.webkit.ConsoleMessage
import android.webkit.JavascriptInterface
import android.webkit.WebChromeClient
import android.webkit.WebSettings.MIXED_CONTENT_NEVER_ALLOW
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.compose.runtime.MutableState
import android.webkit.CookieManager
import android.webkit.SslErrorHandler
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import android.webkit.WebStorage
import com.omarmesqq.grunfeld.BuildConfig
import com.omarmesqq.grunfeld.utils.Avocado.avocadoLog
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlin.Throwable

private const val TAG = "WebViewUtils"
private const val BRIDGE_NAME = "GrunfeldBridge"

object WebViewUtils {
    private lateinit var trueUserAgent: String
    private val spoofedUserAgent = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_3_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Mobile/15E148 Safari/604.1"
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
            blockNetworkLoads = true
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
            trueUserAgent = userAgentString
        }

        // Native-JS Bridge for monkey patching
        webView.addJavascriptInterface(GrunfeldWebNativeIface(webView, urlText, trueUserAgent), BRIDGE_NAME)

        webView.webViewClient = object : WebViewClient() {
            override fun doUpdateVisitedHistory(view: WebView?, url: String?, isReload: Boolean) {
                super.doUpdateVisitedHistory(view, url, isReload)
                canGoBack.value = view?.canGoBack() ?: false
                url?.let { urlText.value = it }
            }
            override fun onPageStarted(view: WebView?, url: String?, favicon: android.graphics.Bitmap?) {
                super.onPageStarted(view, url, favicon)
                // Inject JS at every page load
                view?.evaluateJavascript(getMonkeyPatchJS(), null)
                isLoading.value = true
                if (url != null) {
                    urlText.value = url
                }
            }
            override fun onPageFinished(view: WebView?, url: String?) {
                super.onPageFinished(view, url)
                isLoading.value = false

                if (url != null && url.contains("deviceinfo.me")) {
                    view?.let { detectAllDeviceInfoProps(it) }
                }
            }
            override fun shouldInterceptRequest(
                view: WebView?,
                request: WebResourceRequest?
            ): WebResourceResponse? {
                if (view == null || request == null) return null

                val url = request.url?.toString() ?: ""
                val path = request.url?.path?.lowercase() ?: ""

                if (path.contains("favicon") || path.contains("apple-touch-icon")) {
                    avocadoLog(AVOCADO_LOG_LEVEL.AVOCADO_DEBUG, TAG, "Neutering favicon/icon fetch: ${request.url}")
                    return WebResourceResponse("image/png", "UTF-8", null)
                }

                val bodyMethods = listOf("POST", "PUT", "PATCH", "DELETE")
                if (request.method?.uppercase() in bodyMethods) {
                    avocadoLog(AVOCADO_LOG_LEVEL.AVOCADO_ERROR, TAG, "Blocked native ${request.method} leak to ${request.url}", shouldToast = true)
                    return WebResourceResponse("text/plain", "UTF-8", 405, "Method Not Allowed", null, "".byteInputStream())
                }

                // Stop Cookie Consent banner
                if (url.contains("cookieconsent-js.js")) {
                    return WebResourceResponse("text/plain", "utf-8", null)
                }
                return Icarus.handleRequest(view.context, request, urlText.value, trueUserAgent)
            }
            override fun onReceivedSslError(
                view: WebView?,
                handler: SslErrorHandler?,
                error: SslError?
            ) {
                if (BuildConfig.DEBUG) {
                    avocadoLog(AVOCADO_LOG_LEVEL.AVOCADO_ERROR, TAG, "onReceivedSslError: $error", shouldToast = true)
                    // handler?.proceed()
                    throw Throwable()
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

    private fun getMonkeyPatchJS(): String {
        return """
    (function() {
        if (window.bridgeInitialized) return;
        window.bridgeInitialized = true;
        window.grunfeldCallbacks = {};
        let requestId = 0;

        const b64DecodeUnicode = (str) => {
            return decodeURIComponent(atob(str).split('').map(function(c) {
                return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
            }).join(''));
        };

        const bodyVerbs = ['POST', 'PUT', 'PATCH', 'DELETE'];

        // 1. Hook Forms
        const originalSubmit = HTMLFormElement.prototype.submit;
        HTMLFormElement.prototype.submit = function() {
            const method = this.method.toUpperCase();
            if (bodyVerbs.includes(method)) {
                const params = new URLSearchParams(new FormData(this)).toString();
                GrunfeldBridge.performInterceptedRequest(this.action, params, "application/x-www-form-urlencoded", true, -1, method);
                return;
            }
            originalSubmit.apply(this, arguments);
        };

        // 2. Hook Fetch
        const originalFetch = window.fetch;
        window.fetch = function(input, init) {
            const method = (init && init.method) ? init.method.toUpperCase() : 'GET';
            if (bodyVerbs.includes(method)) {
                const id = requestId++;
                const url = (typeof input === 'string') ? input : input.url;
                return new Promise((resolve) => {
                    window.grunfeldCallbacks[id] = (respB64) => {
                        const decoded = b64DecodeUnicode(respB64);
                        resolve(new Response(decoded, { status: 200 }));
                    };
                    GrunfeldBridge.performInterceptedRequest(url, init.body || "", init.headers && init.headers['Content-Type'] ? init.headers['Content-Type'] : "", false, id, method);
                });
            }
            return originalFetch.apply(this, arguments);
        };

        // 3. Hook XMLHttpRequest
        const XHR = XMLHttpRequest.prototype;
        const send = XHR.send;
        const open = XHR.open;

        XHR.open = function(method, url) {
            this._method = method.toUpperCase();
            this._url = url;
            return open.apply(this, arguments);
        };

        XHR.send = function(data) {
            if (bodyVerbs.includes(this._method)) {
                const id = requestId++;
                window.grunfeldCallbacks[id] = (respB64) => {
                    const decoded = b64DecodeUnicode(respB64);
                    Object.defineProperty(this, 'readyState', { value: 4 });
                    Object.defineProperty(this, 'status', { value: 200 });
                    Object.defineProperty(this, 'responseText', { value: decoded });
                    Object.defineProperty(this, 'response', { value: decoded });
                    if (typeof this.onreadystatechange === 'function') this.onreadystatechange();
                    if (typeof this.onload === 'function') this.onload();
                };
                // XHR doesn't expose Content-Type easily before send, default to empty or extract if needed.
                GrunfeldBridge.performInterceptedRequest(this._url, data || "", "", false, id, this._method);
                return;
            }
            return send.apply(this, arguments);
        };

        // Kotlin calls this
        window.grunfeldResolve = function(id, dataB64) {
            if (window.grunfeldCallbacks[id]) {
                window.grunfeldCallbacks[id](dataB64);
                delete window.grunfeldCallbacks[id];
            }
        };
    })();
    """.trimIndent()
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
            avocadoLog(AVOCADO_LOG_LEVEL.AVOCADO_DEBUG, TAG, "JS Injection worked. Res: $result")
        }
    }

    private class GrunfeldWebNativeIface(
        private val webView: WebView,
        private val currentUrlState: MutableState<String>,
        private val userAgent: String
    ) {
        @JavascriptInterface
        fun performInterceptedRequest(
            url: String,
            body: String,
            contentType: String,
            isNavigation: Boolean,
            callbackId: Int,
            method: String
        ) {
            CoroutineScope(Dispatchers.IO).launch {
                val allowedHost = currentUrlState.value
                val responseData = Icarus.executeManualBodyRequest(url, body, contentType, allowedHost, method, userAgent)

                val base64Data = android.util.Base64.encodeToString(
                    responseData?.toByteArray(Charsets.UTF_8),
                    android.util.Base64.NO_WRAP
                ) ?: ""

                withContext(Dispatchers.Main) {
                    if (isNavigation) {
                        webView.loadDataWithBaseURL(url, base64Data, "text/html", "base64", url)
                    } else {
                        webView.evaluateJavascript(
                            "window.grunfeldResolve($callbackId, '$base64Data')",
                            null
                        )
                    }
                }
            }
        }
    }
}

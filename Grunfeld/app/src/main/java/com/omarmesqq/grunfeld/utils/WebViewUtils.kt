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
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import android.webkit.WebStorage
import com.omarmesqq.grunfeld.BuildConfig
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlin.Throwable

private const val TAG = "WebViewUtils"
private const val BRIDGE_NAME = "GrunfeldBridge"

object WebViewUtils {
    fun configureSettings(
        webView: WebView,
        canGoBack: MutableState<Boolean>,
        isLoading: MutableState<Boolean>,
        urlText: MutableState<String>
    ) {
        webView.addJavascriptInterface(GrunfeldWebNativeIface(webView, urlText.value), BRIDGE_NAME)
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
                view?.evaluateJavascript(getPostInterceptionJs(), null)
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
                if (request.url?.path?.endsWith("favicon.ico") == true) {
                    return WebResourceResponse("image/x-icon", "UTF-8", null)
                }

                if (request.method == "POST") {
                    return WebResourceResponse("text/plain", "UTF-8", 405, "Method Not Allowed", null, "".byteInputStream())
                }

                // Stop Cookie Consent banner
                if (url.contains("cookieconsent-js.js")) {
                    return WebResourceResponse("text/plain", "utf-8", null)
                }

                return Icarus.handleRequest(view.context, request)
            }
            override fun onReceivedSslError(
                view: WebView?,
                handler: SslErrorHandler?,
                error: SslError?
            ) {
                if (BuildConfig.DEBUG) {
                    Log.e(TAG, "onReceivedSslError: $error")
                    // handler?.proceed()
                    throw Throwable()
                } else {
                    super.onReceivedSslError(view, handler, error)
                }
            }
        }

        webView.webChromeClient = object : WebChromeClient() {
            override fun onConsoleMessage(consoleMessage: ConsoleMessage?): Boolean {
                Log.d(TAG, "JS Console: ${consoleMessage?.message()}")
                return super.onConsoleMessage(consoleMessage)
            }
        }
    }

    private fun getPostInterceptionJs(): String {
        return """
    (function() {
        if (window.bridgeInitialized) return;
        window.bridgeInitialized = true;
        window.grunfeldCallbacks = {};
        let requestId = 0;

        // Helper to decode UTF-8 Base64 accurately
        const b64DecodeUnicode = (str) => {
            return decodeURIComponent(atob(str).split('').map(function(c) {
                return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
            }).join(''));
        };

        // 1. Hook Forms
        const originalSubmit = HTMLFormElement.prototype.submit;
        HTMLFormElement.prototype.submit = function() {
            if (this.method.toLowerCase() === 'post') {
                const params = new URLSearchParams(new FormData(this)).toString();
                GrunfeldBridge.performInterceptedPost(this.action, params, "application/x-www-form-urlencoded", true, -1);
                return;
            }
            originalSubmit.apply(this, arguments);
        };

        // 2. Hook Fetch
        const originalFetch = window.fetch;
        window.fetch = function(input, init) {
            if (init && init.method && init.method.toUpperCase() === 'POST') {
                const id = requestId++;
                const url = (typeof input === 'string') ? input : input.url;
                return new Promise((resolve) => {
                    window.grunfeldCallbacks[id] = (respB64) => {
                        const decoded = b64DecodeUnicode(respB64);
                        resolve(new Response(decoded, { status: 200 }));
                    };
                    GrunfeldBridge.performInterceptedPost(url, init.body || "", init.headers['Content-Type'] || "", false, id);
                });
            }
            return originalFetch.apply(this, arguments);
        };

        // 3. Hook XMLHttpRequest
        const XHR = XMLHttpRequest.prototype;
        const send = XHR.send;
        const open = XHR.open;

        XHR.open = function(method, url) {
            this._method = method;
            this._url = url;
            return open.apply(this, arguments);
        };

        XHR.send = function(data) {
            if (this._method === 'POST') {
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
                GrunfeldBridge.performInterceptedPost(this._url, data || "", "", false, id);
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


    fun detectAllDeviceInfoProps(webView: WebView) {
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
            Log.d(TAG, "JS Injection worked. Res: $result")
        }
    }

    class GrunfeldWebNativeIface(private val webView: WebView, private val allowedHost: String) {
        @JavascriptInterface
        fun performInterceptedPost(
            url: String,
            body: String,
            contentType: String,
            isNavigation: Boolean,
            callbackId: Int
        ) {
            CoroutineScope(Dispatchers.IO).launch {
                val responseData = Icarus.executeManualPost(url, body, contentType, allowedHost)

                // Encode to Base64 (Using NO_WRAP to keep it in one line for JS)
                val base64Data = android.util.Base64.encodeToString(
                    responseData?.toByteArray(Charsets.UTF_8),
                    android.util.Base64.NO_WRAP
                ) ?: ""

                withContext(Dispatchers.Main) {
                    if (isNavigation) {
                        // Full Page Navigation (Base64 is native to loadDataWithBaseURL)
                        webView.loadDataWithBaseURL(url, base64Data, "text/html", "base64", url)
                    } else {
                        // Background AJAX (Return encoded string to our JS decoder)
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

package com.omarmesqq.grunfeld.viewmodel

import android.annotation.SuppressLint
import android.content.Context
import android.graphics.Bitmap
import android.view.ViewGroup
import android.webkit.ConsoleMessage
import android.webkit.CookieManager
import android.webkit.RenderProcessGoneDetail
import android.webkit.WebChromeClient
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import android.webkit.WebSettings.LOAD_CACHE_ELSE_NETWORK
import android.webkit.WebSettings.LOAD_CACHE_ONLY
import android.webkit.WebSettings.MENU_ITEM_PROCESS_TEXT
import android.webkit.WebSettings.MIXED_CONTENT_NEVER_ALLOW
import android.webkit.WebStorage
import android.webkit.WebView
import android.webkit.WebView.RENDERER_PRIORITY_BOUND
import android.webkit.WebView.clearClientCertPreferences
import android.webkit.WebView.setWebContentsDebuggingEnabled
import android.webkit.WebViewClient
import android.webkit.WebViewDatabase
import androidx.compose.runtime.MutableState
import androidx.compose.runtime.mutableStateOf
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.ViewModel
import androidx.webkit.ServiceWorkerControllerCompat
import androidx.webkit.WebSettingsCompat
import androidx.webkit.WebViewFeature
import androidx.webkit.WebViewFeature.SERVICE_WORKER_BASIC_USAGE
import androidx.webkit.WebViewFeature.isFeatureSupported
import com.omarmesqq.grunfeld.BuildConfig
import com.omarmesqq.grunfeld.utils.AVOCADO_LOG_LEVEL
import com.omarmesqq.grunfeld.utils.Avocado.avocadoLog
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

private const val TAG = "WebViewModel"
class WebViewModel : ViewModel() {
    private val initialUrl = "about:blank"
    private val userAgent = "Grunfeld/${BuildConfig.VERSION_NAME}"
    var webView: WebView? = null

    // UI States
    var canGoBack = mutableStateOf(false)
    var isLoading = mutableStateOf(true)
    var urlText = mutableStateOf(initialUrl)
    var currLifecycleState = Lifecycle.State.DESTROYED
    var isCurrentlyInDarkTheme = false
    var isWebViewPendingRecovery = false
    fun getOrCreateWebView(context: Context): WebView? {
        if (webView == null) {
            webView = WebView(context).apply {
                layoutParams = ViewGroup.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.MATCH_PARENT
                )
            }
            configureSettings(canGoBack, isLoading, urlText)
            webView?.loadUrl(urlText.value)
        }
        return webView
    }

    fun navigateToUrl(url: String) {
        val formattedUrl = if (url.startsWith("http://") || url.startsWith("https://")) {
            url
        } else {
            "https://$url"
        }
        urlText.value = formattedUrl
        webView?.loadUrl(formattedUrl)
    }

    fun clearAndReset() {
        avocadoLog(AVOCADO_LOG_LEVEL.AVOCADO_DEBUG, TAG, "Cleared all site data!", shouldToast = true)
        fullCleanup(webView)
        urlText.value = initialUrl
        webView?.loadUrl(initialUrl)
    }

    // https://developer.android.com/guide/components/activities/activity-lifecycle

    fun wvmOnStop() {
        webView?.apply {
            setNetworkAvailable(false)
            stopLoading()
            onPause()
            pauseTimers()
        }
    }

    fun wvmOnPause() {
        webView?.apply {
            setNetworkAvailable(false)
            onPause()
            pauseTimers()
        }
    }

    fun wvmOnResume() {
        currLifecycleState = Lifecycle.State.RESUMED
        webView?.apply {
            setNetworkAvailable(true)
            reload() // causes full refresh, maybe unnecessary
            onResume()
            resumeTimers()
        }
    }

    override fun onCleared() {
        super.onCleared()
        fullCleanup(webView)
        webView?.apply {
            (parent as? ViewGroup)?.removeView(this)
            removeAllViews()
            destroy()
        }
        webView = null
        avocadoLog(AVOCADO_LOG_LEVEL.AVOCADO_DEBUG, TAG, "onCleared: destroyed WebView")
    }

    private fun configureSettings(
        canGoBack: MutableState<Boolean>,
        isLoading: MutableState<Boolean>,
        urlText: MutableState<String>
    ) {
        if (BuildConfig.DEBUG) {
            setWebContentsDebuggingEnabled(true)
        } else {
            setWebContentsDebuggingEnabled(false)
        }

        val cookieManager = CookieManager.getInstance()
        cookieManager.setAcceptCookie(true)
        cookieManager.setAcceptThirdPartyCookies(webView, false)

        webView?.setBackgroundColor(android.graphics.Color.TRANSPARENT)
        webView?.setLayerType(android.view.View.LAYER_TYPE_HARDWARE, null)
        webView?.setRendererPriorityPolicy(RENDERER_PRIORITY_BOUND, false)


        if (isFeatureSupported(SERVICE_WORKER_BASIC_USAGE)) {
            @SuppressLint("RequiresFeature")
            ServiceWorkerControllerCompat.getInstance().serviceWorkerWebSettings.apply {
                blockNetworkLoads = true
                cacheMode = LOAD_CACHE_ONLY
                allowFileAccess = false
                allowContentAccess = false
            }
        }

        webView!!.settings.apply {
            javaScriptEnabled = true
            isAlgorithmicDarkeningAllowed = true
            domStorageEnabled = false
            javaScriptCanOpenWindowsAutomatically = false
            safeBrowsingEnabled = false
            allowFileAccess = false
            allowContentAccess = false
            builtInZoomControls = false
            displayZoomControls = false
            setGeolocationEnabled(false)
            setSupportZoom(false)
            mixedContentMode = MIXED_CONTENT_NEVER_ALLOW
            userAgentString = userAgent
            offscreenPreRaster = false
            disabledActionModeMenuItems = MENU_ITEM_PROCESS_TEXT
            cacheMode = LOAD_CACHE_ELSE_NETWORK

            if (isFeatureSupported(WebViewFeature.SAFE_BROWSING_ENABLE)) {
                WebSettingsCompat.setSafeBrowsingEnabled(this, false)
            }

            if (isFeatureSupported(WebViewFeature.DOWNLOAD_FAVICONS_ENABLED)) {
                WebSettingsCompat.setDownloadFaviconsEnabled(this, false)
            }

            saveFormData = false
            databaseEnabled = false
            allowUniversalAccessFromFileURLs = false
            allowFileAccessFromFileURLs = false
        }

        webView?.webViewClient = object : WebViewClient() {
            override fun onRenderProcessGone(view: WebView, detail: RenderProcessGoneDetail): Boolean {
                if (detail.didCrash()) {
                    avocadoLog(AVOCADO_LOG_LEVEL.AVOCADO_ERROR, TAG, "onRenderProcessGone: WebView crashed!", shouldToast = true)
                } else {
                    avocadoLog(AVOCADO_LOG_LEVEL.AVOCADO_ERROR, TAG, "onRenderProcessGone: WebView killed to reclaim memory", shouldToast = true)
                }
                webView?.apply {
                    (parent as? ViewGroup)?.removeView(this)
                    removeAllViews()
                    destroy()
                }
                webView = null

                if (currLifecycleState.isAtLeast(Lifecycle.State.RESUMED)) {
                    avocadoLog(AVOCADO_LOG_LEVEL.AVOCADO_DEBUG, TAG, "onRenderProcessGone: Activity in foreground. Starting WebView recovery!")
                } else {
                    avocadoLog(AVOCADO_LOG_LEVEL.AVOCADO_DEBUG, TAG, "onRenderProcessGone: Activity in background. Postponing recovery until user returns")
                    isWebViewPendingRecovery = true
                }
                return true
            }

            override fun doUpdateVisitedHistory(view: WebView?, url: String?, isReload: Boolean) {
                super.doUpdateVisitedHistory(view, url, isReload)
                canGoBack.value = view?.canGoBack() ?: false
                url?.let { urlText.value = it }
            }

            override fun onPageStarted(
                view: WebView?,
                url: String?,
                favicon: Bitmap?
            ) {
                super.onPageStarted(view, url, favicon)
                isLoading.value = true

                if (url != null && url != initialUrl) {
                    if (isCurrentlyInDarkTheme) {
                        view?.let {
                            injectDark(it)
                        }
                    }
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

                // Stop favicons
                if (path.contains("favicon") || path.contains("apple-touch-icon")) {
                    avocadoLog(
                        AVOCADO_LOG_LEVEL.AVOCADO_DEBUG,
                        TAG,
                        "Neutering favicon request: ${request.url}"
                    )
                    return WebResourceResponse("image/png", "UTF-8", null)
                }

                // Stop Cookie Consent banner from deviceinfo[.].me
                if (url.contains("cookieconsent-js.js")) {
                    return WebResourceResponse("text/plain", "utf-8", null)
                }

                return null
            }
        }

        webView?.webChromeClient = object : WebChromeClient() {
            override fun onConsoleMessage(consoleMessage: ConsoleMessage?): Boolean {
                val formattedMsg = StringBuilder()

                formattedMsg.appendLine("===== [JS Console] =====")
                formattedMsg.appendLine("Message: ${consoleMessage?.message()}")
                formattedMsg.appendLine("Source file:${consoleMessage?.sourceId()}")
                formattedMsg.appendLine("===== [JS Console] =====")

                avocadoLog(AVOCADO_LOG_LEVEL.AVOCADO_DEBUG,
                    TAG,
                    formattedMsg.toString()
                )
                return super.onConsoleMessage(consoleMessage)
            }
        }
    }

    fun fullCleanup(webView: WebView?) {
        webView?.apply {
            setNetworkAvailable(false)

            clearCache(true)
            clearHistory()
            clearFormData()
            clearSslPreferences()
            clearMatches()

            clearClientCertPreferences(null)
            CoroutineScope(Dispatchers.IO).launch {
                WebViewDatabase.getInstance(webView.context).clearHttpAuthUsernamePassword()
            }
        }

        val cookieManager = CookieManager.getInstance()
        cookieManager.removeAllCookies(null)
        cookieManager.flush() // Force disk sync
        WebStorage.getInstance().deleteAllData()
    }


    // Auto click detect all and scroll to sensors sections in deviceinfo[.].me
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

        webView.evaluateJavascript(js) { res ->
            if (res != null && res != "null") {
                avocadoLog(AVOCADO_LOG_LEVEL.AVOCADO_WARNING, TAG,"Deviceinfo injection returned non null: $res")
            }
        }
    }


    private fun injectDark(webView: WebView) {
        val js = """
            (function() {
              const originalMatchMedia = window.matchMedia;
              window.matchMedia = function(query) {
                if (query.includes('prefers-color-scheme: dark')) {
                  return {
                    matches: true,
                    media: query,
                    onchange: null,
                    addListener: function() {},
                    removeListener: function() {},
                    addEventListener: function() {},
                    removeEventListener: function() {},
                    dispatchEvent: function() { return true; }
                  };
                }
                if (query.includes('prefers-color-scheme: light')) {
                  return {
                    matches: false,
                    media: query,
                    onchange: null,
                    addListener: function() {},
                    removeListener: function() {},
                    addEventListener: function() {},
                    removeEventListener: function() {},
                    dispatchEvent: function() { return true; }
                  };
                }
                return originalMatchMedia.call(window, query);
              };
            })();
            """.trimIndent()

        webView.evaluateJavascript(js) { res ->
            if (res != null && res != "null") {
                avocadoLog(AVOCADO_LOG_LEVEL.AVOCADO_WARNING, TAG,"Dark theme injection returned non null: $res")
            }
        }
    }
}
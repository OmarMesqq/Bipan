package com.omarmesqq.grunfeld.viewmodel

import android.content.Context
import android.view.ViewGroup
import android.webkit.WebView
import androidx.compose.runtime.mutableStateOf
import androidx.lifecycle.ViewModel
import com.omarmesqq.grunfeld.utils.AVOCADO_LOG_LEVEL
import com.omarmesqq.grunfeld.utils.Avocado.avocadoLog
import com.omarmesqq.grunfeld.utils.WebViewUtils

private const val TAG = "WebViewModel"
class WebViewModel : ViewModel() {
    var webView: WebView? = null

    // UI States
    var canGoBack = mutableStateOf(false)
    var isLoading = mutableStateOf(true)
    var urlText = mutableStateOf("https://httpbin.org")
    fun getOrCreateWebView(context: Context): WebView? {
        if (webView == null) {
            webView = WebView(context.applicationContext).apply {
                layoutParams = ViewGroup.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.MATCH_PARENT
                )

                WebViewUtils.configureSettings(this, canGoBack, isLoading, urlText)

                loadUrl(urlText.value)
            }
        }
        return webView
    }

    fun navigateToUrl(url: String) {
        urlText.value = url
        webView?.loadUrl(url)
    }

    fun clearAndReset() {
        avocadoLog(AVOCADO_LOG_LEVEL.AVOCADO_DEBUG, TAG, "clearAndReset")
        WebViewUtils.fullCleanup(webView)
        urlText.value = "about:blank"
        webView?.loadUrl("about:blank")
    }

    override fun onCleared() {
        super.onCleared()
        WebViewUtils.fullCleanup(webView)
        webView?.apply {
            stopLoading()
            (parent as? ViewGroup)?.removeView(this)
            removeAllViews()
            destroy()
        }
        webView = null
        avocadoLog(AVOCADO_LOG_LEVEL.AVOCADO_WARNING, TAG, "onCleared: automatically destroyed WebView")
    }
}
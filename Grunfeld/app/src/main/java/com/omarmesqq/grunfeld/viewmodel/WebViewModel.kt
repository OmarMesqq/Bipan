package com.omarmesqq.grunfeld.viewmodel

import android.content.Context
import android.view.ViewGroup
import android.webkit.WebView
import androidx.compose.runtime.mutableStateOf
import androidx.lifecycle.ViewModel
import com.omarmesqq.grunfeld.utils.WebViewUtils

/**
 * Stores the WebView in Application Context
 * to avoid reloading the page when switching tabs
 */
class WebViewModel : ViewModel() {
    var webView: WebView? = null

    // We use this to tell the BackHandler if it should intercept
    var canGoBack = mutableStateOf(false)

    fun getOrCreateWebView(context: Context, url: String): WebView? {
        if (webView == null) {
            webView = WebView(context.applicationContext).apply {
                layoutParams = ViewGroup.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.MATCH_PARENT
                )

                WebViewUtils.configureSettings(this, canGoBack)

                loadUrl(url)
            }
        }
        return webView
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
    }
}
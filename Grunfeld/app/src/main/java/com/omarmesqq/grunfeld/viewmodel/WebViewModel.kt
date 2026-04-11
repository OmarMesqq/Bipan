package com.omarmesqq.grunfeld.viewmodel

import android.content.Context
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.compose.runtime.mutableStateOf
import androidx.lifecycle.ViewModel
import com.omarmesqq.grunfeld.utils.WebViewUtils

/**
 * Stores the WebView to avoid reloading the page
 * TODO: this probably leaks memory
 */
class WebViewModel : ViewModel() {
    var webView: WebView? = null

    // We use this to tell the BackHandler if it should intercept
    var canGoBack = mutableStateOf(false)

    fun getOrCreateWebView(context: Context, url: String): WebView? {
        if (webView == null) {
            webView = WebView(context).apply {
                WebViewUtils.configureSettings(this)
                webViewClient = object : WebViewClient() {
                    override fun doUpdateVisitedHistory(view: WebView?, url: String?, isReload: Boolean) {
                        super.doUpdateVisitedHistory(view, url, isReload)
                        // Update the Compose state so BackHandler knows to activate
                        canGoBack.value = view?.canGoBack() ?: false
                    }
                }
                loadUrl(url)
            }
        }
        return webView
    }
}
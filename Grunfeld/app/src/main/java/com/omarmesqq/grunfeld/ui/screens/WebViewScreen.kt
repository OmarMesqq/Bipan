package com.omarmesqq.grunfeld.ui.screens

import android.view.ViewGroup
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.viewinterop.AndroidView
import androidx.lifecycle.viewmodel.compose.viewModel
import com.omarmesqq.grunfeld.viewmodel.WebViewModel

@Composable
fun WebViewScreen(url: String, webViewModel: WebViewModel = viewModel()) {
    val context = LocalContext.current
    val webView = webViewModel.getOrCreateWebView(context, url)

    BackHandler(enabled = true) {
        webView?.goBack()
    }

    if (webView != null) {
        AndroidView(
            factory = {
                (webView.parent as? ViewGroup)?.removeView(webView)
                webView
            },
            modifier = Modifier.fillMaxSize()
        )
    } else {
        Box(
            modifier = Modifier.fillMaxSize(),
            contentAlignment = Alignment.Center
        ) {
            Text("Failed to initialize WebView", color = MaterialTheme.colorScheme.error)
        }
    }
}

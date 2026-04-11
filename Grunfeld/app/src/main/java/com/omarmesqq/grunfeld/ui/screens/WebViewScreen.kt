package com.omarmesqq.grunfeld.ui.screens

import android.view.ViewGroup
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.lifecycle.viewmodel.compose.viewModel
import com.omarmesqq.grunfeld.viewmodel.WebViewModel
import androidx.compose.ui.text.input.ImeAction

@Composable
fun WebViewScreen(webViewModel: WebViewModel = viewModel()) {
    val context = LocalContext.current
    val webView = webViewModel.getOrCreateWebView(context)
    val isLoading by webViewModel.isLoading
    val urlText by webViewModel.urlText

    BackHandler(enabled = true) {
        webView?.goBack()
    }

    if (webView != null) {
        Column(modifier = Modifier
            .fillMaxSize()
            .background(MaterialTheme.colorScheme.surface)
        ) {
            // --- 1. SEARCH BAR (Native) ---
            OutlinedTextField(
                value = urlText,
                onValueChange = { webViewModel.urlText.value = it },
                modifier = Modifier.fillMaxWidth().padding(8.dp),
                label = { Text("Search or type URL") },
                singleLine = true,
                keyboardOptions = KeyboardOptions(imeAction = ImeAction.Search),
                keyboardActions = KeyboardActions(onSearch = { webViewModel.navigateToUrl(urlText) })
            )

            // --- 2. WEBVIEW CONTAINER ---
            Box(
                modifier = Modifier
                    .fillMaxWidth()
            ) {

                    AndroidView(
                        factory = {
                            // Re-parenting logic
                            (webView.parent as? ViewGroup)?.removeView(webView)
                            webView
                        },
                        modifier = Modifier.fillMaxSize()
                    )


                if (isLoading) {
                    LinearProgressIndicator(
                        modifier = Modifier.fillMaxWidth().align(Alignment.TopCenter),
                        color = MaterialTheme.colorScheme.primary,
                        trackColor = MaterialTheme.colorScheme.surfaceVariant
                    )
                }
            }
        }
    } else {
        Box(
            modifier = Modifier.fillMaxSize(),
            contentAlignment = Alignment.Center
        ) {
            Text("Failed to initialize WebView", color = MaterialTheme.colorScheme.error)
        }
    }
}

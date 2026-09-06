package com.omarmesqq.grunfeld.ui.screens

import android.view.ViewGroup
import android.webkit.WebView
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.MenuAnchorType.Companion.PrimaryEditable
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.platform.LocalSoftwareKeyboardController
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LifecycleEventEffect
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.viewmodel.compose.viewModel
import com.omarmesqq.grunfeld.utils.AVOCADO_LOG_LEVEL
import com.omarmesqq.grunfeld.utils.Avocado.avocadoLog
import com.omarmesqq.grunfeld.viewmodel.WebViewModel
import java.lang.ref.WeakReference

private const val TAG = "WebviewScreen"

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun WebviewScreen(wvVM: WebViewModel = viewModel()) {
    val context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current

    var wvWeakRef: WeakReference<WebView> = WeakReference(wvVM.getOrCreateWebView(context))
    var webView: WebView? = wvWeakRef.get()
    avocadoLog(AVOCADO_LOG_LEVEL.AVOCADO_DEBUG, TAG, "WV at top: ${webView.hashCode()}")

    val isDark = isSystemInDarkTheme()
    val isDarkPersist = remember { mutableStateOf(isDark) }

    LifecycleEventEffect(Lifecycle.Event.ON_CREATE) {
        avocadoLog(AVOCADO_LOG_LEVEL.AVOCADO_DEBUG, TAG, "ON_CREATE")
        updateWebViewViewModel(wvVM, Lifecycle.State.CREATED, isDarkPersist.value)
        wvVM.wvmOnPause()
    }

    LifecycleEventEffect(Lifecycle.Event.ON_START) {
        avocadoLog(AVOCADO_LOG_LEVEL.AVOCADO_DEBUG, TAG, "ON_START")
        updateWebViewViewModel(wvVM, Lifecycle.State.STARTED, isDarkPersist.value)
        wvVM.wvmOnPause()
    }

    LifecycleEventEffect(Lifecycle.Event.ON_RESUME) {
        avocadoLog(AVOCADO_LOG_LEVEL.AVOCADO_DEBUG, TAG, "ON_RESUME")
        updateWebViewViewModel(wvVM, Lifecycle.State.RESUMED, isDarkPersist.value)
        wvVM.wvmOnResume()
    }

    LifecycleEventEffect(Lifecycle.Event.ON_PAUSE) {
        avocadoLog(AVOCADO_LOG_LEVEL.AVOCADO_DEBUG, TAG, "ON_PAUSE")
        updateWebViewViewModel(wvVM, Lifecycle.State.STARTED, isDarkPersist.value)
        wvVM.wvmOnPause()
    }
    LifecycleEventEffect(Lifecycle.Event.ON_STOP) {
        avocadoLog(AVOCADO_LOG_LEVEL.AVOCADO_DEBUG, TAG, "ON_STOP")
        updateWebViewViewModel(wvVM, Lifecycle.State.CREATED, isDarkPersist.value)
        wvVM.wvmOnStop()
    }

    LifecycleEventEffect(Lifecycle.Event.ON_ANY) {
        val currentState = lifecycleOwner.lifecycle.currentState

        if (currentState.isAtLeast(Lifecycle.State.RESUMED) && wvVM.isWebViewPendingRecovery) {
            wvWeakRef = WeakReference(wvVM.getOrCreateWebView(context))
            webView = wvWeakRef.get()
            wvVM.isWebViewPendingRecovery = false
        }
    }


    val keyboardController = LocalSoftwareKeyboardController.current
    val focusManager = LocalFocusManager.current

    val isLoading by wvVM.isLoading
    val urlText by wvVM.urlText

    // Dropdown State
    var expanded by remember { mutableStateOf(false) }
    val predefinedSites = listOf(
        "https://i2dk.com/",
        "https://start.duckduckgo.com/",
        "https://deviceinfo.me/",
        "https://browserleaks.com/",
        "https://panopticlick.org",
        "https://www.cloudflare.com/ssl/encrypted-sni/",
        "https://cloudflare-quic.com/",
        "https://one.one.one.one/help",
        "https://amiunique.org/",
        "https://3d-gauss.com/",
        "https://abrahamjuliot.github.io/creepjs/",
        "https://thetest.com/tests/browser",
        "https://webglreport.com"
    )

    BackHandler(enabled = true) {
        webView?.goBack()
    }

    if (webView == null) {
        avocadoLog(AVOCADO_LOG_LEVEL.AVOCADO_DEBUG, TAG, "WV null")
        Box(
            modifier = Modifier.fillMaxSize(),
            contentAlignment = Alignment.Center
        ) {
            Text("Failed to initialize WebView :(", color = MaterialTheme.colorScheme.error)
        }
    } else {
        avocadoLog(AVOCADO_LOG_LEVEL.AVOCADO_DEBUG, TAG, "WV valid: ${webView.hashCode()}")
        Column(modifier = Modifier
            .fillMaxSize()
            .background(MaterialTheme.colorScheme.surface)
        ) {
            ExposedDropdownMenuBox(
                expanded = expanded,
                onExpandedChange = { expanded = !expanded },
                modifier = Modifier.fillMaxWidth().padding(8.dp)
            ) {
                OutlinedTextField(
                    value = urlText,
                    onValueChange = { wvVM.urlText.value = it },
                    modifier = Modifier
                         .menuAnchor(PrimaryEditable, true)
                        .fillMaxWidth(),
                    label = { Text("Type or Select URL") },
                    singleLine = true,
                    trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = expanded) },
                    colors = ExposedDropdownMenuDefaults.outlinedTextFieldColors(),
                    keyboardOptions = KeyboardOptions(imeAction = ImeAction.Search),
                    keyboardActions = KeyboardActions(
                        onSearch = {
                            wvVM.navigateToUrl(urlText)
                            keyboardController?.hide()
                            focusManager.clearFocus()
                            expanded = false
                        }
                    )
                )

                ExposedDropdownMenu(
                    expanded = expanded,
                    onDismissRequest = { expanded = false }
                ) {
                    predefinedSites.forEach { site ->
                        DropdownMenuItem(
                            text = { Text(site) },
                            onClick = {
                                wvVM.urlText.value = site
                                wvVM.navigateToUrl(site)
                                expanded = false
                                focusManager.clearFocus()
                            },
                            contentPadding = ExposedDropdownMenuDefaults.ItemContentPadding
                        )
                    }
                }
            }

            if (isLoading) {
                LinearProgressIndicator(
                    modifier = Modifier.fillMaxWidth(),
                    color = MaterialTheme.colorScheme.primary,
                    trackColor = MaterialTheme.colorScheme.surfaceVariant
                )
            }


            // Container for webview
            Box(
                modifier = Modifier
                    .weight(1f)
                    .fillMaxWidth()
            ) {
                AndroidView(
                    factory = {
                        // Re-parenting logic
                        (webView!!.parent as? ViewGroup)?.removeView(webView)
                        webView as WebView
                    },
                    modifier = Modifier.fillMaxSize()
                )

                Box(
                    modifier = Modifier
                        .align(Alignment.BottomStart)
                        .padding(18.dp)
                        .size(56.dp)
                        .clip(CircleShape)
                        .background(Color(0xFF6200EE))
                        .clickable {
                            wvVM.clearAndReset()
                        },
                    contentAlignment = Alignment.Center
                ) {
                    Icon(
                        imageVector = Icons.Default.Delete,
                        contentDescription = "Clear Session",
                        tint = Color.Black,
                        modifier = Modifier.size(24.dp)
                    )
                }
            }
        }
    }
}


private fun updateWebViewViewModel(wvVM: WebViewModel, lcState: Lifecycle.State, isDarkTheme: Boolean) {
    wvVM.currLifecycleState = lcState
    wvVM.isCurrentlyInDarkTheme = isDarkTheme
}

package com.omarmesqq.grunfeld.ui.screens

import android.view.ViewGroup
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
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
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
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
import androidx.lifecycle.viewmodel.compose.viewModel
import com.omarmesqq.grunfeld.viewmodel.WebViewModel
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun WebviewScreen(webViewModel: WebViewModel = viewModel()) {
    val context = LocalContext.current
    val webView = webViewModel.getOrCreateWebView(context)

    val keyboardController = LocalSoftwareKeyboardController.current
    val focusManager = LocalFocusManager.current

    val isLoading by webViewModel.isLoading
    val urlText by webViewModel.urlText

    // Dropdown State
    var expanded by remember { mutableStateOf(false) }
    val predefinedSites = listOf(
        "https://start.duckduckgo.com/",
        "https://deviceinfo.me/",
        "https://browserleaks.com/",
        "https://www.cloudflare.com/ssl/encrypted-sni/",
        "https://cloudflare-quic.com/",
        "https://1.1.1.1/help"
    )

    BackHandler(enabled = true) {
        webView?.goBack()
    }

    if (webView != null) {
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
                    onValueChange = { webViewModel.urlText.value = it },
                    modifier = Modifier
                        .menuAnchor()
                        .fillMaxWidth(),
                    label = { Text("Type or Select URL") },
                    singleLine = true,
                    trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = expanded) },
                    colors = ExposedDropdownMenuDefaults.outlinedTextFieldColors(),
                    keyboardOptions = KeyboardOptions(imeAction = ImeAction.Search),
                    keyboardActions = KeyboardActions(
                        onSearch = {
                            webViewModel.navigateToUrl(urlText)
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
                                webViewModel.urlText.value = site
                                webViewModel.navigateToUrl(site)
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
                            (webView.parent as? ViewGroup)?.removeView(webView)
                            webView
                        },
                        modifier = Modifier.fillMaxSize()
                    )

                Box(
                    modifier = Modifier
                        .align(Alignment.BottomStart)
                        .padding(18.dp)
                        .size(56.dp) // Total button size
                        .clip(CircleShape)
                        .background(Color(0xFF6200EE))
                        .clickable { webViewModel.clearAndReset() },
                    contentAlignment = Alignment.Center
                ) {
                    Icon(
                        imageVector = Icons.Default.Delete,
                        contentDescription = "Clear Session",
                        tint = Color.Black,
                        modifier = Modifier.size(24.dp) // Icon size
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



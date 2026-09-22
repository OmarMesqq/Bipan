package org.omarmesqq.bipanmanager.composables

import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Android
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.dp
import androidx.core.graphics.drawable.toBitmap
import kotlinx.coroutines.launch
import org.omarmesqq.bipanmanager.data.AppInitParams
import org.omarmesqq.bipanmanager.data.DROIDGUARD_PKG_NAME
import org.omarmesqq.bipanmanager.data.PACKAGE_NAME

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AppListScreen(initParams: AppInitParams) {
    val mVM = initParams.mainViewModel

    val installedApps = mVM.appList.collectAsState().value
    val currentTargets = mVM.currentTargets.collectAsState().value
    val staleTargets = mVM.staleTargets.collectAsState().value

    var isRefreshing by remember { mutableStateOf(false) }
    val coroutineScope = rememberCoroutineScope()

    PullToRefreshBox(
        isRefreshing = isRefreshing,
        onRefresh = {
            coroutineScope.launch {
                isRefreshing = true
                mVM.refreshAll()
                isRefreshing = false
            }
        },
        modifier = Modifier.fillMaxSize()
    ) {
        if (installedApps == null) {
            Text(
                text = "Failed to fetch app list :(",
                style = MaterialTheme.typography.headlineLarge,
                color = Color.Red,
                modifier = Modifier
                    .fillMaxSize()
                    .background(MaterialTheme.colorScheme.surface)
                    .padding(16.dp)
            )
        } else {
            LazyColumn(
                modifier = Modifier
                    .fillMaxSize()
                    .background(MaterialTheme.colorScheme.surface)
                    .padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(16.dp)
            ) {
                if (staleTargets.isNotEmpty()) {
                    items(
                        items = staleTargets.toList(),
                        key = { "orphan_$it" }
                    )

                    { pkgName ->
                        if (pkgName != DROIDGUARD_PKG_NAME) {
                            AppRow(
                                label = pkgName,
                                isJailed = true,
                                isOrphaned = true,
                                isSystemApp = false,
                                iconBitmap = null,
                                fallbackIcon = Icons.Default.Warning,
                                onToggle = { checked ->
                                    mVM.toggleJail(pkgName, checked)
                                }
                            )
                        }
                    }
                    item { HorizontalDivider() }
                }

                if (staleTargets.contains(DROIDGUARD_PKG_NAME)) {
                    item {
                        AppRow(
                            label = "DroidGuard",
                            isJailed = true,
                            isOrphaned = false,
                            isSystemApp = false,
                            iconBitmap = null,
                            fallbackIcon = Icons.Default.Android,
                            onToggle = { checked ->
                                mVM.toggleJail(DROIDGUARD_PKG_NAME, checked)
                            }
                        )
                    }
                }

                items(
                    items = installedApps
                        .filterNot { it.packageName == PACKAGE_NAME }
                        .sortedBy { !currentTargets.contains(it.packageName) },
                    key = { it.packageName }
                ) { app ->
                    val isJailed = currentTargets.contains(app.packageName)
                    val bitmap = remember(app.packageName) {
                        app.icon.toBitmap().asImageBitmap()
                    }
                    AppRow(
                        label = app.label,
                        isJailed = isJailed,
                        isOrphaned = false,
                        isSystemApp = app.isSystemApp,
                        iconBitmap = bitmap,
                        onToggle = { checked ->
                            mVM.toggleJail(app.packageName, checked)
                        }
                    )
                }
            }
        }
    }
}

@Composable
private fun AppRow(
    label: String,
    isJailed: Boolean,
    isOrphaned: Boolean,
    isSystemApp: Boolean,
    iconBitmap: ImageBitmap?,
    fallbackIcon: ImageVector? = null,
    onToggle: (Boolean) -> Unit
) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 8.dp)
    ) {
        if (iconBitmap != null) {
            Image(
                bitmap = iconBitmap,
                contentDescription = "$label icon",
                modifier = Modifier.size(40.dp)
            )
        } else if (fallbackIcon != null) {
            Icon(
                imageVector = fallbackIcon,
                contentDescription = "$label icon (not installed)",
                tint = MaterialTheme.colorScheme.error,
                modifier = Modifier.size(40.dp)
            )
        }

        Text(
            text = buildAnnotatedString {
                append(label)
                if (isOrphaned) {
                    withStyle(style = SpanStyle(color = MaterialTheme.colorScheme.error)) {
                        append("\nOrphaned (not installed)")
                    }
                } else if (isJailed) {
                    withStyle(style = SpanStyle(color = Color.Green)) {
                        append("\nJailed")
                    }
                }
                if (isSystemApp) {
                    withStyle(style = SpanStyle(color = Color.Cyan)) {
                        append("\nSystem app")
                    }
                }
            },
            modifier = Modifier.weight(1f)
        )

        Switch(
            checked = isJailed,
            onCheckedChange = onToggle,
            colors = SwitchDefaults.colors(
                checkedThumbColor = MaterialTheme.colorScheme.error,
                checkedTrackColor = MaterialTheme.colorScheme.errorContainer,
                uncheckedThumbColor = MaterialTheme.colorScheme.outline,
                uncheckedTrackColor = MaterialTheme.colorScheme.surfaceVariant
            )
        )
    }
}
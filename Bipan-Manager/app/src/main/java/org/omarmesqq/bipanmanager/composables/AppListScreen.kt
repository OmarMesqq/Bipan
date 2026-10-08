package org.omarmesqq.bipanmanager.composables

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Android
import androidx.compose.material.icons.filled.Error
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.compose.ui.window.DialogWindowProvider
import androidx.core.graphics.drawable.toBitmap
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import org.omarmesqq.bipanmanager.data.AppInitParams
import org.omarmesqq.bipanmanager.interfaces.AppListItem
import kotlin.time.Duration.Companion.milliseconds

/** How long the user must wait before either dialog action becomes tappable */
private const val CONFIRM_DELAY_SECONDS = 3

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AppListScreen(initParams: AppInitParams) {
    val mvm = initParams.mainViewModel
    val items by mvm.listItems.collectAsState()
    var isRefreshing by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()

    PullToRefreshBox(
        isRefreshing = isRefreshing,
        onRefresh = {
            scope.launch {
                isRefreshing = true
                try {
                    mvm.refreshAll()
                } finally {
                    isRefreshing = false
                }
            }
        },
        modifier = Modifier.fillMaxSize()
    ) {
        val list = items
        if (list == null) {
            FetchErrorContent()
        } else {
            LazyColumn(
                modifier = Modifier
                    .fillMaxSize()
                    .background(MaterialTheme.colorScheme.surface)
                    .padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(16.dp)
            ) {
                items(list, key = { it.packageName }) { item ->
                    AppRow(item) { checked -> mvm.toggleJail(item, checked) }
                }
            }
        }
    }
}

@Composable
private fun AppRow(item: AppListItem, onToggle: (Boolean) -> Unit) {
    var showUnjailConfirm by remember { mutableStateOf(false) }

    Row(
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 8.dp)
    ) {
        TargetIcon(item)

        Text(
            text = buildStatusText(item),
            modifier = Modifier.weight(1f)
        )

        Switch(
            checked = item.isJailed,
            onCheckedChange = { checked ->
                if (item !is AppListItem.Orphaned && item.isJailed && !checked) {
                    showUnjailConfirm = true
                } else {
                    onToggle(checked)
                }
            },
            colors = SwitchDefaults.colors(
                checkedThumbColor = MaterialTheme.colorScheme.error,
                checkedTrackColor = MaterialTheme.colorScheme.errorContainer,
                uncheckedThumbColor = MaterialTheme.colorScheme.outline,
                uncheckedTrackColor = MaterialTheme.colorScheme.surfaceVariant
            )
        )
    }

    if (showUnjailConfirm) {
        UnjailConfirmationDialog(
            appLabel = item.label,
            onConfirm = { showUnjailConfirm = false; onToggle(false) },
            onDismiss = { showUnjailConfirm = false }
        )
    }
}

@Composable
private fun TargetIcon(item: AppListItem) {
    val size = Modifier.size(40.dp)
    when (item) {
        is AppListItem.Installed -> {
            val bitmap = remember(item.packageName) { item.app.icon.toBitmap().asImageBitmap() }
            Image(bitmap, contentDescription = "${item.label} icon", modifier = size)
        }

        is AppListItem.Orphaned -> FallbackIcon(
            Icons.Default.Warning,
            "${item.label} icon (not installed)",
            size
        )

        AppListItem.DroidGuard -> FallbackIcon(Icons.Default.Android, "DroidGuard icon", size)
    }
}

@Composable
private fun FallbackIcon(icon: ImageVector, description: String, modifier: Modifier) {
    Icon(
        icon,
        contentDescription = description,
        tint = MaterialTheme.colorScheme.error,
        modifier = modifier
    )
}

@Composable
private fun buildStatusText(item: AppListItem): AnnotatedString = buildAnnotatedString {
    append(item.label)
    when (item) {
        is AppListItem.Orphaned -> withStyle(SpanStyle(color = MaterialTheme.colorScheme.error)) {
            append("\nOrphaned (not installed)")
        }

        is AppListItem.Installed -> {
            if (item.isJailed) withStyle(SpanStyle(color = Color.Green)) { append("\nJailed") }
            if (item.app.isSystemApp) withStyle(SpanStyle(color = Color.Cyan)) { append("\nSystem app") }
        }

        AppListItem.DroidGuard -> withStyle(SpanStyle(color = Color.Green)) { append("\nJailed") }
    }
}

@Composable
private fun UnjailConfirmationDialog(
    appLabel: String,
    onConfirm: () -> Unit,
    onDismiss: () -> Unit
) {
    var secondsLeft by remember { mutableIntStateOf(CONFIRM_DELAY_SECONDS) }
    val actionsEnabled = secondsLeft <= 0

    LaunchedEffect(Unit) {
        while (secondsLeft > 0) {
            delay(1000.milliseconds)
            secondsLeft--
        }
    }

    // Only allow back-press to dismiss once the delay has elapsed.
    BackHandler(enabled = actionsEnabled) { onDismiss() }

    Dialog(
        onDismissRequest = {
            if (actionsEnabled) {
                onDismiss()
            }
        },
        properties = DialogProperties(
            dismissOnBackPress = false,
            dismissOnClickOutside = false,
            usePlatformDefaultWidth = true
        )
    ) {
        // Harden the dialog's own window against tapjacking/overlay attacks.
        val view = LocalView.current
        DisposableEffect(view) {
            val window = (view.parent as? DialogWindowProvider)?.window
            window?.decorView?.filterTouchesWhenObscured = true
            onDispose {}
        }

        Card(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(24.dp)) {
                Icon(
                    imageVector = Icons.Default.Warning,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.error
                )
                Spacer(modifier = Modifier.height(12.dp))
                Text(
                    text = "Unjail \"$appLabel\"?",
                    style = MaterialTheme.typography.titleLarge,
                    fontWeight = FontWeight.Bold
                )
                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    text = "This removes Bipan's sandbox for the app and" +
                            " takes effect in the next app launch ",
                    style = MaterialTheme.typography.bodyMedium
                )
                Spacer(modifier = Modifier.height(20.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.End
                ) {
                    TextButton(
                        onClick = onDismiss,
                        enabled = actionsEnabled
                    ) {
                        Text("Cancel")
                    }
                    Spacer(modifier = Modifier.width(8.dp))
                    Button(
                        onClick = onConfirm,
                        enabled = actionsEnabled,
                        colors = androidx.compose.material3.ButtonDefaults.buttonColors(
                            containerColor = MaterialTheme.colorScheme.error
                        )
                    ) {
                        Text(if (actionsEnabled) "Unjail" else "Unjail (${secondsLeft}s)")
                    }
                }
            }
        }
    }
}

@Composable
private fun FetchErrorContent() {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        Icon(
            imageVector = Icons.Filled.Error,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.error,
            modifier = Modifier.size(64.dp)
        )

        Spacer(modifier = Modifier.height(24.dp))

        Text(
            text = "Failed to fetch app list!",
            style = MaterialTheme.typography.headlineMedium,
            color = MaterialTheme.colorScheme.error,
            textAlign = TextAlign.Center
        )
    }
}
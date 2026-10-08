package org.omarmesqq.bipanmanager.composables

import androidx.compose.foundation.Image
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
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
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Android
import androidx.compose.material.icons.outlined.Check
import androidx.compose.material.icons.outlined.Close
import androidx.compose.material.icons.outlined.ErrorOutline
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material.icons.outlined.LockOpen
import androidx.compose.material.icons.outlined.Refresh
import androidx.compose.material.icons.outlined.Search
import androidx.compose.material.icons.outlined.SearchOff
import androidx.compose.material.icons.outlined.Settings
import androidx.compose.material.icons.outlined.Warning
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.ElevatedCard
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
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
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.compose.ui.window.DialogWindowProvider
import androidx.core.graphics.drawable.toBitmap
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import org.omarmesqq.bipanmanager.data.AppInitParams
import org.omarmesqq.bipanmanager.interfaces.AppListItem
import kotlin.time.Duration.Companion.seconds

private const val CONFIRM_DELAY_SECONDS = 3

private enum class AppFilter(val label: String) {
    All("All"), Jailed("Jailed"), NotJailed("Not jailed"), System("System")
}

private fun AppListItem.matches(filter: AppFilter) = when (filter) {
    AppFilter.All -> true
    AppFilter.Jailed -> isJailed
    AppFilter.NotJailed -> !isJailed
    AppFilter.System -> this is AppListItem.Installed && app.isSystemApp
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AppListScreen(initParams: AppInitParams) {
    val mvm = initParams.mainViewModel
    val items by mvm.listItems.collectAsState()
    var isRefreshing by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()

    var query by rememberSaveable { mutableStateOf("") }
    var filter by rememberSaveable { mutableStateOf(AppFilter.All) }

    val refresh: () -> Unit = {
        scope.launch {
            isRefreshing = true
            try {
                mvm.refreshAppsAndTargets()
            } finally {
                isRefreshing = false
            }
        }
    }

    PullToRefreshBox(
        isRefreshing = isRefreshing,
        onRefresh = refresh,
        modifier = Modifier.fillMaxSize()
    ) {
        val list = items
        if (list == null) {
            FetchErrorContent(onRetry = refresh)
            return@PullToRefreshBox
        }

        val visible = remember(list, query, filter) {
            list.filter {
                it.matches(filter) && (query.isBlank() ||
                        it.label.contains(query, ignoreCase = true) ||
                        it.packageName.contains(query, ignoreCase = true))
            }
        }

        LazyColumn(
            modifier = Modifier.fillMaxSize(),
            contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            item(key = "search") {
                SearchField(query, onQueryChange = { query = it })
            }
            item(key = "filters") {
                Row(
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    modifier = Modifier
                        .horizontalScroll(rememberScrollState())
                        .padding(bottom = 4.dp)
                ) {
                    AppFilter.entries.forEach { f ->
                        val count = list.count { it.matches(f) }
                        FilterChip(
                            selected = filter == f,
                            onClick = { filter = f },
                            label = { Text("${f.label} ($count)") },
                            leadingIcon = if (filter == f) {
                                {
                                    Icon(
                                        Icons.Outlined.Check,
                                        null,
                                        Modifier.size(FilterChipDefaults.IconSize)
                                    )
                                }
                            } else null
                        )
                    }
                }
            }

            if (visible.isEmpty()) {
                item(key = "empty") { NoMatches() }
            }

            items(visible, key = { it.packageName }) { item ->
                AppCard(
                    item = item,
                    onToggle = { checked -> mvm.toggleJail(item, checked) },
                    modifier = Modifier.animateItem()
                )
            }
        }
    }
}

@Composable
private fun SearchField(query: String, onQueryChange: (String) -> Unit) {
    OutlinedTextField(
        value = query,
        onValueChange = onQueryChange,
        placeholder = { Text("Search apps or packages") },
        leadingIcon = { Icon(Icons.Outlined.Search, null) },
        trailingIcon = {
            if (query.isNotEmpty()) {
                IconButton(onClick = { onQueryChange("") }) {
                    Icon(Icons.Outlined.Close, "Clear search")
                }
            }
        },
        singleLine = true,
        shape = RoundedCornerShape(28.dp),
        modifier = Modifier.fillMaxWidth()
    )
}

@Composable
private fun AppCard(item: AppListItem, onToggle: (Boolean) -> Unit, modifier: Modifier = Modifier) {
    var showUnjailConfirm by remember { mutableStateOf(false) }

    ElevatedCard(shape = RoundedCornerShape(20.dp), modifier = modifier.fillMaxWidth()) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier.padding(horizontal = 16.dp, vertical = 14.dp)
        ) {
            TargetIcon(item)
            Spacer(Modifier.width(14.dp))

            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text(
                    item.label,
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
                Text(
                    item.packageName,
                    style = MaterialTheme.typography.bodySmall,
                    fontFamily = FontFamily.Monospace,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
                StatusPills(item)
            }

            Spacer(Modifier.width(12.dp))

            Switch(
                checked = item.isJailed,
                onCheckedChange = { checked ->
                    if (item !is AppListItem.Orphaned && item.isJailed && !checked) {
                        showUnjailConfirm = true
                    } else {
                        onToggle(checked)
                    }
                },
                thumbContent = {
                    Icon(
                        if (item.isJailed) Icons.Outlined.Lock else Icons.Outlined.LockOpen,
                        contentDescription = null,
                        modifier = Modifier.size(SwitchDefaults.IconSize)
                    )
                }
            )
        }
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
    val shape = RoundedCornerShape(12.dp)
    when (item) {
        is AppListItem.Installed -> {
            val bitmap = remember(item.packageName) { item.app.icon.toBitmap().asImageBitmap() }
            Image(
                bitmap,
                contentDescription = "${item.label} icon",
                modifier = Modifier
                    .size(44.dp)
                    .clip(shape)
            )
        }

        is AppListItem.Orphaned -> IconTile(
            Icons.Outlined.Warning, "${item.label} icon (not installed)",
            MaterialTheme.colorScheme.errorContainer, MaterialTheme.colorScheme.onErrorContainer
        )

        AppListItem.DroidGuard -> IconTile(
            Icons.Outlined.Android,
            "DroidGuard icon",
            MaterialTheme.colorScheme.secondaryContainer,
            MaterialTheme.colorScheme.onSecondaryContainer
        )
    }
}

@Composable
private fun IconTile(icon: ImageVector, description: String, container: Color, content: Color) {
    Surface(
        shape = RoundedCornerShape(12.dp),
        color = container,
        contentColor = content,
        modifier = Modifier.size(44.dp)
    ) {
        Icon(icon, description, Modifier.padding(10.dp))
    }
}

@Composable
private fun StatusPills(item: AppListItem) {
    val cs = MaterialTheme.colorScheme
    Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
        if (item is AppListItem.Orphaned) {
            StatusPill(
                "Not installed",
                Icons.Outlined.Warning,
                cs.errorContainer,
                cs.onErrorContainer
            )
        }
        if (item.isJailed) {
            StatusPill("Jailed", Icons.Outlined.Lock, cs.primaryContainer, cs.onPrimaryContainer)
        }
        if (item is AppListItem.Installed && item.app.isSystemApp) {
            StatusPill(
                "System",
                Icons.Outlined.Settings,
                cs.secondaryContainer,
                cs.onSecondaryContainer
            )
        }
    }
}

@Composable
private fun StatusPill(text: String, icon: ImageVector, container: Color, content: Color) {
    Surface(shape = CircleShape, color = container, contentColor = content) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(4.dp),
            modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp)
        ) {
            Icon(icon, null, Modifier.size(12.dp))
            Text(text, style = MaterialTheme.typography.labelSmall, fontWeight = FontWeight.Medium)
        }
    }
}

@Composable
private fun UnjailConfirmationDialog(
    appLabel: String,
    onConfirm: () -> Unit,
    onDismiss: () -> Unit
) {
    var secondsLeft by remember { mutableIntStateOf(CONFIRM_DELAY_SECONDS) }
    val confirmEnabled = secondsLeft <= 0

    LaunchedEffect(Unit) {
        while (secondsLeft > 0) {
            delay(1.seconds)
            secondsLeft--
        }
    }

    Dialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(dismissOnClickOutside = false)
    ) {
        // Harden the dialog's own window against tapjacking/overlay attacks.
        val view = LocalView.current
        DisposableEffect(view) {
            (view.parent as? DialogWindowProvider)?.window
                ?.decorView?.filterTouchesWhenObscured = true
            onDispose {}
        }

        Surface(
            shape = RoundedCornerShape(28.dp),
            color = MaterialTheme.colorScheme.surfaceContainerHigh,
            tonalElevation = 6.dp
        ) {
            Column(
                horizontalAlignment = Alignment.CenterHorizontally,
                modifier = Modifier.padding(24.dp)
            ) {
                Surface(
                    shape = CircleShape,
                    color = MaterialTheme.colorScheme.errorContainer,
                    contentColor = MaterialTheme.colorScheme.onErrorContainer,
                    modifier = Modifier.size(56.dp)
                ) {
                    Icon(Icons.Outlined.LockOpen, null, Modifier.padding(14.dp))
                }
                Spacer(Modifier.height(16.dp))
                Text(
                    "Unjail \"$appLabel\"?",
                    style = MaterialTheme.typography.headlineSmall,
                    textAlign = TextAlign.Center
                )
                Spacer(Modifier.height(12.dp))
                Text(
                    "This removes Bipan's sandbox for the app. " +
                            "The change takes effect the next time the app launches.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    textAlign = TextAlign.Center
                )
                Spacer(Modifier.height(24.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp, Alignment.End)
                ) {
                    TextButton(onClick = onDismiss) { Text("Cancel") }
                    Button(
                        onClick = onConfirm,
                        enabled = confirmEnabled,
                        colors = ButtonDefaults.buttonColors(
                            containerColor = MaterialTheme.colorScheme.error,
                            contentColor = MaterialTheme.colorScheme.onError
                        )
                    ) {
                        Text(if (confirmEnabled) "Unjail" else "Unjail (${secondsLeft}s)")
                    }
                }
            }
        }
    }
}

@Composable
private fun NoMatches() {
    Column(
        horizontalAlignment = Alignment.CenterHorizontally,
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 48.dp)
    ) {
        Icon(
            Icons.Outlined.SearchOff, null, Modifier.size(48.dp),
            tint = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Spacer(Modifier.height(12.dp))
        Text("No matching apps", style = MaterialTheme.typography.titleMedium)
    }
}

@Composable
private fun FetchErrorContent(onRetry: () -> Unit) {
    // Scrollable so pull-to-refresh still works on the error screen
    LazyColumn(Modifier.fillMaxSize(), contentPadding = PaddingValues(32.dp)) {
        item {
            Column(
                Modifier.fillParentMaxSize(),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.Center
            ) {
                Surface(
                    shape = CircleShape,
                    color = MaterialTheme.colorScheme.errorContainer,
                    contentColor = MaterialTheme.colorScheme.onErrorContainer,
                    modifier = Modifier.size(80.dp)
                ) {
                    Icon(Icons.Outlined.ErrorOutline, null, Modifier.padding(20.dp))
                }
                Spacer(Modifier.height(20.dp))
                Text(
                    "Couldn't load apps",
                    style = MaterialTheme.typography.headlineSmall,
                    textAlign = TextAlign.Center
                )
                Spacer(Modifier.height(8.dp))
                Text(
                    "Pull down or tap retry to try again.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    textAlign = TextAlign.Center
                )
                Spacer(Modifier.height(20.dp))
                FilledTonalButton(onClick = onRetry) {
                    Icon(Icons.Outlined.Refresh, null, Modifier.size(18.dp))
                    Spacer(Modifier.width(8.dp))
                    Text("Retry")
                }
            }
        }
    }
}
package com.omarmesqq.grunfeld.ui.screens


import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import com.omarmesqq.grunfeld.MainApplication
import kotlinx.coroutines.launch
import com.omarmesqq.grunfeld.BuildConfig

@Composable
fun SettingsScreen() {
    val scope = rememberCoroutineScope()
    val context = LocalContext.current

    val app = context.applicationContext as MainApplication
    val dsRepo = app.container.dataStoreRepo
    val isFlagSecureEnabled by dsRepo.flagSecureEnabledFlow.collectAsState(initial = false)

    Column(
        modifier = Modifier
            .fillMaxSize()
            .safeDrawingPadding()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Text("Toggle Window FLAG_SECURE")

            Switch(
                checked = isFlagSecureEnabled,
                onCheckedChange = {
                    scope.launch {
                        dsRepo.toggleFlagSecure()
                    }
                }
            )
        }
        Text(
            text = "If enabled, you can't take screenshots",
            style = MaterialTheme.typography.bodyMedium
        )

        HorizontalDivider()
        Row(
            horizontalArrangement = Arrangement.Center,
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier.fillMaxWidth()
        ) {
            Text(
                "✦ v${BuildConfig.VERSION_NAME}-${BuildConfig.BUILD_TYPE} ✦",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.primary.copy(alpha = 0.5f)
            )
        }
    }
}
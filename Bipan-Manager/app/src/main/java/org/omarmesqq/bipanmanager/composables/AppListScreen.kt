package org.omarmesqq.bipanmanager.composables

import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.unit.dp
import androidx.core.graphics.drawable.toBitmap
import org.omarmesqq.bipanmanager.viewmodel.MainViewModel

@Composable
fun AppListScreen(mVM: MainViewModel) {
    val installedApps = mVM.appList.collectAsState().value

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
            items(
                items = installedApps,
                key = { it.packageName }
            ) { app ->
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                    modifier = Modifier.padding(vertical = 8.dp)
                ) {
                    val bitmap = remember(app.packageName) {
                        app.icon.toBitmap().asImageBitmap()
                    }
                    Image(
                        bitmap = bitmap,
                        contentDescription = "${app.label} icon",
                        modifier = Modifier.size(40.dp)
                    )
                    Text(
                        text = app.label
                    )
                }
            }
        }
    }
}
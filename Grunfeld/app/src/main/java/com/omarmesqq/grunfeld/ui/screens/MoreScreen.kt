package com.omarmesqq.grunfeld.ui.screens

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Android
import androidx.compose.material.icons.filled.Construction
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.navigation.NavHostController
import com.omarmesqq.grunfeld.ui.Screen

private data class MoreItem(
    val title: String,
    val icon: (@Composable () -> Unit)? = null,
    val onClick: () -> Unit
)

@Composable
fun MoreScreen(navController: NavHostController) {
    val items = listOf(
        MoreItem(
            title = "Root checker",
            icon = { Icon(Icons.Default.Android, contentDescription = "Android") },
            onClick = { navController.navigate(Screen.RootCheckerScreen.route) }
        ),
        MoreItem(
            title = "Settings",
            icon = { Icon(Icons.Default.Settings, contentDescription = "Settings") },
            onClick = { navController.navigate(Screen.SettingsScreen.route) }
        ),
        MoreItem(
            title = "About",
            icon = { Icon(Icons.Default.Info, contentDescription = "Info") },
            onClick = { navController.navigate(Screen.AboutScreen.route) }
        ),
        MoreItem(
            title = "Logcat",
            icon = { Icon(Icons.Default.Construction, contentDescription = "Logcat") },
            onClick = { navController.navigate(Screen.LogcatScreen.route) }
        ),
    )

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        items(items) { item ->
            Button(
                onClick = item.onClick,
                modifier = Modifier
                    .fillMaxWidth()
                    .height(56.dp)
            ) {
                Row(
                    verticalAlignment = androidx.compose.ui.Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.Start,
                    modifier = Modifier.fillMaxWidth()
                ) {
                    item.icon?.let {
                        Box(modifier = Modifier.size(24.dp)) { it() }
                        Spacer(modifier = Modifier.width(12.dp))
                    }
                    Text(
                        text = item.title,
                        style = MaterialTheme.typography.titleMedium,
                        modifier = Modifier.weight(1f)
                    )
                }
            }
        }
    }
}
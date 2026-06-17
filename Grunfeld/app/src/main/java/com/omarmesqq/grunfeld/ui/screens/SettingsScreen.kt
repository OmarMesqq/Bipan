package com.omarmesqq.grunfeld.ui.screens

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Android
import androidx.compose.material.icons.filled.Info
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.navigation.NavHostController
import com.omarmesqq.grunfeld.ui.Screen

private data class SettingItem(
    val title: String,
    val icon: (@Composable () -> Unit)? = null,
    val onClick: () -> Unit
)

@Composable
fun SettingsScreen(navController: NavHostController) {
    val items = listOf(
        SettingItem(
            title = "About",
            icon = { Icon(Icons.Default.Info, contentDescription = "Info") },
            onClick = { navController.navigate(Screen.AboutScreen.route) }
        ),
        SettingItem(
            title = "Root checker",
            icon = { Icon(Icons.Default.Android, contentDescription = "Android") },
            onClick = { navController.navigate(Screen.RootCheckerScreen.route) }
        )
    )

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        items(items) { item ->
            Button(
                onClick = item.onClick,  // ✅ no cast needed
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
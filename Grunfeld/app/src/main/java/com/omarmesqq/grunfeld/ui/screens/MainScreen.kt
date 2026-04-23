package com.omarmesqq.grunfeld.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import com.omarmesqq.grunfeld.ui.Screen

@Composable
fun MainScreen() {
    val navController = rememberNavController()
    val items = listOf(Screen.JavaScreen, Screen.WebviewScreen, Screen.JniScreen)

    Scaffold(
        containerColor = MaterialTheme.colorScheme.surface,
        bottomBar = {
            NavigationBar {
                val navBackStackEntry by navController.currentBackStackEntryAsState()
                val currentRoute = navBackStackEntry?.destination?.route

                items.forEach { screen ->
                    NavigationBarItem(
                        icon = { Icon(screen.icon, contentDescription = screen.title) },
                        label = { Text(screen.title) },
                        selected = currentRoute == screen.route,
                        onClick = {
                            navController.navigate(screen.route) {
                                popUpTo(navController.graph.startDestinationId) { saveState = true }
                                launchSingleTop = true
                                restoreState = true
                            }
                        }
                    )
                }
            }
        }
    ) { innerPadding ->
        // Handles the actual switching of screens
        NavHost(
            navController = navController,
            startDestination = Screen.JavaScreen.route,
            modifier = Modifier
                .padding(innerPadding) // Handles system bar/bottom bar space
                .background(MaterialTheme.colorScheme.surface)
        ) {
            composable(Screen.JavaScreen.route) { JavaInfoScreen() }
            composable(Screen.WebviewScreen.route) { WebviewScreen() }
            composable(Screen.JniScreen.route) { JniScreen() }
        }
    }
}

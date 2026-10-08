package org.omarmesqq.bipanmanager.composables

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Apps
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Security
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import org.omarmesqq.bipanmanager.data.AppInitParams

open class Route(val route: String, val title: String, val icon: ImageVector) {
    object AppListScreenRoute : Route("appList", "App List", Icons.Default.Apps)
    object BrokersScreen : Route("brokers", "Brokers", Icons.Default.Security)
    object AboutScreen : Route("about", "About", Icons.Default.Info)
}

private val START_ROUTE = Route.AppListScreenRoute.route

@Composable
fun App(initParams: AppInitParams) {
    val mainViewModel = initParams.mainViewModel

    if (!initParams.isRooted) {
        NoRootScreen()
        return
    }

    if (!initParams.bipanFolderExists) {
        NoBipanScreen()
        return
    }

    val uiReady by mainViewModel.shouldShowUi.collectAsState()
    if (!uiReady) {
        Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
            CircularProgressIndicator()
        }
        return
    }


    val navController = rememberNavController()
    val routes = listOf(
        Route.AppListScreenRoute,
        Route.BrokersScreen,
        Route.AboutScreen
    )

    Scaffold(
        containerColor = MaterialTheme.colorScheme.surface,
        bottomBar = {
            NavigationBar {
                val navBackStackEntry by navController.currentBackStackEntryAsState()
                val currentRoute = navBackStackEntry?.destination?.route
                routes.forEach { r ->
                    NavigationBarItem(
                        icon = { Icon(r.icon, contentDescription = r.title) },
                        label = { Text(r.title) },
                        selected = currentRoute == r.route,
                        onClick = {
                            navController.navigate(r.route) {
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
        NavHost(
            navController = navController,
            startDestination = START_ROUTE,
            modifier = Modifier
                .padding(innerPadding) // System bar/bottom bar space
                .background(MaterialTheme.colorScheme.surface)
        ) {
            composable(Route.AppListScreenRoute.route) { AppListScreen(initParams) }
            composable(Route.BrokersScreen.route) { BrokersScreen(initParams) }
            composable(Route.AboutScreen.route) { AboutScreen() }
        }
    }
}
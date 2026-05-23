package com.omarmesqq.grunfeld.ui

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.viewModels
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Code
import androidx.compose.material.icons.filled.Coffee
import androidx.compose.material.icons.filled.Public
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.core.splashscreen.SplashScreen.Companion.installSplashScreen
import com.omarmesqq.grunfeld.ui.screens.MainScreen
import com.omarmesqq.grunfeld.viewmodel.MainViewModel
import com.omarmesqq.grunfeld.viewmodel.MainViewModelFactory


sealed class Screen(val route: String, val title: String, val icon: ImageVector) {
    object JavaScreen : Screen("java", "Java", Icons.Default.Coffee)
    object WebviewScreen : Screen("webview", "Webview", Icons.Default.Public)
    object NativeScreen : Screen("native", "Native", Icons.Default.Code)
}

class MainActivity : ComponentActivity() {
    private val viewModel: MainViewModel by viewModels {
        MainViewModelFactory()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        installSplashScreen().setKeepOnScreenCondition {
            !viewModel.isReady.value
        }
        super.onCreate(savedInstanceState)

        enableEdgeToEdge()
        setContent {
            val darkTheme = isSystemInDarkTheme()
            val colors = if (darkTheme) {
                darkColorScheme()
            } else {
                lightColorScheme()
            }
            MaterialTheme(colorScheme = colors) {
                MainScreen()
            }
        }
    }
}

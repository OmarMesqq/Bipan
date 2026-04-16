package com.omarmesqq.grunfeld.ui

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Android
import androidx.compose.material.icons.filled.Build
import androidx.compose.material.icons.filled.Code
import androidx.compose.material.icons.filled.Coffee
import androidx.compose.material.icons.filled.Public
import androidx.compose.material.icons.filled.Route
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.MaterialTheme
import androidx.compose.ui.graphics.vector.ImageVector
import com.omarmesqq.grunfeld.ui.screens.MainScreen


sealed class Screen(val route: String, val title: String, val icon: ImageVector) {
    object BuildInfo : Screen("build_info", "Build", Icons.Default.Coffee)
    object Webview : Screen("webview", "Web", Icons.Default.Public)
    object JniInfo : Screen("jni_info", "JNI", Icons.Default.Route)
}

class MainActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        enableEdgeToEdge()
        setContent {
            MaterialTheme {
                MainScreen()
            }
        }
    }
}

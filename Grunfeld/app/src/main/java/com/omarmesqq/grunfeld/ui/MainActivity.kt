package com.omarmesqq.grunfeld.ui

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Coffee
import androidx.compose.material.icons.filled.Public
import androidx.compose.material.icons.filled.Route
import androidx.compose.material3.MaterialTheme
import androidx.compose.ui.graphics.vector.ImageVector
import com.omarmesqq.grunfeld.ui.screens.MainScreen


sealed class Screen(val route: String, val title: String, val icon: ImageVector) {
    object JavaScreen : Screen("java", "Java", Icons.Default.Coffee)
    object WebviewScreen : Screen("webview", "Webview", Icons.Default.Public)
    object JniScreen : Screen("jni", "JNI", Icons.Default.Route)
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

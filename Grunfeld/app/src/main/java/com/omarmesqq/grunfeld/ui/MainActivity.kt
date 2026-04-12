package com.omarmesqq.grunfeld.ui

import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.annotation.RequiresApi
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Build
import androidx.compose.material.icons.filled.Code
import androidx.compose.material.icons.filled.Public
import androidx.compose.material3.MaterialTheme
import androidx.compose.ui.graphics.vector.ImageVector
import com.omarmesqq.grunfeld.ui.screens.MainScreen


sealed class Screen(val route: String, val title: String, val icon: ImageVector) {
    object BuildInfo : Screen("build_info", "Build", Icons.Default.Build)
    object Webview : Screen("webview", "Web", Icons.Default.Public)
    object JniInfo : Screen("jni_info", "JNI", Icons.Default.Code)
}

class MainActivity : ComponentActivity() {
    @RequiresApi(Build.VERSION_CODES.BAKLAVA)
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

package com.omarmesqq.grunfeld.ui

import android.os.Build
import android.os.Bundle
import android.view.WindowManager
import android.view.WindowManager.SCREEN_RECORDING_STATE_VISIBLE
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.viewModels
import androidx.annotation.RequiresApi
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Android
import androidx.compose.material.icons.filled.Code
import androidx.compose.material.icons.filled.Coffee
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Public
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.core.splashscreen.SplashScreen.Companion.installSplashScreen
import java.util.function.Consumer
import com.omarmesqq.grunfeld.ui.screens.MainScreen
import com.omarmesqq.grunfeld.utils.AVOCADO_LOG_LEVEL
import com.omarmesqq.grunfeld.utils.Avocado.avocadoLog
import com.omarmesqq.grunfeld.viewmodel.MainViewModel
import com.omarmesqq.grunfeld.viewmodel.MainViewModelFactory


open class Screen(val route: String, val title: String, val icon: ImageVector) {
    object JavaScreen : Screen("java", "Java", Icons.Default.Coffee)
    object WebviewScreen : Screen("webview", "Webview", Icons.Default.Public)
    object NativeScreen : Screen("native", "Native", Icons.Default.Code)
    object RootCheckerScreen : Screen("root-check", "Root Check", Icons.Default.Android)
    object SettingsScreen : Screen("settings", "Settings", Icons.Default.Settings)
    object AboutScreen : Screen("about", "About", Icons.Default.Info)
}

private const val TAG = "MainActitvity"
@RequiresApi(Build.VERSION_CODES.VANILLA_ICE_CREAM)
class MainActivity : ComponentActivity() {
    private val viewModel: MainViewModel by viewModels {
        MainViewModelFactory()
    }

    private val screenCaptureCallback = ScreenCaptureCallback {
        avocadoLog(AVOCADO_LOG_LEVEL.AVOCADO_INFO, TAG, "Screenshot detected!", shouldToast = true)
    }
    private val screenRecordCallback = Consumer<Int> {state ->
        if (state == SCREEN_RECORDING_STATE_VISIBLE) {
            avocadoLog(AVOCADO_LOG_LEVEL.AVOCADO_INFO, TAG, "Screen recording in progress!", shouldToast = true)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        installSplashScreen().setKeepOnScreenCondition {
            !viewModel.isReady.value
        }
        this.window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)

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


    override fun onStart() {
        super.onStart()
        registerScreenCaptureCallback(mainExecutor, screenCaptureCallback)
        val initialWindowState = windowManager.addScreenRecordingCallback(mainExecutor, screenRecordCallback)
        screenRecordCallback.accept(initialWindowState)
    }


    override fun onStop() {
        super.onStop()
        unregisterScreenCaptureCallback(screenCaptureCallback)
        windowManager.removeScreenRecordingCallback(screenRecordCallback)
    }
}

package com.omarmesqq.grunfeld.ui

import android.content.pm.LauncherApps
import android.os.Build
import android.os.Bundle
import android.os.UserHandle
import android.view.WindowManager
import android.view.WindowManager.SCREEN_RECORDING_STATE_VISIBLE
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.viewModels
import androidx.annotation.RequiresApi
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.MoreHoriz
import androidx.compose.material.icons.filled.Public
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.core.splashscreen.SplashScreen.Companion.installSplashScreen
import androidx.lifecycle.lifecycleScope
import com.omarmesqq.grunfeld.MainApplication
import com.omarmesqq.grunfeld.ui.screens.MainScreen
import com.omarmesqq.grunfeld.utils.AVOCADO_LOG_LEVEL
import com.omarmesqq.grunfeld.utils.Avocado.avocadoLog
import com.omarmesqq.grunfeld.utils.Persistence.wipeWebviewTraces
import com.omarmesqq.grunfeld.viewmodel.MainViewModel
import com.omarmesqq.grunfeld.viewmodel.MainViewModelFactory
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch
import java.util.function.Consumer
open class Screen(val route: String, val title: String, val icon: ImageVector) {
    object TestsScreen : Screen("tests", "Tests", Icons.Default.CheckCircle)
    object WebviewScreen : Screen("webview", "Webview", Icons.Default.Public)
    object MoreScreen : Screen("more", "More", Icons.Default.MoreHoriz)
    object SettingsScreen : Screen("settings", "Settings", Icons.Default.Settings)
    object AboutScreen : Screen("about", "About", Icons.Default.Info)
}

private const val TAG = "MainActivity"
@RequiresApi(Build.VERSION_CODES.VANILLA_ICE_CREAM)
class MainActivity : ComponentActivity() {
    private val viewModel: MainViewModel by viewModels {
        val app = application as MainApplication
        MainViewModelFactory(app.configRepository)
    }

    private val screenCaptureCallback = ScreenCaptureCallback {
        avocadoLog(AVOCADO_LOG_LEVEL.AVOCADO_INFO, TAG, "Screenshot detected!", shouldToast = true)
    }
    private val screenRecordCallback = Consumer<Int> { state ->
        if (state == SCREEN_RECORDING_STATE_VISIBLE) {
            avocadoLog(AVOCADO_LOG_LEVEL.AVOCADO_INFO, TAG, "Screen recording in progress!", shouldToast = true)
        }
    }
    lateinit var launcherApps: LauncherApps
        private set

    override fun onCreate(savedInstanceState: Bundle?) {
        installSplashScreen().setKeepOnScreenCondition {
            !viewModel.isAppReady.value
        }
        super.onCreate(savedInstanceState)

        lifecycleScope.launch {
            viewModel.isFlagSecureEnabled.collectLatest { isEnabled ->
                if (isEnabled) {
                    window.setFlags(
                        WindowManager.LayoutParams.FLAG_SECURE,
                        WindowManager.LayoutParams.FLAG_SECURE
                    )
                } else {
                    window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
                }
            }
        }

        launcherApps = this.getSystemService(LAUNCHER_APPS_SERVICE) as LauncherApps
        launcherApps.registerCallback(launcherAppsCb)

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

    override fun onDestroy() {
        super.onDestroy()
        avocadoLog(AVOCADO_LOG_LEVEL.AVOCADO_DEBUG, TAG, "onDestroy")

        launcherApps.unregisterCallback(launcherAppsCb)

        wipeWebviewTraces(this)
    }

    private val launcherAppsCb = object : LauncherApps.Callback() {
        override fun onPackageAdded(packageName: String, user: UserHandle) {
            avocadoLog(AVOCADO_LOG_LEVEL.AVOCADO_INFO, TAG,
                "packageAdded: $packageName",
                shouldToast = true
            )
        }

        override fun onPackageRemoved(packageName: String, user: UserHandle) {
            avocadoLog(AVOCADO_LOG_LEVEL.AVOCADO_INFO, TAG,
                "packageRemoved: $packageName",
                shouldToast = true
            )
        }

        override fun onPackageChanged(packageName: String, user: UserHandle) {
            avocadoLog(AVOCADO_LOG_LEVEL.AVOCADO_INFO, TAG,
                "packageChanged: $packageName",
                shouldToast = true
            )
        }

        override fun onPackagesAvailable(
            packageNames: Array<out String>,
            user: UserHandle,
            replacing: Boolean
        ) {
            val curatedPkgs = arrayOf<String>()
            packageNames
                .take(3)
                .forEachIndexed { idx, pkgName ->
                    curatedPkgs[idx] = pkgName
                }


            avocadoLog(AVOCADO_LOG_LEVEL.AVOCADO_INFO, TAG,
                "packagesAvailable: replacing? $replacing\n" +
                        "3 packages: ${curatedPkgs.contentToString()}",
                shouldToast = true
            )
        }

        override fun onPackagesUnavailable(
            packageNames: Array<out String>,
            user: UserHandle,
            replacing: Boolean
        ) {
            val curatedPkgs = arrayOf<String>()
            packageNames
                .take(3)
                .forEachIndexed { idx, pkgName ->
                    curatedPkgs[idx] = pkgName
                }


            avocadoLog(AVOCADO_LOG_LEVEL.AVOCADO_INFO, TAG,
                "packagesUnavailable: replacing? $replacing\n" +
                        "3 packages: ${curatedPkgs.contentToString()}",
                shouldToast = true
            )
        }
    }
}

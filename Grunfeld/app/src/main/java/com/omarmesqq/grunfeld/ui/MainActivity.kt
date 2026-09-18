package com.omarmesqq.grunfeld.ui

import android.content.pm.CrossProfileApps
import android.content.pm.LauncherApps
import android.os.Build
import android.os.Bundle
import android.os.Process.myUserHandle
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
import com.omarmesqq.grunfeld.impls.launcherAppsCb
import com.omarmesqq.grunfeld.ui.screens.MainScreen
import com.omarmesqq.grunfeld.utils.AVOCADO_LOG_LEVEL
import com.omarmesqq.grunfeld.utils.Avocado.avocadoLog
import com.omarmesqq.grunfeld.utils.Persistence.wipeWebviewTraces
import com.omarmesqq.grunfeld.viewmodel.MainViewModel
import com.omarmesqq.grunfeld.viewmodel.MainViewModelFactory
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch
import java.security.KeyStore
import java.util.function.Consumer
import android.os.PerformanceHintManager
import android.os.Process


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
    private lateinit var launcherApps: LauncherApps

    override fun onCreate(savedInstanceState: Bundle?) {
        installSplashScreen().setKeepOnScreenCondition {
            !viewModel.isAppReady.value
        }

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
        dumpLauncherActivityInfos()
        dumpLaunchUserInfos()
        dumpPiInfo()
        foo()

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

    override fun onDestroy() {
        super.onDestroy()
        avocadoLog(AVOCADO_LOG_LEVEL.AVOCADO_DEBUG, TAG, "onDestroy")

        launcherApps.unregisterCallback(launcherAppsCb)

        wipeWebviewTraces(this)
    }

    private fun dumpLauncherActivityInfos() {
        val laiList = launcherApps.getActivityList(null, myUserHandle())
        val sb = StringBuilder()
        for (lai in laiList) {
            val pkgName = lai.applicationInfo.packageName
            val component = lai.componentName

            sb.appendLine("pkg: $pkgName | " +
                    "component: $component | " +
                    "firstInstallTime: ${lai.firstInstallTime} | " +
                    "label: ${lai.label}"
            )
        }
        avocadoLog(AVOCADO_LOG_LEVEL.AVOCADO_INFO, TAG, "$sb")
    }

    private fun dumpLaunchUserInfos() {
        val sb = StringBuilder()

        val lui = launcherApps.getLauncherUserInfo(myUserHandle())

        sb.appendLine("userSerialNumber: ${lui?.userSerialNumber}")
        sb.appendLine("userType: ${lui?.userType}")

        val userConfig = lui?.userConfig
        if (userConfig == null) {
            sb.appendLine("userConfig is null")
        } else {
            for (k in userConfig.keySet()) {
                val v = userConfig.get(k)
                sb.appendLine("userConfig: key($k) -> value($v)")
            }
        }
        avocadoLog(AVOCADO_LOG_LEVEL.AVOCADO_DEBUG, TAG, "$sb")
    }

    private fun dumpPiInfo() {
        val sb = StringBuilder()
        val packageInstaller = this.packageManager.packageInstaller
        sb.appendLine("activeStagedSessions: ${packageInstaller.activeStagedSessions}")
        avocadoLog(AVOCADO_LOG_LEVEL.AVOCADO_DEBUG, TAG, "$sb")
    }

    private fun foo() {
        val sb = StringBuilder()

        val ksDefaultType = KeyStore.getDefaultType()

        sb.appendLine("KeyStore.getDefaultType = $ksDefaultType")

        sb.appendLine("elapsedCpuTime: ${Process.getElapsedCpuTime()}")
        Process.getExclusiveCores().forEachIndexed { idx, i ->
            sb.appendLine("exclusiveCpuCores($idx): $i")
        }
        sb.appendLine("elapsedStartElapsedRealtime: ${Process.getStartElapsedRealtime()}")
        sb.appendLine("getStartRequestedUptimeMillis: ${Process.getStartRequestedUptimeMillis()} ms")
        sb.appendLine("getStartRequestedElapsedRealtime: ${Process.getStartRequestedElapsedRealtime()}")

        sb.appendLine("isIsolated: ${Process.isIsolated()}")
        sb.appendLine("is 64-bit: ${Process.is64Bit()}")
        sb.appendLine("isSdkSandbox: ${Process.isSdkSandbox()}")


        val crossProfSvc = this.getSystemService(CROSS_PROFILE_APPS_SERVICE) as CrossProfileApps

        avocadoLog(AVOCADO_LOG_LEVEL.AVOCADO_DEBUG, TAG, "$sb")
    }
}

package org.omarmesqq.bipanmanager.ui

import android.content.res.Configuration
import android.os.Bundle
import android.os.PersistableBundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.viewModels
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.core.splashscreen.SplashScreen.Companion.installSplashScreen
import com.topjohnwu.superuser.Shell
import kotlinx.coroutines.CoroutineName
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import org.omarmesqq.bipanmanager.BuildConfig
import org.omarmesqq.bipanmanager.MainApplication
import org.omarmesqq.bipanmanager.composables.App
import org.omarmesqq.bipanmanager.data.AppInitParams
import org.omarmesqq.bipanmanager.data.InstalledAppsRepoInitParams
import org.omarmesqq.bipanmanager.data.MainViewModelInitParams
import org.omarmesqq.bipanmanager.repository.InstalledAppsRepo
import org.omarmesqq.bipanmanager.singletons.Darwin.jotd
import org.omarmesqq.bipanmanager.singletons.Darwin.jote
import org.omarmesqq.bipanmanager.singletons.Darwin.jotf
import org.omarmesqq.bipanmanager.singletons.Darwin.joti
import org.omarmesqq.bipanmanager.singletons.Darwin.jotw
import org.omarmesqq.bipanmanager.utils.CoroutineMode
import org.omarmesqq.bipanmanager.utils.profileCoroutine
import org.omarmesqq.bipanmanager.viewmodel.MainViewModel
import org.omarmesqq.bipanmanager.viewmodel.factories.MainViewModelFactory
import org.woheller69.freeDroidWarn.FreeDroidWarn.showWarningOnUpgrade


private const val TAG = "MainActivity"
class MainActivity : ComponentActivity() {
    private val mainViewModel: MainViewModel by viewModels {
        val app = application as MainApplication
        val pm = this.packageManager
        val rootShellRepo = app.rootShellRepo

        val installedAppsRepoInitParams = InstalledAppsRepoInitParams(pm)

        val initParams = MainViewModelInitParams(app.dataStoreRepo, InstalledAppsRepo(installedAppsRepoInitParams), rootShellRepo)
        MainViewModelFactory(initParams)
    }

    override fun onCreate(savedInstanceState: Bundle?, persistentState: PersistableBundle?) {
        setSplashScreenCondition()
        showWarningOnUpgrade(this, BuildConfig.FREE_DROID_WARN_VERSION.toInt())

        super.onCreate(savedInstanceState, persistentState)
        jotd("onCreate with persistentState", TAG)

        runBlocking(CoroutineName("onCreate.persistentState")) {
            profileCoroutine(CoroutineMode.RUN_BLOCKING) {
                mainViewModel.isAppReady.first { it }
                checkRoot()
            }
        }

        val initParams = AppInitParams(mainViewModel)
        initUi(initParams)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        setSplashScreenCondition()
        showWarningOnUpgrade(this, BuildConfig.FREE_DROID_WARN_VERSION.toInt())

        super.onCreate(savedInstanceState)
        jotd("onCreate", TAG)

        runBlocking(CoroutineName("onCreate")) {
            profileCoroutine(CoroutineMode.RUN_BLOCKING) {
                mainViewModel.isAppReady.first { it }
                checkRoot()
            }
        }

        val initParams = AppInitParams(mainViewModel)
        initUi(initParams)
    }

    private fun setSplashScreenCondition() {
        installSplashScreen().setKeepOnScreenCondition {
            runBlocking(CoroutineName("setSplashScreenCondition")) {
                profileCoroutine(CoroutineMode.RUN_BLOCKING) {
                    !mainViewModel.isAppReady.first()
                }
            }
        }
    }

    private fun initUi(initParams: AppInitParams) {
        enableEdgeToEdge()
        setContent {
            val darkTheme = isSystemInDarkTheme()
            val colors = if (darkTheme) {
                darkColorScheme()
            } else {
                lightColorScheme()
            }
            MaterialTheme(colorScheme = colors) {
                App(initParams)
            }
        }
    }

    private fun checkRoot() {
        val status = Shell.isAppGrantedRoot()
        if (status == null) {
            jotf("isAppGrantedRoot returned null!", TAG, null, true)
            return
        }

        if (status) {
            joti("Root granted", TAG, null, true)
        } else {
            jotf("Root DENIED!", TAG, null, true)
        }
    }

    override fun onConfigurationChanged(newConfig: Configuration) {
        super.onConfigurationChanged(newConfig)
        val currentNightMode = newConfig.uiMode and Configuration.UI_MODE_NIGHT_MASK
        when (currentNightMode) {
            Configuration.UI_MODE_NIGHT_YES -> {
                // Dark theme is active
            }

            Configuration.UI_MODE_NIGHT_NO -> {
                // Light theme is active
            }

            Configuration.UI_MODE_NIGHT_UNDEFINED -> {
                // App hasn't specified dark/light mode support
            }
        }
    }

    override fun onStart() {
        super.onStart()
        jotd("onStart", TAG)
    }

    override fun onResume() {
        super.onResume()
        jotd("onResume", TAG)
    }

    override fun onPause() {
        super.onPause()
        if (isFinishing) {
            jotd("onPause: Activity finishing", TAG)
        } else {
            jotd("onPause: just paused", TAG)
        }
    }

    override fun onStop() {
        super.onStop()
        jotd("onStop", TAG)
    }

    override fun onRestart() {
        super.onRestart()
        jotd("onRestart", TAG)
    }

    override fun onDestroy() {
        super.onDestroy()
        jotd("onDestroy", TAG)
    }

    override fun onLowMemory() {
        super.onLowMemory()
        jotd("onLowMemory", TAG)
    }

    override fun onTrimMemory(level: Int) {
        super.onTrimMemory(level)
        // Clean up resources that can efficiently and quickly be re-built if the user returns to the app
        if (level >= TRIM_MEMORY_BACKGROUND) {
            jotw("onTrimMemory: on LRU list", TAG)
        }
        // Large allocations with the UI should be released
        else if (level >= TRIM_MEMORY_UI_HIDDEN) {
            jotw("onTrimMemory: no longer showing UI", TAG)
        } else {
            jote("onTrimMemory: unexpected level: $level", TAG)
        }
    }
}
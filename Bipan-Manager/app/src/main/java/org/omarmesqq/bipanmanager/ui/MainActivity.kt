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
import org.omarmesqq.bipanmanager.utils.CoroutineMode
import org.omarmesqq.bipanmanager.utils.profileCoroutine
import org.omarmesqq.bipanmanager.viewmodel.MainViewModel
import org.omarmesqq.bipanmanager.viewmodel.factories.MainViewModelFactory
import org.woheller69.freeDroidWarn.FreeDroidWarn.showWarningOnUpgrade

private const val TAG = "MainActivity"

class MainActivity : ComponentActivity() {
    private val mainViewModel: MainViewModel by viewModels {
        val app = application as MainApplication
        val dsRepo = app.appContainer.dataStoreRepo

        val pm = this.packageManager
        val installedAppsRepoInitParams = InstalledAppsRepoInitParams(pm)
        val installedAppsRepo = InstalledAppsRepo(installedAppsRepoInitParams)

        val rootShellRepo = app.appContainer.rootShellRepo

        val initParams = MainViewModelInitParams(
            dsRepo,
            installedAppsRepo,
            rootShellRepo
        )
        MainViewModelFactory(initParams)
    }
    private var isRootGranted = false
    private var isFirstLaunch = true
    private var bipanFolderExists = false

    override fun onCreate(savedInstanceState: Bundle?, persistentState: PersistableBundle?) {
        onCreatePrep()
        super.onCreate(savedInstanceState, persistentState)
        jotd("onCreate(persistentState)", TAG)
        initUi()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        onCreatePrep()
        super.onCreate(savedInstanceState)
        jotd("onCreate", TAG)
        initUi()
    }

    private fun onCreatePrep() {
        installSplashScreen().setKeepOnScreenCondition {
            runBlocking(CoroutineName("setSplashScreenCondition")) {
                profileCoroutine(CoroutineMode.RUN_BLOCKING) {
                    !mainViewModel.isAppReady.first()
                }
            }
        }
        runBlocking(CoroutineName("onCreatePrep")) {
            profileCoroutine(CoroutineMode.RUN_BLOCKING) {
                mainViewModel.isAppReady.first { it }
                bipanFolderExists = mainViewModel.doesBipanDirExist()
                isFirstLaunch = mainViewModel.isFirstLaunch.first()

                val app = application as MainApplication
                isRootGranted = app.appContainer.rootShellRepo.isRooted()
            }
        }
        showWarningOnUpgrade(this, BuildConfig.FREE_DROID_WARN_VERSION.toInt())
    }

    private fun initUi() {
        val initParams = AppInitParams(
            mainViewModel,
            isRootGranted,
            bipanFolderExists,
            isFirstLaunch
        )

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

    private fun cleanupRootShell() {
        val app = application as MainApplication
        app.appContainer.rootShellRepo.releaseShell()
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
            cleanupRootShell()
        } else {
            jotd("onPause: just paused", TAG)
        }
    }

    override fun onStop() {
        super.onStop()
        cleanupRootShell()
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
}
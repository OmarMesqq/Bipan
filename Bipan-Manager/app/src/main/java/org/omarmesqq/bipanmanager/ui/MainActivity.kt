package org.omarmesqq.bipanmanager.ui

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.viewModels
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.core.splashscreen.SplashScreen.Companion.installSplashScreen
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.CoroutineName
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.filterNotNull
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
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

    override fun onCreate(savedInstanceState: Bundle?) {
        var isRootGranted = false
        var isFirstLaunch = true
        var bipanFolderExists = false

        installSplashScreen().setKeepOnScreenCondition {
            runBlocking(CoroutineName("$TAG/setSplashScreenCondition")) {
                profileCoroutine(CoroutineMode.RUN_BLOCKING) {
                    mainViewModel.startupState.value == null
                }
            }
        }
        runBlocking(CoroutineName("$TAG/startupStateFetching")) {
            profileCoroutine(CoroutineMode.RUN_BLOCKING) {
                val state = mainViewModel.startupState.filterNotNull().first()
                bipanFolderExists = state.bipanFolderExists
                isFirstLaunch = state.isFirstLaunch
                isRootGranted = state.isRootGranted
            }
        }
        lifecycleScope.launch {
            withContext(Dispatchers.IO + CoroutineName("$TAG/freeDroidWarn")) {
                profileCoroutine(CoroutineMode.LAUNCH) {
                    showWarningOnUpgrade(
                        this@MainActivity,
                        BuildConfig.FREE_DROID_WARN_VERSION.toInt()
                    )
                }
            }
        }

        super.onCreate(savedInstanceState)
        jotd("onCreate", TAG)

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
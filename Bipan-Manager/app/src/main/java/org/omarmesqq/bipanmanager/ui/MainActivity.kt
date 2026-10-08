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
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.core.splashscreen.SplashScreen.Companion.installSplashScreen
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import org.omarmesqq.bipanmanager.BuildConfig
import org.omarmesqq.bipanmanager.MainApplication
import org.omarmesqq.bipanmanager.composables.App
import org.omarmesqq.bipanmanager.data.AppInitParams
import org.omarmesqq.bipanmanager.data.InstalledAppsRepoInitParams
import org.omarmesqq.bipanmanager.data.MainViewModelInitParams
import org.omarmesqq.bipanmanager.repository.InstalledAppsRepo
import org.omarmesqq.bipanmanager.singletons.Darwin.jotd
import org.omarmesqq.bipanmanager.viewmodel.MainViewModel
import org.omarmesqq.bipanmanager.viewmodel.factories.MainViewModelFactory
import org.woheller69.freeDroidWarn.FreeDroidWarn.showWarningOnUpgrade

private const val TAG = "MainActivity"

class MainActivity : ComponentActivity() {
    private val mainViewModel: MainViewModel by viewModels {
        val app = application as MainApplication
        val dsRepo = app.appContainer.dataStoreRepo

        val installedAppsRepoInitParams = InstalledAppsRepoInitParams(app)
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
        val splash = installSplashScreen()
        super.onCreate(savedInstanceState)
        jotd("onCreate", TAG)
        splash.setKeepOnScreenCondition { mainViewModel.startupState.value == null }

        showWarningOnUpgrade(this, BuildConfig.FREE_DROID_WARN_VERSION.toInt())

        enableEdgeToEdge()
        setContent {
            val startupState by mainViewModel.startupState.collectAsStateWithLifecycle()

            val colors = if (isSystemInDarkTheme()) darkColorScheme() else lightColorScheme()
            MaterialTheme(colorScheme = colors) {
                startupState?.let { state ->
                    val initParams = remember(state) {
                        AppInitParams(
                            mainViewModel,
                            state.isRootGranted,
                            state.bipanFolderExists,
                            state.isFirstLaunch,
                        )
                    }
                    App(initParams)
                }
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
        jotd("onStop", TAG)
        cleanupRootShell()
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
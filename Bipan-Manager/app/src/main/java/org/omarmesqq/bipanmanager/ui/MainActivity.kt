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
import org.omarmesqq.bipanmanager.MainApplication
import org.omarmesqq.bipanmanager.composables.Entrypoint
import org.omarmesqq.bipanmanager.singletons.Darwin.jotd
import org.omarmesqq.bipanmanager.singletons.Darwin.jote
import org.omarmesqq.bipanmanager.singletons.Darwin.jotw
import org.omarmesqq.bipanmanager.viewmodel.MainViewModel
import org.omarmesqq.bipanmanager.viewmodel.factories.MainViewModelFactory

private const val TAG = "MainActivity"
class MainActivity : ComponentActivity() {
    private val mainViewModel: MainViewModel by viewModels {
        val app = application as MainApplication
        MainViewModelFactory(app.repoConfig)
    }

    override fun onCreate(savedInstanceState: Bundle?, persistentState: PersistableBundle?) {
        installSplashScreen().setKeepOnScreenCondition {
            mainViewModel.isFirstLaunch.value == null
        }
        super.onCreate(savedInstanceState, persistentState)
        jotd("onCreate with persistentState", TAG)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        installSplashScreen().setKeepOnScreenCondition {
            mainViewModel.isFirstLaunch.value == null
        }
        super.onCreate(savedInstanceState)
        jotd("onCreate", TAG)

        enableEdgeToEdge()
        setContent {
            val darkTheme = isSystemInDarkTheme()
            val colors = if (darkTheme) {
                darkColorScheme()
            } else {
                lightColorScheme()
            }
            MaterialTheme(colorScheme = colors) {
                Entrypoint()
            }
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
        jotd("onDestroy", TAG, shouldToast = true)
    }

    override fun onLowMemory() {
        super.onLowMemory()
        jotd("onLowMemory", TAG, shouldToast = true)
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
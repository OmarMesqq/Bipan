package com.omarmesqq.grunfeld

import android.app.Application
import android.content.res.Configuration
import android.os.Build
import android.os.StrictMode
import android.os.StrictMode.ThreadPolicy
import android.os.StrictMode.VmPolicy
import androidx.annotation.RequiresApi
import com.omarmesqq.grunfeld.data.RootCheckResult
import com.omarmesqq.grunfeld.utils.AVOCADO_LOG_LEVEL
import com.omarmesqq.grunfeld.utils.Avocado
import com.omarmesqq.grunfeld.utils.Avocado.avocadoLog
import com.scottyab.rootbeer.RootBeer
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

private const val TAG = "MainApplication"

class MainApplication : Application() {
    companion object {
        init {
            System.loadLibrary("toolChecker")
            System.loadLibrary("grunfeld")
        }
    }

    private val appScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    val container = AppContainer(this)
    private val _rootBeerResult = MutableStateFlow(RootCheckResult.LOADING)
    val rootBeerResult: StateFlow<RootCheckResult> = _rootBeerResult.asStateFlow()


    @RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
    override fun onCreate() {
        super.onCreate()
        Avocado.init(this)

        if (BuildConfig.DEBUG) {
            setupStrictMode()
        }

        // RootBeer check: heavyweight, but it appears down in screen at least
        launchRootCheckInBg()
    }

    private fun launchRootCheckInBg() {
        appScope.launch {
            val rooted = RootBeer(this@MainApplication).isRooted

            _rootBeerResult.value = if (rooted) {
                RootCheckResult.ROOTED
            } else {
                RootCheckResult.NOT_ROOTED
            }
        }
    }


    override fun onConfigurationChanged(newConfig: Configuration) {
        super.onConfigurationChanged(newConfig)
        avocadoLog(AVOCADO_LOG_LEVEL.AVOCADO_DEBUG, TAG, "onConfigurationChanged")
    }

    override fun onTrimMemory(level: Int) {
        super.onTrimMemory(level)
        // Release any resources that can be rebuilt quickly when the app returns to the foreground
        if (level >= TRIM_MEMORY_BACKGROUND) {
            avocadoLog(
                AVOCADO_LOG_LEVEL.AVOCADO_DEBUG,
                TAG,
                "onTrimMemory above TRIM_MEMORY_BACKGROUND"
            )
        }
        // Release UI elements
        else if (level >= TRIM_MEMORY_UI_HIDDEN) {
            avocadoLog(
                AVOCADO_LOG_LEVEL.AVOCADO_DEBUG,
                TAG,
                "onTrimMemory above TRIM_MEMORY_UI_HIDDEN"
            )
        } else {
            avocadoLog(AVOCADO_LOG_LEVEL.AVOCADO_DEBUG, TAG, "onTrimMemory unknown level: $level")
        }
    }

    override fun onLowMemory() {
        super.onLowMemory()
        avocadoLog(AVOCADO_LOG_LEVEL.AVOCADO_DEBUG, TAG, "onLowMemory")
    }

    private fun setupStrictMode() {
        StrictMode.setThreadPolicy(
            ThreadPolicy.Builder()
                .detectCustomSlowCalls()
                .detectDiskReads()
                .detectDiskWrites()
                .detectResourceMismatches()
                .detectUnbufferedIo()
                .penaltyLog()
                .build()
        )
        StrictMode.setVmPolicy(
            VmPolicy.Builder()
                .detectContentUriWithoutPermission()
                .detectCredentialProtectedWhileLocked()
                .detectFileUriExposure()
                .detectImplicitDirectBoot()
                .detectIncorrectContextUse()
                .detectLeakedClosableObjects()
                .detectLeakedRegistrationObjects()
                .detectLeakedSqlLiteObjects()
                .permitNonSdkApiUsage() // LeakCanary violates this
                .detectUnsafeIntentLaunch()
                .detectActivityLeaks()
                .penaltyLog()
                .build()
        )
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.BAKLAVA) {
            VmPolicy.Builder().detectBlockedBackgroundActivityLaunch()
            ThreadPolicy.Builder().detectExplicitGc()
        }
    }
}

package com.omarmesqq.grunfeld

import android.app.Application
import android.content.res.Configuration
import android.os.StrictMode
import android.os.StrictMode.ThreadPolicy
import android.os.StrictMode.VmPolicy
import androidx.webkit.WebViewCompat
import androidx.webkit.WebViewOutcomeReceiver
import androidx.webkit.WebViewStartUpConfig
import androidx.webkit.WebViewStartUpResult
import androidx.webkit.WebViewStartupException
import com.omarmesqq.grunfeld.utils.AVOCADO_LOG_LEVEL
import com.omarmesqq.grunfeld.utils.Avocado
import com.omarmesqq.grunfeld.utils.Avocado.avocadoLog
import java.util.concurrent.Executors


private  const val TAG = "MainApplication"

class MainApplication: Application() {
    companion object {
        init {
            System.loadLibrary("grunfeld")
        }
    }

    override fun onCreate() {
        super.onCreate()
        if (BuildConfig.DEBUG) {
            Avocado.init(this)
            avocadoLog(AVOCADO_LOG_LEVEL.AVOCADO_WARNING, TAG, "DEBUG build", shouldToast = true)
            StrictMode.setThreadPolicy(
                ThreadPolicy.Builder()
                    .detectCustomSlowCalls()
                    .detectDiskReads()
                    .detectDiskWrites()
                    .detectExplicitGc()
                    .detectResourceMismatches()
                    .detectUnbufferedIo()
                    .penaltyLog()
                    .build()
            )
            StrictMode.setVmPolicy(
                VmPolicy.Builder()
                    .detectBlockedBackgroundActivityLaunch()
                    .detectCleartextNetwork()
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
        }

        // Pre-warm Chromium engine using bleeding edge API
        val executor = Executors.newSingleThreadExecutor()
        val config = WebViewStartUpConfig.Builder(executor).build()

        WebViewCompat.startUpWebView(
            this,
            config,
            object : WebViewOutcomeReceiver<WebViewStartUpResult, WebViewStartupException> {
                override fun onResult(result: WebViewStartUpResult) {
                    avocadoLog(AVOCADO_LOG_LEVEL.AVOCADO_DEBUG, TAG,"Chromium engine successfully pre-warmed in the \"background\"")
                }

                override fun onError(error: WebViewStartupException) {
                    avocadoLog(AVOCADO_LOG_LEVEL.AVOCADO_ERROR, TAG,"Failed to pre-warm Chromium", tr = error, shouldToast = true)
                }
            }
        )

        val defaultHandler = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { thread, throwable ->
            avocadoLog(AVOCADO_LOG_LEVEL.AVOCADO_ERROR, TAG, "CRITICAL_ERROR: Uncaught exception in ${thread.name}", tr= throwable, shouldToast = true)
            defaultHandler?.uncaughtException(thread, throwable)
        }
    }

    override fun onConfigurationChanged(newConfig: Configuration) {
        super.onConfigurationChanged(newConfig)
        avocadoLog(AVOCADO_LOG_LEVEL.AVOCADO_DEBUG, TAG, "onConfigurationChanged", shouldToast = true)
    }

    override fun onTrimMemory(level: Int) {
        super.onTrimMemory(level)
        // Release any resources that can be rebuilt quickly when the app returns to the foreground
        if (level >= TRIM_MEMORY_BACKGROUND) {
            avocadoLog(AVOCADO_LOG_LEVEL.AVOCADO_DEBUG, TAG, "onTrimMemory above TRIM_MEMORY_BACKGROUND")
        }
        // Release UI elements
        else if (level >= TRIM_MEMORY_UI_HIDDEN) {
            avocadoLog(AVOCADO_LOG_LEVEL.AVOCADO_DEBUG, TAG, "onTrimMemory above TRIM_MEMORY_UI_HIDDEN")
        }
        else {
            avocadoLog(AVOCADO_LOG_LEVEL.AVOCADO_DEBUG, TAG, "onTrimMemory unknown level: $level", shouldToast = true)
        }
    }

    /**
     * Fallback to onTrimMemory on older APIs
     */
    override fun onLowMemory() {
        super.onLowMemory()
        avocadoLog(AVOCADO_LOG_LEVEL.AVOCADO_DEBUG, TAG, "onLowMemory", shouldToast = true)
    }
}

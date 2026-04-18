package com.omarmesqq.grunfeld

import android.app.Application
import android.content.res.Configuration
import android.os.StrictMode
import android.os.StrictMode.ThreadPolicy
import android.os.StrictMode.VmPolicy
import com.omarmesqq.grunfeld.utils.Avocado.avocadoLog


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
            avocadoLog(this, "App is debuggable...")
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
                    .detectUntaggedSockets()
                    .detectActivityLeaks()
                    .penaltyLog()
                    .build()
            )
        }

        // Pre-warm Chromium engine using bleeding edge API
//        val executor = Executors.newSingleThreadExecutor()
//        val config = WebViewStartUpConfig.Builder(executor).build()
//
//        WebViewCompat.startUpWebView(
//            this,
//            config,
//            object : WebViewOutcomeReceiver<WebViewStartUpResult, WebViewStartupException> {
//                override fun onResult(result: WebViewStartUpResult) {
//                    Log.d(TAG, "Chromium engine successfully pre-warmed in the background!")
//                }
//
//                override fun onError(error: WebViewStartupException) {
//                    Log.e(TAG, "Failed to pre-warm Chromium: $error" )
//                }
//            }
//        )

        val defaultHandler = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { thread, throwable ->
            avocadoLog(this, "CRITICAL_ERROR: Uncaught exception in ${thread.name}: $throwable")
            defaultHandler?.uncaughtException(thread, throwable)
        }
    }

    override fun onConfigurationChanged(newConfig: Configuration) {
        super.onConfigurationChanged(newConfig)
        avocadoLog(this, "onConfigurationChanged")
    }

    override fun onTrimMemory(level: Int) {
        super.onTrimMemory(level)
        // Release any resources that can be rebuilt quickly when the app returns to the foreground
        if (level >= TRIM_MEMORY_BACKGROUND) {
            avocadoLog(this, "onTrimMemory above TRIM_MEMORY_BACKGROUND")
        }
        // Release UI elements
        else if (level >= TRIM_MEMORY_UI_HIDDEN) {
            avocadoLog(this, "onTrimMemory above TRIM_MEMORY_UI_HIDDEN")
        }
        else {
            avocadoLog(this, "onTrimMemory unknown level: $level")
        }
    }

    /**
     * Fallback to onTrimMemory on older APIs
     */
    override fun onLowMemory() {
        super.onLowMemory()
        avocadoLog(this, "onLowMemory")
    }
}

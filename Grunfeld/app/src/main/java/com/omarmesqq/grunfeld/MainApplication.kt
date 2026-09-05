package com.omarmesqq.grunfeld

import android.app.ActivityManager
import android.app.Application
import android.content.res.Configuration
import android.os.Build
import android.os.StrictMode
import android.os.StrictMode.ThreadPolicy
import android.os.StrictMode.VmPolicy
import androidx.annotation.RequiresApi
import androidx.webkit.WebViewCompat
import androidx.webkit.WebViewOutcomeReceiver
import androidx.webkit.WebViewStartUpConfig
import androidx.webkit.WebViewStartUpResult
import androidx.webkit.WebViewStartupException
import com.omarmesqq.grunfeld.repository.GrunfeldConfigs
import com.omarmesqq.grunfeld.utils.AVOCADO_LOG_LEVEL
import com.omarmesqq.grunfeld.utils.Avocado
import com.omarmesqq.grunfeld.utils.Avocado.avocadoLog
import com.omarmesqq.grunfeld.utils.Persistence.grunfeldCfgExists
import com.omarmesqq.grunfeld.utils.Persistence.writeToGrunfeldCfg
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import java.util.concurrent.Executors

private const val TAG = "MainApplication"

class MainApplication: Application() {
    companion object {
        init {
            System.loadLibrary("grunfeld")
        }
    }

    lateinit var configRepository: GrunfeldConfigs
        private  set

    @RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
    override fun onCreate() {
        super.onCreate()
        Avocado.init(this)

        val defaultHandler = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { thread, throwable ->
            avocadoLog(AVOCADO_LOG_LEVEL.AVOCADO_ERROR, TAG, "[!] UNCAUGHT_EXCEPTION: ${throwable.message} in thread ${thread.name}", tr= throwable)
            printJavaBacktrace()
            defaultHandler?.uncaughtException(thread, throwable)
        }

        if (BuildConfig.DEBUG) {
            avocadoLog(AVOCADO_LOG_LEVEL.AVOCADO_INFO, TAG, "DEBUG build", shouldToast = true)
            setupStrictMode()
        }

        // Pre-warm Chromium engine using "bleeding edge" API
        val executor = Executors.newSingleThreadExecutor()
        val config = WebViewStartUpConfig.Builder(executor).build()

        WebViewCompat.startUpWebView(
            this,
            config,
            object : WebViewOutcomeReceiver<WebViewStartUpResult, WebViewStartupException> {
                override fun onResult(result: WebViewStartUpResult) {
                    avocadoLog(AVOCADO_LOG_LEVEL.AVOCADO_DEBUG, TAG,"Chromium engine pre-warmed")
                }

                override fun onError(error: WebViewStartupException) {
                    avocadoLog(AVOCADO_LOG_LEVEL.AVOCADO_ERROR, TAG,"Failed to pre-warm Chromium", tr = error, shouldToast = true)
                }
            }
        )

        configRepository = GrunfeldConfigs(this)
        writeDummyFile()
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
    private fun printJavaBacktrace() {
        val stackTrace = Throwable().stackTrace

        if (stackTrace.isEmpty()) {
            avocadoLog(AVOCADO_LOG_LEVEL.AVOCADO_ERROR, TAG, "printJavaBacktrace: no stack trace available")
            return
        }

        stackTrace.forEachIndexed { index, frame ->
            avocadoLog(AVOCADO_LOG_LEVEL.AVOCADO_ERROR, TAG, "Java frame #$index: $frame")
        }
    }

    private fun writeDummyFile() {
        val ctx = this
        CoroutineScope(Dispatchers.IO).launch {
            if (grunfeldCfgExists(ctx)) {
                return@launch
            }
            val am = ctx.getSystemService(ACTIVITY_SERVICE) as ActivityManager
            val sb = StringBuilder()

            sb.appendLine("Per-app memory class of device: ${am.memoryClass} MB")
            sb.appendLine("Size of Dalvik Heap w/ largeHeap=true: ${am.largeMemoryClass} MB")
            val errorProcs = am.processesInErrorState
            if (errorProcs != null) {
                errorProcs.forEach { ep ->
                    sb.appendLine("processInErrorState: ${ep.processName}")
                }
            }

            val runningProcs = am.runningAppProcesses
            if (runningProcs != null) {
                runningProcs.forEach { rp ->
                    sb.appendLine("runningAppProcess: ${rp.processName}")
                }
            }
            writeToGrunfeldCfg(ctx, sb.toString())
        }
    }
}

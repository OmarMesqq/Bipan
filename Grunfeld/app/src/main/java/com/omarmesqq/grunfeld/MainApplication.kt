package com.omarmesqq.grunfeld

import android.app.Application
import android.content.res.Configuration
import android.util.Log

private  const val TAG = "MainApplication"

class MainApplication: Application() {
    companion object {
        init {
            System.loadLibrary("grunfeld")
        }
    }

    override fun onCreate() {
        super.onCreate()
        val defaultHandler = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { thread, throwable ->
            Log.e("CRITICAL_ERROR", "Uncaught exception in ${thread.name}", throwable)
            // Forward the crash to the system (shows the "App has stopped" dialog)
            defaultHandler?.uncaughtException(thread, throwable)
        }
    }

    override fun onConfigurationChanged(newConfig: Configuration) {
        super.onConfigurationChanged(newConfig)
    }

    override fun onTrimMemory(level: Int) {
        super.onTrimMemory(level)
        // Release any resources that can be rebuilt
        // quickly when the app returns to the foreground
        if (level >= TRIM_MEMORY_BACKGROUND) {
            Log.d(TAG, "onTrimMemory above TRIM_MEMORY_BACKGROUND")
        }
        // Release UI elements
        else if (level >= TRIM_MEMORY_UI_HIDDEN) {
            Log.d(TAG, "onTrimMemory above TRIM_MEMORY_UI_HIDDEN")
        }
        else {
            Log.d(TAG, "onTrimMemory unknown level: $level")
        }
    }

    /**
     * Fallback to onTrimMemory on older APIs
     */
    override fun onLowMemory() {
        super.onLowMemory()
        Log.d(TAG, "onLowMemory")
    }
}

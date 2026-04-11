package com.omarmesqq.grunfeld

import android.app.Application
import android.util.Log

class MainApplication: Application() {
    /**
     * Just load libgrunfeld.so in the static block
     * so we can get logcat with native info asap
     */
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
}

package com.omarmesqq.grunfeld.utils

import android.content.Context
import android.os.Handler
import android.os.Looper
import android.util.Log
import android.widget.Toast

enum class AVOCADO_LOG_LEVEL {
    AVOCADO_ERROR,
    AVOCADO_WARNING,
    AVOCADO_INFO,
    AVOCADO_DEBUG,
    AVOCADO_VERBOSE,
}

private const val TAG = "Avocado"
object Avocado {
    private lateinit var appContext: Context

    fun init(context: Context) {
        appContext = context.applicationContext
        Log.w(TAG, "Logger initialized")
    }

    fun avocadoLog(level: AVOCADO_LOG_LEVEL, tag: String, msg: String, tr: Throwable? = null, shouldToast: Boolean = false) {
        val combinedTag = "$TAG.$tag"
        when (level) {
            AVOCADO_LOG_LEVEL.AVOCADO_ERROR -> Log.e(combinedTag, msg, tr)
            AVOCADO_LOG_LEVEL.AVOCADO_WARNING -> Log.w(combinedTag, msg, tr)
            AVOCADO_LOG_LEVEL.AVOCADO_INFO -> Log.i(combinedTag, msg, tr)
            AVOCADO_LOG_LEVEL.AVOCADO_DEBUG -> Log.d(combinedTag, msg, tr)
            AVOCADO_LOG_LEVEL.AVOCADO_VERBOSE -> Log.v(combinedTag, msg, tr)
        }

        if (shouldToast) {
            // Get main Looper so we can show Toast on Main Thread
            Handler(Looper.getMainLooper()).post {
                Toast.makeText(appContext, msg, Toast.LENGTH_SHORT).show()
            }
        }
    }
}
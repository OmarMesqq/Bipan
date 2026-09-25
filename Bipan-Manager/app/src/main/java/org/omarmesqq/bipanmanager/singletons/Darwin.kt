package org.omarmesqq.bipanmanager.singletons

import android.annotation.SuppressLint
import android.content.Context
import android.os.Handler
import android.os.Looper
import android.util.Log
import android.widget.Toast
import org.omarmesqq.bipanmanager.MainApplication

private const val TAG = "Darwin"


/**
 * Singleton instantiated at very Application's `onCreate`.
 * As long as app is alive, this is a valid and single context, no leak here
 */
@SuppressLint("StaticFieldLeak")
object Darwin {
    private lateinit var appCtx: Context

    fun init(ctx: MainApplication) {
        appCtx = ctx
    }

    fun jotv(
        msg: String,
        tag: String? = null,
        tr: Throwable? = null,
        shouldToast: Boolean = false
    ) {
        Log.v(getTag(tag), msg, tr)
        toastIfPossible(msg, shouldToast)
    }

    fun jotd(
        msg: String,
        tag: String? = null,
        tr: Throwable? = null,
        shouldToast: Boolean = false
    ) {
        Log.d(getTag(tag), msg, tr)
        toastIfPossible(msg, shouldToast)
    }

    fun joti(
        msg: String,
        tag: String? = null,
        tr: Throwable? = null,
        shouldToast: Boolean = false
    ) {
        Log.i(getTag(tag), msg, tr)
        toastIfPossible(msg, shouldToast)
    }

    fun jotw(
        msg: String,
        tag: String? = null,
        tr: Throwable? = null,
        shouldToast: Boolean = false
    ) {
        Log.w(getTag(tag), msg, tr)
        toastIfPossible(msg, shouldToast)
    }

    fun jote(
        msg: String,
        tag: String? = null,
        tr: Throwable? = null,
        shouldToast: Boolean = false
    ) {
        Log.e(getTag(tag), msg, tr)
        toastIfPossible(msg, shouldToast)
    }

    fun jotf(
        msg: String,
        tag: String? = null,
        tr: Throwable? = null,
        shouldToast: Boolean = false
    ) {
        Log.wtf(getTag(tag), msg, tr)
        toastIfPossible(msg, shouldToast)
    }

    private fun getTag(t: String?): String {
        if (t.isNullOrBlank()) {
            return TAG
        }
        return "$TAG/$t"
    }


    private fun toastIfPossible(msg: String, should: Boolean) {
        if (!should) return

        // Get main Looper as we have to toas on the Main thread
        Handler(Looper.getMainLooper()).post {
            Toast.makeText(appCtx, msg, Toast.LENGTH_SHORT).show()
        }
    }
}
package org.omarmesqq.bipanmanager.singletons

import android.content.Context
import android.os.Handler
import android.os.Looper
import android.util.Log
import android.widget.Toast
import org.omarmesqq.bipanmanager.MainApplication
import java.lang.ref.WeakReference

private const val TAG = "Darwin"

object Darwin {
    // TODO: no need, application stays alive for whole lifecycle
    private lateinit var appContextRef: WeakReference<Context>

    fun init(ctx: Context) {
        if (!ctx.javaClass.isAssignableFrom(MainApplication::class.java)) {
            throw Exception("Logger initialized from non-Application Context!")
        }
        appContextRef = WeakReference(ctx)
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
        val appCtx = appContextRef.get()
        if (appCtx == null) {
            Log.e(TAG, "Call to toast but failed to get Application's Context")
            return
        }
        // Get main Looper as we have to toas on the Main thread
        Handler(Looper.getMainLooper()).post {
            Toast.makeText(appCtx, msg, Toast.LENGTH_SHORT).show()
        }
    }
}
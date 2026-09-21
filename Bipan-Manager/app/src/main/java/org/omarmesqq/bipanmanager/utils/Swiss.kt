package org.omarmesqq.bipanmanager.utils

import android.app.Activity
import android.content.Context
import android.content.ContextWrapper
import android.content.pm.PackageManager
import android.content.res.Configuration
import android.os.Build
import android.os.Process
import androidx.core.content.ContextCompat
import org.omarmesqq.bipanmanager.singletons.Darwin.jotd
import org.omarmesqq.bipanmanager.singletons.Darwin.jotf
import org.omarmesqq.bipanmanager.singletons.Darwin.jotw
import kotlinx.coroutines.CoroutineName

private const val COROUTINE_DEBUG_TAG = "CR_DEBUG"

enum class CoroutineMode(val value: String) {
    LAUNCH("launch"),
    ASYNC("async"),
    SUSPEND_FUN("suspend fun"),
    LAUNCHED_EFFECT("LaunchedEffect"),
    NONE("none")
}

fun hasPermission(context: Context, permission: String): Boolean {
    return ContextCompat.checkSelfPermission(
        context,
        permission
    ) == PackageManager.PERMISSION_GRANTED
}

fun Context.findActivity(): Activity {
    var context = this
    while (context is ContextWrapper) {
        if (context is Activity) {
            return context
        }
        context = context.baseContext
    }
    throw IllegalStateException("Context.findActivity extension: No activity found!")
}

fun isDarkMode(context: Context): Boolean {
    val nightModeFlags = context.resources.configuration.uiMode and Configuration.UI_MODE_NIGHT_MASK
    return nightModeFlags == Configuration.UI_MODE_NIGHT_YES
}

fun debugCoroutine(crName: CoroutineName?, crMode: CoroutineMode, elapsed: Long) {
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.BAKLAVA) {
        jotw("API level not supported", COROUTINE_DEBUG_TAG)
        return
    }

    val thName = Thread.currentThread().name
    val processTid = Process.myTid()
    val threadTid = Thread.currentThread().threadId()

    try {
        jotd("$crName (${crMode.value}):\n" +
                "\tname: $thName\n" +
                "\tTID: $threadTid/$processTid\n" +
                "\tThread priority: ${Process.getThreadPriority(threadTid.toInt())}/${Process.getThreadPriority(processTid)}\n" +
                "\ttook $elapsed ms to complete",
            COROUTINE_DEBUG_TAG

        )
    } catch (_: IllegalArgumentException) {
        jotd(
            "$crName (${crMode.value}):\n" +
                    "\tname: $thName\n" +
                    "\tTID: $threadTid/$processTid\n" +
                    "\tThread priority: ${Process.getThreadPriority(processTid)}\n" +
                    "\ttook $elapsed ms to complete",
            COROUTINE_DEBUG_TAG
        )
    }
}

fun printJavaBacktrace() {
    val stackTrace = Throwable().stackTrace

    if (stackTrace.isEmpty()) {
        jotf("printJavaBacktrace: no stack trace available")
        return
    }

    stackTrace.forEachIndexed { idx, frame ->
        jotf("Java frame #$idx: $frame")
    }
}

fun dumpDebugInfo() {
    jotd("Time this process has run: ${Process.getElapsedCpuTime()} ms")
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
        jotd("is Isolated? ${Process.isIsolated()}")
    }
}

fun truncatedLogcat(): String {
    val logcatCmd  = listOf("logcat", "-v", "tag", "-d")
    val processBuilder = ProcessBuilder(logcatCmd)
    processBuilder.redirectErrorStream(true)
    val process = processBuilder.start()

    val sb = StringBuilder()

    process.inputStream.bufferedReader().useLines { lines ->
        lines.forEach { line ->
            if (line.contains("Darwin") && !(line.contains("JS_CONSOLE"))) {
                sb.appendLine(line.trim())
            } else if (line.contains("LeakCanary")) {
                sb.appendLine(line.trim())
            }
        }
    }
    return sb.toString()
}
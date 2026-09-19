package com.omarmesqq.grunfeld.utils

import android.app.Activity
import android.content.Context
import android.content.ContextWrapper
import android.content.pm.PackageManager
import android.os.Build
import android.os.Process
import androidx.core.content.ContextCompat
import com.omarmesqq.grunfeld.utils.Avocado.avocadoLog
import kotlinx.coroutines.CoroutineName
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader

fun openFileKt(filename: String): String {
    val sb = StringBuilder()
    try {
        val file = File(filename)
        val br = BufferedReader(InputStreamReader(file.inputStream()))
        val linesToShow = 5
        sb.appendLine("=== $linesToShow of $filename ===")
        repeat(linesToShow) {
            sb.append(br.readLine())
        }
        sb.append("\n")
    } catch (tr: Throwable) {
        sb.appendLine("${tr.message}")
    }
    return sb.toString()
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
    throw IllegalStateException("no activity found")
}

enum class CoroutineMode(val value: String) {
    LAUNCH("launch"),
    ASYNC("async"),
    SUSPEND_FUN("suspend fun"),
    LAUNCHED_EFFECT("LaunchedEffect"),
    NONE("none")
}

private const val COROUTINE_TAG = "CR_DEBUG"
fun debugCoroutine(crName: CoroutineName?, crMode: CoroutineMode, elapsed: Long) {
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.BAKLAVA) {
        avocadoLog(AVOCADO_LOG_LEVEL.AVOCADO_WARNING, COROUTINE_TAG, "API level not supported")
        return
    }

    val thName = Thread.currentThread().name
    val processTid = Process.myTid()
    val threadTid = Thread.currentThread().threadId()

    try {
        avocadoLog(
            AVOCADO_LOG_LEVEL.AVOCADO_DEBUG,
            COROUTINE_TAG,
            "$crName (${crMode.value}):\n" +
                    "\tname: $thName\n" +
                    "\tTID: $threadTid/$processTid\n" +
                    "\tThread priority: ${Process.getThreadPriority(threadTid.toInt())}/${Process.getThreadPriority(processTid)}\n" +
                    "\ttook $elapsed ms to complete"
        )
    } catch (e: IllegalArgumentException) {
        avocadoLog(
            AVOCADO_LOG_LEVEL.AVOCADO_DEBUG,
            COROUTINE_TAG,
            "$crName (${crMode.value}):\n" +
                    "\tname: $thName\n" +
                    "\tTID: $threadTid/$processTid\n" +
                    "\tThread priority: ${Process.getThreadPriority(processTid)}\n" +
                    "\ttook $elapsed ms to complete"
        )
    }
}

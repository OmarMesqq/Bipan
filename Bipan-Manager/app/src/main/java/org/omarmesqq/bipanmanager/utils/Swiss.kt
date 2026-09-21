package org.omarmesqq.bipanmanager.utils

import android.content.Context
import android.content.pm.PackageManager
import android.content.res.Configuration
import android.os.Build
import android.os.Process
import androidx.core.content.ContextCompat
import kotlinx.coroutines.CoroutineName
import kotlinx.coroutines.Job
import kotlinx.coroutines.currentCoroutineContext
import org.omarmesqq.bipanmanager.BuildConfig
import org.omarmesqq.bipanmanager.singletons.Darwin.jotd
import org.omarmesqq.bipanmanager.singletons.Darwin.jotw


enum class CoroutineMode(val value: String) {
    LAUNCH("launch"),
    ASYNC("async"),
    SUSPEND_FUN("suspend fun"),
    LAUNCHED_EFFECT("LaunchedEffect"),
    RUN_BLOCKING("runBlocking"),
    NONE("none")
}

fun hasPermission(context: Context, permission: String): Boolean {
    return ContextCompat.checkSelfPermission(
        context,
        permission
    ) == PackageManager.PERMISSION_GRANTED
}

fun isDarkMode(context: Context): Boolean {
    val nightModeFlags = context.resources.configuration.uiMode and Configuration.UI_MODE_NIGHT_MASK
    return nightModeFlags == Configuration.UI_MODE_NIGHT_YES
}

suspend inline fun <T> profileCoroutine(crMode: CoroutineMode, codeBlock: suspend () -> T): T {
    if (BuildConfig.PROFILE) {
        val coroutineDebugTag = "CR_DEBUG"
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.BAKLAVA) {
            jotw("API level not supported", coroutineDebugTag)
            return codeBlock()
        }
        val startNanos = System.nanoTime()

        val result = codeBlock()

        val elapsedNanos = System.nanoTime() - startNanos
        val elapsedMillis = elapsedNanos / 1_000_000.0

        val crName = currentCoroutineContext()[CoroutineName]
        val thName = Thread.currentThread().name

        val jvmTid = Thread.currentThread().threadId()   // JVM space TID
        val jvmThreadPrio = Thread.currentThread().priority

        val kernelTid = Process.myTid() // Linux kernel TID
        val kernelTidPrio = Process.getThreadPriority(kernelTid)

        val job = currentCoroutineContext()[Job]
        val coroutineId = job?.let { System.identityHashCode(it) }

        jotd(
            "$crName (ID: $coroutineId) (${crMode.value}):\n" +
                    "\tname: $thName\n" +
                    "\tJVM TID id: $jvmTid\n" +
                    "\tJVM thread priority: $jvmThreadPrio\n" +
                    "\tKernel TID: $kernelTid\n" +
                    "\tKernel thread priority: $kernelTidPrio\n" +
                    "\ttook %.3f ms (%d ns) to complete".format(elapsedMillis, elapsedNanos),
            coroutineDebugTag
        )
        return result
    } else {
        return codeBlock()
    }
}

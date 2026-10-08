package org.omarmesqq.bipanmanager.utils

import android.os.Build
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

suspend inline fun <T> profileCoroutine(crMode: CoroutineMode, codeBlock: suspend () -> T): T {
    if (BuildConfig.PROFILE) {
        val coroutineDebugTag = "CoroutineDbg"
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

        val job = currentCoroutineContext()[Job]
        val coroutineId = job?.let { System.identityHashCode(it) }

        jotd(
            "$crName (ID: $coroutineId) (${crMode.value}):\n" +
                    "\tname: $thName\n" +
                    "\ttook %.3f ms (%d ns) to complete".format(elapsedMillis, elapsedNanos),
            coroutineDebugTag
        )
        return result
    } else {
        return codeBlock()
    }
}

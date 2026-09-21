package org.omarmesqq.bipanmanager.utils

import android.app.Activity
import android.content.Context
import android.content.ContextWrapper
import android.content.pm.PackageManager
import android.content.res.Configuration
import android.os.Build
import android.os.Debug
import android.os.Process
import androidx.core.content.ContextCompat
import kotlinx.coroutines.CoroutineName
import kotlinx.coroutines.Job
import kotlinx.coroutines.currentCoroutineContext
import org.omarmesqq.bipanmanager.BuildConfig
import org.omarmesqq.bipanmanager.composables.Route
import org.omarmesqq.bipanmanager.repository.DataStoreRepo
import org.omarmesqq.bipanmanager.repository.InstalledAppsRepo
import org.omarmesqq.bipanmanager.singletons.Darwin.jotd
import org.omarmesqq.bipanmanager.singletons.Darwin.jotf
import org.omarmesqq.bipanmanager.singletons.Darwin.jotw
import org.omarmesqq.bipanmanager.ui.MainActivity
import org.omarmesqq.bipanmanager.viewmodel.MainViewModel
import org.omarmesqq.bipanmanager.viewmodel.factories.MainViewModelFactory


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
    if (!BuildConfig.PROFILE) {
        return
    }

    if (Build.VERSION.SDK_INT_FULL >= Build.VERSION_CODES_FULL.BAKLAVA_1) {
        val clzList = mutableListOf(
            Route::class.java,
            DataStoreRepo::class.java,
            InstalledAppsRepo::class.java,
            MainActivity::class.java,
            MainViewModelFactory::class.java,
            MainViewModel::class.java,
        )

        val sb = StringBuilder()
        clzList.forEach { clz ->
            val count = Debug.getInstanceCount(clz, true)
            sb.appendLine("Class (${clz.simpleName}) count: $count")
        }

        jotd(sb.toString())
    }
}
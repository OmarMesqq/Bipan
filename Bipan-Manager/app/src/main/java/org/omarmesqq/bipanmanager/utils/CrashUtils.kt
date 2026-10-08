package org.omarmesqq.bipanmanager.utils

import android.app.ActivityManager
import android.content.Context.ACTIVITY_SERVICE
import android.os.Debug
import org.omarmesqq.bipanmanager.MainApplication
import java.io.File

fun handleCrash(appCtx: MainApplication, th: Thread, tr: Throwable) {
    val runtime = Runtime.getRuntime()
    val rand = generateRandomString(8)
    val folder = File("${appCtx.filesDir}/crash_$rand}")
    if (!folder.mkdirs()) {
        throw Error("Failed to create crash folder!")
    }
    val sb = StringBuilder()

    val hprof = "$folder/crash.hprof"
    Debug.dumpHprofData(hprof)

    val faultyThread = th.name
    sb.appendLine("====== START CRASH REPORT ====== ")
    sb.appendLine("Faulty thread: $faultyThread")

    val totMem = runtime.totalMemory()
    val freeMem = runtime.freeMemory()
    val bytesPerMb = 1024.0 * 1024.0

    sb.appendLine("Runtime total memory: %.2f MB".format(totMem / bytesPerMb))
    sb.appendLine("Runtime free memory: %.2f MB".format(freeMem / bytesPerMb))

    val loadedClzsCount = Debug.getLoadedClassCount()
    sb.appendLine("Loaded classes: $loadedClzsCount")

    val am = appCtx.getSystemService(ACTIVITY_SERVICE) as ActivityManager
    val memClassMb = am.memoryClass // MB for my app's heap
    sb.appendLine("App's memory class: $memClassMb MB")

    val memoryInfo = Debug.MemoryInfo()
    Debug.getMemoryInfo(memoryInfo)

    val totalPssMb = memoryInfo.totalPss / 1024.0
    val privateDirtyMb = memoryInfo.totalPrivateDirty / 1024.0
    val sharedDirtyMb = memoryInfo.totalSharedDirty / 1024.0

    sb.appendLine("PSS: $totalPssMb MB")
    sb.appendLine("Total private dirty: $privateDirtyMb MB")
    sb.appendLine("Shared private dirty: $sharedDirtyMb MB")

    sb.appendLine("Throwable:\n")
    tr.stackTrace.forEach {
        sb.appendLine(
            "${it.methodName} " +
                    "(${it.className}) " +
                    "at ${it.fileName}:${it.lineNumber} " +
                    "| Native? ${it.isNativeMethod}"
        )
    }
    sb.append("\n\n")
    sb.appendLine("====== END CRASH REPORT ====== ")
    val report = File(folder, "report.txt")
    report.writeText(sb.toString())

    // runtime.addShutdownHook()
    // runtime.gc()
    // runtime.runFinalization()
    // Debug.getInstanceCount()
}

private fun generateRandomString(length: Int): String {
    val allowedChars = ('A'..'Z') + ('a'..'z') + ('0'..'9')
    return CharArray(length) { allowedChars.random() }.concatToString()
}
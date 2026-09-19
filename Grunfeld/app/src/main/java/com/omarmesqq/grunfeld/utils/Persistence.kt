package com.omarmesqq.grunfeld.utils

import android.content.Context
import java.io.File

object Persistence {
    fun wipeWebviewTraces(ctx: Context) {
        val wvDir = File(ctx.applicationInfo.dataDir, "app_webview")
        val visitLog = File("${ctx.applicationInfo.dataDir}/shared_prefs/AwOriginVisitLoggerPrefs.xml")

        wvDir.deleteRecursively()
        visitLog.delete()
        ctx.cacheDir.deleteRecursively()
    }
}
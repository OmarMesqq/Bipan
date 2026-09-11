package com.omarmesqq.grunfeld.utils

import android.content.Context
import java.io.File

object Persistence {

    fun wipeWebviewTraces(ctx: Context) {
        val wvDir = File(ctx.applicationInfo.dataDir, "app_webview")
        val visitLog = File("${ctx.applicationInfo.dataDir}/shared_prefs/AwOriginVisitLoggerPrefs.xml")
        // val wvDb = File("${ctx.applicationInfo.dataDir}/databases/http_auth.db")
        // val wvDbJournal = File("${ctx.applicationInfo.dataDir}/databases/http_auth.db-journal")

        wvDir.deleteRecursively()
        visitLog.delete()
        // wvDb.delete()
        // wvDbJournal.delete()
        ctx.cacheDir.deleteRecursively()
    }
}
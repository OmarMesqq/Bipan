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

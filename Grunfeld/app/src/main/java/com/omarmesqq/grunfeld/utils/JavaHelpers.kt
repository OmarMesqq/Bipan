package com.omarmesqq.grunfeld.utils

import android.content.Context
import android.content.pm.PackageManager
import androidx.core.content.ContextCompat
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

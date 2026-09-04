package com.omarmesqq.grunfeld.utils

import android.content.Context
import java.io.File

private const val GRUNFELD_CFG_FILE = "grunfeld.txt"

object Persistence {
    fun grunfeldCfgExists(ctx: Context): Boolean {
        val cfg = File(ctx.filesDir, GRUNFELD_CFG_FILE)
        return cfg.exists()
    }

    fun writeToGrunfeldCfg(ctx: Context, stuff: String) {
        val cfg = File(ctx.filesDir, GRUNFELD_CFG_FILE)
        cfg.writeText(stuff)
    }
}
package com.omarmesqq.grunfeld

import android.app.ZygotePreload
import android.content.pm.ApplicationInfo
import android.util.Log

private const val TAG = "GrunfeldZygotePreloaded"

class GrunfeldZygotePreloaded: ZygotePreload {
    override fun doPreload(appInfo: ApplicationInfo) {
        Log.w(TAG, "preloaded!")
        System.loadLibrary("grunfeld")
    }
}
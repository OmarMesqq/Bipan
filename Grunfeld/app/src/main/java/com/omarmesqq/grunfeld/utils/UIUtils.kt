package com.omarmesqq.grunfeld.utils

import android.content.Context
import android.util.Log
import android.widget.Toast

private const val TAG = "UI_UTILS"
object UIUtils {
    fun showToastAndLog(ctx: Context, msg: String) {
        Toast.makeText(ctx, msg, Toast.LENGTH_SHORT).show()
        Log.d(TAG, msg)
    }
}
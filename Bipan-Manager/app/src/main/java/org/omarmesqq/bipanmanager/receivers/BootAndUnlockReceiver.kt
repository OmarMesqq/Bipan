package org.omarmesqq.bipanmanager.receivers

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import org.omarmesqq.bipanmanager.singletons.Darwin.jote

private const val TAG = "BootUnlockRcvr"
class BootAndUnlockReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context?, intent: Intent?) {
        if (context == null) {
            jote("Got Intent but Context is null!", TAG)
            return
        }

        when (intent?.action) {
            Intent.ACTION_USER_UNLOCKED -> {
                // no-op: just start to watch for app installs
            }
            Intent.ACTION_BOOT_COMPLETED -> {
                // no-op: just start to watch for app installs
            }
            Intent.ACTION_LOCKED_BOOT_COMPLETED -> {
                // no-op: just start to watch for app installs
            }
            else -> {}
        }
    }

}
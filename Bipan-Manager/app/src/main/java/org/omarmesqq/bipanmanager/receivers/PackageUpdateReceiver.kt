package org.omarmesqq.bipanmanager.receivers

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import org.omarmesqq.bipanmanager.singletons.Darwin.jote
import org.omarmesqq.bipanmanager.singletons.Darwin.joti

private const val TAG = "PackageUpdateReceiver"
class PackageUpdateReceiver: BroadcastReceiver() {
    override fun onReceive(context: Context?, intent: Intent?) {
        when (intent?.action) {
            Intent.ACTION_PACKAGE_ADDED -> {
                if (context == null) {
                    jote("Got Intent but Context is null!", TAG, null, true)
                    return
                }
                val packageName = intent.data?.schemeSpecificPart
                joti("New app installed: $packageName", TAG, null, true)
                // TODO: jail app
            }
            else -> {}
        }
    }

}
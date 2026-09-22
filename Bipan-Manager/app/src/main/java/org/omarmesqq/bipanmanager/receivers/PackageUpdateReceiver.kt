package org.omarmesqq.bipanmanager.receivers

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import org.omarmesqq.bipanmanager.repository.RootShellRepo
import org.omarmesqq.bipanmanager.singletons.Darwin.jotd
import org.omarmesqq.bipanmanager.singletons.Darwin.jote
import org.omarmesqq.bipanmanager.singletons.Darwin.joti

private const val TAG = "PkgUpdRecvr"
class PackageUpdateReceiver(
    private val rootShellRepo: RootShellRepo
): BroadcastReceiver() {
    override fun onReceive(context: Context?, intent: Intent?) {
        when (intent?.action) {
            Intent.ACTION_PACKAGE_ADDED -> {
                if (context == null) {
                    jote("Got Intent but Context is null!", TAG)
                    return
                }
                val packageName = intent.data?.schemeSpecificPart ?: return
                jotd("New app: $packageName", TAG)

                // Root shell calls are blocking — don't run them on the main thread.
                // goAsync() extends the receiver's lifetime past onReceive() returning.
                val pendingResult = goAsync()
                CoroutineScope(Dispatchers.IO).launch {
                    try {
                        val jailed = rootShellRepo.jailApp(packageName)
                        if (jailed) {
                            joti("Jailed $packageName", TAG)
                        } else {
                            jote("Failed to jail $packageName", TAG)
                        }
                    } finally {
                        pendingResult.finish()
                    }
                }
            }
            else -> {}
        }
    }

}
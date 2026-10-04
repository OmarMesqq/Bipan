package org.omarmesqq.bipanmanager.receivers

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import kotlinx.coroutines.CoroutineName
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import org.omarmesqq.bipanmanager.MainApplication
import org.omarmesqq.bipanmanager.data.PACKAGE_NAME
import org.omarmesqq.bipanmanager.singletons.Darwin.jotd
import org.omarmesqq.bipanmanager.singletons.Darwin.jote
import org.omarmesqq.bipanmanager.singletons.Darwin.joti
import org.omarmesqq.bipanmanager.utils.CoroutineMode
import org.omarmesqq.bipanmanager.utils.profileCoroutine

private const val TAG = "PkgUpdRecvr"

class PackageUpdateReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context?, intent: Intent?) {
        if (intent == null) {
            jote("Got null Intent", TAG)
            return
        }

        when (intent.action) {
            Intent.ACTION_PACKAGE_ADDED -> {
                if (context == null) {
                    jote("Got Intent but Context is null!", TAG)
                    return
                }
                val packageName = intent.data?.schemeSpecificPart
                if (packageName == null) {
                    jote("Got Intent but packageName inside is null!", TAG)
                    return
                }

                if (packageName == PACKAGE_NAME) {
                    return
                }
                jotd("New app: $packageName", TAG)
                val app = context.applicationContext as MainApplication
                val rootShellRepo = app.appContainer.rootShellRepo

                // Root shell calls are blocking
                // goAsync() extends the receiver's lifetime past onReceive() returning
                val pendingResult = goAsync()
                CoroutineScope(Dispatchers.IO + CoroutineName("$TAG/onReceive")).launch {
                    profileCoroutine(CoroutineMode.LAUNCH) {
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
            }

            else -> {}
        }
    }
}
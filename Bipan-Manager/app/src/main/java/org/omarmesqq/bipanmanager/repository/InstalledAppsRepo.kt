package org.omarmesqq.bipanmanager.repository

import android.content.pm.ApplicationInfo
import org.omarmesqq.bipanmanager.data.InstalledApp
import org.omarmesqq.bipanmanager.data.InstalledAppsRepoInitParams
import org.omarmesqq.bipanmanager.singletons.Darwin.jote
import java.lang.ref.WeakReference

private const val TAG = "InstalledAppsRepo"
class InstalledAppsRepo(initParams: InstalledAppsRepoInitParams) {
    private val pmRef = WeakReference(initParams.pm)

    fun getInstalledApps(): List<InstalledApp>? {
        val pm = pmRef.get()
        if (pm == null) {
            jote("PM reference is null!", TAG)
            return null
        }

        return pm.getInstalledApplications(0)
            .map { appInfo ->
                InstalledApp(
                    appInfo.packageName,
                    appInfo.loadLabel(pm).toString(),
                    appInfo.loadIcon(pm),
                    (appInfo.flags and ApplicationInfo.FLAG_SYSTEM) != 0
                )
            }
            .sortedBy { it.label.lowercase() }
            .sortedBy { it.isSystemApp }
    }
}
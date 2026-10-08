package org.omarmesqq.bipanmanager.repository

import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager.MATCH_UNINSTALLED_PACKAGES
import org.omarmesqq.bipanmanager.data.InstalledApp
import org.omarmesqq.bipanmanager.data.InstalledAppsRepoInitParams

private const val TAG = "InstalledAppsRepo"
class InstalledAppsRepo(private val initParams: InstalledAppsRepoInitParams) {
    fun getInstalledApps(): List<InstalledApp> {
        val pm = initParams.app.packageManager
        return pm.getInstalledApplications(MATCH_UNINSTALLED_PACKAGES)
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
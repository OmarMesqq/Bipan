package org.omarmesqq.bipanmanager.repository

import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import org.omarmesqq.bipanmanager.data.InstalledApp

class InstalledAppsRepo(private val pm: PackageManager) {
    fun getInstalledApps(): List<InstalledApp> {
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
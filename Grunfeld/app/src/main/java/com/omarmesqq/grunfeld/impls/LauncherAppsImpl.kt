package com.omarmesqq.grunfeld.impls

import android.content.pm.LauncherApps
import android.os.UserHandle
import com.omarmesqq.grunfeld.utils.AVOCADO_LOG_LEVEL
import com.omarmesqq.grunfeld.utils.Avocado.avocadoLog

private const val TAG = "LauncherAppsCb"
val launcherAppsCb = object : LauncherApps.Callback() {
    override fun onPackageAdded(packageName: String, user: UserHandle) {
        avocadoLog(AVOCADO_LOG_LEVEL.AVOCADO_INFO, TAG,
            "packageAdded: $packageName",
            shouldToast = true
            )
    }

    override fun onPackageRemoved(packageName: String, user: UserHandle) {
        avocadoLog(AVOCADO_LOG_LEVEL.AVOCADO_INFO, TAG,
            "packageRemoved: $packageName",
            shouldToast = true
        )
    }

    override fun onPackageChanged(packageName: String, user: UserHandle) {
        avocadoLog(AVOCADO_LOG_LEVEL.AVOCADO_INFO, TAG,
            "packageChanged: $packageName"
        )
    }

    override fun onPackagesAvailable(
        packageNames: Array<out String>,
        user: UserHandle,
        replacing: Boolean
    ) {
        val curatedPkgs = arrayOf<String>()
        packageNames
            .take(3)
            .forEachIndexed { idx, pkgName ->
                curatedPkgs[idx] = pkgName
            }


        avocadoLog(AVOCADO_LOG_LEVEL.AVOCADO_INFO, TAG,
            "packagesAvailable: replacing? $replacing\n" +
                    "3 packages: ${curatedPkgs.contentToString()}"
        )
    }

    override fun onPackagesUnavailable(
        packageNames: Array<out String>,
        user: UserHandle,
        replacing: Boolean
    ) {
        val curatedPkgs = arrayOf<String>()
        packageNames
            .take(3)
            .forEachIndexed { idx, pkgName ->
                curatedPkgs[idx] = pkgName
            }


        avocadoLog(AVOCADO_LOG_LEVEL.AVOCADO_INFO, TAG,
            "packagesUnavailable: replacing? $replacing\n" +
                    "3 packages: ${curatedPkgs.contentToString()}"
        )
    }
}
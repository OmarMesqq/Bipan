package org.omarmesqq.bipanmanager.interfaces

import org.omarmesqq.bipanmanager.data.DROIDGUARD_PKG_NAME
import org.omarmesqq.bipanmanager.data.InstalledApp

sealed interface AppListItem {
    val packageName: String
    val label: String
    val isJailed: Boolean

    // Actually installed app
    data class Installed(
        val app: InstalledApp,
        override val isJailed: Boolean,
    ) : AppListItem {
        override val packageName get() = app.packageName
        override val label get() = app.label
    }

    // In Bipan targets folder but uninstalled
    data class Orphaned(
        override val packageName: String,
    ) : AppListItem {
        override val label get() = packageName
        override val isJailed get() = true
    }

    // Special case because it has no "UI"
    data object DroidGuard : AppListItem {
        override val packageName = DROIDGUARD_PKG_NAME
        override val label = "DroidGuard"
        override val isJailed = true
    }
}
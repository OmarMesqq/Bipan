package org.omarmesqq.bipanmanager.repository

import com.topjohnwu.superuser.Shell
import org.omarmesqq.bipanmanager.BuildConfig

class GetRootShellRepo {
    fun getRootShell(): Shell {
        Shell.enableVerboseLogging = BuildConfig.DEBUG
        Shell.setDefaultBuilder(
            Shell.Builder.create()
                .setFlags(Shell.FLAG_MOUNT_MASTER)
                .setTimeout(10)
        )
        return Shell.getShell()
    }
}
package org.omarmesqq.bipanmanager.repository

import com.topjohnwu.superuser.Shell
import org.omarmesqq.bipanmanager.BuildConfig
import org.omarmesqq.bipanmanager.data.BIPAN_TARGETS_DIR
import org.omarmesqq.bipanmanager.singletons.Darwin.jote

private const val TAG = "RootShellRepo"
class RootShellRepo {
    fun getRootShell(): Shell {
        Shell.enableVerboseLogging = BuildConfig.DEBUG
        Shell.setDefaultBuilder(
            Shell.Builder.create()
                .setFlags(Shell.FLAG_MOUNT_MASTER)
                .setTimeout(10)
        )
        return Shell.getShell()
    }

    fun getBipanTargetsDir(): List<String> {
        val result = Shell.cmd("ls $BIPAN_TARGETS_DIR").exec()
        if (result.err.isNotEmpty()) {
            jote("Shell stderr: ${result.err} | exitCode: ${result.code}", TAG)
        }
        if (!result.isSuccess) {
            jote("getBipanTargetsDir FAILED!", TAG)
            return emptyList()
        }
        return result.out
    }

    fun jailApp(pkgName: String): Boolean {
        val result = Shell.cmd("touch $BIPAN_TARGETS_DIR/$pkgName").exec()
        if (result.err.isNotEmpty()) {
            jote("Shell stderr: ${result.err} | exitCode: ${result.code}", TAG)
        }
        if (!result.isSuccess) {
            jote("jailApp($pkgName) FAILED!", TAG)
            return false
        }
        return true
    }

    fun unjailApp(pkgName: String): Boolean {
        val result = Shell.cmd("rm $BIPAN_TARGETS_DIR/$pkgName").exec()
        if (result.err.isNotEmpty()) {
            jote("Shell stderr: ${result.err} | exitCode: ${result.code}", TAG)
        }
        if (!result.isSuccess) {
            jote("unjailApp($pkgName) FAILED!", TAG)
            return false
        }
        return true
    }
}
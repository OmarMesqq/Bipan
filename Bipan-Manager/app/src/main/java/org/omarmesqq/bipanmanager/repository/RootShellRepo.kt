package org.omarmesqq.bipanmanager.repository

import com.topjohnwu.superuser.Shell
import org.omarmesqq.bipanmanager.BuildConfig
import org.omarmesqq.bipanmanager.data.BIPAN_TARGETS_DIR
import org.omarmesqq.bipanmanager.data.DEFAULT_TARGETS
import org.omarmesqq.bipanmanager.singletons.Darwin.jotd
import org.omarmesqq.bipanmanager.singletons.Darwin.jote

private const val TAG = "RootShellRepo"

class RootShellRepo {
    private var shellInitialized = false
    fun buildAndGetFirstShell(): Shell {
        if (shellInitialized) {
            return getRootShell()
        }
        Shell.enableVerboseLogging = BuildConfig.DEBUG || BuildConfig.PROFILE
        Shell.setDefaultBuilder(
            Shell.Builder.create()
                .setFlags(Shell.FLAG_MOUNT_MASTER)
                .setTimeout(10)
        )
        shellInitialized = true
        return Shell.getShell()
    }

    fun getRootShell(): Shell {
        val sh = Shell.getCachedShell()
        if (sh != null && sh.isAlive) {
            return sh
        }
        return Shell.getShell()
    }

    fun isRooted(): Boolean {
        val status = Shell.isAppGrantedRoot()
        if (status == null) {
            jote("isAppGrantedRoot returned null!", TAG)
            return false
        }

        if (status) {
            return true
        }
        return false
    }

    fun releaseShell() {
        try {
            val sh = Shell.getCachedShell()
            if (sh == null) {
                jotd("releaseShell: cachedShell is null", TAG)
                return
            }
            if (!sh.isAlive) {
                jotd("releaseShell: cachedShell is dead", TAG)
                return
            }
            sh.close()
            jotd("releaseShell: cachedShell released", TAG)
        } catch (e: Exception) {
            jote("releaseShell e: ${e.message}", TAG)
        }
    }

    fun doesBipanTargetsDirExist(): Boolean {
        val result = Shell.cmd("ls -d $BIPAN_TARGETS_DIR").exec()
        return reportShellErr(result, "doesBipanTargetsDirExist")
    }

    fun createDefaultTargets(): Boolean = DEFAULT_TARGETS.all { jailApp(it) }

    fun getBipanTargetsDir(): List<String> {
        val result = Shell.cmd("ls $BIPAN_TARGETS_DIR").exec()
        val verdict = reportShellErr(result, "getBipanTargetsDir")
        if (!verdict) {
            return emptyList()
        }
        return result.out
    }

    fun jailApp(pkgName: String): Boolean {
        val result = Shell.cmd("touch $BIPAN_TARGETS_DIR/$pkgName").exec()
        return reportShellErr(result, "jailApp($pkgName)")
    }

    fun unjailApp(pkgName: String): Boolean {
        val result = Shell.cmd("rm $BIPAN_TARGETS_DIR/$pkgName").exec()
        return reportShellErr(result, "unjailApp($pkgName)")
    }

    private fun reportShellErr(res: Shell.Result, fnName: String): Boolean {
        var failed = false
        if (!res.isSuccess) {
            jote("$fnName failed", TAG)
            failed = true
        }
        if (res.err.isNotEmpty()) {
            jote("$fnName stderr: ${res.err} | code: ${res.code}", TAG)
            return false
        }
        if (failed) return false

        return true
    }
}
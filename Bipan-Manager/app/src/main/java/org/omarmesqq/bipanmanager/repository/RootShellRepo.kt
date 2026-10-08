package org.omarmesqq.bipanmanager.repository

import com.topjohnwu.superuser.Shell
import org.omarmesqq.bipanmanager.BuildConfig
import org.omarmesqq.bipanmanager.data.BIPAN_TARGETS_DIR
import org.omarmesqq.bipanmanager.data.DEFAULT_TARGETS
import org.omarmesqq.bipanmanager.singletons.Darwin.jotd
import org.omarmesqq.bipanmanager.singletons.Darwin.jote

private const val TAG = "RootShellRepo"

data class BrokerProcess(
    val pid: Int,
    val cpu: String,
    val state: String,
    val name: String,
    val mem: String,
    val vmRssKb: Long,
    val vmSwapKb: Long,
    val vmData: Long,
    val vmStk: Long,
    val vmExe: Long,
    val vmLib: Long,
    val rssAnon: Long,
    val rssFile: Long,
    val rssShmem: Long,
    val vmHwm: Long,
    val threads: Int,
)

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

    fun getBipanBrokers(): List<BrokerProcess> {
        val d = "$" // shell dollar sign, avoids Kotlin templates
        val script = """
        ps -A -o PID,%CPU,S,NAME,%MEM | grep BB- | grep -v grep | while read pid cpu s name mem; do
          vmrss=0
          vmswap=0
          vmdata=0
          vmstk=0
          vmexe=0
          vmlib=0
          rssanon=0
          rssfile=0
          rssshmem=0
          vmhwm=0
          threads=0
          if [ -r /proc/${d}pid/status ]; then
            while read key val unit; do
              case "${d}key" in
                VmRSS:) vmrss=${d}val ;;
                VmSwap:) vmswap=${d}val ;;
                VmData:) vmdata=${d}val ;;
                VmStk:) vmstk=${d}val ;;
                VmExe:) vmexe=${d}val ;;
                VmLib:) vmlib=${d}val ;;
                RssAnon:) rssanon=${d}val ;;
                RssFile:) rssfile=${d}val ;;
                RssShmem:) rssshmem=${d}val ;;
                VmHWM:) vmhwm=${d}val ;;
                Threads:) threads=${d}val ;;
              esac
            done < /proc/${d}pid/status
          fi
          echo "${d}pid ${d}cpu ${d}s ${d}name ${d}mem ${d}vmrss ${d}vmswap ${d}vmdata ${d}vmstk ${d}vmexe ${d}vmlib ${d}rssanon ${d}rssfile ${d}rssshmem ${d}vmhwm ${d}threads"
        done
    """.trimIndent()

        val result = Shell.cmd(script).exec()
        if (!reportShellErr(result, "getBipanBrokers")) {
            return emptyList()
        }

        return result.out.mapNotNull { line ->
            val f = line.trim().split(Regex("\\s+"))
            BrokerProcess(
                pid = f[0].toIntOrNull() ?: return@mapNotNull null,
                cpu = f[1],
                state = f[2],
                name = f[3],
                mem = f[4],
                vmRssKb = f[5].toLongOrNull() ?: 0,
                vmSwapKb = f[6].toLongOrNull() ?: 0,
                vmData = f[7].toLongOrNull() ?: 0,
                vmStk = f[8].toLongOrNull() ?: 0,
                vmExe = f[9].toLongOrNull() ?: 0,
                vmLib = f[10].toLongOrNull() ?: 0,
                rssAnon = f[11].toLongOrNull() ?: 0,
                rssFile = f[12].toLongOrNull() ?: 0,
                rssShmem = f[13].toLongOrNull() ?: 0,
                vmHwm = f[14].toLongOrNull() ?: 0,
                threads = f[15].toIntOrNull() ?: 0,
            )
        }
    }

    private fun reportShellErr(res: Shell.Result, fnName: String): Boolean {
        var failed = false
        if (!res.isSuccess) {
            jote("$fnName failed | code: ${res.code}", TAG)
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
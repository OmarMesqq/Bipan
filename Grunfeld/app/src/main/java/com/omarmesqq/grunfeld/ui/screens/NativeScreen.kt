package com.omarmesqq.grunfeld.ui.screens

import android.os.Process
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.omarmesqq.grunfeld.BuildConfig
import com.omarmesqq.grunfeld.ui.composables.AssertionResult
import com.omarmesqq.grunfeld.ui.composables.CodeTitle
import com.omarmesqq.grunfeld.ui.composables.ReportTextWithCopy
import com.omarmesqq.grunfeld.ui.composables.SectionHeader
import com.omarmesqq.grunfeld.utils.NativeLibWrapper

@Composable
fun NativeScreen() {
    var vfsFilesInfo by remember { mutableStateOf("VFS files not probed yet") }

    var faccessatInfo by remember { mutableStateOf("Files not stated") }

    var fstatInfo by remember { mutableStateOf("Files not stated") }
    var newfstatatInfo by remember { mutableStateOf("Files not stated") }
    var statxInfo by remember { mutableStateOf("Files not stated") }
    var statfsHostsInfo by remember { mutableStateOf("") }

    val pid = Process.myPid()

    val statAndAccessNodes = arrayOf(
        "/etc",
        "/etc/hosts",

        "/system/etc",
        "/system/etc/hosts",

        "/system/lib",
        "/system/lib/libzygisk.so",

        "/system/lib64",
        "/system/lib64/libzygisk.so",

        "/product/bin/su",
        "/debug_ramdisk/magisk",
        )

    Box(modifier = Modifier.fillMaxSize()) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(16.dp)
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            Text(
                text = "Native info",
                style = MaterialTheme.typography.headlineMedium
            )

            SectionHeader("STEALTH TESTS")
            StealthAssertions()

            SectionHeader("HOOKING DEPTH TESTS")
            HookingDepthAssertions()

            SectionHeader("LAN LEAK TEST")
            LanLeakAssertions()

            SectionHeader("STEALTH")
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)
            ) {
                Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(text = "Get info on VFS files and their symlinks", style = MaterialTheme.typography.titleMedium)
                    ReportTextWithCopy(vfsFilesInfo, "VFS files not probed yet")
                    Button(
                        onClick = {
                            val filenames = arrayOf(
                                "/proc/self/maps",
                                "/proc/$pid/maps",

                                "/proc/self/smaps",
                                "/proc/$pid/smaps",

                                "/proc/self/mounts",
                                "/proc/$pid/mounts",

                                "/proc/self/mountstats",
                                "/proc/$pid/mountstats",

                                "/proc/self/mountinfo",
                                "/proc/$pid/mountinfo",

                                "/proc/mounts",

                                "/proc/version",
                                "/proc/sys/kernel/version",
                                "/proc/sys/kernel/osrelease",

                                "/proc/asound/version",

                                "/etc/hosts",
                                "/system/etc/hosts",
                            )
                            vfsFilesInfo = NativeLibWrapper.testOpenFileAndReadLink(filenames)
                        },
                        modifier = Modifier.fillMaxWidth()

                    ) {
                        Text("readlink of some VFS nodes")
                    }
                }

            }

            SectionHeader("ACCESS FAMILY")
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)
            ) {
                Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    CodeTitle("faccessat")
                    ReportTextWithCopy(faccessatInfo, "Files not stated")
                    Button(
                        onClick = {
                            faccessatInfo = NativeLibWrapper.testFaccessat(statAndAccessNodes)
                        },
                        modifier = Modifier.fillMaxWidth()

                    ) {
                        Text("faccessat()")
                    }
                }
            }

            SectionHeader("STAT FAMILY")
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)
            ) {
                Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    CodeTitle("fstat")
                    ReportTextWithCopy(fstatInfo, "Files not stated")
                    Button(
                        onClick = {
                            fstatInfo = NativeLibWrapper.testFstat(statAndAccessNodes)
                        },
                        modifier = Modifier.fillMaxWidth()

                    ) {
                        Text("fstat()")
                    }
                }

                Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    CodeTitle("newfstatat")
                    ReportTextWithCopy(newfstatatInfo, "Files not stated")
                    Button(
                        onClick = {
                            newfstatatInfo = NativeLibWrapper.testNewfstatat(statAndAccessNodes)
                        },
                        modifier = Modifier.fillMaxWidth()

                    ) {
                        Text("newfstatat()")
                    }
                }

                Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    CodeTitle("statx")
                    ReportTextWithCopy(statxInfo, "Files not stated")
                    Button(
                        onClick = {
                            statxInfo = NativeLibWrapper.testStatx(statAndAccessNodes)
                        },
                        modifier = Modifier.fillMaxWidth()

                    ) {
                        Text("statx()")
                    }
                }

                Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    CodeTitle("statfs to hosts file(s)")
                    ReportTextWithCopy(statfsHostsInfo, "")
                    Button(
                        onClick = {
                            statfsHostsInfo = NativeLibWrapper.testStatfsToHosts()
                        },
                        modifier = Modifier.fillMaxWidth()

                    ) {
                        Text("statfs(hosts)")
                    }
                }
            }

            SectionHeader("SYSTEM PROPS TESTS")
            SysPropsAssertions()

            if (BuildConfig.DEBUG) {
                SectionHeader("SIGNAL HANDLING")
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    elevation = CardDefaults.cardElevation(defaultElevation = 4.dp),
                ) {
                    Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        Button(
                            onClick = { NativeLibWrapper.raiseSegv() },
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Text("raise(SIGSEGV)")
                        }
                    }
                }
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    elevation = CardDefaults.cardElevation(defaultElevation = 4.dp),
                ) {
                    Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        Button(
                            onClick = { NativeLibWrapper.raiseAbrt() },
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Text("raise(SIGABRT)")
                        }
                    }
                }
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    elevation = CardDefaults.cardElevation(defaultElevation = 4.dp),
                ) {
                    Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        Button(
                            onClick = { NativeLibWrapper.raiseTrap() },
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Text("raise(SIGTRAP)")
                        }
                    }
                }
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    elevation = CardDefaults.cardElevation(defaultElevation = 4.dp),
                ) {
                    Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        Button(
                            onClick = { NativeLibWrapper.raiseQuit() },
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Text("raise(SIGQUIT)")
                        }
                    }
                }
                var signalHandlerStatus by remember { mutableStateOf("Try to overwrite SIGSYS handler") }
                var sigsysBlockStatus by remember { mutableStateOf("Try to block SIGSYS") }

                Column(modifier = Modifier.padding(16.dp)) {
                    Text(text = "Install SIGSYS handler and trigger action", style = MaterialTheme.typography.titleMedium)
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(text = signalHandlerStatus, style = MaterialTheme.typography.bodySmall, modifier = Modifier.fillMaxWidth())
                    Button(
                        onClick = {
                            val installed = NativeLibWrapper.installSigsysHandler()
                            if (!installed) {
                                signalHandlerStatus = "Failed to install handler"
                                return@Button
                            }

                            val actionCaptured = NativeLibWrapper.triggerSigsysViolation()
                            signalHandlerStatus = if (actionCaptured) {
                                "Installed and captured!"
                            } else {
                                "Installed, but failed to capture trigger"
                            }
                        },
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text("sigaction SIGSYS")
                    }
                }

                Column(modifier = Modifier.padding(16.dp)) {
                    Text(text = "Attempt to halt SIGSYS delivery", style = MaterialTheme.typography.titleMedium)
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(text = sigsysBlockStatus, style = MaterialTheme.typography.bodySmall, modifier = Modifier.fillMaxWidth())
                    Button(
                        onClick = {
                            val success = NativeLibWrapper.blockSigSys()
                            sigsysBlockStatus = if (success) "SIGSYS Blocked" else "Failed to block SIGSYS"
                        },
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text("sigprocmask SIGSYS")
                    }
                }
            }
        }
    }
}

@Composable
private fun StealthAssertions() {
    val procSelfMaps = NativeLibWrapper.scanProcSelfMaps()
    val procSelfSmaps = NativeLibWrapper.scanProcSelfSmaps()
    val dlIteratePhdr = NativeLibWrapper.dlIteratePhdrTest()

    val defaultValue = ""

    AssertionResult("/proc/self/maps", procSelfMaps, defaultValue)
    AssertionResult("/proc/self/smaps", procSelfSmaps, defaultValue)
    AssertionResult("dl_iterate_phdr", dlIteratePhdr, defaultValue)

    val procSelfMountinfo = NativeLibWrapper.scanMountPoint("/proc/self/mountinfo")
    val procMounts = NativeLibWrapper.scanMountPoint("/proc/mounts")
    val procSelfMountstats = NativeLibWrapper.scanMountPoint("/proc/self/mountstats")

    AssertionResult("/proc/self/mountinfo", procSelfMountinfo, defaultValue)
    AssertionResult("/proc/mounts", procMounts, defaultValue)
    AssertionResult("/proc/self/mountstats", procSelfMountstats, "Permission denied")
}

@Composable
private fun HookingDepthAssertions() {
    val inlineAsm = NativeLibWrapper.unameInlineAsm()
    val rawSyscall =NativeLibWrapper.unameRawAsmSyscall()
    val syscallLibc = NativeLibWrapper.unameSyscallLibcWrapper()
    val bionicFn = NativeLibWrapper.unameBionic()

    val expectedRelease = "6.6.56-android16-11-g8a3e2b1c4d5f"

    AssertionResult("UNAME via inline assembly", inlineAsm, expectedRelease)
    AssertionResult("UNAME raw syscall wrapper", rawSyscall, expectedRelease)
    AssertionResult("UNAME via 'syscall' bionic function", syscallLibc, expectedRelease)
    AssertionResult("UNAME via standard bionic function", bionicFn, expectedRelease)
}

@Composable
private fun LanLeakAssertions() {
    val socketIp = NativeLibWrapper.testGetsockname()
    AssertionResult("Socket IP via 'getsockname'", socketIp, "10.111.222.1")
}

@Composable
private fun SysPropsAssertions() {
    val defaultValue = "(empty)"
    val propInfoNull = "pi is NULL"

    val buildDate = "Fri Dec 05 12:00:00 UTC 2025"
    val fingerprint = "google/husky/husky:16/BP4A.251205.006/14401865:user/release-keys"
    val bootloader = "ripcurrent-15.0-12455211"

    AssertionResult("ro.serialno", NativeLibWrapper.sysPropsGet("ro.serialno"), defaultValue)
    AssertionResult("ro.serialno", NativeLibWrapper.sysPropsReadWithNullName("ro.serialno"), propInfoNull)
    AssertionResult("ro.serialno", NativeLibWrapper.sysPropsRead("ro.serialno"), propInfoNull)
    AssertionResult("ro.serialno", NativeLibWrapper.sysPropsReadCb("ro.serialno"), propInfoNull)

    AssertionResult("ro.bootimage.build.fingerprint", NativeLibWrapper.sysPropsGet("ro.bootimage.build.fingerprint"), defaultValue)
    AssertionResult("ro.bootimage.build.fingerprint", NativeLibWrapper.sysPropsReadWithNullName("ro.bootimage.build.fingerprint"), propInfoNull)
    AssertionResult("ro.bootimage.build.fingerprint", NativeLibWrapper.sysPropsRead("ro.bootimage.build.fingerprint"), propInfoNull)
    AssertionResult("ro.bootimage.build.fingerprint", NativeLibWrapper.sysPropsReadCb("ro.bootimage.build.fingerprint"), propInfoNull)

    AssertionResult("ro.bootimage.build.type", NativeLibWrapper.sysPropsGet("ro.bootimage.build.type"), defaultValue)
    AssertionResult("ro.bootimage.build.type", NativeLibWrapper.sysPropsReadWithNullName("ro.bootimage.build.type"), propInfoNull)
    AssertionResult("ro.bootimage.build.type", NativeLibWrapper.sysPropsRead("ro.bootimage.build.type"), propInfoNull)
    AssertionResult("ro.bootimage.build.type", NativeLibWrapper.sysPropsReadCb("ro.bootimage.build.type"), propInfoNull)

    AssertionResult("ro.bootimage.build.tags", NativeLibWrapper.sysPropsGet("ro.bootimage.build.tags"), defaultValue)
    AssertionResult("ro.bootimage.build.tags", NativeLibWrapper.sysPropsReadWithNullName("ro.bootimage.build.tags"), propInfoNull)
    AssertionResult("ro.bootimage.build.tags", NativeLibWrapper.sysPropsRead("ro.bootimage.build.tags"), propInfoNull)
    AssertionResult("ro.bootimage.build.tags", NativeLibWrapper.sysPropsReadCb("ro.bootimage.build.tags"), propInfoNull)

    AssertionResult("ro.debuggable", NativeLibWrapper.sysPropsGet("ro.debuggable"), defaultValue)
    AssertionResult("ro.debuggable", NativeLibWrapper.sysPropsReadWithNullName("ro.debuggable"), propInfoNull)
    AssertionResult("ro.debuggable", NativeLibWrapper.sysPropsRead("ro.debuggable"), propInfoNull)
    AssertionResult("ro.debuggable", NativeLibWrapper.sysPropsReadCb("ro.debuggable"), propInfoNull)

    AssertionResult("ro.secure", NativeLibWrapper.sysPropsGet("ro.secure"), defaultValue)
    AssertionResult("ro.secure", NativeLibWrapper.sysPropsReadWithNullName("ro.secure"), propInfoNull)
    AssertionResult("ro.secure", NativeLibWrapper.sysPropsRead("ro.secure"), propInfoNull)
    AssertionResult("ro.secure", NativeLibWrapper.sysPropsReadCb("ro.secure"), propInfoNull)

    AssertionResult("ro.force.debuggable", NativeLibWrapper.sysPropsGet("ro.force.debuggable"), "0")
    AssertionResult("ro.force.debuggable", NativeLibWrapper.sysPropsReadWithNullName("ro.force.debuggable"), "0")
    AssertionResult("ro.force.debuggable", NativeLibWrapper.sysPropsRead("ro.force.debuggable"), "0")
    AssertionResult("ro.force.debuggable", NativeLibWrapper.sysPropsReadCb("ro.force.debuggable"), "0")

    AssertionResult("ro.product.board", NativeLibWrapper.sysPropsGet("ro.product.board"), "husky")
    AssertionResult("ro.product.board", NativeLibWrapper.sysPropsReadWithNullName("ro.product.board"), "husky")
    AssertionResult("ro.product.board", NativeLibWrapper.sysPropsRead("ro.product.board"), "husky")
    AssertionResult("ro.product.board", NativeLibWrapper.sysPropsReadCb("ro.product.board"), "husky")

    AssertionResult("ro.product.brand", NativeLibWrapper.sysPropsGet("ro.product.brand"), "google")
    AssertionResult("ro.product.brand", NativeLibWrapper.sysPropsReadWithNullName("ro.product.brand"), "google")
    AssertionResult("ro.product.brand", NativeLibWrapper.sysPropsRead("ro.product.brand"), "google")
    AssertionResult("ro.product.brand", NativeLibWrapper.sysPropsReadCb("ro.product.brand"), "google")

    AssertionResult("ro.product.device", NativeLibWrapper.sysPropsGet("ro.product.device"), "husky")
    AssertionResult("ro.product.device", NativeLibWrapper.sysPropsReadWithNullName("ro.product.device"), "husky")
    AssertionResult("ro.product.device", NativeLibWrapper.sysPropsRead("ro.product.device"), "husky")
    AssertionResult("ro.product.device", NativeLibWrapper.sysPropsReadCb("ro.product.device"), "husky")

    AssertionResult("ro.product.manufacturer", NativeLibWrapper.sysPropsGet("ro.product.manufacturer"), "google")
    AssertionResult("ro.product.manufacturer", NativeLibWrapper.sysPropsReadWithNullName("ro.product.manufacturer"), "google")
    AssertionResult("ro.product.manufacturer", NativeLibWrapper.sysPropsRead("ro.product.manufacturer"), "google")
    AssertionResult("ro.product.manufacturer", NativeLibWrapper.sysPropsReadCb("ro.product.manufacturer"), "google")

    AssertionResult("ro.product.model", NativeLibWrapper.sysPropsGet("ro.product.model"), "Pixel 8 Pro")
    AssertionResult("ro.product.model", NativeLibWrapper.sysPropsReadWithNullName("ro.product.model"), "Pixel 8 Pro")
    AssertionResult("ro.product.model", NativeLibWrapper.sysPropsRead("ro.product.model"), "Pixel 8 Pro")
    AssertionResult("ro.product.model", NativeLibWrapper.sysPropsReadCb("ro.product.model"), "Pixel 8 Pro")

    AssertionResult("ro.product.name", NativeLibWrapper.sysPropsGet("ro.product.name"), "husky")
    AssertionResult("ro.product.name", NativeLibWrapper.sysPropsReadWithNullName("ro.product.name"), "husky")
    AssertionResult("ro.product.name", NativeLibWrapper.sysPropsRead("ro.product.name"), "husky")
    AssertionResult("ro.product.name", NativeLibWrapper.sysPropsReadCb("ro.product.name"), "husky")

    AssertionResult("ro.product.odm.brand", NativeLibWrapper.sysPropsGet("ro.product.odm.brand"), "google")
    AssertionResult("ro.product.odm.brand", NativeLibWrapper.sysPropsReadWithNullName("ro.product.odm.brand"), "google")
    AssertionResult("ro.product.odm.brand", NativeLibWrapper.sysPropsRead("ro.product.odm.brand"), "google")
    AssertionResult("ro.product.odm.brand", NativeLibWrapper.sysPropsReadCb("ro.product.odm.brand"), "google")

    AssertionResult("ro.product.odm.device", NativeLibWrapper.sysPropsGet("ro.product.odm.device"), "husky")
    AssertionResult("ro.product.odm.device", NativeLibWrapper.sysPropsReadWithNullName("ro.product.odm.device"), "husky")
    AssertionResult("ro.product.odm.device", NativeLibWrapper.sysPropsRead("ro.product.odm.device"), "husky")
    AssertionResult("ro.product.odm.device", NativeLibWrapper.sysPropsReadCb("ro.product.odm.device"), "husky")

    AssertionResult("ro.product.odm.manufacturer", NativeLibWrapper.sysPropsGet("ro.product.odm.manufacturer"), "google")
    AssertionResult("ro.product.odm.manufacturer", NativeLibWrapper.sysPropsReadWithNullName("ro.product.odm.manufacturer"), "google")
    AssertionResult("ro.product.odm.manufacturer", NativeLibWrapper.sysPropsRead("ro.product.odm.manufacturer"), "google")
    AssertionResult("ro.product.odm.manufacturer", NativeLibWrapper.sysPropsReadCb("ro.product.odm.manufacturer"), "google")

    AssertionResult("ro.product.odm.model", NativeLibWrapper.sysPropsGet("ro.product.odm.model"), "Pixel 8 Pro")
    AssertionResult("ro.product.odm.model", NativeLibWrapper.sysPropsReadWithNullName("ro.product.odm.model"), "Pixel 8 Pro")
    AssertionResult("ro.product.odm.model", NativeLibWrapper.sysPropsRead("ro.product.odm.model"), "Pixel 8 Pro")
    AssertionResult("ro.product.odm.model", NativeLibWrapper.sysPropsReadCb("ro.product.odm.model"), "Pixel 8 Pro")

    AssertionResult("ro.product.odm.name", NativeLibWrapper.sysPropsGet("ro.product.odm.name"), "husky")
    AssertionResult("ro.product.odm.name", NativeLibWrapper.sysPropsReadWithNullName("ro.product.odm.name"), "husky")
    AssertionResult("ro.product.odm.name", NativeLibWrapper.sysPropsRead("ro.product.odm.name"), "husky")
    AssertionResult("ro.product.odm.name", NativeLibWrapper.sysPropsReadCb("ro.product.odm.name"), "husky")

    AssertionResult("ro.product.product.brand", NativeLibWrapper.sysPropsGet("ro.product.product.brand"), "google")
    AssertionResult("ro.product.product.brand", NativeLibWrapper.sysPropsReadWithNullName("ro.product.product.brand"), "google")
    AssertionResult("ro.product.product.brand", NativeLibWrapper.sysPropsRead("ro.product.product.brand"), "google")
    AssertionResult("ro.product.product.brand", NativeLibWrapper.sysPropsReadCb("ro.product.product.brand"), "google")

    AssertionResult("ro.product.product.device", NativeLibWrapper.sysPropsGet("ro.product.product.device"), "husky")
    AssertionResult("ro.product.product.device", NativeLibWrapper.sysPropsReadWithNullName("ro.product.product.device"), "husky")
    AssertionResult("ro.product.product.device", NativeLibWrapper.sysPropsRead("ro.product.product.device"), "husky")
    AssertionResult("ro.product.product.device", NativeLibWrapper.sysPropsReadCb("ro.product.product.device"), "husky")

    AssertionResult("ro.product.product.manufacturer", NativeLibWrapper.sysPropsGet("ro.product.product.manufacturer"), "google")
    AssertionResult("ro.product.product.manufacturer", NativeLibWrapper.sysPropsReadWithNullName("ro.product.product.manufacturer"), "google")
    AssertionResult("ro.product.product.manufacturer", NativeLibWrapper.sysPropsRead("ro.product.product.manufacturer"), "google")
    AssertionResult("ro.product.product.manufacturer", NativeLibWrapper.sysPropsReadCb("ro.product.product.manufacturer"), "google")

    AssertionResult("ro.product.product.model", NativeLibWrapper.sysPropsGet("ro.product.product.model"), "Pixel 8 Pro")
    AssertionResult("ro.product.product.model", NativeLibWrapper.sysPropsReadWithNullName("ro.product.product.model"), "Pixel 8 Pro")
    AssertionResult("ro.product.product.model", NativeLibWrapper.sysPropsRead("ro.product.product.model"), "Pixel 8 Pro")
    AssertionResult("ro.product.product.model", NativeLibWrapper.sysPropsReadCb("ro.product.product.model"), "Pixel 8 Pro")

    AssertionResult("ro.product.product.name", NativeLibWrapper.sysPropsGet("ro.product.product.name"), "husky")
    AssertionResult("ro.product.product.name", NativeLibWrapper.sysPropsReadWithNullName("ro.product.product.name"), "husky")
    AssertionResult("ro.product.product.name", NativeLibWrapper.sysPropsRead("ro.product.product.name"), "husky")
    AssertionResult("ro.product.product.name", NativeLibWrapper.sysPropsReadCb("ro.product.product.name"), "husky")

    AssertionResult("ro.build.product", NativeLibWrapper.sysPropsGet("ro.build.product"), "husky")
    AssertionResult("ro.build.product", NativeLibWrapper.sysPropsReadWithNullName("ro.build.product"), "husky")
    AssertionResult("ro.build.product", NativeLibWrapper.sysPropsRead("ro.build.product"), "husky")
    AssertionResult("ro.build.product", NativeLibWrapper.sysPropsReadCb("ro.build.product"), "husky")

    AssertionResult("ro.product.system.brand", NativeLibWrapper.sysPropsGet("ro.product.system.brand"), "google")
    AssertionResult("ro.product.system.brand", NativeLibWrapper.sysPropsReadWithNullName("ro.product.system.brand"), "google")
    AssertionResult("ro.product.system.brand", NativeLibWrapper.sysPropsRead("ro.product.system.brand"), "google")
    AssertionResult("ro.product.system.brand", NativeLibWrapper.sysPropsReadCb("ro.product.system.brand"), "google")

    AssertionResult("ro.product.system.device", NativeLibWrapper.sysPropsGet("ro.product.system.device"), "husky")
    AssertionResult("ro.product.system.device", NativeLibWrapper.sysPropsReadWithNullName("ro.product.system.device"), "husky")
    AssertionResult("ro.product.system.device", NativeLibWrapper.sysPropsRead("ro.product.system.device"), "husky")
    AssertionResult("ro.product.system.device", NativeLibWrapper.sysPropsReadCb("ro.product.system.device"), "husky")

    AssertionResult("ro.product.system.manufacturer", NativeLibWrapper.sysPropsGet("ro.product.system.manufacturer"), "google")
    AssertionResult("ro.product.system.manufacturer", NativeLibWrapper.sysPropsReadWithNullName("ro.product.system.manufacturer"), "google")
    AssertionResult("ro.product.system.manufacturer", NativeLibWrapper.sysPropsRead("ro.product.system.manufacturer"), "google")
    AssertionResult("ro.product.system.manufacturer", NativeLibWrapper.sysPropsReadCb("ro.product.system.manufacturer"), "google")

    AssertionResult("ro.product.system.model", NativeLibWrapper.sysPropsGet("ro.product.system.model"), "Pixel 8 Pro")
    AssertionResult("ro.product.system.model", NativeLibWrapper.sysPropsReadWithNullName("ro.product.system.model"), "Pixel 8 Pro")
    AssertionResult("ro.product.system.model", NativeLibWrapper.sysPropsRead("ro.product.system.model"), "Pixel 8 Pro")
    AssertionResult("ro.product.system.model", NativeLibWrapper.sysPropsReadCb("ro.product.system.model"), "Pixel 8 Pro")

    AssertionResult("ro.product.system.name", NativeLibWrapper.sysPropsGet("ro.product.system.name"), "husky")
    AssertionResult("ro.product.system.name", NativeLibWrapper.sysPropsReadWithNullName("ro.product.system.name"), "husky")
    AssertionResult("ro.product.system.name", NativeLibWrapper.sysPropsRead("ro.product.system.name"), "husky")
    AssertionResult("ro.product.system.name", NativeLibWrapper.sysPropsReadCb("ro.product.system.name"), "husky")

    AssertionResult("ro.product.system_ext.brand", NativeLibWrapper.sysPropsGet("ro.product.system_ext.brand"), "google")
    AssertionResult("ro.product.system_ext.brand", NativeLibWrapper.sysPropsReadWithNullName("ro.product.system_ext.brand"), "google")
    AssertionResult("ro.product.system_ext.brand", NativeLibWrapper.sysPropsRead("ro.product.system_ext.brand"), "google")
    AssertionResult("ro.product.system_ext.brand", NativeLibWrapper.sysPropsReadCb("ro.product.system_ext.brand"), "google")

    AssertionResult("ro.product.system_ext.device", NativeLibWrapper.sysPropsGet("ro.product.system_ext.device"), "husky")
    AssertionResult("ro.product.system_ext.device", NativeLibWrapper.sysPropsReadWithNullName("ro.product.system_ext.device"), "husky")
    AssertionResult("ro.product.system_ext.device", NativeLibWrapper.sysPropsRead("ro.product.system_ext.device"), "husky")
    AssertionResult("ro.product.system_ext.device", NativeLibWrapper.sysPropsReadCb("ro.product.system_ext.device"), "husky")

    AssertionResult("ro.product.system_ext.manufacturer", NativeLibWrapper.sysPropsGet("ro.product.system_ext.manufacturer"), "google")
    AssertionResult("ro.product.system_ext.manufacturer", NativeLibWrapper.sysPropsReadWithNullName("ro.product.system_ext.manufacturer"), "google")
    AssertionResult("ro.product.system_ext.manufacturer", NativeLibWrapper.sysPropsRead("ro.product.system_ext.manufacturer"), "google")
    AssertionResult("ro.product.system_ext.manufacturer", NativeLibWrapper.sysPropsReadCb("ro.product.system_ext.manufacturer"), "google")

    AssertionResult("ro.product.system_ext.model", NativeLibWrapper.sysPropsGet("ro.product.system_ext.model"), "Pixel 8 Pro")
    AssertionResult("ro.product.system_ext.model", NativeLibWrapper.sysPropsReadWithNullName("ro.product.system_ext.model"), "Pixel 8 Pro")
    AssertionResult("ro.product.system_ext.model", NativeLibWrapper.sysPropsRead("ro.product.system_ext.model"), "Pixel 8 Pro")
    AssertionResult("ro.product.system_ext.model", NativeLibWrapper.sysPropsReadCb("ro.product.system_ext.model"), "Pixel 8 Pro")

    AssertionResult("ro.product.system_ext.name", NativeLibWrapper.sysPropsGet("ro.product.system_ext.name"), "husky")
    AssertionResult("ro.product.system_ext.name", NativeLibWrapper.sysPropsReadWithNullName("ro.product.system_ext.name"), "husky")
    AssertionResult("ro.product.system_ext.name", NativeLibWrapper.sysPropsRead("ro.product.system_ext.name"), "husky")
    AssertionResult("ro.product.system_ext.name", NativeLibWrapper.sysPropsReadCb("ro.product.system_ext.name"), "husky")

    AssertionResult("ro.product.vendor.brand", NativeLibWrapper.sysPropsGet("ro.product.vendor.brand"), "google")
    AssertionResult("ro.product.vendor.brand", NativeLibWrapper.sysPropsReadWithNullName("ro.product.vendor.brand"), "google")
    AssertionResult("ro.product.vendor.brand", NativeLibWrapper.sysPropsRead("ro.product.vendor.brand"), "google")
    AssertionResult("ro.product.vendor.brand", NativeLibWrapper.sysPropsReadCb("ro.product.vendor.brand"), "google")

    AssertionResult("ro.product.vendor.device", NativeLibWrapper.sysPropsGet("ro.product.vendor.device"), "husky")
    AssertionResult("ro.product.vendor.device", NativeLibWrapper.sysPropsReadWithNullName("ro.product.vendor.device"), "husky")
    AssertionResult("ro.product.vendor.device", NativeLibWrapper.sysPropsRead("ro.product.vendor.device"), "husky")
    AssertionResult("ro.product.vendor.device", NativeLibWrapper.sysPropsReadCb("ro.product.vendor.device"), "husky")

    AssertionResult("ro.product.vendor.manufacturer", NativeLibWrapper.sysPropsGet("ro.product.vendor.manufacturer"), "google")
    AssertionResult("ro.product.vendor.manufacturer", NativeLibWrapper.sysPropsReadWithNullName("ro.product.vendor.manufacturer"), "google")
    AssertionResult("ro.product.vendor.manufacturer", NativeLibWrapper.sysPropsRead("ro.product.vendor.manufacturer"), "google")
    AssertionResult("ro.product.vendor.manufacturer", NativeLibWrapper.sysPropsReadCb("ro.product.vendor.manufacturer"), "google")

    AssertionResult("ro.product.vendor.model", NativeLibWrapper.sysPropsGet("ro.product.vendor.model"), "Pixel 8 Pro")
    AssertionResult("ro.product.vendor.model", NativeLibWrapper.sysPropsReadWithNullName("ro.product.vendor.model"), "Pixel 8 Pro")
    AssertionResult("ro.product.vendor.model", NativeLibWrapper.sysPropsRead("ro.product.vendor.model"), "Pixel 8 Pro")
    AssertionResult("ro.product.vendor.model", NativeLibWrapper.sysPropsReadCb("ro.product.vendor.model"), "Pixel 8 Pro")

    AssertionResult("ro.product.vendor.name", NativeLibWrapper.sysPropsGet("ro.product.vendor.name"), "husky")
    AssertionResult("ro.product.vendor.name", NativeLibWrapper.sysPropsReadWithNullName("ro.product.vendor.name"), "husky")
    AssertionResult("ro.product.vendor.name", NativeLibWrapper.sysPropsRead("ro.product.vendor.name"), "husky")
    AssertionResult("ro.product.vendor.name", NativeLibWrapper.sysPropsReadCb("ro.product.vendor.name"), "husky")

    AssertionResult("ro.product.vendor_dlkm.brand", NativeLibWrapper.sysPropsGet("ro.product.vendor_dlkm.brand"), "google")
    AssertionResult("ro.product.vendor_dlkm.brand", NativeLibWrapper.sysPropsReadWithNullName("ro.product.vendor_dlkm.brand"), "google")
    AssertionResult("ro.product.vendor_dlkm.brand", NativeLibWrapper.sysPropsRead("ro.product.vendor_dlkm.brand"), "google")
    AssertionResult("ro.product.vendor_dlkm.brand", NativeLibWrapper.sysPropsReadCb("ro.product.vendor_dlkm.brand"), "google")

    AssertionResult("ro.product.vendor_dlkm.device", NativeLibWrapper.sysPropsGet("ro.product.vendor_dlkm.device"), "husky")
    AssertionResult("ro.product.vendor_dlkm.device", NativeLibWrapper.sysPropsReadWithNullName("ro.product.vendor_dlkm.device"), "husky")
    AssertionResult("ro.product.vendor_dlkm.device", NativeLibWrapper.sysPropsRead("ro.product.vendor_dlkm.device"), "husky")
    AssertionResult("ro.product.vendor_dlkm.device", NativeLibWrapper.sysPropsReadCb("ro.product.vendor_dlkm.device"), "husky")

    AssertionResult("ro.product.vendor_dlkm.manufacturer", NativeLibWrapper.sysPropsGet("ro.product.vendor_dlkm.manufacturer"), "google")
    AssertionResult("ro.product.vendor_dlkm.manufacturer", NativeLibWrapper.sysPropsReadWithNullName("ro.product.vendor_dlkm.manufacturer"), "google")
    AssertionResult("ro.product.vendor_dlkm.manufacturer", NativeLibWrapper.sysPropsRead("ro.product.vendor_dlkm.manufacturer"), "google")
    AssertionResult("ro.product.vendor_dlkm.manufacturer", NativeLibWrapper.sysPropsReadCb("ro.product.vendor_dlkm.manufacturer"), "google")

    AssertionResult("ro.product.vendor_dlkm.model", NativeLibWrapper.sysPropsGet("ro.product.vendor_dlkm.model"), "Pixel 8 Pro")
    AssertionResult("ro.product.vendor_dlkm.model", NativeLibWrapper.sysPropsReadWithNullName("ro.product.vendor_dlkm.model"), "Pixel 8 Pro")
    AssertionResult("ro.product.vendor_dlkm.model", NativeLibWrapper.sysPropsRead("ro.product.vendor_dlkm.model"), "Pixel 8 Pro")
    AssertionResult("ro.product.vendor_dlkm.model", NativeLibWrapper.sysPropsReadCb("ro.product.vendor_dlkm.model"), "Pixel 8 Pro")

    AssertionResult("ro.product.vendor_dlkm.name", NativeLibWrapper.sysPropsGet("ro.product.vendor_dlkm.name"), "husky")
    AssertionResult("ro.product.vendor_dlkm.name", NativeLibWrapper.sysPropsReadWithNullName("ro.product.vendor_dlkm.name"), "husky")
    AssertionResult("ro.product.vendor_dlkm.name", NativeLibWrapper.sysPropsRead("ro.product.vendor_dlkm.name"), "husky")
    AssertionResult("ro.product.vendor_dlkm.name", NativeLibWrapper.sysPropsReadCb("ro.product.vendor_dlkm.name"), "husky")

    AssertionResult("ro.build.host", NativeLibWrapper.sysPropsGet("ro.build.host"), "abfarm-20038")
    AssertionResult("ro.build.host", NativeLibWrapper.sysPropsReadWithNullName("ro.build.host"), "abfarm-20038")
    AssertionResult("ro.build.host", NativeLibWrapper.sysPropsRead("ro.build.host"), "abfarm-20038")
    AssertionResult("ro.build.host", NativeLibWrapper.sysPropsReadCb("ro.build.host"), "abfarm-20038")

    AssertionResult("ro.build.id", NativeLibWrapper.sysPropsGet("ro.build.id"), "BP4A.251205.006")
    AssertionResult("ro.build.id", NativeLibWrapper.sysPropsReadWithNullName("ro.build.id"), "BP4A.251205.006")
    AssertionResult("ro.build.id", NativeLibWrapper.sysPropsRead("ro.build.id"), "BP4A.251205.006")
    AssertionResult("ro.build.id", NativeLibWrapper.sysPropsReadCb("ro.build.id"), "BP4A.251205.006")

    AssertionResult("ro.vendor.build.id", NativeLibWrapper.sysPropsGet("ro.vendor.build.id"), "BP4A.251205.006")
    AssertionResult("ro.vendor.build.id", NativeLibWrapper.sysPropsReadWithNullName("ro.vendor.build.id"), "BP4A.251205.006")
    AssertionResult("ro.vendor.build.id", NativeLibWrapper.sysPropsRead("ro.vendor.build.id"), "BP4A.251205.006")
    AssertionResult("ro.vendor.build.id", NativeLibWrapper.sysPropsReadCb("ro.vendor.build.id"), "BP4A.251205.006")

    AssertionResult("ro.product.build.id", NativeLibWrapper.sysPropsGet("ro.product.build.id"), "BP4A.251205.006")
    AssertionResult("ro.product.build.id", NativeLibWrapper.sysPropsReadWithNullName("ro.product.build.id"), "BP4A.251205.006")
    AssertionResult("ro.product.build.id", NativeLibWrapper.sysPropsRead("ro.product.build.id"), "BP4A.251205.006")
    AssertionResult("ro.product.build.id", NativeLibWrapper.sysPropsReadCb("ro.product.build.id"), "BP4A.251205.006")

    AssertionResult("ro.system.build.id", NativeLibWrapper.sysPropsGet("ro.system.build.id"), "BP4A.251205.006")
    AssertionResult("ro.system.build.id", NativeLibWrapper.sysPropsReadWithNullName("ro.system.build.id"), "BP4A.251205.006")
    AssertionResult("ro.system.build.id", NativeLibWrapper.sysPropsRead("ro.system.build.id"), "BP4A.251205.006")
    AssertionResult("ro.system.build.id", NativeLibWrapper.sysPropsReadCb("ro.system.build.id"), "BP4A.251205.006")

    AssertionResult("ro.vendor_dlkm.build.id", NativeLibWrapper.sysPropsGet("ro.vendor_dlkm.build.id"), "BP4A.251205.006")
    AssertionResult("ro.vendor_dlkm.build.id", NativeLibWrapper.sysPropsReadWithNullName("ro.vendor_dlkm.build.id"), "BP4A.251205.006")
    AssertionResult("ro.vendor_dlkm.build.id", NativeLibWrapper.sysPropsRead("ro.vendor_dlkm.build.id"), "BP4A.251205.006")
    AssertionResult("ro.vendor_dlkm.build.id", NativeLibWrapper.sysPropsReadCb("ro.vendor_dlkm.build.id"), "BP4A.251205.006")

    AssertionResult("ro.system_ext.build.id", NativeLibWrapper.sysPropsGet("ro.system_ext.build.id"), "BP4A.251205.006")
    AssertionResult("ro.system_ext.build.id", NativeLibWrapper.sysPropsReadWithNullName("ro.system_ext.build.id"), "BP4A.251205.006")
    AssertionResult("ro.system_ext.build.id", NativeLibWrapper.sysPropsRead("ro.system_ext.build.id"), "BP4A.251205.006")
    AssertionResult("ro.system_ext.build.id", NativeLibWrapper.sysPropsReadCb("ro.system_ext.build.id"), "BP4A.251205.006")

    AssertionResult("ro.build.display.id", NativeLibWrapper.sysPropsGet("ro.build.display.id"), "BP4A.251205.006")
    AssertionResult("ro.build.display.id", NativeLibWrapper.sysPropsReadWithNullName("ro.build.display.id"), "BP4A.251205.006")
    AssertionResult("ro.build.display.id", NativeLibWrapper.sysPropsRead("ro.build.display.id"), "BP4A.251205.006")
    AssertionResult("ro.build.display.id", NativeLibWrapper.sysPropsReadCb("ro.build.display.id"), "BP4A.251205.006")

    AssertionResult("ro.build.tags", NativeLibWrapper.sysPropsGet("ro.build.tags"), "release-keys")
    AssertionResult("ro.build.tags", NativeLibWrapper.sysPropsReadWithNullName("ro.build.tags"), "release-keys")
    AssertionResult("ro.build.tags", NativeLibWrapper.sysPropsRead("ro.build.tags"), "release-keys")
    AssertionResult("ro.build.tags", NativeLibWrapper.sysPropsReadCb("ro.build.tags"), "release-keys")

    AssertionResult("ro.vendor.build.tags", NativeLibWrapper.sysPropsGet("ro.vendor.build.tags"), "release-keys")
    AssertionResult("ro.vendor.build.tags", NativeLibWrapper.sysPropsReadWithNullName("ro.vendor.build.tags"), "release-keys")
    AssertionResult("ro.vendor.build.tags", NativeLibWrapper.sysPropsRead("ro.vendor.build.tags"), "release-keys")
    AssertionResult("ro.vendor.build.tags", NativeLibWrapper.sysPropsReadCb("ro.vendor.build.tags"), "release-keys")

    AssertionResult("ro.product.build.tags", NativeLibWrapper.sysPropsGet("ro.product.build.tags"), "release-keys")
    AssertionResult("ro.product.build.tags", NativeLibWrapper.sysPropsReadWithNullName("ro.product.build.tags"), "release-keys")
    AssertionResult("ro.product.build.tags", NativeLibWrapper.sysPropsRead("ro.product.build.tags"), "release-keys")
    AssertionResult("ro.product.build.tags", NativeLibWrapper.sysPropsReadCb("ro.product.build.tags"), "release-keys")

    AssertionResult("ro.system.build.tags", NativeLibWrapper.sysPropsGet("ro.system.build.tags"), "release-keys")
    AssertionResult("ro.system.build.tags", NativeLibWrapper.sysPropsReadWithNullName("ro.system.build.tags"), "release-keys")
    AssertionResult("ro.system.build.tags", NativeLibWrapper.sysPropsRead("ro.system.build.tags"), "release-keys")
    AssertionResult("ro.system.build.tags", NativeLibWrapper.sysPropsReadCb("ro.system.build.tags"), "release-keys")

    AssertionResult("ro.vendor_dlkm.build.tags", NativeLibWrapper.sysPropsGet("ro.vendor_dlkm.build.tags"), "release-keys")
    AssertionResult("ro.vendor_dlkm.build.tags", NativeLibWrapper.sysPropsReadWithNullName("ro.vendor_dlkm.build.tags"), "release-keys")
    AssertionResult("ro.vendor_dlkm.build.tags", NativeLibWrapper.sysPropsRead("ro.vendor_dlkm.build.tags"), "release-keys")
    AssertionResult("ro.vendor_dlkm.build.tags", NativeLibWrapper.sysPropsReadCb("ro.vendor_dlkm.build.tags"), "release-keys")

    AssertionResult("ro.system_ext.build.tags", NativeLibWrapper.sysPropsGet("ro.system_ext.build.tags"), "release-keys")
    AssertionResult("ro.system_ext.build.tags", NativeLibWrapper.sysPropsReadWithNullName("ro.system_ext.build.tags"), "release-keys")
    AssertionResult("ro.system_ext.build.tags", NativeLibWrapper.sysPropsRead("ro.system_ext.build.tags"), "release-keys")
    AssertionResult("ro.system_ext.build.tags", NativeLibWrapper.sysPropsReadCb("ro.system_ext.build.tags"), "release-keys")

    AssertionResult("ro.build.type", NativeLibWrapper.sysPropsGet("ro.build.type"), "user")
    AssertionResult("ro.build.type", NativeLibWrapper.sysPropsReadWithNullName("ro.build.type"), "user")
    AssertionResult("ro.build.type", NativeLibWrapper.sysPropsRead("ro.build.type"), "user")
    AssertionResult("ro.build.type", NativeLibWrapper.sysPropsReadCb("ro.build.type"), "user")

    AssertionResult("ro.vendor.build.type", NativeLibWrapper.sysPropsGet("ro.vendor.build.type"), "user")
    AssertionResult("ro.vendor.build.type", NativeLibWrapper.sysPropsReadWithNullName("ro.vendor.build.type"), "user")
    AssertionResult("ro.vendor.build.type", NativeLibWrapper.sysPropsRead("ro.vendor.build.type"), "user")
    AssertionResult("ro.vendor.build.type", NativeLibWrapper.sysPropsReadCb("ro.vendor.build.type"), "user")

    AssertionResult("ro.product.build.type", NativeLibWrapper.sysPropsGet("ro.product.build.type"), "user")
    AssertionResult("ro.product.build.type", NativeLibWrapper.sysPropsReadWithNullName("ro.product.build.type"), "user")
    AssertionResult("ro.product.build.type", NativeLibWrapper.sysPropsRead("ro.product.build.type"), "user")
    AssertionResult("ro.product.build.type", NativeLibWrapper.sysPropsReadCb("ro.product.build.type"), "user")

    AssertionResult("ro.system.build.type", NativeLibWrapper.sysPropsGet("ro.system.build.type"), "user")
    AssertionResult("ro.system.build.type", NativeLibWrapper.sysPropsReadWithNullName("ro.system.build.type"), "user")
    AssertionResult("ro.system.build.type", NativeLibWrapper.sysPropsRead("ro.system.build.type"), "user")
    AssertionResult("ro.system.build.type", NativeLibWrapper.sysPropsReadCb("ro.system.build.type"), "user")

    AssertionResult("ro.vendor_dlkm.build.type", NativeLibWrapper.sysPropsGet("ro.vendor_dlkm.build.type"), "user")
    AssertionResult("ro.vendor_dlkm.build.type", NativeLibWrapper.sysPropsReadWithNullName("ro.vendor_dlkm.build.type"), "user")
    AssertionResult("ro.vendor_dlkm.build.type", NativeLibWrapper.sysPropsRead("ro.vendor_dlkm.build.type"), "user")
    AssertionResult("ro.vendor_dlkm.build.type", NativeLibWrapper.sysPropsReadCb("ro.vendor_dlkm.build.type"), "user")

    AssertionResult("ro.system_ext.build.type", NativeLibWrapper.sysPropsGet("ro.system_ext.build.type"), "user")
    AssertionResult("ro.system_ext.build.type", NativeLibWrapper.sysPropsReadWithNullName("ro.system_ext.build.type"), "user")
    AssertionResult("ro.system_ext.build.type", NativeLibWrapper.sysPropsRead("ro.system_ext.build.type"), "user")
    AssertionResult("ro.system_ext.build.type", NativeLibWrapper.sysPropsReadCb("ro.system_ext.build.type"), "user")

    AssertionResult("ro.build.user", NativeLibWrapper.sysPropsGet("ro.build.user"), "android-build")
    AssertionResult("ro.build.user", NativeLibWrapper.sysPropsReadWithNullName("ro.build.user"), "android-build")
    AssertionResult("ro.build.user", NativeLibWrapper.sysPropsRead("ro.build.user"), "android-build")
    AssertionResult("ro.build.user", NativeLibWrapper.sysPropsReadCb("ro.build.user"), "android-build")

    AssertionResult("ro.build.date.utc", NativeLibWrapper.sysPropsGet("ro.build.date.utc"), "1764954000")
    AssertionResult("ro.build.date.utc", NativeLibWrapper.sysPropsReadWithNullName("ro.build.date.utc"), "1764954000")
    AssertionResult("ro.build.date.utc", NativeLibWrapper.sysPropsRead("ro.build.date.utc"), "1764954000")
    AssertionResult("ro.build.date.utc", NativeLibWrapper.sysPropsReadCb("ro.build.date.utc"), "1764954000")

    AssertionResult("ro.odm.build.date.utc", NativeLibWrapper.sysPropsGet("ro.odm.build.date.utc"), "1764954000")
    AssertionResult("ro.odm.build.date.utc", NativeLibWrapper.sysPropsReadWithNullName("ro.odm.build.date.utc"), "1764954000")
    AssertionResult("ro.odm.build.date.utc", NativeLibWrapper.sysPropsRead("ro.odm.build.date.utc"), "1764954000")
    AssertionResult("ro.odm.build.date.utc", NativeLibWrapper.sysPropsReadCb("ro.odm.build.date.utc"), "1764954000")

    AssertionResult("ro.product.build.date.utc", NativeLibWrapper.sysPropsGet("ro.product.build.date.utc"), "1764954000")
    AssertionResult("ro.product.build.date.utc", NativeLibWrapper.sysPropsReadWithNullName("ro.product.build.date.utc"), "1764954000")
    AssertionResult("ro.product.build.date.utc", NativeLibWrapper.sysPropsRead("ro.product.build.date.utc"), "1764954000")
    AssertionResult("ro.product.build.date.utc", NativeLibWrapper.sysPropsReadCb("ro.product.build.date.utc"), "1764954000")

    AssertionResult("ro.system.build.date.utc", NativeLibWrapper.sysPropsGet("ro.system.build.date.utc"), "1764954000")
    AssertionResult("ro.system.build.date.utc", NativeLibWrapper.sysPropsReadWithNullName("ro.system.build.date.utc"), "1764954000")
    AssertionResult("ro.system.build.date.utc", NativeLibWrapper.sysPropsRead("ro.system.build.date.utc"), "1764954000")
    AssertionResult("ro.system.build.date.utc", NativeLibWrapper.sysPropsReadCb("ro.system.build.date.utc"), "1764954000")

    AssertionResult("ro.system_ext.build.date.utc", NativeLibWrapper.sysPropsGet("ro.system_ext.build.date.utc"), "1764954000")
    AssertionResult("ro.system_ext.build.date.utc", NativeLibWrapper.sysPropsReadWithNullName("ro.system_ext.build.date.utc"), "1764954000")
    AssertionResult("ro.system_ext.build.date.utc", NativeLibWrapper.sysPropsRead("ro.system_ext.build.date.utc"), "1764954000")
    AssertionResult("ro.system_ext.build.date.utc", NativeLibWrapper.sysPropsReadCb("ro.system_ext.build.date.utc"), "1764954000")

    AssertionResult("ro.vendor_dlkm.build.date.utc", NativeLibWrapper.sysPropsGet("ro.vendor_dlkm.build.date.utc"), "1764954000")
    AssertionResult("ro.vendor_dlkm.build.date.utc", NativeLibWrapper.sysPropsReadWithNullName("ro.vendor_dlkm.build.date.utc"), "1764954000")
    AssertionResult("ro.vendor_dlkm.build.date.utc", NativeLibWrapper.sysPropsRead("ro.vendor_dlkm.build.date.utc"), "1764954000")
    AssertionResult("ro.vendor_dlkm.build.date.utc", NativeLibWrapper.sysPropsReadCb("ro.vendor_dlkm.build.date.utc"), "1764954000")

    AssertionResult("ro.vendor.build.date.utc", NativeLibWrapper.sysPropsGet("ro.vendor.build.date.utc"), "1764954000")
    AssertionResult("ro.vendor.build.date.utc", NativeLibWrapper.sysPropsReadWithNullName("ro.vendor.build.date.utc"), "1764954000")
    AssertionResult("ro.vendor.build.date.utc", NativeLibWrapper.sysPropsRead("ro.vendor.build.date.utc"), "1764954000")
    AssertionResult("ro.vendor.build.date.utc", NativeLibWrapper.sysPropsReadCb("ro.vendor.build.date.utc"), "1764954000")

    AssertionResult("ro.build.version.all_codenames", NativeLibWrapper.sysPropsGet("ro.build.version.all_codenames"), "REL")
    AssertionResult("ro.build.version.all_codenames", NativeLibWrapper.sysPropsReadWithNullName("ro.build.version.all_codenames"), "REL")
    AssertionResult("ro.build.version.all_codenames", NativeLibWrapper.sysPropsRead("ro.build.version.all_codenames"), "REL")
    AssertionResult("ro.build.version.all_codenames", NativeLibWrapper.sysPropsReadCb("ro.build.version.all_codenames"), "REL")

    AssertionResult("ro.build.version.preview_sdk_fingerprint", NativeLibWrapper.sysPropsGet("ro.build.version.preview_sdk_fingerprint"), "REL")
    AssertionResult("ro.build.version.preview_sdk_fingerprint", NativeLibWrapper.sysPropsReadWithNullName("ro.build.version.preview_sdk_fingerprint"), "REL")
    AssertionResult("ro.build.version.preview_sdk_fingerprint", NativeLibWrapper.sysPropsRead("ro.build.version.preview_sdk_fingerprint"), "REL")
    AssertionResult("ro.build.version.preview_sdk_fingerprint", NativeLibWrapper.sysPropsReadCb("ro.build.version.preview_sdk_fingerprint"), "REL")

    AssertionResult("ro.build.date", NativeLibWrapper.sysPropsGet("ro.build.date"), buildDate)
    AssertionResult("ro.build.date", NativeLibWrapper.sysPropsReadWithNullName("ro.build.date"), buildDate)
    AssertionResult("ro.build.date", NativeLibWrapper.sysPropsRead("ro.build.date"), buildDate)
    AssertionResult("ro.build.date", NativeLibWrapper.sysPropsReadCb("ro.build.date"), buildDate)

    AssertionResult("ro.odm.build.date", NativeLibWrapper.sysPropsGet("ro.odm.build.date"), buildDate)
    AssertionResult("ro.odm.build.date", NativeLibWrapper.sysPropsReadWithNullName("ro.odm.build.date"), buildDate)
    AssertionResult("ro.odm.build.date", NativeLibWrapper.sysPropsRead("ro.odm.build.date"), buildDate)
    AssertionResult("ro.odm.build.date", NativeLibWrapper.sysPropsReadCb("ro.odm.build.date"), buildDate)

    AssertionResult("ro.product.build.date", NativeLibWrapper.sysPropsGet("ro.product.build.date"), buildDate)
    AssertionResult("ro.product.build.date", NativeLibWrapper.sysPropsReadWithNullName("ro.product.build.date"), buildDate)
    AssertionResult("ro.product.build.date", NativeLibWrapper.sysPropsRead("ro.product.build.date"), buildDate)
    AssertionResult("ro.product.build.date", NativeLibWrapper.sysPropsReadCb("ro.product.build.date"), buildDate)

    AssertionResult("ro.system.build.date", NativeLibWrapper.sysPropsGet("ro.system.build.date"), buildDate)
    AssertionResult("ro.system.build.date", NativeLibWrapper.sysPropsReadWithNullName("ro.system.build.date"), buildDate)
    AssertionResult("ro.system.build.date", NativeLibWrapper.sysPropsRead("ro.system.build.date"), buildDate)
    AssertionResult("ro.system.build.date", NativeLibWrapper.sysPropsReadCb("ro.system.build.date"), buildDate)

    AssertionResult("ro.system_ext.build.date", NativeLibWrapper.sysPropsGet("ro.system_ext.build.date"), buildDate)
    AssertionResult("ro.system_ext.build.date", NativeLibWrapper.sysPropsReadWithNullName("ro.system_ext.build.date"), buildDate)
    AssertionResult("ro.system_ext.build.date", NativeLibWrapper.sysPropsRead("ro.system_ext.build.date"), buildDate)
    AssertionResult("ro.system_ext.build.date", NativeLibWrapper.sysPropsReadCb("ro.system_ext.build.date"), buildDate)

    AssertionResult("ro.vendor.build.date", NativeLibWrapper.sysPropsGet("ro.vendor.build.date"), buildDate)
    AssertionResult("ro.vendor.build.date", NativeLibWrapper.sysPropsReadWithNullName("ro.vendor.build.date"), buildDate)
    AssertionResult("ro.vendor.build.date", NativeLibWrapper.sysPropsRead("ro.vendor.build.date"), buildDate)
    AssertionResult("ro.vendor.build.date", NativeLibWrapper.sysPropsReadCb("ro.vendor.build.date"), buildDate)

    AssertionResult("ro.vendor_dlkm.build.date", NativeLibWrapper.sysPropsGet("ro.vendor_dlkm.build.date"), buildDate)
    AssertionResult("ro.vendor_dlkm.build.date", NativeLibWrapper.sysPropsReadWithNullName("ro.vendor_dlkm.build.date"), buildDate)
    AssertionResult("ro.vendor_dlkm.build.date", NativeLibWrapper.sysPropsRead("ro.vendor_dlkm.build.date"), buildDate)
    AssertionResult("ro.vendor_dlkm.build.date", NativeLibWrapper.sysPropsReadCb("ro.vendor_dlkm.build.date"), buildDate)

    AssertionResult("ro.build.description", NativeLibWrapper.sysPropsGet("ro.build.description"), "husky-user 16 BP4A.251205.006 release-keys")
    AssertionResult("ro.build.description", NativeLibWrapper.sysPropsReadWithNullName("ro.build.description"), "husky-user 16 BP4A.251205.006 release-keys")
    AssertionResult("ro.build.description", NativeLibWrapper.sysPropsRead("ro.build.description"), "husky-user 16 BP4A.251205.006 release-keys")
    AssertionResult("ro.build.description", NativeLibWrapper.sysPropsReadCb("ro.build.description"), "husky-user 16 BP4A.251205.006 release-keys")

    AssertionResult("ro.build.flavor", NativeLibWrapper.sysPropsGet("ro.build.flavor"), "husky-user")
    AssertionResult("ro.build.flavor", NativeLibWrapper.sysPropsReadWithNullName("ro.build.flavor"), "husky-user")
    AssertionResult("ro.build.flavor", NativeLibWrapper.sysPropsRead("ro.build.flavor"), "husky-user")
    AssertionResult("ro.build.flavor", NativeLibWrapper.sysPropsReadCb("ro.build.flavor"), "husky-user")

    AssertionResult("ro.build.version.incremental", NativeLibWrapper.sysPropsGet("ro.build.version.incremental"), "14401865")
    AssertionResult("ro.build.version.incremental", NativeLibWrapper.sysPropsReadWithNullName("ro.build.version.incremental"), "14401865")
    AssertionResult("ro.build.version.incremental", NativeLibWrapper.sysPropsRead("ro.build.version.incremental"), "14401865")
    AssertionResult("ro.build.version.incremental", NativeLibWrapper.sysPropsReadCb("ro.build.version.incremental"), "14401865")

    AssertionResult("ro.vendor.build.version.incremental", NativeLibWrapper.sysPropsGet("ro.vendor.build.version.incremental"), "14401865")
    AssertionResult("ro.vendor.build.version.incremental", NativeLibWrapper.sysPropsReadWithNullName("ro.vendor.build.version.incremental"), "14401865")
    AssertionResult("ro.vendor.build.version.incremental", NativeLibWrapper.sysPropsRead("ro.vendor.build.version.incremental"), "14401865")
    AssertionResult("ro.vendor.build.version.incremental", NativeLibWrapper.sysPropsReadCb("ro.vendor.build.version.incremental"), "14401865")

    AssertionResult("ro.odm.build.version.incremental", NativeLibWrapper.sysPropsGet("ro.odm.build.version.incremental"), "14401865")
    AssertionResult("ro.odm.build.version.incremental", NativeLibWrapper.sysPropsReadWithNullName("ro.odm.build.version.incremental"), "14401865")
    AssertionResult("ro.odm.build.version.incremental", NativeLibWrapper.sysPropsRead("ro.odm.build.version.incremental"), "14401865")
    AssertionResult("ro.odm.build.version.incremental", NativeLibWrapper.sysPropsReadCb("ro.odm.build.version.incremental"), "14401865")

    AssertionResult("ro.product.build.version.incremental", NativeLibWrapper.sysPropsGet("ro.product.build.version.incremental"), "14401865")
    AssertionResult("ro.product.build.version.incremental", NativeLibWrapper.sysPropsReadWithNullName("ro.product.build.version.incremental"), "14401865")
    AssertionResult("ro.product.build.version.incremental", NativeLibWrapper.sysPropsRead("ro.product.build.version.incremental"), "14401865")
    AssertionResult("ro.product.build.version.incremental", NativeLibWrapper.sysPropsReadCb("ro.product.build.version.incremental"), "14401865")

    AssertionResult("ro.system.build.version.incremental", NativeLibWrapper.sysPropsGet("ro.system.build.version.incremental"), "14401865")
    AssertionResult("ro.system.build.version.incremental", NativeLibWrapper.sysPropsReadWithNullName("ro.system.build.version.incremental"), "14401865")
    AssertionResult("ro.system.build.version.incremental", NativeLibWrapper.sysPropsRead("ro.system.build.version.incremental"), "14401865")
    AssertionResult("ro.system.build.version.incremental", NativeLibWrapper.sysPropsReadCb("ro.system.build.version.incremental"), "14401865")

    AssertionResult("ro.vendor_dlkm.build.version.incremental", NativeLibWrapper.sysPropsGet("ro.vendor_dlkm.build.version.incremental"), "14401865")
    AssertionResult("ro.vendor_dlkm.build.version.incremental", NativeLibWrapper.sysPropsReadWithNullName("ro.vendor_dlkm.build.version.incremental"), "14401865")
    AssertionResult("ro.vendor_dlkm.build.version.incremental", NativeLibWrapper.sysPropsRead("ro.vendor_dlkm.build.version.incremental"), "14401865")
    AssertionResult("ro.vendor_dlkm.build.version.incremental", NativeLibWrapper.sysPropsReadCb("ro.vendor_dlkm.build.version.incremental"), "14401865")

    AssertionResult("ro.system_ext.build.version.incremental", NativeLibWrapper.sysPropsGet("ro.system_ext.build.version.incremental"), "14401865")
    AssertionResult("ro.system_ext.build.version.incremental", NativeLibWrapper.sysPropsReadWithNullName("ro.system_ext.build.version.incremental"), "14401865")
    AssertionResult("ro.system_ext.build.version.incremental", NativeLibWrapper.sysPropsRead("ro.system_ext.build.version.incremental"), "14401865")
    AssertionResult("ro.system_ext.build.version.incremental", NativeLibWrapper.sysPropsReadCb("ro.system_ext.build.version.incremental"), "14401865")

//    AssertionResult("ro.build.version.release", NativeLibWrapper.sysPropsGet("ro.build.version.release"), "16")
//    AssertionResult("ro.build.version.release", NativeLibWrapper.sysPropsReadWithNullName("ro.build.version.release"), propInfoNull)
//    AssertionResult("ro.build.version.release", NativeLibWrapper.sysPropsRead("ro.build.version.release"), "16")
//    AssertionResult("ro.build.version.release", NativeLibWrapper.sysPropsReadCb("ro.build.version.release"), "16")

//    AssertionResult("ro.product.build.version.release", NativeLibWrapper.sysPropsGet("ro.product.build.version.release"), "16")
//    AssertionResult("ro.product.build.version.release", NativeLibWrapper.sysPropsReadWithNullName("ro.product.build.version.release"), propInfoNull)
//    AssertionResult("ro.product.build.version.release", NativeLibWrapper.sysPropsRead("ro.product.build.version.release"), "16")
//    AssertionResult("ro.product.build.version.release", NativeLibWrapper.sysPropsReadCb("ro.product.build.version.release"), "16")
//
//    AssertionResult("ro.vendor_dlkm.build.version.release", NativeLibWrapper.sysPropsGet("ro.vendor_dlkm.build.version.release"), "16")
//    AssertionResult("ro.vendor_dlkm.build.version.release", NativeLibWrapper.sysPropsReadWithNullName("ro.vendor_dlkm.build.version.release"), propInfoNull)
//    AssertionResult("ro.vendor_dlkm.build.version.release", NativeLibWrapper.sysPropsRead("ro.vendor_dlkm.build.version.release"), "16")
//    AssertionResult("ro.vendor_dlkm.build.version.release", NativeLibWrapper.sysPropsReadCb("ro.vendor_dlkm.build.version.release"), "16")
//
//    AssertionResult("ro.vendor.build.version.release", NativeLibWrapper.sysPropsGet("ro.vendor.build.version.release"), "16")
//    AssertionResult("ro.vendor.build.version.release", NativeLibWrapper.sysPropsReadWithNullName("ro.vendor.build.version.release"), propInfoNull)
//    AssertionResult("ro.vendor.build.version.release", NativeLibWrapper.sysPropsRead("ro.vendor.build.version.release"), "16")
//    AssertionResult("ro.vendor.build.version.release", NativeLibWrapper.sysPropsReadCb("ro.vendor.build.version.release"), "16")
//
//    AssertionResult("ro.system_ext.build.version.release", NativeLibWrapper.sysPropsGet("ro.system_ext.build.version.release"), "16")
//    AssertionResult("ro.system_ext.build.version.release", NativeLibWrapper.sysPropsReadWithNullName("ro.system_ext.build.version.release"), propInfoNull)
//    AssertionResult("ro.system_ext.build.version.release", NativeLibWrapper.sysPropsRead("ro.system_ext.build.version.release"), "16")
//    AssertionResult("ro.system_ext.build.version.release", NativeLibWrapper.sysPropsReadCb("ro.system_ext.build.version.release"), "16")
//
//    AssertionResult("ro.system.build.version.release", NativeLibWrapper.sysPropsGet("ro.system.build.version.release"), "16")
//    AssertionResult("ro.system.build.version.release", NativeLibWrapper.sysPropsReadWithNullName("ro.system.build.version.release"), propInfoNull)
//    AssertionResult("ro.system.build.version.release", NativeLibWrapper.sysPropsRead("ro.system.build.version.release"), "16")
//    AssertionResult("ro.system.build.version.release", NativeLibWrapper.sysPropsReadCb("ro.system.build.version.release"), "16")
//
//    AssertionResult("ro.build.version.release_or_codename", NativeLibWrapper.sysPropsGet("ro.build.version.release_or_codename"), "16")
//    AssertionResult("ro.build.version.release_or_codename", NativeLibWrapper.sysPropsReadWithNullName("ro.build.version.release_or_codename"), propInfoNull)
//    AssertionResult("ro.build.version.release_or_codename", NativeLibWrapper.sysPropsRead("ro.build.version.release_or_codename"), "16")
//    AssertionResult("ro.build.version.release_or_codename", NativeLibWrapper.sysPropsReadCb("ro.build.version.release_or_codename"), "16")
//
//    AssertionResult("ro.vendor.build.version.release_or_codename", NativeLibWrapper.sysPropsGet("ro.vendor.build.version.release_or_codename"), "16")
//    AssertionResult("ro.vendor.build.version.release_or_codename", NativeLibWrapper.sysPropsReadWithNullName("ro.vendor.build.version.release_or_codename"), propInfoNull)
//    AssertionResult("ro.vendor.build.version.release_or_codename", NativeLibWrapper.sysPropsRead("ro.vendor.build.version.release_or_codename"), "16")
//    AssertionResult("ro.vendor.build.version.release_or_codename", NativeLibWrapper.sysPropsReadCb("ro.vendor.build.version.release_or_codename"), "16")
//
//    AssertionResult("ro.product.build.version.release_or_codename", NativeLibWrapper.sysPropsGet("ro.product.build.version.release_or_codename"), "16")
//    AssertionResult("ro.product.build.version.release_or_codename", NativeLibWrapper.sysPropsReadWithNullName("ro.product.build.version.release_or_codename"), propInfoNull)
//    AssertionResult("ro.product.build.version.release_or_codename", NativeLibWrapper.sysPropsRead("ro.product.build.version.release_or_codename"), "16")
//    AssertionResult("ro.product.build.version.release_or_codename", NativeLibWrapper.sysPropsReadCb("ro.product.build.version.release_or_codename"), "16")
//
//    AssertionResult("ro.vendor_dlkm.build.version.release_or_codename", NativeLibWrapper.sysPropsGet("ro.vendor_dlkm.build.version.release_or_codename"), "16")
//    AssertionResult("ro.vendor_dlkm.build.version.release_or_codename", NativeLibWrapper.sysPropsReadWithNullName("ro.vendor_dlkm.build.version.release_or_codename"), propInfoNull)
//    AssertionResult("ro.vendor_dlkm.build.version.release_or_codename", NativeLibWrapper.sysPropsRead("ro.vendor_dlkm.build.version.release_or_codename"), "16")
//    AssertionResult("ro.vendor_dlkm.build.version.release_or_codename", NativeLibWrapper.sysPropsReadCb("ro.vendor_dlkm.build.version.release_or_codename"), "16")
//
//    AssertionResult("ro.system.build.version.release_or_codename", NativeLibWrapper.sysPropsGet("ro.system.build.version.release_or_codename"), "16")
//    AssertionResult("ro.system.build.version.release_or_codename", NativeLibWrapper.sysPropsReadWithNullName("ro.system.build.version.release_or_codename"), propInfoNull)
//    AssertionResult("ro.system.build.version.release_or_codename", NativeLibWrapper.sysPropsRead("ro.system.build.version.release_or_codename"), "16")
//    AssertionResult("ro.system.build.version.release_or_codename", NativeLibWrapper.sysPropsReadCb("ro.system.build.version.release_or_codename"), "16")
//
//    AssertionResult("ro.system_ext.build.version.release_or_codename", NativeLibWrapper.sysPropsGet("ro.system_ext.build.version.release_or_codename"), "16")
//    AssertionResult("ro.system_ext.build.version.release_or_codename", NativeLibWrapper.sysPropsReadWithNullName("ro.system_ext.build.version.release_or_codename"), propInfoNull)
//    AssertionResult("ro.system_ext.build.version.release_or_codename", NativeLibWrapper.sysPropsRead("ro.system_ext.build.version.release_or_codename"), "16")
//    AssertionResult("ro.system_ext.build.version.release_or_codename", NativeLibWrapper.sysPropsReadCb("ro.system_ext.build.version.release_or_codename"), "16")
//
//    AssertionResult("ro.build.version.release_or_preview_display", NativeLibWrapper.sysPropsGet("ro.build.version.release_or_preview_display"), "16")
//    AssertionResult("ro.build.version.release_or_preview_display", NativeLibWrapper.sysPropsReadWithNullName("ro.build.version.release_or_preview_display"), propInfoNull)
//    AssertionResult("ro.build.version.release_or_preview_display", NativeLibWrapper.sysPropsRead("ro.build.version.release_or_preview_display"), "16")
//    AssertionResult("ro.build.version.release_or_preview_display", NativeLibWrapper.sysPropsReadCb("ro.build.version.release_or_preview_display"), "16")

//    AssertionResult("ro.build.version.sdk", NativeLibWrapper.sysPropsGet("ro.build.version.sdk"), "36")
//    AssertionResult("ro.build.version.sdk", NativeLibWrapper.sysPropsReadWithNullName("ro.build.version.sdk"), propInfoNull)
//    AssertionResult("ro.build.version.sdk", NativeLibWrapper.sysPropsRead("ro.build.version.sdk"), "36")
//    AssertionResult("ro.build.version.sdk", NativeLibWrapper.sysPropsReadCb("ro.build.version.sdk"), "36")
//
//    AssertionResult("ro.product.build.version.sdk", NativeLibWrapper.sysPropsGet("ro.product.build.version.sdk"), "36")
//    AssertionResult("ro.product.build.version.sdk", NativeLibWrapper.sysPropsReadWithNullName("ro.product.build.version.sdk"), propInfoNull)
//    AssertionResult("ro.product.build.version.sdk", NativeLibWrapper.sysPropsRead("ro.product.build.version.sdk"), "36")
//    AssertionResult("ro.product.build.version.sdk", NativeLibWrapper.sysPropsReadCb("ro.product.build.version.sdk"), "36")
//
//    AssertionResult("ro.vendor.build.version.sdk", NativeLibWrapper.sysPropsGet("ro.vendor.build.version.sdk"), "36")
//    AssertionResult("ro.vendor.build.version.sdk", NativeLibWrapper.sysPropsReadWithNullName("ro.vendor.build.version.sdk"), propInfoNull)
//    AssertionResult("ro.vendor.build.version.sdk", NativeLibWrapper.sysPropsRead("ro.vendor.build.version.sdk"), "36")
//    AssertionResult("ro.vendor.build.version.sdk", NativeLibWrapper.sysPropsReadCb("ro.vendor.build.version.sdk"), "36")
//
//    AssertionResult("ro.vendor_dlkm.build.version.sdk", NativeLibWrapper.sysPropsGet("ro.vendor_dlkm.build.version.sdk"), "36")
//    AssertionResult("ro.vendor_dlkm.build.version.sdk", NativeLibWrapper.sysPropsReadWithNullName("ro.vendor_dlkm.build.version.sdk"), propInfoNull)
//    AssertionResult("ro.vendor_dlkm.build.version.sdk", NativeLibWrapper.sysPropsRead("ro.vendor_dlkm.build.version.sdk"), "36")
//    AssertionResult("ro.vendor_dlkm.build.version.sdk", NativeLibWrapper.sysPropsReadCb("ro.vendor_dlkm.build.version.sdk"), "36")
//
//    AssertionResult("ro.system_ext.build.version.sdk", NativeLibWrapper.sysPropsGet("ro.system_ext.build.version.sdk"), "36")
//    AssertionResult("ro.system_ext.build.version.sdk", NativeLibWrapper.sysPropsReadWithNullName("ro.system_ext.build.version.sdk"), propInfoNull)
//    AssertionResult("ro.system_ext.build.version.sdk", NativeLibWrapper.sysPropsRead("ro.system_ext.build.version.sdk"), "36")
//    AssertionResult("ro.system_ext.build.version.sdk", NativeLibWrapper.sysPropsReadCb("ro.system_ext.build.version.sdk"), "36")
//
//    AssertionResult("ro.system.build.version.sdk", NativeLibWrapper.sysPropsGet("ro.system.build.version.sdk"), "36")
//    AssertionResult("ro.system.build.version.sdk", NativeLibWrapper.sysPropsReadWithNullName("ro.system.build.version.sdk"), propInfoNull)
//    AssertionResult("ro.system.build.version.sdk", NativeLibWrapper.sysPropsRead("ro.system.build.version.sdk"), "36")
//    AssertionResult("ro.system.build.version.sdk", NativeLibWrapper.sysPropsReadCb("ro.system.build.version.sdk"), "36")

//    AssertionResult("ro.build.version.sdk_full", NativeLibWrapper.sysPropsGet("ro.build.version.sdk_full"), "36.1")
//    AssertionResult("ro.build.version.sdk_full", NativeLibWrapper.sysPropsReadWithNullName("ro.build.version.sdk_full"), propInfoNull)
//    AssertionResult("ro.build.version.sdk_full", NativeLibWrapper.sysPropsRead("ro.build.version.sdk_full"), "36.1")
//    AssertionResult("ro.build.version.sdk_full", NativeLibWrapper.sysPropsReadCb("ro.build.version.sdk_full"), "36.1")

//    AssertionResult("ro.product.build.version.sdk_full", NativeLibWrapper.sysPropsGet("ro.product.build.version.sdk_full"), "36.1")
//    AssertionResult("ro.product.build.version.sdk_full", NativeLibWrapper.sysPropsReadWithNullName("ro.product.build.version.sdk_full"), propInfoNull)
//    AssertionResult("ro.product.build.version.sdk_full", NativeLibWrapper.sysPropsRead("ro.product.build.version.sdk_full"), "36.1")
//    AssertionResult("ro.product.build.version.sdk_full", NativeLibWrapper.sysPropsReadCb("ro.product.build.version.sdk_full"), "36.1")
//
//    AssertionResult("ro.system_ext.build.version.sdk_full", NativeLibWrapper.sysPropsGet("ro.system_ext.build.version.sdk_full"), "36.1")
//    AssertionResult("ro.system_ext.build.version.sdk_full", NativeLibWrapper.sysPropsReadWithNullName("ro.system_ext.build.version.sdk_full"), propInfoNull)
//    AssertionResult("ro.system_ext.build.version.sdk_full", NativeLibWrapper.sysPropsRead("ro.system_ext.build.version.sdk_full"), "36.1")
//    AssertionResult("ro.system_ext.build.version.sdk_full", NativeLibWrapper.sysPropsReadCb("ro.system_ext.build.version.sdk_full"), "36.1")
//
//    AssertionResult("ro.system.build.version.sdk_full", NativeLibWrapper.sysPropsGet("ro.system.build.version.sdk_full"), "36.1")
//    AssertionResult("ro.system.build.version.sdk_full", NativeLibWrapper.sysPropsReadWithNullName("ro.system.build.version.sdk_full"), propInfoNull)
//    AssertionResult("ro.system.build.version.sdk_full", NativeLibWrapper.sysPropsRead("ro.system.build.version.sdk_full"), "36.1")
//    AssertionResult("ro.system.build.version.sdk_full", NativeLibWrapper.sysPropsReadCb("ro.system.build.version.sdk_full"), "36.1")

    AssertionResult("ro.build.version.security_patch", NativeLibWrapper.sysPropsGet("ro.build.version.security_patch"), "2025-12-05")
    AssertionResult("ro.build.version.security_patch", NativeLibWrapper.sysPropsReadWithNullName("ro.build.version.security_patch"), "2025-12-05")
    AssertionResult("ro.build.version.security_patch", NativeLibWrapper.sysPropsRead("ro.build.version.security_patch"), "2025-12-05")
    AssertionResult("ro.build.version.security_patch", NativeLibWrapper.sysPropsReadCb("ro.build.version.security_patch"), "2025-12-05")

    AssertionResult("ro.build.version.codename", NativeLibWrapper.sysPropsGet("ro.build.version.codename"), "REL")
    AssertionResult("ro.build.version.codename", NativeLibWrapper.sysPropsReadWithNullName("ro.build.version.codename"), "REL")
    AssertionResult("ro.build.version.codename", NativeLibWrapper.sysPropsRead("ro.build.version.codename"), "REL")
    AssertionResult("ro.build.version.codename", NativeLibWrapper.sysPropsReadCb("ro.build.version.codename"), "REL")

    AssertionResult("ro.build.version.base_os", NativeLibWrapper.sysPropsGet("ro.build.version.base_os"), defaultValue)
    AssertionResult("ro.build.version.base_os", NativeLibWrapper.sysPropsReadWithNullName("ro.build.version.base_os"), defaultValue)
    AssertionResult("ro.build.version.base_os", NativeLibWrapper.sysPropsRead("ro.build.version.base_os"), defaultValue)
    AssertionResult("ro.build.version.base_os", NativeLibWrapper.sysPropsReadCb("ro.build.version.base_os"), defaultValue)

    AssertionResult("ro.build.version.preview_sdk", NativeLibWrapper.sysPropsGet("ro.build.version.preview_sdk"), "0")
    AssertionResult("ro.build.version.preview_sdk", NativeLibWrapper.sysPropsReadWithNullName("ro.build.version.preview_sdk"), "0")
    AssertionResult("ro.build.version.preview_sdk", NativeLibWrapper.sysPropsRead("ro.build.version.preview_sdk"), "0")
    AssertionResult("ro.build.version.preview_sdk", NativeLibWrapper.sysPropsReadCb("ro.build.version.preview_sdk"), "0")

    AssertionResult("ro.build.fingerprint", NativeLibWrapper.sysPropsGet("ro.build.fingerprint"), fingerprint)
    AssertionResult("ro.build.fingerprint", NativeLibWrapper.sysPropsReadWithNullName("ro.build.fingerprint"), fingerprint)
    AssertionResult("ro.build.fingerprint", NativeLibWrapper.sysPropsRead("ro.build.fingerprint"), fingerprint)
    AssertionResult("ro.build.fingerprint", NativeLibWrapper.sysPropsReadCb("ro.build.fingerprint"), fingerprint)

    AssertionResult("ro.odm.build.fingerprint", NativeLibWrapper.sysPropsGet("ro.odm.build.fingerprint"), fingerprint)
    AssertionResult("ro.odm.build.fingerprint", NativeLibWrapper.sysPropsReadWithNullName("ro.odm.build.fingerprint"), fingerprint)
    AssertionResult("ro.odm.build.fingerprint", NativeLibWrapper.sysPropsRead("ro.odm.build.fingerprint"), fingerprint)
    AssertionResult("ro.odm.build.fingerprint", NativeLibWrapper.sysPropsReadCb("ro.odm.build.fingerprint"), fingerprint)

    AssertionResult("ro.product.build.fingerprint", NativeLibWrapper.sysPropsGet("ro.product.build.fingerprint"), fingerprint)
    AssertionResult("ro.product.build.fingerprint", NativeLibWrapper.sysPropsReadWithNullName("ro.product.build.fingerprint"), fingerprint)
    AssertionResult("ro.product.build.fingerprint", NativeLibWrapper.sysPropsRead("ro.product.build.fingerprint"), fingerprint)
    AssertionResult("ro.product.build.fingerprint", NativeLibWrapper.sysPropsReadCb("ro.product.build.fingerprint"), fingerprint)

    AssertionResult("ro.system.build.fingerprint", NativeLibWrapper.sysPropsGet("ro.system.build.fingerprint"), fingerprint)
    AssertionResult("ro.system.build.fingerprint", NativeLibWrapper.sysPropsReadWithNullName("ro.system.build.fingerprint"), fingerprint)
    AssertionResult("ro.system.build.fingerprint", NativeLibWrapper.sysPropsRead("ro.system.build.fingerprint"), fingerprint)
    AssertionResult("ro.system.build.fingerprint", NativeLibWrapper.sysPropsReadCb("ro.system.build.fingerprint"), fingerprint)

    AssertionResult("ro.system_ext.build.fingerprint", NativeLibWrapper.sysPropsGet("ro.system_ext.build.fingerprint"), fingerprint)
    AssertionResult("ro.system_ext.build.fingerprint", NativeLibWrapper.sysPropsReadWithNullName("ro.system_ext.build.fingerprint"), fingerprint)
    AssertionResult("ro.system_ext.build.fingerprint", NativeLibWrapper.sysPropsRead("ro.system_ext.build.fingerprint"), fingerprint)
    AssertionResult("ro.system_ext.build.fingerprint", NativeLibWrapper.sysPropsReadCb("ro.system_ext.build.fingerprint"), fingerprint)

    AssertionResult("ro.vendor.build.fingerprint", NativeLibWrapper.sysPropsGet("ro.vendor.build.fingerprint"), fingerprint)
    AssertionResult("ro.vendor.build.fingerprint", NativeLibWrapper.sysPropsReadWithNullName("ro.vendor.build.fingerprint"), fingerprint)
    AssertionResult("ro.vendor.build.fingerprint", NativeLibWrapper.sysPropsRead("ro.vendor.build.fingerprint"), fingerprint)
    AssertionResult("ro.vendor.build.fingerprint", NativeLibWrapper.sysPropsReadCb("ro.vendor.build.fingerprint"), fingerprint)

    AssertionResult("ro.vendor_dlkm.build.fingerprint", NativeLibWrapper.sysPropsGet("ro.vendor_dlkm.build.fingerprint"), fingerprint)
    AssertionResult("ro.vendor_dlkm.build.fingerprint", NativeLibWrapper.sysPropsReadWithNullName("ro.vendor_dlkm.build.fingerprint"), fingerprint)
    AssertionResult("ro.vendor_dlkm.build.fingerprint", NativeLibWrapper.sysPropsRead("ro.vendor_dlkm.build.fingerprint"), fingerprint)
    AssertionResult("ro.vendor_dlkm.build.fingerprint", NativeLibWrapper.sysPropsReadCb("ro.vendor_dlkm.build.fingerprint"), fingerprint)

    AssertionResult("gsm.version.baseband", NativeLibWrapper.sysPropsGet("gsm.version.baseband"), "g5300g-251108-251202-B-12876551")
    AssertionResult("gsm.version.baseband", NativeLibWrapper.sysPropsReadWithNullName("gsm.version.baseband"), "g5300g-251108-251202-B-12876551")
    AssertionResult("gsm.version.baseband", NativeLibWrapper.sysPropsRead("gsm.version.baseband"), "g5300g-251108-251202-B-12876551")
    AssertionResult("gsm.version.baseband", NativeLibWrapper.sysPropsReadCb("gsm.version.baseband"), "g5300g-251108-251202-B-12876551")

    AssertionResult("gsm.version.ril-impl", NativeLibWrapper.sysPropsGet("gsm.version.ril-impl"), "com.google.android.telephony.modem")
    AssertionResult("gsm.version.ril-impl", NativeLibWrapper.sysPropsReadWithNullName("gsm.version.ril-impl"), "com.google.android.telephony.modem")
    AssertionResult("gsm.version.ril-impl", NativeLibWrapper.sysPropsRead("gsm.version.ril-impl"), "com.google.android.telephony.modem")
    AssertionResult("gsm.version.ril-impl", NativeLibWrapper.sysPropsReadCb("gsm.version.ril-impl"), "com.google.android.telephony.modem")

    AssertionResult("ril.sw_ver", NativeLibWrapper.sysPropsGet("ril.sw_ver"), defaultValue)
    AssertionResult("ril.sw_ver", NativeLibWrapper.sysPropsReadWithNullName("ril.sw_ver"), defaultValue)
    AssertionResult("ril.sw_ver", NativeLibWrapper.sysPropsRead("ril.sw_ver"), defaultValue)
    AssertionResult("ril.sw_ver", NativeLibWrapper.sysPropsReadCb("ril.sw_ver"), defaultValue)

    AssertionResult("ril.sw_ver2", NativeLibWrapper.sysPropsGet("ril.sw_ver2"), defaultValue)
    AssertionResult("ril.sw_ver2", NativeLibWrapper.sysPropsReadWithNullName("ril.sw_ver2"), defaultValue)
    AssertionResult("ril.sw_ver2", NativeLibWrapper.sysPropsRead("ril.sw_ver2"), defaultValue)
    AssertionResult("ril.sw_ver2", NativeLibWrapper.sysPropsReadCb("ril.sw_ver2"), defaultValue)

    AssertionResult("ro.baseband", NativeLibWrapper.sysPropsGet("ro.baseband"), "g5300g-251108-251202-B-12876551")
    AssertionResult("ro.baseband", NativeLibWrapper.sysPropsReadWithNullName("ro.baseband"), "g5300g-251108-251202-B-12876551")
    AssertionResult("ro.baseband", NativeLibWrapper.sysPropsRead("ro.baseband"), "g5300g-251108-251202-B-12876551")
    AssertionResult("ro.baseband", NativeLibWrapper.sysPropsReadCb("ro.baseband"), "g5300g-251108-251202-B-12876551")

    AssertionResult("ro.config.alarm_alert", NativeLibWrapper.sysPropsGet("ro.config.alarm_alert"), "Hassium.ogg")
    AssertionResult("ro.config.alarm_alert", NativeLibWrapper.sysPropsReadWithNullName("ro.config.alarm_alert"), "Hassium.ogg")
    AssertionResult("ro.config.alarm_alert", NativeLibWrapper.sysPropsRead("ro.config.alarm_alert"), "Hassium.ogg")
    AssertionResult("ro.config.alarm_alert", NativeLibWrapper.sysPropsReadCb("ro.config.alarm_alert"), "Hassium.ogg")

    AssertionResult("ro.config.notification_sound", NativeLibWrapper.sysPropsGet("ro.config.notification_sound"), "Argon.ogg")
    AssertionResult("ro.config.notification_sound", NativeLibWrapper.sysPropsReadWithNullName("ro.config.notification_sound"), "Argon.ogg")
    AssertionResult("ro.config.notification_sound", NativeLibWrapper.sysPropsRead("ro.config.notification_sound"), "Argon.ogg")
    AssertionResult("ro.config.notification_sound", NativeLibWrapper.sysPropsReadCb("ro.config.notification_sound"), "Argon.ogg")

    AssertionResult("ro.config.ringtone", NativeLibWrapper.sysPropsGet("ro.config.ringtone"), "Orion.ogg")
    AssertionResult("ro.config.ringtone", NativeLibWrapper.sysPropsReadWithNullName("ro.config.ringtone"), "Orion.ogg")
    AssertionResult("ro.config.ringtone", NativeLibWrapper.sysPropsRead("ro.config.ringtone"), "Orion.ogg")
    AssertionResult("ro.config.ringtone", NativeLibWrapper.sysPropsReadCb("ro.config.ringtone"), "Orion.ogg")

    AssertionResult("ro.product.locale", NativeLibWrapper.sysPropsGet("ro.product.locale"), "en-US")
    AssertionResult("ro.product.locale", NativeLibWrapper.sysPropsReadWithNullName("ro.product.locale"), "en-US")
    AssertionResult("ro.product.locale", NativeLibWrapper.sysPropsRead("ro.product.locale"), "en-US")
    AssertionResult("ro.product.locale", NativeLibWrapper.sysPropsReadCb("ro.product.locale"), "en-US")

//    AssertionResult("persist.sys.locale", NativeLibWrapper.sysPropsGet("persist.sys.locale"), defaultValue)
//    AssertionResult("persist.sys.locale", NativeLibWrapper.sysPropsReadWithNullName("persist.sys.locale"), propInfoNull)
//    AssertionResult("persist.sys.locale", NativeLibWrapper.sysPropsRead("persist.sys.locale"), defaultValue)
//    AssertionResult("persist.sys.locale", NativeLibWrapper.sysPropsReadCb("persist.sys.locale"), defaultValue)

    AssertionResult("bluetooth.device.default_name", NativeLibWrapper.sysPropsGet("bluetooth.device.default_name"), "Pixel 8 Pro")
    AssertionResult("bluetooth.device.default_name", NativeLibWrapper.sysPropsReadWithNullName("bluetooth.device.default_name"), "Pixel 8 Pro")
    AssertionResult("bluetooth.device.default_name", NativeLibWrapper.sysPropsRead("bluetooth.device.default_name"), "Pixel 8 Pro")
    AssertionResult("bluetooth.device.default_name", NativeLibWrapper.sysPropsReadCb("bluetooth.device.default_name"), "Pixel 8 Pro")

    AssertionResult("debug.debuggerd.wait_for_debugger", NativeLibWrapper.sysPropsGet("debug.debuggerd.wait_for_debugger"), defaultValue)
    AssertionResult("debug.debuggerd.wait_for_debugger", NativeLibWrapper.sysPropsReadWithNullName("debug.debuggerd.wait_for_debugger"), propInfoNull)
    AssertionResult("debug.debuggerd.wait_for_debugger", NativeLibWrapper.sysPropsRead("debug.debuggerd.wait_for_debugger"), propInfoNull)
    AssertionResult("debug.debuggerd.wait_for_debugger", NativeLibWrapper.sysPropsReadCb("debug.debuggerd.wait_for_debugger"), propInfoNull)

    AssertionResult("nfc.initialized", NativeLibWrapper.sysPropsGet("nfc.initialized"), "false")
    AssertionResult("nfc.initialized", NativeLibWrapper.sysPropsReadWithNullName("nfc.initialized"), "false")
    AssertionResult("nfc.initialized", NativeLibWrapper.sysPropsRead("nfc.initialized"), "false")
    AssertionResult("nfc.initialized", NativeLibWrapper.sysPropsReadCb("nfc.initialized"), "false")

    AssertionResult("ro.support_one_handed_mode", NativeLibWrapper.sysPropsGet("ro.support_one_handed_mode"), "false")
    AssertionResult("ro.support_one_handed_mode", NativeLibWrapper.sysPropsReadWithNullName("ro.support_one_handed_mode"), "false")
    AssertionResult("ro.support_one_handed_mode", NativeLibWrapper.sysPropsRead("ro.support_one_handed_mode"), "false")
    AssertionResult("ro.support_one_handed_mode", NativeLibWrapper.sysPropsReadCb("ro.support_one_handed_mode"), "false")

    AssertionResult("init.svc.vaultkeeper", NativeLibWrapper.sysPropsGet("init.svc.vaultkeeper"), defaultValue)
    AssertionResult("init.svc.vaultkeeper", NativeLibWrapper.sysPropsReadWithNullName("init.svc.vaultkeeper"), defaultValue)
    AssertionResult("init.svc.vaultkeeper", NativeLibWrapper.sysPropsRead("init.svc.vaultkeeper"), defaultValue)
    AssertionResult("init.svc.vaultkeeper", NativeLibWrapper.sysPropsReadCb("init.svc.vaultkeeper"), defaultValue)

    AssertionResult("init.svc.vendor_flash_recovery", NativeLibWrapper.sysPropsGet("init.svc.vendor_flash_recovery"), defaultValue)
    AssertionResult("init.svc.vendor_flash_recovery", NativeLibWrapper.sysPropsReadWithNullName("init.svc.vendor_flash_recovery"), defaultValue)
    AssertionResult("init.svc.vendor_flash_recovery", NativeLibWrapper.sysPropsRead("init.svc.vendor_flash_recovery"), defaultValue)
    AssertionResult("init.svc.vendor_flash_recovery", NativeLibWrapper.sysPropsReadCb("init.svc.vendor_flash_recovery"), defaultValue)

    AssertionResult("init.svc.lineage-bugreport", NativeLibWrapper.sysPropsGet("init.svc.lineage-bugreport"), defaultValue)
    AssertionResult("init.svc.lineage-bugreport", NativeLibWrapper.sysPropsReadWithNullName("init.svc.lineage-bugreport"), propInfoNull)
    AssertionResult("init.svc.lineage-bugreport", NativeLibWrapper.sysPropsRead("init.svc.lineage-bugreport"), propInfoNull)
    AssertionResult("init.svc.lineage-bugreport", NativeLibWrapper.sysPropsReadCb("init.svc.lineage-bugreport"), propInfoNull)

    AssertionResult("ro.board.api_frozen", NativeLibWrapper.sysPropsGet("ro.board.api_frozen"), defaultValue)
    AssertionResult("ro.board.api_frozen", NativeLibWrapper.sysPropsReadWithNullName("ro.board.api_frozen"), defaultValue)
    AssertionResult("ro.board.api_frozen", NativeLibWrapper.sysPropsRead("ro.board.api_frozen"), defaultValue)
    AssertionResult("ro.board.api_frozen", NativeLibWrapper.sysPropsReadCb("ro.board.api_frozen"), defaultValue)

    AssertionResult("init.svc.adb_root", NativeLibWrapper.sysPropsGet("init.svc.adb_root"), defaultValue)
    AssertionResult("init.svc.adb_root", NativeLibWrapper.sysPropsReadWithNullName("init.svc.adb_root"), defaultValue)
    AssertionResult("init.svc.adb_root", NativeLibWrapper.sysPropsRead("init.svc.adb_root"), defaultValue)
    AssertionResult("init.svc.adb_root", NativeLibWrapper.sysPropsReadCb("init.svc.adb_root"), defaultValue)

    AssertionResult("service.adb.root", NativeLibWrapper.sysPropsGet("service.adb.root"), defaultValue)
    AssertionResult("service.adb.root", NativeLibWrapper.sysPropsReadWithNullName("service.adb.root"), propInfoNull)
    AssertionResult("service.adb.root", NativeLibWrapper.sysPropsRead("service.adb.root"), propInfoNull)
    AssertionResult("service.adb.root", NativeLibWrapper.sysPropsReadCb("service.adb.root"), propInfoNull)

    AssertionResult("persist.sys.usb.config", NativeLibWrapper.sysPropsGet("persist.sys.usb.config"), defaultValue)
    AssertionResult("persist.sys.usb.config", NativeLibWrapper.sysPropsReadWithNullName("persist.sys.usb.config"), defaultValue)
    AssertionResult("persist.sys.usb.config", NativeLibWrapper.sysPropsRead("persist.sys.usb.config"), defaultValue)
    AssertionResult("persist.sys.usb.config", NativeLibWrapper.sysPropsReadCb("persist.sys.usb.config"), defaultValue)

    AssertionResult("sys.usb.config", NativeLibWrapper.sysPropsGet("sys.usb.config"), "mtp")
    AssertionResult("sys.usb.config", NativeLibWrapper.sysPropsReadWithNullName("sys.usb.config"), "mtp")
    AssertionResult("sys.usb.config", NativeLibWrapper.sysPropsRead("sys.usb.config"), "mtp")
    AssertionResult("sys.usb.config", NativeLibWrapper.sysPropsReadCb("sys.usb.config"), "mtp")

    AssertionResult("sys.usb.configfs", NativeLibWrapper.sysPropsGet("sys.usb.configfs"), "1")
    AssertionResult("sys.usb.configfs", NativeLibWrapper.sysPropsReadWithNullName("sys.usb.configfs"), "1")
    AssertionResult("sys.usb.configfs", NativeLibWrapper.sysPropsRead("sys.usb.configfs"), "1")
    AssertionResult("sys.usb.configfs", NativeLibWrapper.sysPropsReadCb("sys.usb.configfs"), "1")

    AssertionResult("init.svc.usbd", NativeLibWrapper.sysPropsGet("init.svc.usbd"), "stopped")
    AssertionResult("init.svc.usbd", NativeLibWrapper.sysPropsReadWithNullName("init.svc.usbd"), "stopped")
    AssertionResult("init.svc.usbd", NativeLibWrapper.sysPropsRead("init.svc.usbd"), "stopped")
    AssertionResult("init.svc.usbd", NativeLibWrapper.sysPropsReadCb("init.svc.usbd"), "stopped")

    AssertionResult("init.svc.adbd", NativeLibWrapper.sysPropsGet("init.svc.adbd"), "stopped")
    AssertionResult("init.svc.adbd", NativeLibWrapper.sysPropsReadWithNullName("init.svc.adbd"), "stopped")
    AssertionResult("init.svc.adbd", NativeLibWrapper.sysPropsRead("init.svc.adbd"), "stopped")
    AssertionResult("init.svc.adbd", NativeLibWrapper.sysPropsReadCb("init.svc.adbd"), "stopped")

    AssertionResult("sys.usb.controller", NativeLibWrapper.sysPropsGet("sys.usb.controller"), defaultValue)
    AssertionResult("sys.usb.controller", NativeLibWrapper.sysPropsReadWithNullName("sys.usb.controller"), defaultValue)
    AssertionResult("sys.usb.controller", NativeLibWrapper.sysPropsRead("sys.usb.controller"), defaultValue)
    AssertionResult("sys.usb.controller", NativeLibWrapper.sysPropsReadCb("sys.usb.controller"), defaultValue)

    AssertionResult("ro.kernel.version", NativeLibWrapper.sysPropsGet("ro.kernel.version"), "6.6")
    AssertionResult("ro.kernel.version", NativeLibWrapper.sysPropsReadWithNullName("ro.kernel.version"), "6.6")
    AssertionResult("ro.kernel.version", NativeLibWrapper.sysPropsRead("ro.kernel.version"), "6.6")
    AssertionResult("ro.kernel.version", NativeLibWrapper.sysPropsReadCb("ro.kernel.version"), "6.6")

    AssertionResult("ro.odm.product.cpu.abilist32", NativeLibWrapper.sysPropsGet("ro.odm.product.cpu.abilist32"), defaultValue)
    AssertionResult("ro.odm.product.cpu.abilist32", NativeLibWrapper.sysPropsReadWithNullName("ro.odm.product.cpu.abilist32"), propInfoNull)
    AssertionResult("ro.odm.product.cpu.abilist32", NativeLibWrapper.sysPropsRead("ro.odm.product.cpu.abilist32"), propInfoNull)
    AssertionResult("ro.odm.product.cpu.abilist32", NativeLibWrapper.sysPropsReadCb("ro.odm.product.cpu.abilist32"), propInfoNull)

    AssertionResult("ro.product.cpu.abilist32", NativeLibWrapper.sysPropsGet("ro.product.cpu.abilist32"), defaultValue)
    AssertionResult("ro.product.cpu.abilist32", NativeLibWrapper.sysPropsReadWithNullName("ro.product.cpu.abilist32"), defaultValue)
    AssertionResult("ro.product.cpu.abilist32", NativeLibWrapper.sysPropsRead("ro.product.cpu.abilist32"), defaultValue)
    AssertionResult("ro.product.cpu.abilist32", NativeLibWrapper.sysPropsReadCb("ro.product.cpu.abilist32"), defaultValue)

    AssertionResult("ro.system.product.cpu.abilist32", NativeLibWrapper.sysPropsGet("ro.system.product.cpu.abilist32"), defaultValue)
    AssertionResult("ro.system.product.cpu.abilist32", NativeLibWrapper.sysPropsReadWithNullName("ro.system.product.cpu.abilist32"), defaultValue)
    AssertionResult("ro.system.product.cpu.abilist32", NativeLibWrapper.sysPropsRead("ro.system.product.cpu.abilist32"), defaultValue)
    AssertionResult("ro.system.product.cpu.abilist32", NativeLibWrapper.sysPropsReadCb("ro.system.product.cpu.abilist32"), defaultValue)

    AssertionResult("ro.vendor.product.cpu.abilist32", NativeLibWrapper.sysPropsGet("ro.vendor.product.cpu.abilist32"), defaultValue)
    AssertionResult("ro.vendor.product.cpu.abilist32", NativeLibWrapper.sysPropsReadWithNullName("ro.vendor.product.cpu.abilist32"), defaultValue)
    AssertionResult("ro.vendor.product.cpu.abilist32", NativeLibWrapper.sysPropsRead("ro.vendor.product.cpu.abilist32"), defaultValue)
    AssertionResult("ro.vendor.product.cpu.abilist32", NativeLibWrapper.sysPropsReadCb("ro.vendor.product.cpu.abilist32"), defaultValue)

    AssertionResult("ro.odm.product.cpu.abilist", NativeLibWrapper.sysPropsGet("ro.odm.product.cpu.abilist"), defaultValue)
    AssertionResult("ro.odm.product.cpu.abilist", NativeLibWrapper.sysPropsReadWithNullName("ro.odm.product.cpu.abilist"), propInfoNull)
    AssertionResult("ro.odm.product.cpu.abilist", NativeLibWrapper.sysPropsRead("ro.odm.product.cpu.abilist"), propInfoNull)
    AssertionResult("ro.odm.product.cpu.abilist", NativeLibWrapper.sysPropsReadCb("ro.odm.product.cpu.abilist"), propInfoNull)

    AssertionResult("ro.product.cpu.abilist", NativeLibWrapper.sysPropsGet("ro.product.cpu.abilist"), "arm64-v8a")
    AssertionResult("ro.product.cpu.abilist", NativeLibWrapper.sysPropsReadWithNullName("ro.product.cpu.abilist"), "arm64-v8a")
    AssertionResult("ro.product.cpu.abilist", NativeLibWrapper.sysPropsRead("ro.product.cpu.abilist"), "arm64-v8a")
    AssertionResult("ro.product.cpu.abilist", NativeLibWrapper.sysPropsReadCb("ro.product.cpu.abilist"), "arm64-v8a")

    AssertionResult("ro.system.product.cpu.abilist", NativeLibWrapper.sysPropsGet("ro.system.product.cpu.abilist"), "arm64-v8a")
    AssertionResult("ro.system.product.cpu.abilist", NativeLibWrapper.sysPropsReadWithNullName("ro.system.product.cpu.abilist"), "arm64-v8a")
    AssertionResult("ro.system.product.cpu.abilist", NativeLibWrapper.sysPropsRead("ro.system.product.cpu.abilist"), "arm64-v8a")
    AssertionResult("ro.system.product.cpu.abilist", NativeLibWrapper.sysPropsReadCb("ro.system.product.cpu.abilist"), "arm64-v8a")

    AssertionResult("ro.vendor.product.cpu.abilist", NativeLibWrapper.sysPropsGet("ro.vendor.product.cpu.abilist"), "arm64-v8a")
    AssertionResult("ro.vendor.product.cpu.abilist", NativeLibWrapper.sysPropsReadWithNullName("ro.vendor.product.cpu.abilist"), "arm64-v8a")
    AssertionResult("ro.vendor.product.cpu.abilist", NativeLibWrapper.sysPropsRead("ro.vendor.product.cpu.abilist"), "arm64-v8a")
    AssertionResult("ro.vendor.product.cpu.abilist", NativeLibWrapper.sysPropsReadCb("ro.vendor.product.cpu.abilist"), "arm64-v8a")

    AssertionResult("ro.zygote", NativeLibWrapper.sysPropsGet("ro.zygote"), "zygote64")
    AssertionResult("ro.zygote", NativeLibWrapper.sysPropsReadWithNullName("ro.zygote"), "zygote64")
    AssertionResult("ro.zygote", NativeLibWrapper.sysPropsRead("ro.zygote"), "zygote64")
    AssertionResult("ro.zygote", NativeLibWrapper.sysPropsReadCb("ro.zygote"), "zygote64")

    AssertionResult("init.svc.zygote_secondary", NativeLibWrapper.sysPropsGet("init.svc.zygote_secondary"), defaultValue)
    AssertionResult("init.svc.zygote_secondary", NativeLibWrapper.sysPropsReadWithNullName("init.svc.zygote_secondary"), defaultValue)
    AssertionResult("init.svc.zygote_secondary", NativeLibWrapper.sysPropsRead("init.svc.zygote_secondary"), defaultValue)
    AssertionResult("init.svc.zygote_secondary", NativeLibWrapper.sysPropsReadCb("init.svc.zygote_secondary"), defaultValue)

    AssertionResult("ro.bootmode", NativeLibWrapper.sysPropsGet("ro.bootmode"), "normal")
    AssertionResult("ro.bootmode", NativeLibWrapper.sysPropsReadWithNullName("ro.bootmode"), "normal")
    AssertionResult("ro.bootmode", NativeLibWrapper.sysPropsRead("ro.bootmode"), "normal")
    AssertionResult("ro.bootmode", NativeLibWrapper.sysPropsReadCb("ro.bootmode"), "normal")

    AssertionResult("bootreceiver.enable", NativeLibWrapper.sysPropsGet("bootreceiver.enable"), "1")
    AssertionResult("bootreceiver.enable", NativeLibWrapper.sysPropsReadWithNullName("bootreceiver.enable"), "1")
    AssertionResult("bootreceiver.enable", NativeLibWrapper.sysPropsRead("bootreceiver.enable"), "1")
    AssertionResult("bootreceiver.enable", NativeLibWrapper.sysPropsReadCb("bootreceiver.enable"), "1")

    AssertionResult("ro.bootloader", NativeLibWrapper.sysPropsGet("ro.bootloader"), bootloader)
    AssertionResult("ro.bootloader", NativeLibWrapper.sysPropsReadWithNullName("ro.bootloader"), bootloader)
    AssertionResult("ro.bootloader", NativeLibWrapper.sysPropsRead("ro.bootloader"), bootloader)
    AssertionResult("ro.bootloader", NativeLibWrapper.sysPropsReadCb("ro.bootloader"), bootloader)

    AssertionResult("ro.soc.manufacturer", NativeLibWrapper.sysPropsGet("ro.soc.manufacturer"), "Google")
    AssertionResult("ro.soc.manufacturer", NativeLibWrapper.sysPropsReadWithNullName("ro.soc.manufacturer"), "Google")
    AssertionResult("ro.soc.manufacturer", NativeLibWrapper.sysPropsRead("ro.soc.manufacturer"), "Google")
    AssertionResult("ro.soc.manufacturer", NativeLibWrapper.sysPropsReadCb("ro.soc.manufacturer"), "Google")

    AssertionResult("ro.soc.model", NativeLibWrapper.sysPropsGet("ro.soc.model"), "Tensor G3")
    AssertionResult("ro.soc.model", NativeLibWrapper.sysPropsReadWithNullName("ro.soc.model"), "Tensor G3")
    AssertionResult("ro.soc.model", NativeLibWrapper.sysPropsRead("ro.soc.model"), "Tensor G3")
    AssertionResult("ro.soc.model", NativeLibWrapper.sysPropsReadCb("ro.soc.model"), "Tensor G3")

    AssertionResult("ro.boot.boot_devices", NativeLibWrapper.sysPropsGet("ro.boot.boot_devices"), "soc/1d84000.ufshc")
    AssertionResult("ro.boot.boot_devices", NativeLibWrapper.sysPropsReadWithNullName("ro.boot.boot_devices"), "soc/1d84000.ufshc")
    AssertionResult("ro.boot.boot_devices", NativeLibWrapper.sysPropsRead("ro.boot.boot_devices"), "soc/1d84000.ufshc")
    AssertionResult("ro.boot.boot_devices", NativeLibWrapper.sysPropsReadCb("ro.boot.boot_devices"), "soc/1d84000.ufshc")

    AssertionResult("ro.boot.bootloader", NativeLibWrapper.sysPropsGet("ro.boot.bootloader"), bootloader)
    AssertionResult("ro.boot.bootloader", NativeLibWrapper.sysPropsReadWithNullName("ro.boot.bootloader"), bootloader)
    AssertionResult("ro.boot.bootloader", NativeLibWrapper.sysPropsRead("ro.boot.bootloader"), bootloader)
    AssertionResult("ro.boot.bootloader", NativeLibWrapper.sysPropsReadCb("ro.boot.bootloader"), bootloader)

    AssertionResult("ro.boot.em.did", NativeLibWrapper.sysPropsGet("ro.boot.em.did"), defaultValue)
    AssertionResult("ro.boot.em.did", NativeLibWrapper.sysPropsReadWithNullName("ro.boot.em.did"), defaultValue)
    AssertionResult("ro.boot.em.did", NativeLibWrapper.sysPropsRead("ro.boot.em.did"), defaultValue)
    AssertionResult("ro.boot.em.did", NativeLibWrapper.sysPropsReadCb("ro.boot.em.did"), defaultValue)

    AssertionResult("ro.boot.em.model", NativeLibWrapper.sysPropsGet("ro.boot.em.model"), bootloader)
    AssertionResult("ro.boot.em.model", NativeLibWrapper.sysPropsReadWithNullName("ro.boot.em.model"), bootloader)
    AssertionResult("ro.boot.em.model", NativeLibWrapper.sysPropsRead("ro.boot.em.model"), bootloader)
    AssertionResult("ro.boot.em.model", NativeLibWrapper.sysPropsReadCb("ro.boot.em.model"), bootloader)

    AssertionResult("ro.boot.hardware", NativeLibWrapper.sysPropsGet("ro.boot.hardware"), "zuma")
    AssertionResult("ro.boot.hardware", NativeLibWrapper.sysPropsReadWithNullName("ro.boot.hardware"), "zuma")
    AssertionResult("ro.boot.hardware", NativeLibWrapper.sysPropsRead("ro.boot.hardware"), "zuma")
    AssertionResult("ro.boot.hardware", NativeLibWrapper.sysPropsReadCb("ro.boot.hardware"), "zuma")

    AssertionResult("ro.boot.odin_download", NativeLibWrapper.sysPropsGet("ro.boot.odin_download"), defaultValue)
    AssertionResult("ro.boot.odin_download", NativeLibWrapper.sysPropsReadWithNullName("ro.boot.odin_download"), defaultValue)
    AssertionResult("ro.boot.odin_download", NativeLibWrapper.sysPropsRead("ro.boot.odin_download"), defaultValue)
    AssertionResult("ro.boot.odin_download", NativeLibWrapper.sysPropsReadCb("ro.boot.odin_download"), defaultValue)

    AssertionResult("ro.boot.wb.snapQB", NativeLibWrapper.sysPropsGet("ro.boot.wb.snapQB"), defaultValue)
    AssertionResult("ro.boot.wb.snapQB", NativeLibWrapper.sysPropsReadWithNullName("ro.boot.wb.snapQB"), defaultValue)
    AssertionResult("ro.boot.wb.snapQB", NativeLibWrapper.sysPropsRead("ro.boot.wb.snapQB"), defaultValue)
    AssertionResult("ro.boot.wb.snapQB", NativeLibWrapper.sysPropsReadCb("ro.boot.wb.snapQB"), defaultValue)

    AssertionResult("ro.com.google.clientidbase", NativeLibWrapper.sysPropsGet("ro.com.google.clientidbase"), "android-google")
    AssertionResult("ro.com.google.clientidbase", NativeLibWrapper.sysPropsReadWithNullName("ro.com.google.clientidbase"), "android-google")
    AssertionResult("ro.com.google.clientidbase", NativeLibWrapper.sysPropsRead("ro.com.google.clientidbase"), "android-google")
    AssertionResult("ro.com.google.clientidbase", NativeLibWrapper.sysPropsReadCb("ro.com.google.clientidbase"), "android-google")

    AssertionResult("ro.hardware", NativeLibWrapper.sysPropsGet("ro.hardware"), "zuma")
    AssertionResult("ro.hardware", NativeLibWrapper.sysPropsReadWithNullName("ro.hardware"), "zuma")
    AssertionResult("ro.hardware", NativeLibWrapper.sysPropsRead("ro.hardware"), "zuma")
    AssertionResult("ro.hardware", NativeLibWrapper.sysPropsReadCb("ro.hardware"), "zuma")

    AssertionResult("ro.boot.ap_serial", NativeLibWrapper.sysPropsGet("ro.boot.ap_serial"), defaultValue)
    AssertionResult("ro.boot.ap_serial", NativeLibWrapper.sysPropsReadWithNullName("ro.boot.ap_serial"), defaultValue)
    AssertionResult("ro.boot.ap_serial", NativeLibWrapper.sysPropsRead("ro.boot.ap_serial"), defaultValue)
    AssertionResult("ro.boot.ap_serial", NativeLibWrapper.sysPropsReadCb("ro.boot.ap_serial"), defaultValue)

    AssertionResult("ro.boot.verifiedbootstate", NativeLibWrapper.sysPropsGet("ro.boot.verifiedbootstate"), "green")
    AssertionResult("ro.boot.verifiedbootstate", NativeLibWrapper.sysPropsReadWithNullName("ro.boot.verifiedbootstate"), "green")
    AssertionResult("ro.boot.verifiedbootstate", NativeLibWrapper.sysPropsRead("ro.boot.verifiedbootstate"), "green")
    AssertionResult("ro.boot.verifiedbootstate", NativeLibWrapper.sysPropsReadCb("ro.boot.verifiedbootstate"), "green")

    AssertionResult("ro.boot.warranty_bit", NativeLibWrapper.sysPropsGet("ro.boot.warranty_bit"), defaultValue)
    AssertionResult("ro.boot.warranty_bit", NativeLibWrapper.sysPropsReadWithNullName("ro.boot.warranty_bit"), defaultValue)
    AssertionResult("ro.boot.warranty_bit", NativeLibWrapper.sysPropsRead("ro.boot.warranty_bit"), defaultValue)
    AssertionResult("ro.boot.warranty_bit", NativeLibWrapper.sysPropsReadCb("ro.boot.warranty_bit"), defaultValue)

    AssertionResult("ro.boot.force_upload", NativeLibWrapper.sysPropsGet("ro.boot.force_upload"), defaultValue)
    AssertionResult("ro.boot.force_upload", NativeLibWrapper.sysPropsReadWithNullName("ro.boot.force_upload"), defaultValue)
    AssertionResult("ro.boot.force_upload", NativeLibWrapper.sysPropsRead("ro.boot.force_upload"), defaultValue)
    AssertionResult("ro.boot.force_upload", NativeLibWrapper.sysPropsReadCb("ro.boot.force_upload"), defaultValue)

    // TODO: figure out how to insert the non-existing props on-the-fly
    AssertionResult("sys.oem_unlock_allowed", NativeLibWrapper.sysPropsGet("sys.oem_unlock_allowed"), "0")
    AssertionResult("sys.oem_unlock_allowed", NativeLibWrapper.sysPropsReadWithNullName("sys.oem_unlock_allowed"), propInfoNull)
    AssertionResult("sys.oem_unlock_allowed", NativeLibWrapper.sysPropsRead("sys.oem_unlock_allowed"), propInfoNull)
    AssertionResult("sys.oem_unlock_allowed", NativeLibWrapper.sysPropsReadCb("sys.oem_unlock_allowed"), propInfoNull)

    AssertionResult("ro.boot.write_protect", NativeLibWrapper.sysPropsGet("ro.boot.write_protect"), "1")
    AssertionResult("ro.boot.write_protect", NativeLibWrapper.sysPropsReadWithNullName("ro.boot.write_protect"), propInfoNull)
    AssertionResult("ro.boot.write_protect", NativeLibWrapper.sysPropsRead("ro.boot.write_protect"), propInfoNull)
    AssertionResult("ro.boot.write_protect", NativeLibWrapper.sysPropsReadCb("ro.boot.write_protect"), propInfoNull)

    AssertionResult("ro.boot.veritymode.managed", NativeLibWrapper.sysPropsGet("ro.boot.veritymode.managed"), "yes")
    AssertionResult("ro.boot.veritymode.managed", NativeLibWrapper.sysPropsReadWithNullName("ro.boot.veritymode.managed"), propInfoNull)
    AssertionResult("ro.boot.veritymode.managed", NativeLibWrapper.sysPropsRead("ro.boot.veritymode.managed"), propInfoNull)
    AssertionResult("ro.boot.veritymode.managed", NativeLibWrapper.sysPropsReadCb("ro.boot.veritymode.managed"), propInfoNull)

    AssertionResult("ro.boot.veritymode", NativeLibWrapper.sysPropsGet("ro.boot.veritymode"), "enforcing")
    AssertionResult("ro.boot.veritymode", NativeLibWrapper.sysPropsReadWithNullName("ro.boot.veritymode"), propInfoNull)
    AssertionResult("ro.boot.veritymode", NativeLibWrapper.sysPropsRead("ro.boot.veritymode"), propInfoNull)
    AssertionResult("ro.boot.veritymode", NativeLibWrapper.sysPropsReadCb("ro.boot.veritymode"), propInfoNull)

    AssertionResult("ro.boot.vbmeta.hash_alg", NativeLibWrapper.sysPropsGet("ro.boot.vbmeta.hash_alg"), "sha256")
    AssertionResult("ro.boot.vbmeta.hash_alg", NativeLibWrapper.sysPropsReadWithNullName("ro.boot.vbmeta.hash_alg"), propInfoNull)
    AssertionResult("ro.boot.vbmeta.hash_alg", NativeLibWrapper.sysPropsRead("ro.boot.vbmeta.hash_alg"), propInfoNull)
    AssertionResult("ro.boot.vbmeta.hash_alg", NativeLibWrapper.sysPropsReadCb("ro.boot.vbmeta.hash_alg"), propInfoNull)

    AssertionResult("ro.boot.vbmeta.device_state", NativeLibWrapper.sysPropsGet("ro.boot.vbmeta.device_state"), "locked")
    AssertionResult("ro.boot.vbmeta.device_state", NativeLibWrapper.sysPropsReadWithNullName("ro.boot.vbmeta.device_state"), propInfoNull)
    AssertionResult("ro.boot.vbmeta.device_state", NativeLibWrapper.sysPropsRead("ro.boot.vbmeta.device_state"), propInfoNull)
    AssertionResult("ro.boot.vbmeta.device_state", NativeLibWrapper.sysPropsReadCb("ro.boot.vbmeta.device_state"), propInfoNull)

    AssertionResult("ro.boot.vbmeta.avb_version", NativeLibWrapper.sysPropsGet("ro.boot.vbmeta.avb_version"), "1.2")
    AssertionResult("ro.boot.vbmeta.avb_version", NativeLibWrapper.sysPropsReadWithNullName("ro.boot.vbmeta.avb_version"), propInfoNull)
    AssertionResult("ro.boot.vbmeta.avb_version", NativeLibWrapper.sysPropsRead("ro.boot.vbmeta.avb_version"), propInfoNull)
    AssertionResult("ro.boot.vbmeta.avb_version", NativeLibWrapper.sysPropsReadCb("ro.boot.vbmeta.avb_version"), propInfoNull)

    AssertionResult("ro.boot.secure_hardware", NativeLibWrapper.sysPropsGet("ro.boot.secure_hardware"), "1")
    AssertionResult("ro.boot.secure_hardware", NativeLibWrapper.sysPropsReadWithNullName("ro.boot.secure_hardware"), propInfoNull)
    AssertionResult("ro.boot.secure_hardware", NativeLibWrapper.sysPropsRead("ro.boot.secure_hardware"), propInfoNull)
    AssertionResult("ro.boot.secure_hardware", NativeLibWrapper.sysPropsReadCb("ro.boot.secure_hardware"), propInfoNull)

    AssertionResult("ro.boot.mode", NativeLibWrapper.sysPropsGet("ro.boot.mode"), "normal")
    AssertionResult("ro.boot.mode", NativeLibWrapper.sysPropsReadWithNullName("ro.boot.mode"), propInfoNull)
    AssertionResult("ro.boot.mode", NativeLibWrapper.sysPropsRead("ro.boot.mode"), propInfoNull)
    AssertionResult("ro.boot.mode", NativeLibWrapper.sysPropsReadCb("ro.boot.mode"), propInfoNull)

    AssertionResult("ro.boot.force_normal_boot", NativeLibWrapper.sysPropsGet("ro.boot.force_normal_boot"), "1")
    AssertionResult("ro.boot.force_normal_boot", NativeLibWrapper.sysPropsReadWithNullName("ro.boot.force_normal_boot"), propInfoNull)
    AssertionResult("ro.boot.force_normal_boot", NativeLibWrapper.sysPropsRead("ro.boot.force_normal_boot"), propInfoNull)
    AssertionResult("ro.boot.force_normal_boot", NativeLibWrapper.sysPropsReadCb("ro.boot.force_normal_boot"), propInfoNull)

    AssertionResult("ro.boot.flash.locked", NativeLibWrapper.sysPropsGet("ro.boot.flash.locked"), "1")
    AssertionResult("ro.boot.flash.locked", NativeLibWrapper.sysPropsReadWithNullName("ro.boot.flash.locked"), propInfoNull)
    AssertionResult("ro.boot.flash.locked", NativeLibWrapper.sysPropsRead("ro.boot.flash.locked"), propInfoNull)
    AssertionResult("ro.boot.flash.locked", NativeLibWrapper.sysPropsReadCb("ro.boot.flash.locked"), propInfoNull)

    AssertionResult("ro.boot.avb_version", NativeLibWrapper.sysPropsGet("ro.boot.avb_version"), "1.2")
    AssertionResult("ro.boot.avb_version", NativeLibWrapper.sysPropsReadWithNullName("ro.boot.avb_version"), propInfoNull)
    AssertionResult("ro.boot.avb_version", NativeLibWrapper.sysPropsRead("ro.boot.avb_version"), propInfoNull)
    AssertionResult("ro.boot.avb_version", NativeLibWrapper.sysPropsReadCb("ro.boot.avb_version"), propInfoNull)
    // END TODO

    AssertionResult("ro.carrier", NativeLibWrapper.sysPropsGet("ro.carrier"), "retbr")
    AssertionResult("ro.carrier", NativeLibWrapper.sysPropsReadWithNullName("ro.carrier"), "retbr")
    AssertionResult("ro.carrier", NativeLibWrapper.sysPropsRead("ro.carrier"), "retbr")
    AssertionResult("ro.carrier", NativeLibWrapper.sysPropsReadCb("ro.carrier"), "retbr")

    AssertionResult("ro.boot.carrierid", NativeLibWrapper.sysPropsGet("ro.boot.carrierid"), defaultValue)
    AssertionResult("ro.boot.carrierid", NativeLibWrapper.sysPropsReadWithNullName("ro.boot.carrierid"), defaultValue)
    AssertionResult("ro.boot.carrierid", NativeLibWrapper.sysPropsRead("ro.boot.carrierid"), defaultValue)
    AssertionResult("ro.boot.carrierid", NativeLibWrapper.sysPropsReadCb("ro.boot.carrierid"), defaultValue)

    AssertionResult("gsm.sim.state", NativeLibWrapper.sysPropsGet("gsm.sim.state"), "READY,")
    AssertionResult("gsm.sim.state", NativeLibWrapper.sysPropsReadWithNullName("gsm.sim.state"), "READY,")
    AssertionResult("gsm.sim.state", NativeLibWrapper.sysPropsRead("gsm.sim.state"), "READY,")
    AssertionResult("gsm.sim.state", NativeLibWrapper.sysPropsReadCb("gsm.sim.state"), "READY,")

    AssertionResult("gsm.sim.eventList", NativeLibWrapper.sysPropsGet("gsm.sim.eventList"), defaultValue)
    AssertionResult("gsm.sim.eventList", NativeLibWrapper.sysPropsReadWithNullName("gsm.sim.eventList"), defaultValue)
    AssertionResult("gsm.sim.eventList", NativeLibWrapper.sysPropsRead("gsm.sim.eventList"), defaultValue)
    AssertionResult("gsm.sim.eventList", NativeLibWrapper.sysPropsReadCb("gsm.sim.eventList"), defaultValue)

    AssertionResult("ril.simoperator", NativeLibWrapper.sysPropsGet("ril.simoperator"), ",")
    AssertionResult("ril.simoperator", NativeLibWrapper.sysPropsReadWithNullName("ril.simoperator"), ",")
    AssertionResult("ril.simoperator", NativeLibWrapper.sysPropsRead("ril.simoperator"), ",")
    AssertionResult("ril.simoperator", NativeLibWrapper.sysPropsReadCb("ril.simoperator"), ",")

    AssertionResult("ril.cidManager.initiated", NativeLibWrapper.sysPropsGet("ril.cidManager.initiated"), "1")
    AssertionResult("ril.cidManager.initiated", NativeLibWrapper.sysPropsReadWithNullName("ril.cidManager.initiated"), "1")
    AssertionResult("ril.cidManager.initiated", NativeLibWrapper.sysPropsRead("ril.cidManager.initiated"), "1")
    AssertionResult("ril.cidManager.initiated", NativeLibWrapper.sysPropsReadCb("ril.cidManager.initiated"), "1")

    AssertionResult("ril.dds.call.ongoing0", NativeLibWrapper.sysPropsGet("ril.dds.call.ongoing0"), "0")
    AssertionResult("ril.dds.call.ongoing0", NativeLibWrapper.sysPropsReadWithNullName("ril.dds.call.ongoing0"), "0")
    AssertionResult("ril.dds.call.ongoing0", NativeLibWrapper.sysPropsRead("ril.dds.call.ongoing0"), "0")
    AssertionResult("ril.dds.call.ongoing0", NativeLibWrapper.sysPropsReadCb("ril.dds.call.ongoing0"), "0")

    AssertionResult("ril.dds.call.ongoing1", NativeLibWrapper.sysPropsGet("ril.dds.call.ongoing1"), "0")
    AssertionResult("ril.dds.call.ongoing1", NativeLibWrapper.sysPropsReadWithNullName("ril.dds.call.ongoing1"), "0")
    AssertionResult("ril.dds.call.ongoing1", NativeLibWrapper.sysPropsRead("ril.dds.call.ongoing1"), "0")
    AssertionResult("ril.dds.call.ongoing1", NativeLibWrapper.sysPropsReadCb("ril.dds.call.ongoing1"), "0")

    AssertionResult("ril.modem.board", NativeLibWrapper.sysPropsGet("ril.modem.board"), defaultValue)
    AssertionResult("ril.modem.board", NativeLibWrapper.sysPropsReadWithNullName("ril.modem.board"), defaultValue)
    AssertionResult("ril.modem.board", NativeLibWrapper.sysPropsRead("ril.modem.board"), defaultValue)
    AssertionResult("ril.modem.board", NativeLibWrapper.sysPropsReadCb("ril.modem.board"), defaultValue)

    AssertionResult("ril.modem.board2", NativeLibWrapper.sysPropsGet("ril.modem.board2"), defaultValue)
    AssertionResult("ril.modem.board2", NativeLibWrapper.sysPropsReadWithNullName("ril.modem.board2"), defaultValue)
    AssertionResult("ril.modem.board2", NativeLibWrapper.sysPropsRead("ril.modem.board2"), defaultValue)
    AssertionResult("ril.modem.board2", NativeLibWrapper.sysPropsReadCb("ril.modem.board2"), defaultValue)

    AssertionResult("ril.attach.apn0", NativeLibWrapper.sysPropsGet("ril.attach.apn0"), defaultValue)
    AssertionResult("ril.attach.apn0", NativeLibWrapper.sysPropsReadWithNullName("ril.attach.apn0"), defaultValue)
    AssertionResult("ril.attach.apn0", NativeLibWrapper.sysPropsRead("ril.attach.apn0"), defaultValue)
    AssertionResult("ril.attach.apn0", NativeLibWrapper.sysPropsReadCb("ril.attach.apn0"), defaultValue)

    AssertionResult("ril.hw_ver", NativeLibWrapper.sysPropsGet("ril.hw_ver"), defaultValue)
    AssertionResult("ril.hw_ver", NativeLibWrapper.sysPropsReadWithNullName("ril.hw_ver"), defaultValue)
    AssertionResult("ril.hw_ver", NativeLibWrapper.sysPropsRead("ril.hw_ver"), defaultValue)
    AssertionResult("ril.hw_ver", NativeLibWrapper.sysPropsReadCb("ril.hw_ver"), defaultValue)

    AssertionResult("ril.hw_ver2", NativeLibWrapper.sysPropsGet("ril.hw_ver2"), defaultValue)
    AssertionResult("ril.hw_ver2", NativeLibWrapper.sysPropsReadWithNullName("ril.hw_ver2"), defaultValue)
    AssertionResult("ril.hw_ver2", NativeLibWrapper.sysPropsRead("ril.hw_ver2"), defaultValue)
    AssertionResult("ril.hw_ver2", NativeLibWrapper.sysPropsReadCb("ril.hw_ver2"), defaultValue)

    AssertionResult("ril.model_id", NativeLibWrapper.sysPropsGet("ril.model_id"), defaultValue)
    AssertionResult("ril.model_id", NativeLibWrapper.sysPropsReadWithNullName("ril.model_id"), defaultValue)
    AssertionResult("ril.model_id", NativeLibWrapper.sysPropsRead("ril.model_id"), defaultValue)
    AssertionResult("ril.model_id", NativeLibWrapper.sysPropsReadCb("ril.model_id"), defaultValue)

    AssertionResult("ril.model_id2", NativeLibWrapper.sysPropsGet("ril.model_id2"), defaultValue)
    AssertionResult("ril.model_id2", NativeLibWrapper.sysPropsReadWithNullName("ril.model_id2"), defaultValue)
    AssertionResult("ril.model_id2", NativeLibWrapper.sysPropsRead("ril.model_id2"), defaultValue)
    AssertionResult("ril.model_id2", NativeLibWrapper.sysPropsReadCb("ril.model_id2"), defaultValue)

    AssertionResult("ril.rfcal_date", NativeLibWrapper.sysPropsGet("ril.rfcal_date"), defaultValue)
    AssertionResult("ril.rfcal_date", NativeLibWrapper.sysPropsReadWithNullName("ril.rfcal_date"), defaultValue)
    AssertionResult("ril.rfcal_date", NativeLibWrapper.sysPropsRead("ril.rfcal_date"), defaultValue)
    AssertionResult("ril.rfcal_date", NativeLibWrapper.sysPropsReadCb("ril.rfcal_date"), defaultValue)

    AssertionResult("ril.rfcal_date2", NativeLibWrapper.sysPropsGet("ril.rfcal_date2"), defaultValue)
    AssertionResult("ril.rfcal_date2", NativeLibWrapper.sysPropsReadWithNullName("ril.rfcal_date2"), defaultValue)
    AssertionResult("ril.rfcal_date2", NativeLibWrapper.sysPropsRead("ril.rfcal_date2"), defaultValue)
    AssertionResult("ril.rfcal_date2", NativeLibWrapper.sysPropsReadCb("ril.rfcal_date2"), defaultValue)

    AssertionResult("ril.product_code", NativeLibWrapper.sysPropsGet("ril.product_code"), defaultValue)
    AssertionResult("ril.product_code", NativeLibWrapper.sysPropsReadWithNullName("ril.product_code"), defaultValue)
    AssertionResult("ril.product_code", NativeLibWrapper.sysPropsRead("ril.product_code"), defaultValue)
    AssertionResult("ril.product_code", NativeLibWrapper.sysPropsReadCb("ril.product_code"), defaultValue)

    AssertionResult("ril.product_code2", NativeLibWrapper.sysPropsGet("ril.product_code2"), defaultValue)
    AssertionResult("ril.product_code2", NativeLibWrapper.sysPropsReadWithNullName("ril.product_code2"), defaultValue)
    AssertionResult("ril.product_code2", NativeLibWrapper.sysPropsRead("ril.product_code2"), defaultValue)
    AssertionResult("ril.product_code2", NativeLibWrapper.sysPropsReadCb("ril.product_code2"), defaultValue)

    AssertionResult("gsm.operator.iso-country", NativeLibWrapper.sysPropsGet("gsm.operator.iso-country"), "br,")
    AssertionResult("gsm.operator.iso-country", NativeLibWrapper.sysPropsReadWithNullName("gsm.operator.iso-country"), "br,")
    AssertionResult("gsm.operator.iso-country", NativeLibWrapper.sysPropsRead("gsm.operator.iso-country"), "br,")
    AssertionResult("gsm.operator.iso-country", NativeLibWrapper.sysPropsReadCb("gsm.operator.iso-country"), "br,")

    AssertionResult("gsm.sim.operator.iso-country", NativeLibWrapper.sysPropsGet("gsm.sim.operator.iso-country"), "br,")
    AssertionResult("gsm.sim.operator.iso-country", NativeLibWrapper.sysPropsReadWithNullName("gsm.sim.operator.iso-country"), "br,")
    AssertionResult("gsm.sim.operator.iso-country", NativeLibWrapper.sysPropsRead("gsm.sim.operator.iso-country"), "br,")
    AssertionResult("gsm.sim.operator.iso-country", NativeLibWrapper.sysPropsReadCb("gsm.sim.operator.iso-country"), "br,")

    AssertionResult("gsm.sim.operator.numeric", NativeLibWrapper.sysPropsGet("gsm.sim.operator.numeric"), "72406,")
    AssertionResult("gsm.sim.operator.numeric", NativeLibWrapper.sysPropsReadWithNullName("gsm.sim.operator.numeric"), "72406,")
    AssertionResult("gsm.sim.operator.numeric", NativeLibWrapper.sysPropsRead("gsm.sim.operator.numeric"), "72406,")
    AssertionResult("gsm.sim.operator.numeric", NativeLibWrapper.sysPropsReadCb("gsm.sim.operator.numeric"), "72406,")

    AssertionResult("gsm.operator.numeric", NativeLibWrapper.sysPropsGet("gsm.operator.numeric"), "72406,")
    AssertionResult("gsm.operator.numeric", NativeLibWrapper.sysPropsReadWithNullName("gsm.operator.numeric"), "72406,")
    AssertionResult("gsm.operator.numeric", NativeLibWrapper.sysPropsRead("gsm.operator.numeric"), "72406,")
    AssertionResult("gsm.operator.numeric", NativeLibWrapper.sysPropsReadCb("gsm.operator.numeric"), "72406,")

    AssertionResult("gsm.sim.operator.alpha", NativeLibWrapper.sysPropsGet("gsm.sim.operator.alpha"), "Vivo,")
    AssertionResult("gsm.sim.operator.alpha", NativeLibWrapper.sysPropsReadWithNullName("gsm.sim.operator.alpha"), "Vivo,")
    AssertionResult("gsm.sim.operator.alpha", NativeLibWrapper.sysPropsRead("gsm.sim.operator.alpha"), "Vivo,")
    AssertionResult("gsm.sim.operator.alpha", NativeLibWrapper.sysPropsReadCb("gsm.sim.operator.alpha"), "Vivo,")

    AssertionResult("gsm.operator.alpha", NativeLibWrapper.sysPropsGet("gsm.operator.alpha"), "Vivo,")
    AssertionResult("gsm.operator.alpha", NativeLibWrapper.sysPropsReadWithNullName("gsm.operator.alpha"),"Vivo,")
    AssertionResult("gsm.operator.alpha", NativeLibWrapper.sysPropsRead("gsm.operator.alpha"), "Vivo,")
    AssertionResult("gsm.operator.alpha", NativeLibWrapper.sysPropsReadCb("gsm.operator.alpha"), "Vivo,")

    AssertionResult("debug.tracing.mnc", NativeLibWrapper.sysPropsGet("debug.tracing.mnc"), "6")
    AssertionResult("debug.tracing.mnc", NativeLibWrapper.sysPropsReadWithNullName("debug.tracing.mnc"), "6")
    AssertionResult("debug.tracing.mnc", NativeLibWrapper.sysPropsRead("debug.tracing.mnc"), "6")
    AssertionResult("debug.tracing.mnc", NativeLibWrapper.sysPropsReadCb("debug.tracing.mnc"), "6")

//    AssertionResult("ro.sf.lcd_density", NativeLibWrapper.sysPropsGet("ro.sf.lcd_density"), "400")
//    AssertionResult("ro.sf.lcd_density", NativeLibWrapper.sysPropsReadWithNullName("ro.sf.lcd_density"), "400")
//    AssertionResult("ro.sf.lcd_density", NativeLibWrapper.sysPropsRead("ro.sf.lcd_density"), "400")
//    AssertionResult("ro.sf.lcd_density", NativeLibWrapper.sysPropsReadCb("ro.sf.lcd_density"), "400")

    AssertionResult("ro.boot.selinux", NativeLibWrapper.sysPropsGet("ro.boot.selinux"), "enforcing")
    AssertionResult("ro.boot.selinux", NativeLibWrapper.sysPropsReadWithNullName("ro.boot.selinux"), "enforcing")
    AssertionResult("ro.boot.selinux", NativeLibWrapper.sysPropsRead("ro.boot.selinux"), "enforcing")
    AssertionResult("ro.boot.selinux", NativeLibWrapper.sysPropsReadCb("ro.boot.selinux"), "enforcing")

    AssertionResult("ro.adb.secure", NativeLibWrapper.sysPropsGet("ro.adb.secure"), "1")
    AssertionResult("ro.adb.secure", NativeLibWrapper.sysPropsReadWithNullName("ro.adb.secure"), "1")
    AssertionResult("ro.adb.secure", NativeLibWrapper.sysPropsRead("ro.adb.secure"), "1")
    AssertionResult("ro.adb.secure", NativeLibWrapper.sysPropsReadCb("ro.adb.secure"), "1")

    AssertionResult("ro.allow.mock.location", NativeLibWrapper.sysPropsGet("ro.allow.mock.location"), "0")
    AssertionResult("ro.allow.mock.location", NativeLibWrapper.sysPropsReadWithNullName("ro.allow.mock.location"), "0")
    AssertionResult("ro.allow.mock.location", NativeLibWrapper.sysPropsRead("ro.allow.mock.location"), "0")
    AssertionResult("ro.allow.mock.location", NativeLibWrapper.sysPropsReadCb("ro.allow.mock.location"), "0")

    AssertionResult("persist.sys.strictmode.disable", NativeLibWrapper.sysPropsGet("persist.sys.strictmode.disable"), "true")
    AssertionResult("persist.sys.strictmode.disable", NativeLibWrapper.sysPropsReadWithNullName("persist.sys.strictmode.disable"), "true")
    AssertionResult("persist.sys.strictmode.disable", NativeLibWrapper.sysPropsRead("persist.sys.strictmode.disable"), "true")
    AssertionResult("persist.sys.strictmode.disable", NativeLibWrapper.sysPropsReadCb("persist.sys.strictmode.disable"), "true")

    AssertionResult("ro.control_privapp_permissions", NativeLibWrapper.sysPropsGet("ro.control_privapp_permissions"), "enforce")
    AssertionResult("ro.control_privapp_permissions", NativeLibWrapper.sysPropsReadWithNullName("ro.control_privapp_permissions"), "enforce")
    AssertionResult("ro.control_privapp_permissions", NativeLibWrapper.sysPropsRead("ro.control_privapp_permissions"), "enforce")
    AssertionResult("ro.control_privapp_permissions", NativeLibWrapper.sysPropsReadCb("ro.control_privapp_permissions"), "enforce")

    AssertionResult("ro.build.characteristics", NativeLibWrapper.sysPropsGet("ro.build.characteristics"), "default")
    AssertionResult("ro.build.characteristics", NativeLibWrapper.sysPropsReadWithNullName("ro.build.characteristics"), "default")
    AssertionResult("ro.build.characteristics", NativeLibWrapper.sysPropsRead("ro.build.characteristics"), "default")
    AssertionResult("ro.build.characteristics", NativeLibWrapper.sysPropsReadCb("ro.build.characteristics"), "default")

//    AssertionResult("ro.surface_flinger.enable_frame_rate_override", NativeLibWrapper.sysPropsGet("ro.surface_flinger.enable_frame_rate_override"), "false")
//    AssertionResult("ro.surface_flinger.enable_frame_rate_override", NativeLibWrapper.sysPropsReadWithNullName("ro.surface_flinger.enable_frame_rate_override"), propInfoNull)
//    AssertionResult("ro.surface_flinger.enable_frame_rate_override", NativeLibWrapper.sysPropsRead("ro.surface_flinger.enable_frame_rate_override"), "false")
//    AssertionResult("ro.surface_flinger.enable_frame_rate_override", NativeLibWrapper.sysPropsReadCb("ro.surface_flinger.enable_frame_rate_override"), "false")

//    AssertionResult("ro.surface_flinger.game_default_frame_rate_override", NativeLibWrapper.sysPropsGet("ro.surface_flinger.game_default_frame_rate_override"), "60")
//    AssertionResult("ro.surface_flinger.game_default_frame_rate_override", NativeLibWrapper.sysPropsReadWithNullName("ro.surface_flinger.game_default_frame_rate_override"), propInfoNull)
//    AssertionResult("ro.surface_flinger.game_default_frame_rate_override", NativeLibWrapper.sysPropsRead("ro.surface_flinger.game_default_frame_rate_override"), "60")
//    AssertionResult("ro.surface_flinger.game_default_frame_rate_override", NativeLibWrapper.sysPropsReadCb("ro.surface_flinger.game_default_frame_rate_override"), "60")

    AssertionResult("security.perf_harden", NativeLibWrapper.sysPropsGet("security.perf_harden"), "1")
    AssertionResult("security.perf_harden", NativeLibWrapper.sysPropsReadWithNullName("security.perf_harden"), "1")
    AssertionResult("security.perf_harden", NativeLibWrapper.sysPropsRead("security.perf_harden"), "1")
    AssertionResult("security.perf_harden", NativeLibWrapper.sysPropsReadCb("security.perf_harden"), "1")

    AssertionResult("ril.halservice.registered.slot1", NativeLibWrapper.sysPropsGet("ril.halservice.registered.slot1"), "true")
    AssertionResult("ril.halservice.registered.slot1", NativeLibWrapper.sysPropsReadWithNullName("ril.halservice.registered.slot1"), "true")
    AssertionResult("ril.halservice.registered.slot1", NativeLibWrapper.sysPropsRead("ril.halservice.registered.slot1"), "true")
    AssertionResult("ril.halservice.registered.slot1", NativeLibWrapper.sysPropsReadCb("ril.halservice.registered.slot1"), "true")

    AssertionResult("ril.halservice.registered.slot2", NativeLibWrapper.sysPropsGet("ril.halservice.registered.slot2"), "true")
    AssertionResult("ril.halservice.registered.slot2", NativeLibWrapper.sysPropsReadWithNullName("ril.halservice.registered.slot2"), "true")
    AssertionResult("ril.halservice.registered.slot2", NativeLibWrapper.sysPropsRead("ril.halservice.registered.slot2"), "true")
    AssertionResult("ril.halservice.registered.slot2", NativeLibWrapper.sysPropsReadCb("ril.halservice.registered.slot2"), "true")

    AssertionResult("ril.rejectedPlmn", NativeLibWrapper.sysPropsGet("ril.rejectedPlmn"), ",")
    AssertionResult("ril.rejectedPlmn", NativeLibWrapper.sysPropsReadWithNullName("ril.rejectedPlmn"), ",")
    AssertionResult("ril.rejectedPlmn", NativeLibWrapper.sysPropsRead("ril.rejectedPlmn"), ",")
    AssertionResult("ril.rejectedPlmn", NativeLibWrapper.sysPropsReadCb("ril.rejectedPlmn"), ",")
}

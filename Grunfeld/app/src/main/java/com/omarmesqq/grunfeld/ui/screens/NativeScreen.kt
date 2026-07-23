package com.omarmesqq.grunfeld.ui.screens

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
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import com.omarmesqq.grunfeld.ui.composables.CodeTitle
import com.omarmesqq.grunfeld.ui.composables.ReportTextWithCopy
import com.omarmesqq.grunfeld.ui.composables.SectionHeader
import com.omarmesqq.grunfeld.utils.NativeLibWrapper
import android.os.Process;

@Composable
fun NativeScreen() {
    val context = LocalContext.current

    var sensorReport by remember { mutableStateOf("Sensors not tested at native layer yet") }
    var unameReport by remember { mutableStateOf("Uname not fetched yet") }

    var bindReport by remember { mutableStateOf("bind not tested yet") }
    var listenReport by remember { mutableStateOf("listen not tested yet") }
    var sendtoReport by remember { mutableStateOf("sendto not tested yet") }
    var getsocknameReport by remember { mutableStateOf("getsockname not tested yet") }
    var socketReport by remember { mutableStateOf("AF_NETLINK socket not tested yet") }
    var sendmsgReport by remember { mutableStateOf("sendmsg not tested yet") }
    var getifaddrsReport by remember { mutableStateOf("getifaddrs not tested yet") }

    var signalHandlerStatus by remember { mutableStateOf("Try to overwrite SIGSYS handler") }
    var sigsysBlockStatus by remember { mutableStateOf("Try to block SIGSYS") }
    var procSelfStatusReport by remember { mutableStateOf("/proc/self/status not read yet") }
    var dliteratephdrInfo by remember { mutableStateOf("dl_iterate_phdr not run yet") }
    var vfsFilesInfo by remember { mutableStateOf("VFS files not probed yet") }

    var faccessatInfo by remember { mutableStateOf("Files not stated") }

    var fstatInfo by remember { mutableStateOf("Files not stated") }
    var statfsInfo by remember { mutableStateOf("Files not stated") }
    var fstatfsInfo by remember { mutableStateOf("Files not stated") }
    var newfstatatInfo by remember { mutableStateOf("Files not stated") }
    var statxInfo by remember { mutableStateOf("Files not stated") }

    var procSelFdInfo by remember { mutableStateOf("/proc/self/fd not read yet") }
    var procSelfAuxvInfo by remember { mutableStateOf("/proc/self/auxv not read yet") }
    var hooksInfo by remember { mutableStateOf("hooks not inspected yet") }
    var procSelfTaskInfo by remember { mutableStateOf("/proc/self/task not inspected yet") }
    var forkExecInfo by remember { mutableStateOf("fork/exec inspected yet") }
    var procSelfMapsInfo by remember { mutableStateOf("/proc/self/maps not studied yet") }
    var procMountPoints by remember { mutableStateOf("mounts not studied yet") }

    val pid = Process.myPid()

    /**
     * /data/misc/user/0/cacerts-added
     * /data/anr
     */
    val statAndAccessNodes = arrayOf(
        "/etc",
        "/etc/hosts",

        "/system/etc",
        "/system/etc/hosts",

        "/proc/self/maps",
        "/proc/$pid/maps",


//        "/system/bin",
//        "/system/bin/mdnsd",
//
//        "/system/etc/security",
//        "/system/etc/security/cacerts",
//
//        "/system/lib",
//        "/system/lib/libzygisk.so",
//
//        "/system/lib64",
//        "/system/lib64/libzygisk.so",

//        "/product/bin",
//        "/system/bin/app_process64"
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
                    CodeTitle("statfs")
                    ReportTextWithCopy(statfsInfo, "Files not stated")
                    Button(
                        onClick = {
                            statfsInfo = NativeLibWrapper.testStatfs(statAndAccessNodes)
                        },
                        modifier = Modifier.fillMaxWidth()

                    ) {
                        Text("statfs()")
                    }
                }

                Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    CodeTitle("fstatfs")
                    ReportTextWithCopy(fstatfsInfo, "Files not stated")
                    Button(
                        onClick = {
                            fstatfsInfo = NativeLibWrapper.testFstatfs(statAndAccessNodes)
                        },
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text("fstatfs()")
                    }
                }
            }

            SectionHeader("ANTI-TAMPER")
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)
            ) {
                Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(text = "Study mount points", style = MaterialTheme.typography.titleMedium)
                    ReportTextWithCopy(procMountPoints, "mounts not studied yet")
                    Button(
                        onClick = {
                            procMountPoints = NativeLibWrapper.scanMountNodes()
                        },
                        modifier = Modifier.fillMaxWidth()

                    ) {
                        Text("scan mount points")
                    }
                }

                Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(text = "Study /proc/self/maps", style = MaterialTheme.typography.titleMedium)
                    ReportTextWithCopy(procSelfMapsInfo, "/proc/self/maps not studied yet")
                    Button(
                        onClick = {
                            procSelfMapsInfo = NativeLibWrapper.scanProcSelfMaps()
                        },
                        modifier = Modifier.fillMaxWidth()

                    ) {
                        Text("open(/proc/self/maps)")
                    }
                }

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

                                "/proc/self/status",
                                "/proc/$pid/status",

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


                Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(text = "List shared objects in process", style = MaterialTheme.typography.titleMedium)
                    ReportTextWithCopy(dliteratephdrInfo, "dl_iterate_phdr not run yet")
                    Button(onClick = { dliteratephdrInfo = NativeLibWrapper.dl_iterate_phdrTest() }, modifier = Modifier.fillMaxWidth()) {
                        Text("dl_iterate_phdr()")
                    }
                }

                Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(text = "List file descriptors and their links", style = MaterialTheme.typography.titleMedium)
                    ReportTextWithCopy(procSelFdInfo, "/proc/self/fd not read yet")
                    Button(onClick = { procSelFdInfo = NativeLibWrapper.getallfds() }, modifier = Modifier.fillMaxWidth()) {
                        Text("getdents64(/proc/self/fd) && readlinkat(fdX)")
                    }
                }

                Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(text = "Read program's auxiliary vector", style = MaterialTheme.typography.titleMedium)
                    ReportTextWithCopy(procSelfAuxvInfo, "/proc/self/auxv not read yet")
                    Button(onClick = { procSelfAuxvInfo = NativeLibWrapper.testProcSelfAuxv() }, modifier = Modifier.fillMaxWidth()) {
                        Text("parse /proc/self/auxv")
                    }
                }

                Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(text = "Show program's threads", style = MaterialTheme.typography.titleMedium)
                    ReportTextWithCopy(procSelfTaskInfo, "/proc/self/task not read yet")
                    Button(onClick = { procSelfTaskInfo = NativeLibWrapper.testProcSelfTask() }, modifier = Modifier.fillMaxWidth()) {
                        Text("read /proc/self/task")
                    }
                }

                Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(text = "Processes' status ", style = MaterialTheme.typography.titleMedium)
                    ReportTextWithCopy(procSelfStatusReport, "/proc/self/status not read yet")
                    Button(onClick = { procSelfStatusReport = NativeLibWrapper.queryProcStatus() }, modifier = Modifier.fillMaxWidth()) {
                        Text("read /proc/self/status")
                    }
                }

                Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(text = "Inspect libraries for hooks", style = MaterialTheme.typography.titleMedium)
                    ReportTextWithCopy(hooksInfo, "hooks not inspected yet")
                    Button(onClick = { hooksInfo = NativeLibWrapper.inspectHooks() }, modifier = Modifier.fillMaxWidth()) {
                        Text("Study function prologues for hooks")
                    }
                }

                Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    CodeTitle("fork()/exec()")
                    ReportTextWithCopy(forkExecInfo, "fork/exec inspected yet")
                    Button(onClick = { forkExecInfo = NativeLibWrapper.testForkExec("") }, modifier = Modifier.fillMaxWidth()) {
                        Text("Create a child process and inspect its result")
                    }
                }

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
                            signalHandlerStatus = if (actionCaptured) "Installed and captured!" else "Installed, but failed to capture trigger"
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

            SectionHeader("BUILD AND SETTINGS INFO")
            Card(
                modifier = Modifier.fillMaxWidth(),
                elevation = CardDefaults.cardElevation(defaultElevation = 4.dp)
            ) {
                ReportTextWithCopy(NativeLibWrapper.getDeviceData(context), "")
            }

            SectionHeader("SENSORS")
            Card(
                modifier = Modifier.fillMaxWidth(),
                elevation = CardDefaults.cardElevation(defaultElevation = 4.dp),
            ) {
                Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(text = "Native Layer", style = MaterialTheme.typography.titleMedium)
                    ReportTextWithCopy(sensorReport, "Sensors not tested at native layer yet")
                    Button(
                        onClick = { sensorReport = NativeLibWrapper.testSensors() },
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text("Probe Sensors using native code")
                    }
                }
            }

            SectionHeader("SYSTEM INFO")
            Card(
                modifier = Modifier.fillMaxWidth(),
                elevation = CardDefaults.cardElevation(defaultElevation = 4.dp)
            ) {
                Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(text = "Uname", style = MaterialTheme.typography.titleMedium)
                    ReportTextWithCopy(unameReport, "Uname not fetched yet")
                    Button(onClick = { unameReport = NativeLibWrapper.getUname() }, modifier = Modifier.fillMaxWidth()) {
                        Text("Fetch uname")
                    }
                }
            }

            SectionHeader("NETWORKING")
            Card(
                modifier = Modifier.fillMaxWidth(),
                elevation = CardDefaults.cardElevation(defaultElevation = 4.dp)
            ) {
                Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    CodeTitle("bind()")
                    ReportTextWithCopy(bindReport, "bind not tested yet")
                    Button(onClick = { bindReport = NativeLibWrapper.testBind() }, modifier = Modifier.fillMaxWidth()) {
                        Text("bind")
                    }
                }
                Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    CodeTitle("listen()")
                    ReportTextWithCopy(listenReport, "listen not tested yet")
                    Button(onClick = { listenReport = NativeLibWrapper.testListen() }, modifier = Modifier.fillMaxWidth()) {
                        Text("listen")
                    }
                }
                Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    CodeTitle("sendto()")
                    ReportTextWithCopy(sendtoReport, "sendto not tested yet")
                    Button(onClick = { sendtoReport = NativeLibWrapper.testSendto() }, modifier = Modifier.fillMaxWidth()) {
                        Text("sendto LAN")
                    }
                }
                Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    CodeTitle("getsockname()")
                    ReportTextWithCopy(getsocknameReport, "getsockname not tested yet")
                    Button(onClick = { getsocknameReport = NativeLibWrapper.testGetsockname() }, modifier = Modifier.fillMaxWidth()) {
                        Text("getsockname")
                    }
                }
                Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    CodeTitle("socket(AF_NETLINK)")
                    ReportTextWithCopy(socketReport, "AF_NETLINK socket not tested yet")
                    Button(onClick = { socketReport = NativeLibWrapper.testSocket() }, modifier = Modifier.fillMaxWidth()) {
                        Text("AF_NETLINK socket")
                    }
                }
                Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    CodeTitle("sendmsg()")
                    ReportTextWithCopy(sendmsgReport, "sendmsg not tested yet")
                    Button(onClick = { sendmsgReport = NativeLibWrapper.testSendmsg() }, modifier = Modifier.fillMaxWidth()) {
                        Text("sendmsg LAN")
                    }
                }
                Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    CodeTitle("getifaddrs()")
                    ReportTextWithCopy(getifaddrsReport, "getifaddrs not tested yet")
                    Button(onClick = { getifaddrsReport = NativeLibWrapper.getifaddrs() }, modifier = Modifier.fillMaxWidth()) {
                        Text("Enumerate interfaces")
                    }
                }
            }

        }
    }
}

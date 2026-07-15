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
    var someFileFdInfo by remember { mutableStateOf("testOpenFileAndReadLink not queried") }
    var procSelFdInfo by remember { mutableStateOf("/proc/self/fd not read yet") }
    var procSelfAuxvInfo by remember { mutableStateOf("/proc/self/auxv not read yet") }
    var hooksInfo by remember { mutableStateOf("hooks not inspected yet") }
    var procSelfTaskInfo by remember { mutableStateOf("/proc/self/task not inspected yet") }
    var forkExecInfo by remember { mutableStateOf("fork/exec inspected yet") }

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

            SectionHeader("ANTI-TAMPER")
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)
            ) {
                Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(text = "Open some file and get its symlink", style = MaterialTheme.typography.titleMedium)
                    ReportTextWithCopy(someFileFdInfo, "testOpenFileAndReadLink not queried")
                    Button(
                        onClick = {
                            val filenames = arrayOf(
                                "/proc/self/maps",
                                "/proc/self/smaps",
                                "/proc/mounts",
                                "/proc/self/mounts",
                                "/proc/self/mountstats",
                                "/proc/self/mountinfo",
                                "/proc/self/status",
                                "/etc/hosts",
                                "/system/etc/hosts",
                                "/proc/version",
                                "/proc/sys/kernel/version",
                                "/proc/sys/kernel/osrelease",
                                "/proc/asound/version",
                                )
                            someFileFdInfo = NativeLibWrapper.testOpenFileAndReadLink(filenames)
                       },
                        modifier = Modifier.fillMaxWidth()

                    ) {
                        Text("open(somefile) && readlink(somefile)")
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
                    Text(text = "Get socket FDs and their links", style = MaterialTheme.typography.titleMedium)
                    ReportTextWithCopy(procSelFdInfo, "/proc/self/fd not read yet")
                    Button(onClick = { procSelFdInfo = NativeLibWrapper.getallsocketfds() }, modifier = Modifier.fillMaxWidth()) {
                        Text("Dump socket FDs and their symlinks")
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
                        Text("open(/proc/self/task)")
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
                    Text(text = "Debugger attached?", style = MaterialTheme.typography.titleMedium)
                    ReportTextWithCopy(procSelfStatusReport, "/proc/self/status not read yet")
                    Button(onClick = { procSelfStatusReport = NativeLibWrapper.queryProcStatus() }, modifier = Modifier.fillMaxWidth()) {
                        Text("read /proc/self/status")
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
        }
    }
}

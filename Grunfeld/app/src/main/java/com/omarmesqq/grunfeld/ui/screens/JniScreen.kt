package com.omarmesqq.grunfeld.ui.screens

import androidx.compose.foundation.layout.Arrangement
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
import com.omarmesqq.grunfeld.ui.composables.CodeTitle
import com.omarmesqq.grunfeld.ui.composables.ReportTextWithCopy
import com.omarmesqq.grunfeld.ui.composables.SectionHeader
import androidx.compose.ui.platform.LocalContext
import com.omarmesqq.grunfeld.utils.NativeLibWrapper

@Composable
fun JniScreen() {
    val context = LocalContext.current

    var sensorReport by remember { mutableStateOf("Sensors not tested at native layer yet") }
    var unameReport by remember { mutableStateOf("Uname not fetched yet") }
    var mapsReport by remember { mutableStateOf("Maps not scanned yet") }
    var smapsReport by remember { mutableStateOf("Smaps not scanned yet") }
    var devPropertiesReport by remember { mutableStateOf("dev properties not probed yet") }
    var bindReport by remember { mutableStateOf("bind not tested yet") }
    var listenReport by remember { mutableStateOf("listen not tested yet") }
    var sendtoReport by remember { mutableStateOf("sendto not tested yet") }
    var getsocknameReport by remember { mutableStateOf("getsockname not tested yet") }
    var socketReport by remember { mutableStateOf("socket not tested yet") }
    var sendmsgReport by remember { mutableStateOf("sendmsg not tested yet") }

    var signalHandlerStatus by remember { mutableStateOf("Try to overwrite SIGSYS handler") }
    var sigsysBlockStatus by remember { mutableStateOf("Try to block SIGSYS") }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp)
            .verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        Text(
            text = "JNI info",
            style = MaterialTheme.typography.headlineMedium
        )

        SectionHeader("BUILD AND SETTINGS INFO")
        Card(
            modifier = Modifier.fillMaxWidth(),
            elevation = CardDefaults.cardElevation(defaultElevation = 4.dp)
        ) {
            Text(
                text = NativeLibWrapper.getDeviceData(context),
                modifier = Modifier.padding(16.dp),
                style = MaterialTheme.typography.bodyMedium
            )
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
                    onClick = {
                        sensorReport = NativeLibWrapper.testSensors()
                    },
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

        SectionHeader("FILESYSTEM")
        Card(
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(
                modifier = Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Text(text = "/proc/self/maps", style = MaterialTheme.typography.titleMedium)
                ReportTextWithCopy(mapsReport, "Maps not scanned yet")

                Button(
                    onClick = { mapsReport = NativeLibWrapper.scanMaps() },
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text("Scan /proc/self/maps")
                }
            }
        }

        Card(
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(
                modifier = Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Text(text = "/proc/self/smaps", style = MaterialTheme.typography.titleMedium)
                ReportTextWithCopy(smapsReport, "Smaps not scanned yet")

                Button(
                    onClick = { smapsReport = NativeLibWrapper.scanSmaps() },
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text("Scan /proc/self/smaps")
                }
            }
        }

        Card(
            modifier = Modifier.fillMaxWidth(),
            elevation = CardDefaults.cardElevation(defaultElevation = 4.dp)
        ) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(text = "/dev/__properties__", style = MaterialTheme.typography.titleMedium)
                ReportTextWithCopy(devPropertiesReport, "dev properties not probed yet")
                Button(onClick = {
                        NativeLibWrapper.scanDevProperties()
                }, modifier = Modifier.fillMaxWidth()) {
                    Text("Test SELinux enforcement")
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
                Button(
                    onClick = {
                        bindReport = NativeLibWrapper.testBind()
                    },
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text("bind")
                }
            }
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                CodeTitle("listen()")
                ReportTextWithCopy(listenReport, "listen not tested yet")
                Button(
                    onClick = {
                        listenReport = NativeLibWrapper.testListen()
                    },
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text("listen")
                }
            }
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                CodeTitle("sendto()")
                ReportTextWithCopy(sendtoReport, "sendto not tested yet")
                Button(
                    onClick = {
                        sendtoReport = NativeLibWrapper.testSendto()
                    },
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text("sendto LAN")
                }
            }

            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                CodeTitle("getsockname()")
                ReportTextWithCopy(getsocknameReport, "getsockname not tested yet")
                Button(
                    onClick = {
                        getsocknameReport = NativeLibWrapper.testGetsockname()
                    },
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text("getsockname on LAN info")
                }
            }

            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                CodeTitle("socket()")
                ReportTextWithCopy(socketReport, "socket not tested yet")
                Button(
                    onClick = {
                        socketReport = NativeLibWrapper.testSocket()
                    },
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text("socket")
                }
            }

            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                CodeTitle("sendmsg()")
                ReportTextWithCopy(sendmsgReport, "sendmsg not tested yet")
                Button(
                    onClick = {
                        // NativeLibWrapper.testNetworkLeaks()
                    },
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text("sendmsg")
                }
            }
        }

        SectionHeader("ANTI-TAMPER")
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)
        ) {
            Column(modifier = Modifier.padding(16.dp)) {
                Text(text = "Attempt to overwrite SIGSYS handler", style = MaterialTheme.typography.titleMedium)

                Spacer(modifier = Modifier.height(8.dp))

                Text(
                    text = signalHandlerStatus,
                    style = MaterialTheme.typography.bodySmall,
                    modifier = Modifier.fillMaxWidth()
                )
                Button(
                    onClick = {
                        val success = NativeLibWrapper.installSigsysHandler()
                        signalHandlerStatus = if (success) "Active" else "Failed"
                    },
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text("sigaction SIGSYS")
                }
            }

            Column(modifier = Modifier.padding(16.dp)) {
                Text(text = "Attempt to halt SIGSYS delivery", style = MaterialTheme.typography.titleMedium)

                Spacer(modifier = Modifier.height(8.dp))

                Text(
                    text = sigsysBlockStatus,
                    style = MaterialTheme.typography.bodySmall,
                    modifier = Modifier.fillMaxWidth()
                )

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

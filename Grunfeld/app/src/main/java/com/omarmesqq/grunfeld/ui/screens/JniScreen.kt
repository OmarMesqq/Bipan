package com.omarmesqq.grunfeld.ui.screens

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.omarmesqq.grunfeld.utils.NativeLibWrapper

@Composable
fun JniScreen() {
    var sensorData by remember { mutableStateOf("Sensors not tested.") }
    var stealthReport by remember { mutableStateOf("Run scan to verify Bipan hiding...") }
    var jniData by remember { mutableStateOf("No data loaded yet.") }
    var handlerStatus by remember { mutableStateOf("Not installed") }
    var lastAction by remember { mutableStateOf("Standby") }

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

        Card(
            modifier = Modifier.fillMaxWidth(),
            elevation = CardDefaults.cardElevation(defaultElevation = 4.dp),
            colors = if (sensorData.contains("LEAK"))
                CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer)
            else CardDefaults.cardColors()
        ) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(text = "Sensors Privacy (NDK Layer)", style = MaterialTheme.typography.titleMedium)
                Text(text = sensorData, style = MaterialTheme.typography.bodyMedium)
                Button(
                    onClick = {
                        sensorData = NativeLibWrapper.testSensors()
                    },
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text("Test Native Sensors")
                }
            }
        }

        Card(
            modifier = Modifier.fillMaxWidth(),
            elevation = CardDefaults.cardElevation(defaultElevation = 4.dp)
        ) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(text = "Uname", style = MaterialTheme.typography.titleMedium)
                Text(text = jniData, style = MaterialTheme.typography.bodyMedium)
                Button(onClick = { jniData = NativeLibWrapper.getUname() }, modifier = Modifier.fillMaxWidth()) {
                    Text("Get uname")
                }
            }
        }

        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(
                containerColor = if (stealthReport.contains("!!"))
                    MaterialTheme.colorScheme.errorContainer
                else MaterialTheme.colorScheme.surfaceVariant
            )
        ) {
            Column(
                modifier = Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Text(text = "Anti-Forensics Scan", style = MaterialTheme.typography.titleMedium)

                // Display the raw report from C
                Text(
                    text = stealthReport,
                    style = MaterialTheme.typography.bodySmall,
                    modifier = Modifier.fillMaxWidth()
                )

                Button(
                    onClick = { stealthReport = NativeLibWrapper.scanMaps() },
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text("Scan /proc/self/maps")
                }
            }
        }

        Card(
            modifier = Modifier.fillMaxWidth(),
            elevation = CardDefaults.cardElevation(defaultElevation = 4.dp)
        ) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(text = "File System Inspection", style = MaterialTheme.typography.titleMedium)
                Button(
                    onClick = {
                        NativeLibWrapper.testFileSystemProbes()
                        lastAction = "Filesystem Probes sent to Logcat"
                    },
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text("Probe filesystem")
                }
            }
        }

        Card(
            modifier = Modifier.fillMaxWidth(),
            elevation = CardDefaults.cardElevation(defaultElevation = 4.dp)
        ) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(text = "Networking", style = MaterialTheme.typography.titleMedium)

                Button(
                    onClick = {
                        NativeLibWrapper.testBind()
                    },
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text("Bind on LAN (IPv4/IPv6 and TCP/UDP)")
                }

                Button(
                    onClick = {
                        NativeLibWrapper.testNetworkLeaks()
                    },
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text("Test Sendto/GetSockName (Leaks)")
                }
            }
        }

        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)
        ) {
            Column(modifier = Modifier.padding(16.dp)) {
                Text(text = "Signal Handler: $handlerStatus", style = MaterialTheme.typography.bodySmall)

                Spacer(modifier = Modifier.height(8.dp))

                Button(
                    onClick = {
                        val success = NativeLibWrapper.installSigsysHandler()
                        handlerStatus = if (success) "Active" else "Failed"
                    },
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text("Install SIGSYS handler")
                }
            }
        }
    }
}

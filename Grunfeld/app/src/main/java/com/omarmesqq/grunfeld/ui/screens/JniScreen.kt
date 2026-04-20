package com.omarmesqq.grunfeld.ui.screens

import android.R.attr.onClick
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.omarmesqq.grunfeld.utils.NativeLibWrapper

@Composable
fun JniScreen() {
    var sensorData by remember { mutableStateOf("Sensors not tested yet") }
    var stealthReport by remember { mutableStateOf("Maps not tested yet") }
    var bindReport by remember { mutableStateOf("Bind not tested yet") }
    var unameReport by remember { mutableStateOf("Uname not fetched yet") }
    var signalHandlerStatus by remember { mutableStateOf("SIGSYS handler not installed yet") }

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

        SectionHeader("SENSORS")
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

        SectionHeader("SYSTEM INFO")
        Card(
            modifier = Modifier.fillMaxWidth(),
            elevation = CardDefaults.cardElevation(defaultElevation = 4.dp)
        ) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(text = "Uname", style = MaterialTheme.typography.titleMedium)
                Text(text = unameReport, style = MaterialTheme.typography.bodyMedium)
                Button(onClick = { unameReport = NativeLibWrapper.getUname() }, modifier = Modifier.fillMaxWidth()) {
                    Text("Get uname")
                }
            }
        }

        SectionHeader("STEALTH")
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

        SectionHeader("FILESYSTEM")
        Card(
            modifier = Modifier.fillMaxWidth(),
            elevation = CardDefaults.cardElevation(defaultElevation = 4.dp)
        ) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(text = "File System Inspection", style = MaterialTheme.typography.titleMedium)
                Button(
                    onClick = {
                        NativeLibWrapper.testFileSystemProbes()
                    },
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text("Probe filesystem")
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
                Text(text = bindReport, style = MaterialTheme.typography.bodySmall)
                Button(
                    onClick = {
                        bindReport = NativeLibWrapper.testBind()
                    },
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text("Bind on LAN (IPv4/IPv6 and TCP/UDP)")
                }
            }
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                CodeTitle("sendto()")
                Text(text = bindReport, style = MaterialTheme.typography.bodySmall)
                Button(
                    onClick = {
                        NativeLibWrapper.testNetworkLeaks()
                    },
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text("sendto LAN")
                }
            }

            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                CodeTitle("getsockname()")
                Text(text = bindReport, style = MaterialTheme.typography.bodySmall)
                Button(
                    onClick = {
                        NativeLibWrapper.testNetworkLeaks()
                    },
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text("getsockname on LAN info")
                }
            }
        }

        SectionHeader("MISC")
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)
        ) {
            Column(modifier = Modifier.padding(16.dp)) {
                Text(text = "Signal Handler", style = MaterialTheme.typography.titleMedium)

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
                    Text("Install SIGSYS handler")
                }
            }
        }
    }
}


@Composable
fun SectionHeader(title: String) {
    Column(modifier = Modifier.padding(top = 16.dp, bottom = 8.dp)) {
        Text(
            text = title,
            style = MaterialTheme.typography.labelLarge,
            color = MaterialTheme.colorScheme.primary,
            modifier = Modifier.padding(bottom = 4.dp)
        )
        HorizontalDivider(
            thickness = 1.dp,
            color = MaterialTheme.colorScheme.outlineVariant
        )
    }
}

@Composable
fun CodeTitle(text: String) {
    Surface(
        color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f),
        shape = MaterialTheme.shapes.extraSmall
    ) {
        Text(
            text = text,
            modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
            style = MaterialTheme.typography.titleMedium.copy(
                fontFamily = FontFamily.Monospace,
                fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        )
    }
}

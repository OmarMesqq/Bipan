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
    var jniData by remember { mutableStateOf("No data loaded yet.") }
    var handlerStatus by remember { mutableStateOf("Not installed") }
    var lastAction by remember { mutableStateOf("Standby") }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp)
            .verticalScroll(rememberScrollState()), // Added scroll in case screen fills up
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        Text(
            text = "Bipan Sandbox Tester",
            style = MaterialTheme.typography.headlineMedium
        )

        // --- UNAME CARD ---
        Card(
            modifier = Modifier.fillMaxWidth(),
            elevation = CardDefaults.cardElevation(defaultElevation = 4.dp)
        ) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(text = "Identity Gaslighting", style = MaterialTheme.typography.titleMedium)
                Text(text = jniData, style = MaterialTheme.typography.bodyMedium)
                Button(onClick = { jniData = NativeLibWrapper.getUname() }, modifier = Modifier.fillMaxWidth()) {
                    Text("Verify Uname Spoof")
                }
            }
        }

        // --- VFS PROBES CARD ---
        Card(
            modifier = Modifier.fillMaxWidth(),
            elevation = CardDefaults.cardElevation(defaultElevation = 4.dp)
        ) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(text = "Virtual File System", style = MaterialTheme.typography.titleMedium)
                Text(text = "Tests: /proc/self/maps, smaps, and mounts", style = MaterialTheme.typography.bodySmall)
                Button(
                    onClick = {
                        NativeLibWrapper.testVfsProbes()
                        lastAction = "VFS Probes sent to Logcat"
                    },
                    modifier = Modifier.fillMaxWidth(),
                    colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.secondary)
                ) {
                    Text("Trigger VFS Probes")
                }
            }
        }

        // --- NETWORK SECURITY CARD ---
        Card(
            modifier = Modifier.fillMaxWidth(),
            elevation = CardDefaults.cardElevation(defaultElevation = 4.dp)
        ) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(text = "Network Firewall", style = MaterialTheme.typography.titleMedium)

                Button(
                    onClick = {
                        NativeLibWrapper.testNetworkIdentity()
                        lastAction = "Network Identity checks sent to Logcat"
                    },
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text("Test Bind/Listen (Identity)")
                }

                Button(
                    onClick = {
                        NativeLibWrapper.testNetworkLeaks()
                        lastAction = "LAN Leak checks sent to Logcat"
                    },
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text("Test Sendto/GetSockName (Leaks)")
                }
            }
        }

        // --- SYSTEM STATUS CARD ---
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)
        ) {
            Column(modifier = Modifier.padding(16.dp)) {
                Text(text = "Last Action: $lastAction", style = MaterialTheme.typography.bodySmall)
                Text(text = "Sigsys Handler: $handlerStatus", style = MaterialTheme.typography.bodySmall)

                Spacer(modifier = Modifier.height(8.dp))

                Button(
                    onClick = {
                        val success = NativeLibWrapper.installSigsysHandler()
                        handlerStatus = if (success) "Active (Ring 0)" else "Failed"
                    },
                    modifier = Modifier.fillMaxWidth(),
                    enabled = handlerStatus == "Not installed"
                ) {
                    Text("Arm Seccomp Trap")
                }
            }
        }
    }
}

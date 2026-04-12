package com.omarmesqq.grunfeld.ui.screens

import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.omarmesqq.grunfeld.utils.NativeLibWrapper

@Composable
fun JniScreen() {
    // 1. Change to mutableStateOf so we can update it later
    var jniData by remember { mutableStateOf("No data loaded yet.") }

    // State for signal handler status
    var handlerStatus by remember { mutableStateOf("Not installed") }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        Text(
            text = "Native Security",
            style = MaterialTheme.typography.headlineMedium
        )

        // Uname Card
        Card(
            modifier = Modifier.fillMaxWidth(),
            elevation = CardDefaults.cardElevation(defaultElevation = 4.dp)
        ) {
            Column(
                modifier = Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Text(text = "Uname Info", style = MaterialTheme.typography.titleMedium)

                // Display the current state of jniData
                Text(text = jniData, style = MaterialTheme.typography.bodyLarge)

                // 2. Added button to trigger the JNI call
                Button(
                    onClick = {
                        jniData = try {
                            NativeLibWrapper.getUname()
                        } catch (e: Exception) {
                            "Error: ${e.message}"
                        }
                    },
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text("Fetch Uname via Syscall")
                }
            }
        }

        // Signal Handler Card
        Card(
            modifier = Modifier.fillMaxWidth(),
            elevation = CardDefaults.cardElevation(defaultElevation = 4.dp)
        ) {
            Column(
                modifier = Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Text(text = "Signal Handling", style = MaterialTheme.typography.titleMedium)

                Text(text = "Status: $handlerStatus")

                Button(
                    onClick = {
                        val success = NativeLibWrapper.installSigsysHandler()
                        handlerStatus = if (success) "Installed Successfully" else "Installation Failed"
                    },
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text("Install SIGSYS Handler")
                }
            }
        }
    }
}

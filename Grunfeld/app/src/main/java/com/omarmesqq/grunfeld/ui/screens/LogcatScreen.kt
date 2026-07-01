package com.omarmesqq.grunfeld.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
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
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.omarmesqq.grunfeld.utils.readLogcatWithProcessBuilder
import com.omarmesqq.grunfeld.utils.readLogcatWithRuntime
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@Composable
fun LogcatScreen() {
    val screenScrollState = rememberScrollState()
    var logcatSnippetWithRuntime by remember { mutableStateOf("") }
    var logcatSnippetWithProcessBuilder by remember { mutableStateOf("") }
    // Get a CoroutineScope bound to and by this composition
    val scope = rememberCoroutineScope()

    Column(
        modifier = Modifier
            .fillMaxSize()
            .safeDrawingPadding()
            .verticalScroll(screenScrollState)
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {

        Card(
            modifier = Modifier.fillMaxWidth(),
            elevation = CardDefaults.cardElevation(defaultElevation = 4.dp)
        ) {
            Button(
                onClick = {
                    scope.launch {
                        // Switch to I/O thread
                        logcatSnippetWithRuntime = withContext(Dispatchers.IO) {
                            readLogcatWithRuntime()
                        }
                    }
                },
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("Dump Grunfeld's logcat using Runtime")
            }
            Text(text = logcatSnippetWithRuntime, style = MaterialTheme.typography.titleMedium)
        }

        Card(
            modifier = Modifier.fillMaxWidth(),
            elevation = CardDefaults.cardElevation(defaultElevation = 4.dp)
        ) {
            Button(
                onClick = {
                    scope.launch {
                        // Switch to I/O thread
                        logcatSnippetWithProcessBuilder = withContext(Dispatchers.IO) {
                            readLogcatWithProcessBuilder()
                        }
                    }
                },
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("Dump Grunfeld's logcat using ProcessBuilder")
            }
            Text(text = logcatSnippetWithProcessBuilder, style = MaterialTheme.typography.titleMedium)
        }
    }
}
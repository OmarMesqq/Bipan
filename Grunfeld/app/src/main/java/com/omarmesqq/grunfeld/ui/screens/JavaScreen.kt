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
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import com.omarmesqq.grunfeld.ui.composables.ReportTextWithCopy
import com.omarmesqq.grunfeld.ui.composables.SectionHeader
import com.omarmesqq.grunfeld.utils.DumpJavaInfo
import com.omarmesqq.grunfeld.utils.dumpJavaSensorInfo

@Composable
fun JavaInfoScreen() {
    val context = LocalContext.current
    var buildAndSettingsInfo by remember { mutableStateOf(DumpJavaInfo(context)) }
    var javaSensorsReport by remember { mutableStateOf("Sensors not tested at Java layer yet") }

    val screenScrollState = rememberScrollState()

    Column(
        modifier = Modifier
            .fillMaxSize()
            .safeDrawingPadding()
            .verticalScroll(screenScrollState)
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        Text(text = "Java info", style = MaterialTheme.typography.headlineMedium)

        SectionHeader("BUILD AND SETTINGS INFO")
        Card(
            modifier = Modifier.fillMaxWidth(),
            elevation = CardDefaults.cardElevation(defaultElevation = 4.dp)
        ) {
            Text(
                text = buildAndSettingsInfo,
                modifier = Modifier.padding(16.dp),
                style = MaterialTheme.typography.bodyMedium
            )
        }

        SectionHeader("SENSORS")
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Text(text = "Java Layer", style = MaterialTheme.typography.titleMedium)
            Button(
                onClick = { javaSensorsReport = dumpJavaSensorInfo(context) },
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("Probe Sensors using Java")
            }
            ReportTextWithCopy(javaSensorsReport, "Sensors not tested at Java layer yet")
        }
    }
}
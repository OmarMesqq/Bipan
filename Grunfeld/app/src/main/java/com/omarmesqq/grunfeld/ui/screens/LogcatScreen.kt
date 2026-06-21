package com.omarmesqq.grunfeld.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.omarmesqq.grunfeld.ui.composables.SectionHeader
import com.omarmesqq.grunfeld.utils.readLogcatWithProcessBuilder
import com.omarmesqq.grunfeld.utils.readLogcatWithRuntime

@Composable
fun LogcatScreen() {
    val screenScrollState = rememberScrollState()
    val logcatSnippetWithRuntime = readLogcatWithRuntime()
    val logcatSnippetWithProcessBuilder = readLogcatWithProcessBuilder()

    Column(
        modifier = Modifier
            .fillMaxSize()
            .safeDrawingPadding()
            .verticalScroll(screenScrollState)
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {

        SectionHeader("Grunfeld's logcat using Runtime")
        Card(
            modifier = Modifier.fillMaxWidth(),
            elevation = CardDefaults.cardElevation(defaultElevation = 4.dp)
        ) {
            Text(text = logcatSnippetWithRuntime, style = MaterialTheme.typography.titleMedium)
        }

        SectionHeader("Grunfeld's logcat using ProcessBuilder")
        Card(
            modifier = Modifier.fillMaxWidth(),
            elevation = CardDefaults.cardElevation(defaultElevation = 4.dp)
        ) {
            Text(text = logcatSnippetWithProcessBuilder, style = MaterialTheme.typography.titleMedium)
        }
    }
}
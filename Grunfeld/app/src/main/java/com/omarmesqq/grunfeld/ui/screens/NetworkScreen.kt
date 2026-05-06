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
import com.omarmesqq.grunfeld.utils.dumpNetworkInfo

@Composable
fun NetworkScreen() {
    val context = LocalContext.current
    val netInfo = remember { dumpNetworkInfo(context) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp)
            .verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        Text(
            text = "Network info",
            style = MaterialTheme.typography.headlineMedium
        )

        SectionHeader("VPN")
        Card(
            modifier = Modifier.fillMaxWidth(),
            elevation = CardDefaults.cardElevation(defaultElevation = 4.dp)
        ) {
            Text(
                text = netInfo,
                modifier = Modifier.padding(16.dp),
                style = MaterialTheme.typography.bodyMedium
            )
        }
    }
}
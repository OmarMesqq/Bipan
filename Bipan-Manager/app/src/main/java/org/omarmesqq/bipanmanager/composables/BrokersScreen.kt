package org.omarmesqq.bipanmanager.composables

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch
import org.omarmesqq.bipanmanager.data.AppInitParams

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun BrokersScreen(initParams: AppInitParams) {
    val mvm = initParams.mainViewModel
    val brokers by mvm.brokerProcesses.collectAsState()
    var isRefreshing by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()

    LaunchedEffect(Unit) {
        mvm.fetchBipanBrokers()
    }

    PullToRefreshBox(
        isRefreshing = isRefreshing,
        onRefresh = {
            scope.launch {
                isRefreshing = true
                try {
                    mvm.fetchBipanBrokers()
                } finally {
                    isRefreshing = false
                }
            }
        },
        modifier = Modifier.fillMaxSize()
    ) {
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .background(MaterialTheme.colorScheme.surface)
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            items(brokers, key = { it.pid }) { bb ->
                Text(
                    "${bb.name} (${bb.pid})\n" +
                            "CPU usage: ${bb.cpu}%\n" +
                            "RAM usage (VmRSS): ${bb.vmRss} kB (${bb.vmRss / 1024} MB)\n" +
                            "Swapped memory (VmSwap): ${bb.vmSwap} kB (${bb.vmSwap / 1024} MB)\n" +
                            "Highest RSS (VmHWM): ${bb.vmHwm} kB (${bb.vmHwm / 1024} MB)\n" +
                            "Threads: ${bb.threads}\n"
                )
                HorizontalDivider()
            }
        }
    }
}
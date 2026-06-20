package com.omarmesqq.grunfeld.ui.screens

import android.content.Context
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import com.omarmesqq.grunfeld.ui.composables.ReportTextWithCopy
import com.scottyab.rootbeer.RootBeer
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext


suspend fun checkRoot(ctx: Context): String {
    var isRooted = ""
    withContext(Dispatchers.IO) {
        val rootBeer = RootBeer(ctx)
        isRooted = if (rootBeer.isRooted) "Rooted!" else "NOT rooted"
    }
    return isRooted
}

@Composable
fun RootCheckerScreen() {
    val context = LocalContext.current
    val screenScrollState = rememberScrollState()

    var isRootedInfo by remember { mutableStateOf("Root not checked") }
    LaunchedEffect(isRootedInfo) {
        isRootedInfo = checkRoot(context)
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .safeDrawingPadding()
            .verticalScroll(screenScrollState)
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(text = "RootBeer check", style = MaterialTheme.typography.titleLarge)
            Text(text = isRootedInfo, style = MaterialTheme.typography.titleMedium)
        }
    }
}

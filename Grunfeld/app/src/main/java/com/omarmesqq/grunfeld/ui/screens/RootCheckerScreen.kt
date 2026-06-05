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
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import com.omarmesqq.grunfeld.ui.composables.ReportTextWithCopy
import com.scottyab.rootbeer.RootBeer


@Composable
fun RootCheckerScreen() {
    val context = LocalContext.current
    val screenScrollState = rememberScrollState()
    var isRootedInfo by remember { mutableStateOf("Root not checked") }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .safeDrawingPadding()
            .verticalScroll(screenScrollState)
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(text = "RootBeer check", style = MaterialTheme.typography.titleMedium)

            ReportTextWithCopy(isRootedInfo, "Root not checked")
            Button(
                onClick = {
                    isRootedInfo = checkRootWithRootBeer(context)
                },
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("checkRootWithRootBeer()")
            }
        }
    }
}

private fun checkRootWithRootBeer(ctx: Context): String {
    val rootBeer = RootBeer(ctx)
    if (rootBeer.isRooted) {
        return "Rooted"
    } else {
        return "NOT rooted"
    }
}
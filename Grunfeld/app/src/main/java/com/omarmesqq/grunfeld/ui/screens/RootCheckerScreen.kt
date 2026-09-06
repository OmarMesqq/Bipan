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
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import com.scottyab.rootbeer.RootBeer
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@Composable
fun RootCheckerScreen() {
    val context = LocalContext.current
    val screenScrollState = rememberScrollState()
    val composableScope = rememberCoroutineScope()

    var isRootedInfo by remember { mutableStateOf("Root not checked") }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .safeDrawingPadding()
            .verticalScroll(screenScrollState)
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        Text(text = "Check root with RootBeer", style = MaterialTheme.typography.headlineMedium)

        Button(
            onClick = {
                composableScope.launch {
                    isRootedInfo = withContext(Dispatchers.IO) {
                        val rootBeer = RootBeer(context)
                        if (rootBeer.isRooted) {
                            "Rooted!"
                        } else {
                            "NOT rooted :-)"
                        }
                    }
                }
            },
            modifier = Modifier.fillMaxWidth()
        ) {
            Text("isRooted()")
        }

        Text(isRootedInfo)
    }
}

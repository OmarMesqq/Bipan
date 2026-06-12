package com.omarmesqq.grunfeld.ui.screens

import android.os.Build
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
import com.omarmesqq.grunfeld.utils.dumpNetworkInfo
import androidx.annotation.RequiresApi
import com.omarmesqq.grunfeld.utils.dumpGetApplicationInfo
import com.omarmesqq.grunfeld.utils.dumpGetInstalledApplications
import com.omarmesqq.grunfeld.utils.dumpGetPackageInfo
import com.omarmesqq.grunfeld.utils.dumpGetSystemAvailableFeaturesInfo
import com.omarmesqq.grunfeld.utils.dumpInstallerInfo
import com.omarmesqq.grunfeld.utils.dumpQueryIntentActivities

@RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
@Composable
fun JavaInfoScreen() {
    val context = LocalContext.current
    var buildAndSettingsInfo by remember { mutableStateOf(DumpJavaInfo(context)) }
    var javaSensorsReport by remember { mutableStateOf("Sensors not tested at Java layer yet") }
    var netInfo by remember { mutableStateOf("VPN status not checked yet") }
    var installerInfo by remember { mutableStateOf("Installer info not queried") }
    var dumpQueryIntentActivities by remember { mutableStateOf("Query Intent Activities not tested") }
    var getPackageInfoStatus by remember { mutableStateOf("Get Package Info not queried") }
    var getInstalledPackagesInfo by remember { mutableStateOf("Installed applications not queried") }
    var applicationInfoForSelf by remember { mutableStateOf("Get Application info not queried") }
    var getSystemAvailableFeaturesInfo by remember { mutableStateOf("getSystemAvailableFeatures not queried") }

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
            ReportTextWithCopy(buildAndSettingsInfo, "")
        }

        SectionHeader("SENSORS")
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Button(
                onClick = { javaSensorsReport = dumpJavaSensorInfo(context) },
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("Probe Sensors using Java")
            }
            ReportTextWithCopy(javaSensorsReport, "Sensors not tested at Java layer yet")
        }

        SectionHeader("Networking")
        Card(
            modifier = Modifier.fillMaxWidth(),
            elevation = CardDefaults.cardElevation(defaultElevation = 4.dp)
        ) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(
                    onClick = {
                        netInfo = dumpNetworkInfo(context)
                    },
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text("Query network stats")
                }

                Text(
                    text = netInfo,
                    style = MaterialTheme.typography.bodyMedium
                )
            }
        }

        SectionHeader("PACKAGE MANAGER")
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(text = "Get installer info for self (Grunfeld)", style = MaterialTheme.typography.titleMedium)

            ReportTextWithCopy(installerInfo, "Installer info not queried")
            Button(
                onClick = {
                    installerInfo = dumpInstallerInfo(context)
                },
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("getInstallSourceInfo()")
            }

            Text(text = "Query Intent Activities", style = MaterialTheme.typography.titleMedium)

            ReportTextWithCopy(dumpQueryIntentActivities, "Query Intent Activities not tested")
            Button(
                onClick = {
                    dumpQueryIntentActivities = dumpQueryIntentActivities(context)
                },
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("dumpQueryIntentActivities()")
            }

            Text(text = "Get Package Info for an arbitrary package", style = MaterialTheme.typography.titleMedium)

            ReportTextWithCopy(getPackageInfoStatus, "Get Package Info not queried")
            Button(
                onClick = {
                    getPackageInfoStatus = dumpGetPackageInfo(context, "com.topjohnwu.magisk")
                },
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("getPackageInfo(\"Magisk\")")
            }

            Text(text = "Get Installed Applications", style = MaterialTheme.typography.titleMedium)

            ReportTextWithCopy(getInstalledPackagesInfo, "Installed applications not queried")
            Button(
                onClick = {
                    getInstalledPackagesInfo = dumpGetInstalledApplications(context)
                },
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("getInstalledApplications() && getInstalledPackages()")
            }

            Text(text = "Get Application Info for an arbitrary package", style = MaterialTheme.typography.titleMedium)

            ReportTextWithCopy(applicationInfoForSelf, "Get Application info not queried")
            Button(
                onClick = {
                    applicationInfoForSelf = dumpGetApplicationInfo(context)
                },
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("getApplicationInfo(\"WhatsApp\")")
            }

            Text(text = "Get getSystemAvailableFeatures", style = MaterialTheme.typography.titleMedium)

            ReportTextWithCopy(getSystemAvailableFeaturesInfo, "getSystemAvailableFeatures not queried")
            Button(
                onClick = {
                    getSystemAvailableFeaturesInfo = dumpGetSystemAvailableFeaturesInfo(context)
                },
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("getSystemAvailableFeaturesInfo()")
            }

        }
    }
}
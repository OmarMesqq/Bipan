package com.omarmesqq.grunfeld.ui.screens

import android.app.Activity
import android.os.Build
import androidx.annotation.RequiresApi
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
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import com.omarmesqq.grunfeld.MainApplication
import com.omarmesqq.grunfeld.ui.composables.ReportTextWithCopy
import com.omarmesqq.grunfeld.ui.composables.SectionHeader
import com.omarmesqq.grunfeld.utils.DumpJavaInfo
import com.omarmesqq.grunfeld.utils.dumpCpuInfo
import com.omarmesqq.grunfeld.utils.dumpDevProperties
import com.omarmesqq.grunfeld.utils.dumpGetApplicationInfo
import com.omarmesqq.grunfeld.utils.dumpGetInstalledApplications
import com.omarmesqq.grunfeld.utils.dumpGetInstalledPackages
import com.omarmesqq.grunfeld.utils.dumpGetPackageInfo
import com.omarmesqq.grunfeld.utils.dumpGetSystemAvailableFeaturesInfo
import com.omarmesqq.grunfeld.utils.dumpGsfId
import com.omarmesqq.grunfeld.utils.dumpInstallerInfo
import com.omarmesqq.grunfeld.utils.dumpJavaSensorInfo
import com.omarmesqq.grunfeld.utils.dumpMediaDrmId
import com.omarmesqq.grunfeld.utils.dumpNetworkInfo
import com.omarmesqq.grunfeld.utils.dumpQueryIntentActivities
import com.omarmesqq.grunfeld.utils.dumpTelephonyInfo
import com.omarmesqq.grunfeld.utils.getMemoryInfo
import com.omarmesqq.grunfeld.utils.getPlayInstallReferrerInfo
import com.omarmesqq.grunfeld.utils.getSomeSystemFeatures
import com.omarmesqq.grunfeld.utils.getSystemProps
import com.omarmesqq.grunfeld.utils.inspectPackageManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
@Composable
fun JavaInfoScreen() {
    val context = LocalContext.current
    val screenScrollState = rememberScrollState()
    val composableScope = rememberCoroutineScope()

    var buildAndSettingsInfo by remember { mutableStateOf(DumpJavaInfo(context)) }

    var javaSensorsReport by remember { mutableStateOf("Sensors not tested yet") }

    var netInfo by remember { mutableStateOf("") }

    var installerInfo by remember { mutableStateOf("Installer info not queried") }
    var dumpQueryIntentActivities by remember { mutableStateOf("Query Intent Activities not tested") }
    var getPackageInfoStatus by remember { mutableStateOf("Get Package Info not queried") }
    var getInstalledApplicationsInfo by remember { mutableStateOf("Installed applications not queried") }
    var getInstalledPackagesInfo by remember { mutableStateOf("Installed packages not queried") }
    var applicationInfoForSelf by remember { mutableStateOf("Application info not queried") }
    var getSystemAvailableFeaturesInfo by remember { mutableStateOf("System available features not queried") }
    var getSomeSystemFeaturesInfo by remember { mutableStateOf("hasSystemFeature not queried") }

    var memInfo by remember { mutableStateOf("Memory not queried") }
    var cpuInfo by remember { mutableStateOf("CPU info not queried") }

    var sysPropsInfo by remember { mutableStateOf("Sys props not queried") }
    var devPropsInfo by remember { mutableStateOf("Dev properties not queried") }

    var gsfId by remember { mutableStateOf("GSF ID not queried") }
    var mediaDrmIdInfo by remember { mutableStateOf("Media DRM ID not queried") }
    var playInstallReferrerInfo by remember { mutableStateOf("playInstallReferrerInfo not queried") }
    var packageManagerClassInfo by remember { mutableStateOf("PM not inspected") }

    var telephonyInfo by remember { mutableStateOf("Telephony info not queried") }
    var stackTraceInfo by remember { mutableStateOf("Stack trace info not queried") }

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
                ReportTextWithCopy(netInfo, "")
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

            ReportTextWithCopy(getInstalledApplicationsInfo, "Installed applications not queried")
            Button(
                onClick = {
                    getInstalledApplicationsInfo = dumpGetInstalledApplications(context)
                },
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("getInstalledApplications()")
            }

            Text(text = "Get Installed Packages", style = MaterialTheme.typography.titleMedium)

            ReportTextWithCopy(getInstalledPackagesInfo, "Installed applications not queried")
            Button(
                onClick = {
                    getInstalledPackagesInfo = dumpGetInstalledPackages(context)
                },
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("getInstalledPackages()")
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

            Text(text = "Get ALL available system features", style = MaterialTheme.typography.titleMedium)

            ReportTextWithCopy(getSystemAvailableFeaturesInfo, "getSystemAvailableFeatures not queried")
            Button(
                onClick = {
                    getSystemAvailableFeaturesInfo = dumpGetSystemAvailableFeaturesInfo(context)
                },
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("getSystemAvailableFeaturesInfo()")
            }


            Text(text = "Get some system features by querying their keys", style = MaterialTheme.typography.titleMedium)
            ReportTextWithCopy(getSomeSystemFeaturesInfo, "getSomeSystemFeaturesInfo not queried")
            Button(
                onClick = {
                    getSomeSystemFeaturesInfo = getSomeSystemFeatures(context)
                },
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("getSomeSystemFeatures()")
            }

            Text(text = "Inspect PM", style = MaterialTheme.typography.titleMedium)
            ReportTextWithCopy(packageManagerClassInfo, "PM not inspected")
            Button(
                onClick = {
                    packageManagerClassInfo = inspectPackageManager(context)
                },
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("Inspect Package Manager with reflection")
            }
        }

        SectionHeader("HARDWARE")
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(
                onClick = {
                    memInfo = getMemoryInfo(context)
                },
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("MEMORY INFO")
            }

            Text(
                text = memInfo,
                style = MaterialTheme.typography.bodyMedium
            )


            Button(
                onClick = {
                    cpuInfo = dumpCpuInfo()
                },
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("CPU INFO")
            }

            Text(
                text = cpuInfo,
                style = MaterialTheme.typography.bodyMedium
            )
        }



        SectionHeader("SYSTEM PROPERTIES")
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(
                onClick = {
                    sysPropsInfo = getSystemProps()
                },
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("Get some system properties")
            }

            Text(
                text = sysPropsInfo,
                style = MaterialTheme.typography.bodyMedium
            )

            Button(
                onClick = { devPropsInfo = dumpDevProperties() },
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("Dump prop contexts")
            }
            ReportTextWithCopy(devPropsInfo, "Dev properties not queried")
        }

        SectionHeader("DEVICE IDENTIFIERS")
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(
                onClick = {
                    gsfId = dumpGsfId(context)
                },
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("Get GSF ID")
            }
            Text(
                text = gsfId,
                style = MaterialTheme.typography.bodyMedium
            )

            Button(
                onClick = {
                    mediaDrmIdInfo = dumpMediaDrmId()
                },
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("Get Media DRM ID")
            }

            Text(
                text = mediaDrmIdInfo,
                style = MaterialTheme.typography.bodyMedium
            )

            Button(
                onClick = {
                    playInstallReferrerInfo = getPlayInstallReferrerInfo(context)
                },
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("Get Play Install Referrer Info")
            }

            Text(
                text = playInstallReferrerInfo,
                style = MaterialTheme.typography.bodyMedium
            )
        }


        SectionHeader("TELEPHONY")
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(
                onClick = {
                    composableScope.launch {
                        telephonyInfo = withContext(Dispatchers.IO) {
                            dumpTelephonyInfo(context)
                        }
                    }
                },
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("Get Telephony info")
            }
            ReportTextWithCopy(telephonyInfo, "", MaterialTheme.typography.bodyMedium)
        }

        SectionHeader("ANTI-TAMPER")
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(
                onClick = {
                    val activity = context as? Activity
                    val app = activity?.application as MainApplication
                    stackTraceInfo = app.baseCtxStackTrace
                },
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("Dump early application's stack trace")
            }
            ReportTextWithCopy(stackTraceInfo, "", MaterialTheme.typography.bodyMedium)
        }
    }
}
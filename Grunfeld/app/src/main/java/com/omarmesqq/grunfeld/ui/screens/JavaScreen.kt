package com.omarmesqq.grunfeld.ui.screens

import android.content.Context
import android.os.Build
import android.provider.Settings.Global
import android.text.TextUtils.split
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
import androidx.compose.material3.Divider
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import com.omarmesqq.grunfeld.ui.composables.AssertionResult
import com.omarmesqq.grunfeld.ui.composables.AssertionResultEmpty
import com.omarmesqq.grunfeld.ui.composables.AssertionResultNotContains
import com.omarmesqq.grunfeld.ui.composables.AssertionResultNull
import com.omarmesqq.grunfeld.ui.composables.ReportTextWithCopy
import com.omarmesqq.grunfeld.ui.composables.SectionHeader
import com.omarmesqq.grunfeld.utils.dumpDevProperties
import com.omarmesqq.grunfeld.utils.dumpGetApplicationInfo
import com.omarmesqq.grunfeld.utils.dumpGetInstalledApplications
import com.omarmesqq.grunfeld.utils.dumpGetInstalledPackages
import com.omarmesqq.grunfeld.utils.dumpGetPackageInfo
import com.omarmesqq.grunfeld.utils.dumpGetSystemAvailableFeaturesInfo
import com.omarmesqq.grunfeld.utils.dumpGsfId
import com.omarmesqq.grunfeld.utils.dumpInstallerInfo
import com.omarmesqq.grunfeld.utils.dumpMediaDrmId
import com.omarmesqq.grunfeld.utils.dumpNetworkInfo
import com.omarmesqq.grunfeld.utils.dumpNetworkInterfaces
import com.omarmesqq.grunfeld.utils.dumpQueryIntentActivities
import com.omarmesqq.grunfeld.utils.dumpSensorInfo
import com.omarmesqq.grunfeld.utils.dumpSomeSystemFeatures
import com.omarmesqq.grunfeld.utils.dumpSystemProps
import com.omarmesqq.grunfeld.utils.dumpTelephonyInfo
import com.omarmesqq.grunfeld.utils.runtimeExecWithCmd
import com.omarmesqq.grunfeld.utils.runtimeExecWithCmdArray
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.net.NetworkInterface
import java.util.Enumeration

@RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
@Composable
fun JavaInfoScreen() {
    val context = LocalContext.current
    val screenScrollState = rememberScrollState()
    val composableScope = rememberCoroutineScope()


    var netInfo by remember { mutableStateOf("") }

    var installerInfo by remember { mutableStateOf("Installer info not queried") }
    var dumpQueryIntentActivities by remember { mutableStateOf("Query Intent Activities not tested") }
    var getPackageInfoStatus by remember { mutableStateOf("Get Package Info not queried") }
    var getInstalledApplicationsInfo by remember { mutableStateOf("Installed applications not queried") }
    var getInstalledPackagesInfo by remember { mutableStateOf("Installed packages not queried") }
    var applicationInfoForSelf by remember { mutableStateOf("Application info not queried") }
    var getSystemAvailableFeaturesInfo by remember { mutableStateOf("System available features not queried") }
    var getSomeSystemFeaturesInfo by remember { mutableStateOf("hasSystemFeature not queried") }

    var sysPropsInfo by remember { mutableStateOf("Sys props not queried") }
    var devPropsInfo by remember { mutableStateOf("Dev properties not queried") }

    var gsfId by remember { mutableStateOf("GSF ID not queried") }
    var mediaDrmIdInfo by remember { mutableStateOf("Media DRM ID not queried") }

    var telephonyInfo by remember { mutableStateOf("Telephony info not queried") }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .safeDrawingPadding()
            .verticalScroll(screenScrollState)
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        Text(text = "Java info", style = MaterialTheme.typography.headlineMedium)

        SectionHeader("BUILD AND SETTINGS TESTS")
        Card(
            modifier = Modifier.fillMaxWidth(),
            elevation = CardDefaults.cardElevation(defaultElevation = 4.dp)
        ) {
            BuildAssertions()
            SettingsAssertions(context)
        }

        SectionHeader("RUNTIME EXEC TESTS")
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            RuntimeAssertions()
        }

        SectionHeader("SENSORS TESTS")
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            SensorsAssertions(context)
        }


        SectionHeader("NETWORK INTERFACES TESTS")
        Card(
            modifier = Modifier.fillMaxWidth(),
            elevation = CardDefaults.cardElevation(defaultElevation = 4.dp)
        ) {
            Column(
                modifier = Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                NetworkIfacesAssertions(context)
            }
        }
        SectionHeader("WIFI MANAGER TESTS")
        SectionHeader("LINK PROPERTIES TESTS")

        SectionHeader("PACKAGE MANAGER")
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {

            Text(
                text = "Get Package Info for an arbitrary package",
                style = MaterialTheme.typography.titleMedium
            )
            ReportTextWithCopy(getPackageInfoStatus, "Get Package Info not queried")
            Button(
                onClick = {
                    getPackageInfoStatus = dumpGetPackageInfo(
                        context,
                        "com.google.android.gms"
                    )
                },
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("getPackageInfo(Google Play Services)")
            }

            Text(
                text = "Get Application Info for an arbitrary package",
                style = MaterialTheme.typography.titleMedium
            )
            ReportTextWithCopy(applicationInfoForSelf, "Get Application info not queried")
            Button(
                onClick = {
                    applicationInfoForSelf = dumpGetApplicationInfo(
                        context,
                        "com.android.webview"
                    )
                },
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("getApplicationInfo(Webview)")
            }

            Text(
                text = "Get installer info for Grunfeld",
                style = MaterialTheme.typography.titleMedium
            )
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

            Text(
                text = "Get ALL available system features",
                style = MaterialTheme.typography.titleMedium
            )
            ReportTextWithCopy(
                getSystemAvailableFeaturesInfo,
                "getSystemAvailableFeatures not queried"
            )
            Button(
                onClick = {
                    getSystemAvailableFeaturesInfo = dumpGetSystemAvailableFeaturesInfo(context)
                },
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("getSystemAvailableFeaturesInfo()")
            }


            Text(
                text = "Get some system features by querying their keys",
                style = MaterialTheme.typography.titleMedium
            )
            ReportTextWithCopy(getSomeSystemFeaturesInfo, "getSomeSystemFeaturesInfo not queried")
            Button(
                onClick = {
                    getSomeSystemFeaturesInfo = dumpSomeSystemFeatures(context)
                },
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("getSomeSystemFeatures()")
            }
        }

        SectionHeader("TELEPHONY")
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
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

        SectionHeader("SYSTEM PROPERTIES")
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Button(
                onClick = {
                    sysPropsInfo = dumpSystemProps()
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
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
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
        }
    }
}

@Suppress("DEPRECATION")
@Composable
private fun BuildAssertions() {
    AssertionResult("BOARD", Build.BOARD, "husky")
    AssertionResult("BOOTLOADER", Build.BOOTLOADER, "ripcurrent-15.0-12455211")
    AssertionResult("BRAND", Build.BRAND, "google")
    AssertionResult("DEVICE", Build.DEVICE, "husky")
    AssertionResult("DISPLAY", Build.DISPLAY, "BP4A.251205.006")
    AssertionResult(
        "FINGERPRINT",
        Build.FINGERPRINT,
        "google/husky/husky:16/BP4A.251205.006/14401865:user/release-keys"
    )
    AssertionResult("HARDWARE", Build.HARDWARE, "zuma")
    AssertionResult("HOST", Build.HOST, "abfarm-20038")
    AssertionResult("ID", Build.ID, "BP4A.251205.006")
    AssertionResult("MANUFACTURER", Build.MANUFACTURER, "google")
    AssertionResult("MODEL", Build.MODEL, "Pixel 8 Pro")
    AssertionResult("PRODUCT", Build.PRODUCT, "husky")
    AssertionResult("SOC_MANUFACTURER", Build.SOC_MANUFACTURER, "Google")
    AssertionResult("SOC_MODEL", Build.SOC_MODEL, "Tensor G3")
    AssertionResult("CPU_ABI", Build.CPU_ABI, "arm64-v8a")
    AssertionResult("CPU_ABI2", Build.CPU_ABI2, "")
    AssertionResult("TYPE", Build.TYPE, "user")
    AssertionResult("TIME", Build.TIME, "1764954000000")
    AssertionResult("USER", Build.USER, "android-build")
    AssertionResult("RADIO", Build.getRadioVersion(), "g5300g-251108-251202-B-12876551")
    AssertionResult("INCREMENTAL", Build.VERSION.INCREMENTAL, "14401865")
    AssertionResult("SECURITY_PATCH", Build.VERSION.SECURITY_PATCH, "2025-12-05")

    // ODM_SKU: not set by spoofer - retains real device value
    // SKU: not set by spoofer - retains real device value
    // SUPPORTED_32_BIT_ABIS: not set by spoofer - retains real device value
    // SUPPORTED_64_BIT_ABIS: not set by spoofer - retains real device value
    // SUPPORTED_ABIS: not set by spoofer - retains real device value
    // TIME: field ID retrieved but value not shown being set in snippet - retains real/set value if set elsewhere
    // MAJOR_SDK: not set by spoofer - derived from real SDK_INT_FULL
    // MINOR_SDK: not set by spoofer - derived from real SDK_INT_FULL
    // PARTITIONS: not set by spoofer - retains real device value
    // BASE_OS: not set by spoofer - retains real device value
    // CODENAME: not set by spoofer - retains real device value
    // MEDIA_PERFORMANCE_CLASS: not set by spoofer - retains real device value
    // PREVIEW_SDK_INT: not set by spoofer - retains real device value
    // RELEASE: not set by spoofer - retains real device value
    // RELEASE_OR_CODENAME: not set by spoofer - retains real device value
    // RELEASE_OR_PREVIEW_DISPLAY: not set by spoofer - retains real device value
    // SDK_INT: not set by spoofer - retains real device value
    // SDK_INT_FULL: not set by spoofer - retains real device value
}

@Composable
private fun SettingsAssertions(ctx: Context) {
    val cr = ctx.contentResolver
    val notFoundKey = -999


    val devSettingsOn = Global.getInt(cr, Global.DEVELOPMENT_SETTINGS_ENABLED, notFoundKey)
    val adbEnabled = Global.getInt(cr, Global.ADB_ENABLED, notFoundKey)
    val bootCount = Global.getInt(cr, Global.BOOT_COUNT, notFoundKey)
    val waitForDebugger = Global.getInt(cr, Global.WAIT_FOR_DEBUGGER, notFoundKey)

    AssertionResult("DEVELOPMENT_SETTINGS_ENABLED", devSettingsOn, "0")
    AssertionResult("ADB_ENABLED", adbEnabled, "0")
    AssertionResult("BOOT_COUNT", bootCount, "43")
    AssertionResult("WAIT_FOR_DEBUGGER", waitForDebugger, "0")
}

@Composable
private fun RuntimeAssertions() {
    AssertionResult("which su", runtimeExecWithCmdArray(arrayOf("which", "su")), "")
    AssertionResult("getprop", runtimeExecWithCmd("getprop"), "")
}

@Composable
private fun SensorsAssertions(ctx: Context) {
    AssertionResult("Sensors", dumpSensorInfo(ctx), "")
}

@Composable
private fun NetworkIfacesAssertions(ctx: Context) {
    val interfaceList = try {
        dumpNetworkInterfaces()
    } catch (e: Exception) {
        Text(
            text = "dumpNetworkInterfaces failed: ${e.message}",
            color = Color.Red
        )
        return
    }


    interfaceList
        .asSequence()
        .toList()
        .forEach { iface ->
            AssertionResultNotContains("Interface name", iface.name, "tun")

            if (iface.name.contains("wlan") || iface.name.contains("rmnet")) {
                iface.interfaceAddresses.forEach { addr ->
                    AssertionResult("MTU", iface.mtu, "1500")

                    val localIp = addr.address.hostAddress ?: ""
                    val prefix = addr.networkPrefixLength
                    val broadcast = addr.broadcast?.hostAddress ?: ""

                    AssertionResult("Local IP", localIp, "10.111.222.1")
                    AssertionResult("Prefix length (subnet mask)", prefix.toInt(), "24")
                    AssertionResult("IPv4 broadcast", broadcast, "10.111.222.255")
                }
            }

            val parent = iface.parent
            val subs = iface.subInterfaces.asSequence().toList()

            AssertionResultNull("Parent interface", parent)
            AssertionResultEmpty("Sub interfaces", subs)
            HorizontalDivider()
        }

}
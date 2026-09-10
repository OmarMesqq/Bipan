package com.omarmesqq.grunfeld.ui.screens

import android.content.ContentResolver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import android.provider.Settings.Global
import android.text.format.Formatter
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
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
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
import com.omarmesqq.grunfeld.ui.composables.AssertionResultSingleSpecificValueInIterable
import com.omarmesqq.grunfeld.ui.composables.AssertionResultSomeValuesInIterable
import com.omarmesqq.grunfeld.ui.composables.ReportTextWithCopy
import com.omarmesqq.grunfeld.ui.composables.SectionHeader
import com.omarmesqq.grunfeld.utils.dumpDevProperties
import com.omarmesqq.grunfeld.utils.dumpDeviceIds
import com.omarmesqq.grunfeld.utils.dumpNetworkInterfaces
import com.omarmesqq.grunfeld.utils.dumpSensorInfo
import com.omarmesqq.grunfeld.utils.dumpTelephonyInfo
import com.omarmesqq.grunfeld.utils.dumpWifiManagerInfo
import com.omarmesqq.grunfeld.utils.runtimeExecWithCmd
import com.omarmesqq.grunfeld.utils.runtimeExecWithCmdArray
import com.scottyab.rootbeer.RootBeer
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.BufferedReader
import java.io.InputStreamReader

@RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
@Composable
fun JavaInfoScreen() {
    val context = LocalContext.current
    val screenScrollState = rememberScrollState()
    val composableScope = rememberCoroutineScope()
    val cr = context.contentResolver

    var devPropsInfo by remember { mutableStateOf("Dev properties not queried") }
    var deviceIds by remember { mutableStateOf("Device IDs not queried") }
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

        SectionHeader("BUILD, SETTINGS AND SYSTEM PROPERTIES TESTS")
        Card(
            modifier = Modifier.fillMaxWidth(),
            elevation = CardDefaults.cardElevation(defaultElevation = 4.dp)
        ) {
            BuildAssertions()
            HorizontalDivider()
            SettingsAssertions(cr)
            HorizontalDivider()
            SystemPropertiesAssertions()
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
                NetworkIfacesAssertions()
            }
        }
        SectionHeader("WIFI MANAGER TESTS")
        WifiManagerAssertions(context)

        SectionHeader("LINK PROPERTIES TESTS")
        LinkPropertiesAssertions(context)

        SectionHeader("APP INSTALLER TEST")
        AppInstallerAssertions(context)

        SectionHeader("FOREIGN APP INSPECTION TESTS")
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            QueryIntentActivitiesAssertions(context)
            InstalledApplicationsAssertions(context)
            InstalledPackagesAssertions(context)
        }

        SectionHeader("SELF-ANALYSIS")
        LogcatAssertions()

        SectionHeader("ROOTBER ROOT CHECK")
        RootCheckAssertions(context)

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
                    deviceIds = dumpDeviceIds(context, cr)
                },
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("Get some device unique IDs")
            }
            Text(
                text = deviceIds,
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
    AssertionResult("FINGERPRINT",Build.FINGERPRINT,"google/husky/husky:16/BP4A.251205.006/14401865:user/release-keys")
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


    val abis32 = Build.SUPPORTED_32_BIT_ABIS
    AssertionResultEmpty("SUPPORTED_32_BIT_ABIS", abis32.toList())

    val abis64 = Build.SUPPORTED_64_BIT_ABIS
    AssertionResultSingleSpecificValueInIterable("SUPPORTED_64_BIT_ABIS", abis64.toList(), "arm64-v8a")

    val abis = Build.SUPPORTED_ABIS
    AssertionResultSingleSpecificValueInIterable("SUPPORTED_ABIS", abis.toList(), "arm64-v8a")


    // ODM_SKU: not set by spoofer - retains real device value
    // SKU: not set by spoofer - retains real device value
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
private fun SettingsAssertions(cr: ContentResolver) {
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
private fun SystemPropertiesAssertions() {
    val arch = System.getProperty("os.arch")
    val name = System.getProperty("os.name")
    val version = System.getProperty("os.version")

    AssertionResult("os.arch", arch ?: "", "aarch64")
    AssertionResult("os.name", name ?: "", "Linux")
    AssertionResult("os.version", version ?: "", "6.6.56-android16-11-g8a3e2b1c4d5f")
}

@Composable
private fun RuntimeAssertions() {
    AssertionResult("which su", runtimeExecWithCmdArray(arrayOf("which", "su")), "")
    AssertionResult("getprop", runtimeExecWithCmd("getprop"), "null")
}

@Composable
private fun SensorsAssertions(ctx: Context) {
    AssertionResult("Sensors", dumpSensorInfo(ctx), "")
}

@Composable
private fun NetworkIfacesAssertions() {
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

@Suppress("DEPRECATION")
@Composable
private fun WifiManagerAssertions(ctx: Context) {
    val wifiInfo = try {
        dumpWifiManagerInfo(ctx)
    } catch (e: Exception) {
        Text(
            text = "dumpWifiManagerInfo failed: ${e.message}",
            color = Color.Red
        )
        return
    }

    AssertionResult("BSSID", wifiInfo.bssid, "02:00:00:00:00:00")
    AssertionResult("SSID", wifiInfo.ssid, "<unknown ssid>")
    AssertionResult("IPv4 address", Formatter.formatIpAddress(wifiInfo.ipAddress), "10.111.222.1")
    AssertionResult("Network ID", wifiInfo.networkId, "4")
}

@Suppress("DEPRECATION")
@Composable
private fun LinkPropertiesAssertions(ctx: Context) {
     val cm = ctx.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
     val activeNetworkInfo = cm.activeNetworkInfo


    AssertionResultNotContains("Active network VPN?", activeNetworkInfo?.typeName ?: "", "VPN")
    AssertionResult("All networks size", cm.allNetworks.size, "0")
    AssertionResultEmpty("All networks content", cm.allNetworks.toList())

    val caps = cm.getNetworkCapabilities(cm.activeNetwork)
    if (caps == null) {
        Text(
            text = "Failed to getNetworkCapabilities via CM",
            color = Color.Red
        )
        return
    }
    val hasTransportVpn = caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
    val hasCapNotVpn = caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
    AssertionResult("Network has VPN transport?", hasTransportVpn, false)
    AssertionResult("Network has cap NOT_VPN?", hasCapNotVpn, true)

    val activeNetwork = cm.activeNetwork
    if (activeNetwork == null) {
        Text(
            text = "activeNetwork is null",
            color = Color.Red
        )
        return
    }
    val linkProperties = cm.getLinkProperties(activeNetwork)
    if (linkProperties == null) {
        Text(
            text = "linkProperties is null",
            color = Color.Red
        )
        return
    }

    val linkAddrs = linkProperties.linkAddresses.map {
        it.address.hostAddress
    }


    AssertionResultNull("DHCP Server", linkProperties.dhcpServerAddress)
    AssertionResultNotContains("Interface name", linkProperties.interfaceName.toString(), "tun")
    AssertionResultSingleSpecificValueInIterable("IP address", linkAddrs, "10.111.222.1")
    AssertionResult("MTU", linkProperties.mtu, "1500")
    AssertionResult("Private DNS active?", linkProperties.isPrivateDnsActive, false)
    AssertionResult("Private DNS Server", linkProperties.privateDnsServerName ?: "", "")

    val dnsServers = linkProperties.dnsServers.map {
        it.hostAddress
    }
    val expectedDnsServers = listOf("8.8.8.8", "8.8.4.4")
    AssertionResultSomeValuesInIterable("DNS Servers", dnsServers, expectedDnsServers)

    val routes = linkProperties.routes
    routes.forEachIndexed { idx, r ->
        Text(
            text = "Route $idx: $r",
            color = Color.Yellow
        )
    }
}

@Composable
private fun AppInstallerAssertions(ctx: Context) {
    val pm = ctx.packageManager
    val packageName = ctx.packageName
    val info = pm.getInstallSourceInfo(packageName)

    val originator = info.originatingPackageName
    val initiator = info.initiatingPackageName
    val installer = info.installingPackageName
    val updateOwner = info.updateOwnerPackageName

    AssertionResultNull("Originator (\"source\" of installation)", originator)
    AssertionResult("Initiator (called the installation)", initiator ?: "", "com.android.vending")
    AssertionResult("Installer (did the actual installation)", installer ?: "", "com.android.vending")
    AssertionResult("Update owner (pkg that will keep app up-to-date)", updateOwner ?: "", "com.android.vending")

    @Suppress("DEPRECATION")
    val legacyInstaller = pm.getInstallerPackageName(packageName)

    AssertionResult("Installer package name (Legacy API)", legacyInstaller ?: "", "com.android.vending")
}

@Composable
private fun QueryIntentActivitiesAssertions(ctx: Context) {
    val pm = ctx.packageManager

    val launcherIntent = Intent(Intent.ACTION_MAIN).apply {
        addCategory(Intent.CATEGORY_LAUNCHER)
    }
    val appsWithLauncher = pm.queryIntentActivities(launcherIntent, 0)
    AssertionResultEmpty("Apps with launcher", appsWithLauncher)
}

@Composable
private fun InstalledApplicationsAssertions(ctx: Context) {
    // Using Application's for diversity, should be hooked too
    val pm = ctx.applicationContext.packageManager

    val installedApps = pm.getInstalledApplications(PackageManager.GET_META_DATA)
    AssertionResultEmpty("Installed applications", installedApps)

}

@Composable
private fun InstalledPackagesAssertions(ctx: Context) {
    val pm = ctx.packageManager
    val flags = (
            PackageManager.GET_PERMISSIONS or
                    PackageManager.GET_ACTIVITIES or
                    PackageManager.GET_SERVICES or
                    PackageManager.GET_RECEIVERS or
                    PackageManager.GET_PROVIDERS
            )
    val installedPackages = pm.getInstalledPackages(flags)
    AssertionResultEmpty("Installed packages", installedPackages)
}

@Composable
private fun LogcatAssertions() {

    val execd =  Runtime.getRuntime().exec("logcat -d")
    val bufferedReader = BufferedReader(InputStreamReader(execd.inputStream))
    var i = 1
    repeat(5) {
        AssertionResultNull("Logcat (Runtime) line $i", bufferedReader.readLine())
        i++
    }

    HorizontalDivider()

    val processBuilder = ProcessBuilder("logcat", "-d", "-m", "5")
    val process = processBuilder.start()
    val exitCode = process.waitFor()
    AssertionResult("Exit code of logcat (ProcessBuilder)", exitCode, "0")
}
@Composable
private fun RootCheckAssertions(ctx: Context) {
    var isRooted by remember { mutableStateOf<Boolean?>(null) }

    LaunchedEffect(Unit) {
        isRooted = RootBeer(ctx).isRooted
    }

    when (val rooted = isRooted) {
        null -> {
            Text("Loading...")
        }

        else -> {
            AssertionResult("Is rooted?",rooted,false
            )
        }
    }
}


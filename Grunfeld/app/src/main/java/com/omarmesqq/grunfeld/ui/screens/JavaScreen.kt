package com.omarmesqq.grunfeld.ui.screens

import android.Manifest
import android.annotation.SuppressLint
import android.content.ContentResolver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import android.provider.Settings.Global
import android.telephony.TelephonyManager
import android.text.format.Formatter
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
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import com.omarmesqq.grunfeld.MainApplication
import com.omarmesqq.grunfeld.ui.composables.AssertionResult
import com.omarmesqq.grunfeld.ui.composables.AssertionResultContains
import com.omarmesqq.grunfeld.ui.composables.AssertionResultEmpty
import com.omarmesqq.grunfeld.ui.composables.AssertionResultNotContains
import com.omarmesqq.grunfeld.ui.composables.AssertionResultNotEqualStrings
import com.omarmesqq.grunfeld.ui.composables.AssertionResultNull
import com.omarmesqq.grunfeld.ui.composables.AssertionResultSingleSpecificValueInIterable
import com.omarmesqq.grunfeld.ui.composables.AssertionResultSomeValuesInIterable
import com.omarmesqq.grunfeld.ui.composables.SectionHeader
import com.omarmesqq.grunfeld.utils.NativeLibWrapper
import com.omarmesqq.grunfeld.utils.getGsfId
import com.omarmesqq.grunfeld.utils.getMediaDrmId
import com.omarmesqq.grunfeld.utils.getNetworkInterfaces
import com.omarmesqq.grunfeld.utils.getSensorsInfo
import com.omarmesqq.grunfeld.utils.getSsaid
import com.omarmesqq.grunfeld.utils.getSystemProperty
import com.omarmesqq.grunfeld.utils.getWifiManagerInfo
import com.omarmesqq.grunfeld.utils.runtimeExecWithCmd
import com.omarmesqq.grunfeld.utils.runtimeExecWithCmdArray
import com.scottyab.rootbeer.RootBeer
import kotlinx.coroutines.flow.first
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.NetworkInterface


private const val FAKE_IP = "10.111.222.1"
private const val PLAY_STORE_PKG_NAME = "com.android.vending"

@Composable
fun JavaInfoScreen() {
    val context = LocalContext.current
    val screenScrollState = rememberScrollState()
    val cr = context.contentResolver

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

        SectionHeader("EXEC TESTS")
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            RuntimeAssertions()
        }

        SectionHeader("SENSORS TESTS (Java API and NDK)")
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            SensorsAssertions(context)
        }


        SectionHeader("NETWORK INTERFACES TESTS")
        NetworkIfacesAssertions()

        SectionHeader("LINK PROPERTIES AND WIFI MANAGER TESTS")
        LinkPropertiesAndWifiAssertions(context)

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

        SectionHeader("SELF-ANALYSIS TESTS")
        LogcatAssertions()

        SectionHeader("TELEPHONY TESTS")
        TelephonyAssertions(context)

        SectionHeader("ROOTBER ROOT CHECK")
        RootCheckAssertions(context)

        SectionHeader("DEVICE IDENTIFIERS")
        DeviceIdAssertions(context, cr)

        SectionHeader("SYSTEM PROPERTIES TESTS")
        SystemPropsAssertions()
    }
}

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

    @Suppress("DEPRECATION")
    AssertionResult("CPU_ABI", Build.CPU_ABI, "arm64-v8a")
    @Suppress("DEPRECATION")
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
    AssertionResultSingleSpecificValueInIterable("SUPPORTED_64_BIT_ABIS",abis64.toList(),"arm64-v8a")

    val abis = Build.SUPPORTED_ABIS
    AssertionResultSingleSpecificValueInIterable("SUPPORTED_ABIS", abis.toList(), "arm64-v8a")


    AssertionResult("BASE_OS", Build.VERSION.BASE_OS, "")
    AssertionResult("ODM_SKU", Build.ODM_SKU, Build.UNKNOWN)
    AssertionResult("SKU", Build.SKU, Build.UNKNOWN)
    AssertionResult("CODENAME", Build.VERSION.CODENAME, "REL")

    Build.getFingerprintedPartitions().forEachIndexed { idx, partition ->
        Text(
            text = "Partition $idx: ${partition.name}",
            color = Color.Magenta
        )
        AssertionResult("PARTITION FINGERPRINT", partition.fingerprint, "google/husky/husky:16/BP4A.251205.006/14401865:user/release-keys")
        AssertionResult("PARTITION BUILD TIME", partition.buildTimeMillis, "1764954000000")
    }
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
    AssertionResult("Runtime.exec('which', 'su')", runtimeExecWithCmdArray(arrayOf("which", "su")), "")
    AssertionResult("Runtime.exec('getprop')", runtimeExecWithCmd("getprop"), "null")
    AssertionResult("fork()/exec('uname')", NativeLibWrapper.testForkExec(""), "")
}

@Composable
private fun SensorsAssertions(ctx: Context) {
    AssertionResult("Sensors", getSensorsInfo(ctx), "")
}

@Composable
private fun NetworkIfacesAssertions() {
    var ifaceList by remember { mutableStateOf<List<NetworkInterface>?>(null) }
    LaunchedEffect(Unit) {
        ifaceList = getNetworkInterfaces()
    }

    when (val interfaceList = ifaceList) {
        null -> {
            Text("Loading...")
        }
        else -> {
            interfaceList
                .forEach { iface ->
                    AssertionResultNotContains("Interface name", iface.name, "tun")

                    if (iface.name.contains("wlan") || iface.name.contains("rmnet")) {
                        iface.interfaceAddresses.forEach { addr ->
                            AssertionResult("MTU", iface.mtu, "1500")

                            val localIp = addr.address.hostAddress ?: "NO_LOCAL_IP_THATS_ODD"
                            val prefix = addr.networkPrefixLength
                            val broadcast = addr.broadcast?.hostAddress

                            AssertionResult("Local IP", localIp, FAKE_IP)
                            AssertionResult("Prefix length (subnet mask)", prefix.toInt(), "24")

                            if (broadcast != null) {
                                AssertionResult("IPv4 broadcast", broadcast, "10.111.222.255")
                            }
                        }
                    }

                    val parent = iface.parent
                    val subs = iface.subInterfaces.asSequence().toList()

                    AssertionResultNull("Parent interface", parent)
                    AssertionResultEmpty("Sub interfaces", subs)
                }
        }
    }
}

@Suppress("DEPRECATION")
@Composable
private fun LinkPropertiesAndWifiAssertions(ctx: Context) {
    val cm = ctx.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
    val activeNetworkInfo = cm.activeNetworkInfo

    AssertionResultNotContains("Is active network VPN?", activeNetworkInfo?.typeName ?: "NO_TYPE_NAME_THATS_ODD", "VPN")
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

    val currentInterface = linkProperties.interfaceName
    if (currentInterface == null) {
        Text(
            text = "Couldn't get current interface name",
            color = Color.Red
        )
        return
    }
    AssertionResultNotContains("Interface name", currentInterface, "tun")

    val expectedRoutes = listOf(
        "10.111.222.0/24 -> 0.0.0.0 $currentInterface mtu 0",
        "0.0.0.0/0 -> $FAKE_IP $currentInterface mtu 0",
    )
    val actualRoutes = linkProperties.routes
    AssertionResult("Networking routes", actualRoutes.toString(), expectedRoutes.toString())

    val linkAddrs = linkProperties.linkAddresses.map {
        it.address.hostAddress
    }

    AssertionResultNull("DHCP Server", linkProperties.dhcpServerAddress)

    AssertionResultSingleSpecificValueInIterable("IP address", linkAddrs, FAKE_IP)
    AssertionResult("MTU", linkProperties.mtu, "1500")
    AssertionResult("Private DNS active?", linkProperties.isPrivateDnsActive, false)
    if (linkProperties.privateDnsServerName != null) {
        AssertionResult("Private DNS Server", linkProperties.privateDnsServerName!!, "")
    }

    val dnsServers = linkProperties.dnsServers.map {
        it.hostAddress
    }
    val expectedDnsServers = listOf("8.8.8.8", "8.8.4.4")
    AssertionResultSomeValuesInIterable("DNS Servers", dnsServers, expectedDnsServers)

    HorizontalDivider()

    val wifiInfo = try {
        getWifiManagerInfo(ctx)
    } catch (e: Exception) {
        Text(
            text = "dumpWifiManagerInfo failed: ${e.message}",
            color = Color.Red
        )
        return
    }

    AssertionResult("IPv4 address", Formatter.formatIpAddress(wifiInfo.ipAddress), FAKE_IP)

    if (wifiInfo.bssid != null) {
        AssertionResult("BSSID", wifiInfo.bssid, "02:00:00:00:00:00")
    }
    AssertionResultContains("SSID", wifiInfo.ssid, "<unknown ssid>")
}

@Composable
private fun AppInstallerAssertions(ctx: Context) {
    val pm = ctx.packageManager
    val packageName = ctx.packageName
    val info = pm.getInstallSourceInfo(packageName)

    val originator = info.originatingPackageName
    val initiator = info.initiatingPackageName ?: "NO_INITIATOR_THATS_ODD"
    val installer = info.installingPackageName ?: "NO_INSTALLER_THATS_ODD"

    AssertionResultNull("Originator (\"source\" of installation)", originator)
    AssertionResult("Initiator (called the installation)", initiator, PLAY_STORE_PKG_NAME)
    AssertionResult(
        "Installer (did the actual installation)",
        installer,
        PLAY_STORE_PKG_NAME
    )

    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
        val updateOwner = info.updateOwnerPackageName
        AssertionResult(
            "Update owner (pkg that will keep app up-to-date)",
            updateOwner ?: "NO_UPDATE_OWNER_THATS_ODD",
            PLAY_STORE_PKG_NAME
        )
    }

    @Suppress("DEPRECATION")
    val legacyInstaller = pm.getInstallerPackageName(packageName)

    AssertionResult(
        "Installer package name (Legacy API)",
        legacyInstaller ?: "",
        PLAY_STORE_PKG_NAME
    )
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
    val logcatExecd = Runtime.getRuntime().exec("logcat -d")
    val bufferedReader = BufferedReader(InputStreamReader(logcatExecd.inputStream))
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
private fun TelephonyAssertions(ctx: Context) {
    val tm  = ctx.getSystemService(Context.TELEPHONY_SERVICE) as TelephonyManager

    @SuppressLint("MissingPermission")
    if (hasPermission(ctx, Manifest.permission.ACCESS_FINE_LOCATION)) {
        AssertionResultEmpty("[MODERN] allCellInfo", tm.allCellInfo)
        @Suppress("DEPRECATION")
        AssertionResultNull("[LEGACY] cellLocation", tm.cellLocation)
    }

    AssertionResult("Has carrier privileges?", tm.hasCarrierPrivileges(), false)

    AssertionResult("SIM operator", tm.simOperator, "72406")
    AssertionResult("Network operator", tm.networkOperator, "72406")

    AssertionResult("Network operator name", tm.networkOperatorName, "Vivo")
    AssertionResult("SIM operator name", tm.simOperatorName, "Vivo")
    AssertionResult("SIM carrier ID name", tm.simCarrierIdName.toString(), "Vivo")

    AssertionResult("Network country ISO code", tm.networkCountryIso, "br")
    AssertionResult("SIM country ISO code", tm.simCountryIso, "br")

    AssertionResult("SIM carrier ID", tm.simCarrierId, "530")
    AssertionResult("Carrier ID from SIM MCC/MNC", tm.carrierIdFromSimMccMnc, "530")
    AssertionResult("SIM specific carrier ID", tm.simSpecificCarrierId, "530")
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
            AssertionResult(
                "Is rooted?", rooted, false
            )
        }
    }
}

@Composable
private fun DeviceIdAssertions(ctx: Context, cr: ContentResolver) {
    val context = LocalContext.current
    val app = ctx.applicationContext as MainApplication

    var isFirstAppLaunch by remember { mutableStateOf<Boolean?>(null) }

    LaunchedEffect(Unit) {
        isFirstAppLaunch = app.configRepository.isFirstLaunchFlow.first()
    }

    when (isFirstAppLaunch) {
        null -> {
            Text("Loading...")
        }
        true -> {
            Text(
                text = "First app launch: collected device IDs to check in next launch",
                color = Color.Yellow
            )
            LaunchedEffect(Unit) {
                val ssaid = getSsaid(cr)
                val gsfId = getGsfId(context)
                val drmId = getMediaDrmId()
                val drmIdFromNdk = NativeLibWrapper.getMediaDrmIdNative()

                app.configRepository.updateDeviceIds(ssaid, gsfId, drmId, drmIdFromNdk)
                app.configRepository.toggleFirstLaunch()
            }
        }
        else -> {
            var fetchedFromPrefs by remember { mutableStateOf(false) }
            var ssaidFromPref by remember { mutableStateOf<String?>(null) }
            var gsfIdFromPref by remember { mutableStateOf<String?>(null) }
            var drmIdFromPref by remember { mutableStateOf<String?>(null) }
            var drmIdNdkFromPref by remember { mutableStateOf<String?>(null) }

            LaunchedEffect(Unit) {
                ssaidFromPref = app.configRepository.ssaidFlow.first()
                gsfIdFromPref = app.configRepository.gsfIdFlow.first()
                drmIdFromPref = app.configRepository.drmIdFlow.first()
                drmIdNdkFromPref = app.configRepository.drmIdNdkFlow.first()
                fetchedFromPrefs = true
            }

            val currentSsaid = getSsaid(cr)
            val currentGsfId = getGsfId(context)
            val currentDrmId = getMediaDrmId()
            val currentDrmIdNdk = NativeLibWrapper.getMediaDrmIdNative()

            if (!fetchedFromPrefs) {
                Text("Fetching data from SharedPrefs...")
            } else {
                AssertionResultNotEqualStrings("SSAID", currentSsaid, ssaidFromPref!!)
                AssertionResultNotEqualStrings("GSF ID", currentGsfId, gsfIdFromPref!!)
                AssertionResultNotEqualStrings("DRM ID (Java API)", currentDrmId, drmIdFromPref!!)
                AssertionResultNotEqualStrings("DRM ID (NDK)", currentDrmIdNdk, drmIdNdkFromPref!!)
            }
        }
    }
}

@Composable
private fun SystemPropsAssertions() {
    val defaultValue = "<empty>"

    AssertionResult("ro.serialno", getSystemProperty("ro.serialno"), defaultValue)
    AssertionResult("ro.bootimage.build.fingerprint", getSystemProperty("ro.bootimage.build.fingerprint"), defaultValue)
    AssertionResult("ro.bootimage.build.type", getSystemProperty("ro.bootimage.build.type"), defaultValue)
    AssertionResult("ro.bootimage.build.tags", getSystemProperty("ro.bootimage.build.tags"), defaultValue)

    AssertionResult("ro.debuggable", getSystemProperty("ro.debuggable"), defaultValue)
    AssertionResult("ro.secure", getSystemProperty("ro.secure"), defaultValue)
    AssertionResult("ro.force.debuggable", getSystemProperty("ro.force.debuggable"), "0")

    AssertionResult("ro.product.board", getSystemProperty("ro.product.board"), "husky")
    AssertionResult("ro.product.brand", getSystemProperty("ro.product.brand"), "google")
    AssertionResult("ro.product.device", getSystemProperty("ro.product.device"), "husky")
    AssertionResult("ro.product.manufacturer", getSystemProperty("ro.product.manufacturer"), "google")
    AssertionResult("ro.product.model", getSystemProperty("ro.product.model"), "Pixel 8 Pro")
    AssertionResult("ro.product.name", getSystemProperty("ro.product.name"), "husky")

    // ro.product.odm.*
    AssertionResult("ro.product.odm.brand", getSystemProperty("ro.product.odm.brand"), "google")
    AssertionResult("ro.product.odm.device", getSystemProperty("ro.product.odm.device"), "husky")
    AssertionResult("ro.product.odm.manufacturer", getSystemProperty("ro.product.odm.manufacturer"), "google")
    AssertionResult("ro.product.odm.model", getSystemProperty("ro.product.odm.model"), "Pixel 8 Pro")
    AssertionResult("ro.product.odm.name", getSystemProperty("ro.product.odm.name"), "husky")

    // ro.product.product.*
    AssertionResult("ro.product.product.brand", getSystemProperty("ro.product.product.brand"), "google")
    AssertionResult("ro.product.product.device", getSystemProperty("ro.product.product.device"), "husky")
    AssertionResult("ro.product.product.manufacturer", getSystemProperty("ro.product.product.manufacturer"), "google")
    AssertionResult("ro.product.product.model", getSystemProperty("ro.product.product.model"), "Pixel 8 Pro")
    AssertionResult("ro.product.product.name", getSystemProperty("ro.product.product.name"), "husky")

    AssertionResult("ro.build.product", getSystemProperty("ro.build.product"), "husky")

    // ro.product.system.*
    AssertionResult("ro.product.system.brand", getSystemProperty("ro.product.system.brand"), "google")
    AssertionResult("ro.product.system.device", getSystemProperty("ro.product.system.device"), "husky")
    AssertionResult("ro.product.system.manufacturer", getSystemProperty("ro.product.system.manufacturer"), "google")
    AssertionResult("ro.product.system.model", getSystemProperty("ro.product.system.model"), "Pixel 8 Pro")
    AssertionResult("ro.product.system.name", getSystemProperty("ro.product.system.name"), "husky")

    // ro.product.system_ext.*
    AssertionResult("ro.product.system_ext.brand", getSystemProperty("ro.product.system_ext.brand"), "google")
    AssertionResult("ro.product.system_ext.device", getSystemProperty("ro.product.system_ext.device"), "husky")
    AssertionResult("ro.product.system_ext.manufacturer", getSystemProperty("ro.product.system_ext.manufacturer"), "google")
    AssertionResult("ro.product.system_ext.model", getSystemProperty("ro.product.system_ext.model"), "Pixel 8 Pro")
    AssertionResult("ro.product.system_ext.name", getSystemProperty("ro.product.system_ext.name"), "husky")

    // ro.product.vendor.*
    AssertionResult("ro.product.vendor.brand", getSystemProperty("ro.product.vendor.brand"), "google")
    AssertionResult("ro.product.vendor.device", getSystemProperty("ro.product.vendor.device"), "husky")
    AssertionResult("ro.product.vendor.manufacturer", getSystemProperty("ro.product.vendor.manufacturer"), "google")
    AssertionResult("ro.product.vendor.model", getSystemProperty("ro.product.vendor.model"), "Pixel 8 Pro")
    AssertionResult("ro.product.vendor.name", getSystemProperty("ro.product.vendor.name"), "husky")

    // ro.product.vendor_dlkm.*
    AssertionResult("ro.product.vendor_dlkm.brand", getSystemProperty("ro.product.vendor_dlkm.brand"), "google")
    AssertionResult("ro.product.vendor_dlkm.device", getSystemProperty("ro.product.vendor_dlkm.device"), "husky")
    AssertionResult("ro.product.vendor_dlkm.manufacturer", getSystemProperty("ro.product.vendor_dlkm.manufacturer"), "google")
    AssertionResult("ro.product.vendor_dlkm.model", getSystemProperty("ro.product.vendor_dlkm.model"), "Pixel 8 Pro")
    AssertionResult("ro.product.vendor_dlkm.name", getSystemProperty("ro.product.vendor_dlkm.name"), "husky")

    // Build host / id
    AssertionResult("ro.build.host", getSystemProperty("ro.build.host"), "abfarm-20038")
    AssertionResult("ro.build.id", getSystemProperty("ro.build.id"), "BP4A.251205.006")
    AssertionResult("ro.vendor.build.id", getSystemProperty("ro.vendor.build.id"), "BP4A.251205.006")
    AssertionResult("ro.product.build.id", getSystemProperty("ro.product.build.id"), "BP4A.251205.006")
    AssertionResult("ro.system.build.id", getSystemProperty("ro.system.build.id"), "BP4A.251205.006")
    AssertionResult("ro.vendor_dlkm.build.id", getSystemProperty("ro.vendor_dlkm.build.id"), "BP4A.251205.006")
    AssertionResult("ro.system_ext.build.id", getSystemProperty("ro.system_ext.build.id"), "BP4A.251205.006")
    AssertionResult("ro.build.display.id", getSystemProperty("ro.build.display.id"), "BP4A.251205.006")

    // Tags
    AssertionResult("ro.build.tags", getSystemProperty("ro.build.tags"), "release-keys")
    AssertionResult("ro.vendor.build.tags", getSystemProperty("ro.vendor.build.tags"), "release-keys")
    AssertionResult("ro.product.build.tags", getSystemProperty("ro.product.build.tags"), "release-keys")
    AssertionResult("ro.system.build.tags", getSystemProperty("ro.system.build.tags"), "release-keys")
    AssertionResult("ro.vendor_dlkm.build.tags", getSystemProperty("ro.vendor_dlkm.build.tags"), "release-keys")
    AssertionResult("ro.system_ext.build.tags", getSystemProperty("ro.system_ext.build.tags"), "release-keys")

    // Type
    AssertionResult("ro.build.type", getSystemProperty("ro.build.type"), "user")
    AssertionResult("ro.vendor.build.type", getSystemProperty("ro.vendor.build.type"), "user")
    AssertionResult("ro.product.build.type", getSystemProperty("ro.product.build.type"), "user")
    AssertionResult("ro.system.build.type", getSystemProperty("ro.system.build.type"), "user")
    AssertionResult("ro.vendor_dlkm.build.type", getSystemProperty("ro.vendor_dlkm.build.type"), "user")
    AssertionResult("ro.system_ext.build.type", getSystemProperty("ro.system_ext.build.type"), "user")
    AssertionResult("ro.build.user", getSystemProperty("ro.build.user"), "android-build")

    // Date UTC
    AssertionResult("ro.build.date.utc", getSystemProperty("ro.build.date.utc"), "1764954000")
    AssertionResult("ro.odm.build.date.utc", getSystemProperty("ro.odm.build.date.utc"), "1764954000")
    AssertionResult("ro.product.build.date.utc", getSystemProperty("ro.product.build.date.utc"), "1764954000")
    AssertionResult("ro.system.build.date.utc", getSystemProperty("ro.system.build.date.utc"), "1764954000")
    AssertionResult("ro.system_ext.build.date.utc", getSystemProperty("ro.system_ext.build.date.utc"), "1764954000")
    AssertionResult("ro.vendor_dlkm.build.date.utc", getSystemProperty("ro.vendor_dlkm.build.date.utc"), "1764954000")
    AssertionResult("ro.vendor.build.date.utc", getSystemProperty("ro.vendor.build.date.utc"), "1764954000")

    AssertionResult("ro.build.version.all_codenames", getSystemProperty("ro.build.version.all_codenames"), "REL")
    AssertionResult("ro.build.version.preview_sdk_fingerprint", getSystemProperty("ro.build.version.preview_sdk_fingerprint"), "REL")

    // Build date
    val buildDate = "Fri Dec 05 12:00:00 UTC 2025"
    AssertionResult("ro.build.date", getSystemProperty("ro.build.date"), buildDate)
    AssertionResult("ro.odm.build.date", getSystemProperty("ro.odm.build.date"), buildDate)
    AssertionResult("ro.product.build.date", getSystemProperty("ro.product.build.date"), buildDate)
    AssertionResult("ro.system.build.date", getSystemProperty("ro.system.build.date"), buildDate)
    AssertionResult("ro.system_ext.build.date", getSystemProperty("ro.system_ext.build.date"), buildDate)
    AssertionResult("ro.vendor.build.date", getSystemProperty("ro.vendor.build.date"), buildDate)
    AssertionResult("ro.vendor_dlkm.build.date", getSystemProperty("ro.vendor_dlkm.build.date"), buildDate)

    AssertionResult("ro.build.description", getSystemProperty("ro.build.description"), "husky-user 16 BP4A.251205.006 release-keys")
    AssertionResult("ro.build.flavor", getSystemProperty("ro.build.flavor"), "husky-user")

    // Version incremental
    AssertionResult("ro.build.version.incremental", getSystemProperty("ro.build.version.incremental"), "14401865")
    AssertionResult("ro.vendor.build.version.incremental", getSystemProperty("ro.vendor.build.version.incremental"), "14401865")
    AssertionResult("ro.odm.build.version.incremental", getSystemProperty("ro.odm.build.version.incremental"), "14401865")
    AssertionResult("ro.product.build.version.incremental", getSystemProperty("ro.product.build.version.incremental"), "14401865")
    AssertionResult("ro.system.build.version.incremental", getSystemProperty("ro.system.build.version.incremental"), "14401865")
    AssertionResult("ro.vendor_dlkm.build.version.incremental", getSystemProperty("ro.vendor_dlkm.build.version.incremental"), "14401865")
    AssertionResult("ro.system_ext.build.version.incremental", getSystemProperty("ro.system_ext.build.version.incremental"), "14401865")

    // Version release
    AssertionResult("ro.build.version.release", getSystemProperty("ro.build.version.release"), "16")
    AssertionResult("ro.product.build.version.release", getSystemProperty("ro.product.build.version.release"), "16")
    AssertionResult("ro.vendor_dlkm.build.version.release", getSystemProperty("ro.vendor_dlkm.build.version.release"), "16")
    AssertionResult("ro.vendor.build.version.release", getSystemProperty("ro.vendor.build.version.release"), "16")
    AssertionResult("ro.system_ext.build.version.release", getSystemProperty("ro.system_ext.build.version.release"), "16")
    AssertionResult("ro.system.build.version.release", getSystemProperty("ro.system.build.version.release"), "16")

    // release_or_codename
    AssertionResult("ro.build.version.release_or_codename", getSystemProperty("ro.build.version.release_or_codename"), "16")
    AssertionResult("ro.vendor.build.version.release_or_codename", getSystemProperty("ro.vendor.build.version.release_or_codename"), "16")
    AssertionResult("ro.product.build.version.release_or_codename", getSystemProperty("ro.product.build.version.release_or_codename"), "16")
    AssertionResult("ro.vendor_dlkm.build.version.release_or_codename", getSystemProperty("ro.vendor_dlkm.build.version.release_or_codename"), "16")
    AssertionResult("ro.system.build.version.release_or_codename", getSystemProperty("ro.system.build.version.release_or_codename"), "16")
    AssertionResult("ro.system_ext.build.version.release_or_codename", getSystemProperty("ro.system_ext.build.version.release_or_codename"), "16")

    AssertionResult("ro.build.version.release_or_preview_display", getSystemProperty("ro.build.version.release_or_preview_display"), "16")

    // SDK
    AssertionResult("ro.build.version.sdk", getSystemProperty("ro.build.version.sdk"), "36")
    AssertionResult("ro.product.build.version.sdk", getSystemProperty("ro.product.build.version.sdk"), "36")
    AssertionResult("ro.vendor.build.version.sdk", getSystemProperty("ro.vendor.build.version.sdk"), "36")
    AssertionResult("ro.vendor_dlkm.build.version.sdk", getSystemProperty("ro.vendor_dlkm.build.version.sdk"), "36")
    AssertionResult("ro.system_ext.build.version.sdk", getSystemProperty("ro.system_ext.build.version.sdk"), "36")
    AssertionResult("ro.system.build.version.sdk", getSystemProperty("ro.system.build.version.sdk"), "36")

    AssertionResult("ro.build.version.sdk_full", getSystemProperty("ro.build.version.sdk_full"), "36.1")
    AssertionResult("ro.product.build.version.sdk_full", getSystemProperty("ro.product.build.version.sdk_full"), "36.1")
    AssertionResult("ro.system_ext.build.version.sdk_full", getSystemProperty("ro.system_ext.build.version.sdk_full"), "36.1")
    AssertionResult("ro.system.build.version.sdk_full", getSystemProperty("ro.system.build.version.sdk_full"), "36.1")

    AssertionResult("ro.build.version.security_patch", getSystemProperty("ro.build.version.security_patch"), "2025-12-05")
    AssertionResult("ro.build.version.codename", getSystemProperty("ro.build.version.codename"), "REL")
    AssertionResult("ro.build.version.base_os", getSystemProperty("ro.build.version.base_os"), defaultValue)
    AssertionResult("ro.build.version.preview_sdk", getSystemProperty("ro.build.version.preview_sdk"), "0")

    // Fingerprint
    val fingerprint = "google/husky/husky:16/BP4A.251205.006/14401865:user/release-keys"
    AssertionResult("ro.build.fingerprint", getSystemProperty("ro.build.fingerprint"), fingerprint)
    AssertionResult("ro.odm.build.fingerprint", getSystemProperty("ro.odm.build.fingerprint"), fingerprint)
    AssertionResult("ro.product.build.fingerprint", getSystemProperty("ro.product.build.fingerprint"), fingerprint)
    AssertionResult("ro.system.build.fingerprint", getSystemProperty("ro.system.build.fingerprint"), fingerprint)
    AssertionResult("ro.system_ext.build.fingerprint", getSystemProperty("ro.system_ext.build.fingerprint"), fingerprint)
    AssertionResult("ro.vendor.build.fingerprint", getSystemProperty("ro.vendor.build.fingerprint"), fingerprint)
    AssertionResult("ro.vendor_dlkm.build.fingerprint", getSystemProperty("ro.vendor_dlkm.build.fingerprint"), fingerprint)

    // RADIO
    AssertionResult("gsm.version.baseband", getSystemProperty("gsm.version.baseband"), "g5300g-251108-251202-B-12876551")
    AssertionResult("gsm.version.ril-impl", getSystemProperty("gsm.version.ril-impl"), "com.google.android.telephony.modem")
    AssertionResult("ril.sw_ver", getSystemProperty("ril.sw_ver"), defaultValue)
    AssertionResult("ril.sw_ver2", getSystemProperty("ril.sw_ver2"), defaultValue)
    AssertionResult("ro.baseband", getSystemProperty("ro.baseband"), "g5300g-251108-251202-B-12876551")

    // Fingerprinting vectors
    AssertionResult("ro.config.alarm_alert", getSystemProperty("ro.config.alarm_alert"), "Hassium.ogg")
    AssertionResult("ro.config.notification_sound", getSystemProperty("ro.config.notification_sound"), "Argon.ogg")
    AssertionResult("ro.config.ringtone", getSystemProperty("ro.config.ringtone"), "Orion.ogg")
    AssertionResult("ro.product.locale", getSystemProperty("ro.product.locale"), "en-US")
    AssertionResult("persist.sys.locale", getSystemProperty("persist.sys.locale"), defaultValue)
    AssertionResult("bluetooth.device.default_name", getSystemProperty("bluetooth.device.default_name"), "Pixel 8 Pro")

    // User-set
    AssertionResult("debug.debuggerd.wait_for_debugger", getSystemProperty("debug.debuggerd.wait_for_debugger"), defaultValue)

    // General tuning
    AssertionResult("nfc.initialized", getSystemProperty("nfc.initialized"), "false")
    AssertionResult("ro.support_one_handed_mode", getSystemProperty("ro.support_one_handed_mode"), "false")

    // OEM/ROM specific
    AssertionResult("init.svc.vaultkeeper", getSystemProperty("init.svc.vaultkeeper"), defaultValue)
    AssertionResult("init.svc.vendor_flash_recovery", getSystemProperty("init.svc.vendor_flash_recovery"), defaultValue)
    AssertionResult("init.svc.lineage-bugreport", getSystemProperty("init.svc.lineage-bugreport"), defaultValue)
    AssertionResult("ro.board.api_frozen", getSystemProperty("ro.board.api_frozen"), defaultValue)

    // AOSP
    AssertionResult("init.svc.adb_root", getSystemProperty("init.svc.adb_root"), defaultValue)
    AssertionResult("service.adb.root", getSystemProperty("service.adb.root"), defaultValue)
    AssertionResult("persist.sys.usb.config", getSystemProperty("persist.sys.usb.config"), defaultValue)
    AssertionResult("sys.usb.config", getSystemProperty("sys.usb.config"), "mtp")
    AssertionResult("sys.usb.configfs", getSystemProperty("sys.usb.configfs"), "1")
    AssertionResult("init.svc.usbd", getSystemProperty("init.svc.usbd"), "stopped")
    AssertionResult("init.svc.adbd", getSystemProperty("init.svc.adbd"), "stopped")
    AssertionResult("sys.usb.controller", getSystemProperty("sys.usb.controller"), defaultValue)
    AssertionResult("ro.kernel.version", getSystemProperty("ro.kernel.version"), "6.6")

    // 64-bit only
    AssertionResult("ro.odm.product.cpu.abilist32", getSystemProperty("ro.odm.product.cpu.abilist32"), defaultValue)
    AssertionResult("ro.product.cpu.abilist32", getSystemProperty("ro.product.cpu.abilist32"), defaultValue)
    AssertionResult("ro.system.product.cpu.abilist32", getSystemProperty("ro.system.product.cpu.abilist32"), defaultValue)
    AssertionResult("ro.vendor.product.cpu.abilist32", getSystemProperty("ro.vendor.product.cpu.abilist32"), defaultValue)
    AssertionResult("ro.odm.product.cpu.abilist", getSystemProperty("ro.odm.product.cpu.abilist"), defaultValue)
    AssertionResult("ro.product.cpu.abilist", getSystemProperty("ro.product.cpu.abilist"), "arm64-v8a")
    AssertionResult("ro.system.product.cpu.abilist", getSystemProperty("ro.system.product.cpu.abilist"), "arm64-v8a")
    AssertionResult("ro.vendor.product.cpu.abilist", getSystemProperty("ro.vendor.product.cpu.abilist"), "arm64-v8a")
    AssertionResult("ro.zygote", getSystemProperty("ro.zygote"), "zygote64")
    AssertionResult("init.svc.zygote_secondary", getSystemProperty("init.svc.zygote_secondary"), defaultValue)

    // Hardware fingerprinting
    AssertionResult("ro.bootmode", getSystemProperty("ro.bootmode"), "normal")
    AssertionResult("bootreceiver.enable", getSystemProperty("bootreceiver.enable"), "1")

    val bootloader = "ripcurrent-15.0-12455211"
    AssertionResult("ro.bootloader", getSystemProperty("ro.bootloader"), bootloader)
    AssertionResult("ro.soc.manufacturer", getSystemProperty("ro.soc.manufacturer"), "Google")
    AssertionResult("ro.soc.model", getSystemProperty("ro.soc.model"), "Tensor G3")
    AssertionResult("ro.boot.boot_devices", getSystemProperty("ro.boot.boot_devices"), "soc/1d84000.ufshc")
    AssertionResult("ro.boot.bootloader", getSystemProperty("ro.boot.bootloader"), bootloader)
    AssertionResult("ro.boot.em.did", getSystemProperty("ro.boot.em.did"), defaultValue)
    AssertionResult("ro.boot.em.model", getSystemProperty("ro.boot.em.model"), bootloader)
    AssertionResult("ro.boot.hardware", getSystemProperty("ro.boot.hardware"), "zuma")
    AssertionResult("ro.boot.odin_download", getSystemProperty("ro.boot.odin_download"), defaultValue)
    AssertionResult("ro.boot.wb.snapQB", getSystemProperty("ro.boot.wb.snapQB"), defaultValue)
    AssertionResult("ro.com.google.clientidbase", getSystemProperty("ro.com.google.clientidbase"), "android-google")
    AssertionResult("ro.hardware", getSystemProperty("ro.hardware"), "zuma")
    AssertionResult("ro.boot.ap_serial", getSystemProperty("ro.boot.ap_serial"), defaultValue)
    AssertionResult("ro.boot.verifiedbootstate", getSystemProperty("ro.boot.verifiedbootstate"), "green")
    AssertionResult("ro.boot.warranty_bit", getSystemProperty("ro.boot.warranty_bit"), defaultValue)
    AssertionResult("ro.boot.force_upload", getSystemProperty("ro.boot.force_upload"), defaultValue)
    AssertionResult("sys.oem_unlock_allowed", getSystemProperty("sys.oem_unlock_allowed"), "0")
    AssertionResult("ro.boot.write_protect", getSystemProperty("ro.boot.write_protect"), "1")
    AssertionResult("ro.boot.veritymode.managed", getSystemProperty("ro.boot.veritymode.managed"), "yes")
    AssertionResult("ro.boot.veritymode", getSystemProperty("ro.boot.veritymode"), "enforcing")
    AssertionResult("ro.boot.vbmeta.hash_alg", getSystemProperty("ro.boot.vbmeta.hash_alg"), "sha256")
    AssertionResult("ro.boot.vbmeta.device_state", getSystemProperty("ro.boot.vbmeta.device_state"), "locked")
    AssertionResult("ro.boot.vbmeta.avb_version", getSystemProperty("ro.boot.vbmeta.avb_version"), "1.2")
    AssertionResult("ro.boot.secure_hardware", getSystemProperty("ro.boot.secure_hardware"), "1")
    AssertionResult("ro.boot.mode", getSystemProperty("ro.boot.mode"), "normal")
    AssertionResult("ro.boot.force_normal_boot", getSystemProperty("ro.boot.force_normal_boot"), "1")
    AssertionResult("ro.boot.flash.locked", getSystemProperty("ro.boot.flash.locked"), "1")
    AssertionResult("ro.boot.avb_version", getSystemProperty("ro.boot.avb_version"), "1.2")
    AssertionResult("ro.carrier", getSystemProperty("ro.carrier"), "retbr")
    AssertionResult("ro.boot.carrierid", getSystemProperty("ro.boot.carrierid"), defaultValue)

    // SIM / carrier
    AssertionResult("gsm.sim.state", getSystemProperty("gsm.sim.state"), "READY,")
    AssertionResult("gsm.sim.eventList", getSystemProperty("gsm.sim.eventList"), defaultValue)
    AssertionResult("ril.simoperator", getSystemProperty("ril.simoperator"), ",")
    AssertionResult("ril.cidManager.initiated", getSystemProperty("ril.cidManager.initiated"), "1")
    AssertionResult("ril.dds.call.ongoing0", getSystemProperty("ril.dds.call.ongoing0"), "0")
    AssertionResult("ril.dds.call.ongoing1", getSystemProperty("ril.dds.call.ongoing1"), "0")
    AssertionResult("ril.modem.board", getSystemProperty("ril.modem.board"), defaultValue)
    AssertionResult("ril.modem.board2", getSystemProperty("ril.modem.board2"), defaultValue)
    AssertionResult("ril.attach.apn0", getSystemProperty("ril.attach.apn0"), defaultValue)
    AssertionResult("ril.hw_ver", getSystemProperty("ril.hw_ver"), defaultValue)
    AssertionResult("ril.hw_ver2", getSystemProperty("ril.hw_ver2"), defaultValue)
    AssertionResult("ril.model_id", getSystemProperty("ril.model_id"), defaultValue)
    AssertionResult("ril.model_id2", getSystemProperty("ril.model_id2"), defaultValue)
    AssertionResult("ril.rfcal_date", getSystemProperty("ril.rfcal_date"), defaultValue)
    AssertionResult("ril.rfcal_date2", getSystemProperty("ril.rfcal_date2"), defaultValue)
    AssertionResult("ril.product_code", getSystemProperty("ril.product_code"), defaultValue)
    AssertionResult("ril.product_code2", getSystemProperty("ril.product_code2"), defaultValue)

    AssertionResult("gsm.operator.iso-country", getSystemProperty("gsm.operator.iso-country"), "br,")
    AssertionResult("gsm.sim.operator.iso-country", getSystemProperty("gsm.sim.operator.iso-country"), "br,")

    AssertionResult("gsm.sim.operator.numeric", getSystemProperty("gsm.sim.operator.numeric"), "72406,")
    AssertionResult("gsm.operator.numeric", getSystemProperty("gsm.operator.numeric"), "72406,")

    AssertionResult("gsm.sim.operator.alpha", getSystemProperty("gsm.sim.operator.alpha"), "Vivo,")
    AssertionResult("gsm.operator.alpha", getSystemProperty("gsm.operator.alpha"), "Vivo,")

    AssertionResult("debug.tracing.mnc", getSystemProperty("debug.tracing.mnc"), "6")

    AssertionResult("ro.sf.lcd_density", getSystemProperty("ro.sf.lcd_density"), "400")
    AssertionResult("ro.boot.selinux", getSystemProperty("ro.boot.selinux"), "enforcing")
    AssertionResult("ro.adb.secure", getSystemProperty("ro.adb.secure"), "1")
    AssertionResult("ro.allow.mock.location", getSystemProperty("ro.allow.mock.location"), "0")
    AssertionResult("persist.sys.strictmode.disable", getSystemProperty("persist.sys.strictmode.disable"), "true")
    AssertionResult("ro.control_privapp_permissions", getSystemProperty("ro.control_privapp_permissions"), "enforce")
    AssertionResult("ro.build.characteristics", getSystemProperty("ro.build.characteristics"), "default")
    AssertionResult("ro.surface_flinger.enable_frame_rate_override", getSystemProperty("ro.surface_flinger.enable_frame_rate_override"), "false")
    AssertionResult("ro.surface_flinger.game_default_frame_rate_override", getSystemProperty("ro.surface_flinger.game_default_frame_rate_override"), "60")
    AssertionResult("security.perf_harden", getSystemProperty("security.perf_harden"), "1")
    AssertionResult("ril.halservice.registered.slot1", getSystemProperty("ril.halservice.registered.slot1"), "true")
    AssertionResult("ril.halservice.registered.slot2", getSystemProperty("ril.halservice.registered.slot2"), "true")
    AssertionResult("ril.rejectedPlmn", getSystemProperty("ril.rejectedPlmn"), ",")
}

private fun hasPermission(context: Context, permission: String): Boolean {
    return ContextCompat.checkSelfPermission(
        context,
        permission
    ) == PackageManager.PERMISSION_GRANTED
}

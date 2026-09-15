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
import com.omarmesqq.grunfeld.MainApplication
import com.omarmesqq.grunfeld.ui.composables.AssertionResult
import com.omarmesqq.grunfeld.ui.composables.AssertionResultContains
import com.omarmesqq.grunfeld.ui.composables.AssertionResultEmpty
import com.omarmesqq.grunfeld.ui.composables.AssertionResultNotContains
import com.omarmesqq.grunfeld.ui.composables.AssertionResultNotEqualLongs
import com.omarmesqq.grunfeld.ui.composables.AssertionResultNotEqualStrings
import com.omarmesqq.grunfeld.ui.composables.AssertionResultNull
import com.omarmesqq.grunfeld.ui.composables.AssertionResultSingleSpecificValueInIterable
import com.omarmesqq.grunfeld.ui.composables.AssertionResultSomeValuesInIterable
import com.omarmesqq.grunfeld.ui.composables.CodeTitle
import com.omarmesqq.grunfeld.ui.composables.SectionHeader
import com.omarmesqq.grunfeld.utils.CoroutineMode
import com.omarmesqq.grunfeld.utils.NativeLibWrapper
import com.omarmesqq.grunfeld.utils.debugCoroutine
import com.omarmesqq.grunfeld.utils.getGsfId
import com.omarmesqq.grunfeld.utils.getMediaDrmId
import com.omarmesqq.grunfeld.utils.getNetworkInterfaces
import com.omarmesqq.grunfeld.utils.getSensorsInfo
import com.omarmesqq.grunfeld.utils.getSsaid
import com.omarmesqq.grunfeld.utils.getSystemProperty
import com.omarmesqq.grunfeld.utils.getWifiManagerInfo
import com.omarmesqq.grunfeld.utils.hasPermission
import com.omarmesqq.grunfeld.utils.openFileKt
import com.omarmesqq.grunfeld.utils.runtimeExecWithCmd
import com.omarmesqq.grunfeld.utils.runtimeExecWithCmdArray
import com.scottyab.rootbeer.RootBeer
import kotlinx.coroutines.CoroutineName
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withContext
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.NetworkInterface

private const val FAKE_IP = "10.111.222.1"
private const val PLAY_STORE_PKG_NAME = "com.android.vending"

@Composable
fun TestsScreen() {
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
        Text(text = "Java and native tests", style = MaterialTheme.typography.headlineMedium)

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

        SectionHeader("SENSORS TESTS (JAVA/NDK)")
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

        SectionHeader("STEALTH TESTS")
        StealthAssertions()

        SectionHeader("HOOKING DEPTH TESTS")
        HookingDepthAssertions()

        SectionHeader("LAN LEAK TEST")
        LanLeakAssertions()

        SectionHeader("FILESYSTEM TESTS")
        FilesystemAssertions()

        SectionHeader("SYSTEM PROPERTIES - REFLECTION TESTS")
        SystemPropsReflectionAssertions()
        SectionHeader("SYSTEM PROPERTIES - NDK TESTS")
        SystemPropsNativeAssertions()

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
        val start = System.currentTimeMillis()

        ifaceList = getNetworkInterfaces() // already does its own withContext(IO) internally

        debugCoroutine(CoroutineName("NetworkIfacesAssertionsCr"),
            CoroutineMode.LAUNCHED_EFFECT,
            System.currentTimeMillis() - start
        )
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

@Composable
private fun LinkPropertiesAndWifiAssertions(ctx: Context) {
    val cm = ctx.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager

    @Suppress("DEPRECATION")
    if (cm.activeNetworkInfo != null) {
        val activeNetworkInfo = cm.activeNetworkInfo
        AssertionResultNotContains("Is active network VPN?", activeNetworkInfo?.typeName ?: "NO_TYPE_NAME_THATS_ODD", "VPN")
        AssertionResult("All networks size", cm.allNetworks.size, "0")
        AssertionResultEmpty("All networks content", cm.allNetworks.toList())
    }

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

    @Suppress("DEPRECATION")
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

    AssertionResult("Package source should be PACKAGE_SOURCE_STORE (2)", info.packageSource, "2")
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
        legacyInstaller ?: "NO_LEGACY_INSTALLER_THATS_ODD",
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

    val logcatLines = mutableListOf<Any?>()
    repeat(5) {
        logcatLines.add(bufferedReader.readLine())
    }

    val expectedList = listOf(null)

    AssertionResultSomeValuesInIterable("Logcat (Runtime)", logcatLines, expectedList)

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
        val isRootedInCr = withContext(Dispatchers.IO + CoroutineName("RootCheckAssertionsCr")) {
            val start = System.currentTimeMillis()

            val rootRes = RootBeer(ctx).isRooted

            debugCoroutine(coroutineContext[CoroutineName],
                CoroutineMode.LAUNCHED_EFFECT,
                System.currentTimeMillis() - start
            )
            rootRes
        }
        isRooted = isRootedInCr


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
        withContext(Dispatchers.IO + CoroutineName("DeviceIdAssertionsCr/isFirstAppLaunch_fetch")) {
            val start = System.currentTimeMillis()

            isFirstAppLaunch = app.configRepository.isFirstLaunchFlow.first()

            debugCoroutine(coroutineContext[CoroutineName],
                CoroutineMode.LAUNCHED_EFFECT,
                System.currentTimeMillis() - start
            )
        }
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
                withContext(Dispatchers.IO + CoroutineName("DeviceIdAssertionsCr/isFirstAppLaunch_true")) {
                    val start = System.currentTimeMillis()

                    val ssaid = getSsaid(cr)
                    val gsfId = getGsfId(context)
                    val drmId = getMediaDrmId()
                    val drmIdFromNdk = NativeLibWrapper.getMediaDrmIdNative()

                    app.configRepository.updateDeviceIds(ssaid, gsfId, drmId, drmIdFromNdk)
                    app.configRepository.toggleFirstLaunch()

                    debugCoroutine(coroutineContext[CoroutineName],
                        CoroutineMode.LAUNCHED_EFFECT,
                        System.currentTimeMillis() - start
                    )
                }

            }
        }
        else -> {
            var fetchedFromPrefs by remember { mutableStateOf(false) }
            var ssaidFromPref by remember { mutableStateOf<String?>(null) }
            var gsfIdFromPref by remember { mutableStateOf<String?>(null) }
            var drmIdFromPref by remember { mutableStateOf<String?>(null) }
            var drmIdNdkFromPref by remember { mutableStateOf<String?>(null) }

            LaunchedEffect(Unit) {
                withContext(Dispatchers.IO + CoroutineName("DeviceIdAssertionsCr/isFirstAppLaunch_false")) {
                    val start = System.currentTimeMillis()

                    ssaidFromPref = app.configRepository.ssaidFlow.first()
                    gsfIdFromPref = app.configRepository.gsfIdFlow.first()
                    drmIdFromPref = app.configRepository.drmIdFlow.first()
                    drmIdNdkFromPref = app.configRepository.drmIdNdkFlow.first()
                    fetchedFromPrefs = true

                    debugCoroutine(coroutineContext[CoroutineName],
                        CoroutineMode.LAUNCHED_EFFECT,
                        System.currentTimeMillis() - start
                    )
                }

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
private fun StealthAssertions() {
    val defaultValue = ""

    val procSelfMaps = NativeLibWrapper.scanProcSelfMaps()
    val procSelfSmaps = NativeLibWrapper.scanProcSelfSmaps()
    val procSelfMountinfo = NativeLibWrapper.scanMountPoint("/proc/self/mountinfo")
    val procMounts = NativeLibWrapper.scanMountPoint("/proc/mounts")

    AssertionResult("/proc/self/maps", procSelfMaps, defaultValue)
    AssertionResult("/proc/self/smaps", procSelfSmaps, defaultValue)
    AssertionResult("/proc/self/mountinfo", procSelfMountinfo, defaultValue)
    AssertionResult("/proc/mounts", procMounts, defaultValue)

    val dlIteratePhdr = NativeLibWrapper.dlIteratePhdrTest()
    AssertionResult("dl_iterate_phdr", dlIteratePhdr, defaultValue)
}

@Composable
private fun HookingDepthAssertions() {
    val inlineAsm = NativeLibWrapper.unameInlineAsm()
    val rawSyscall =NativeLibWrapper.unameRawAsmSyscall()
    val syscallLibc = NativeLibWrapper.unameSyscallLibcWrapper()
    val bionicFn = NativeLibWrapper.unameBionic()

    val expectedRelease = "6.6.56-android16-11-g8a3e2b1c4d5f"

    AssertionResult("UNAME via inline assembly", inlineAsm, expectedRelease)
    AssertionResult("UNAME via raw syscall wrapper", rawSyscall, expectedRelease)
    AssertionResult("UNAME via 'syscall' bionic function", syscallLibc, expectedRelease)
    AssertionResult("UNAME via standard bionic function", bionicFn, expectedRelease)
}

@Composable
private fun LanLeakAssertions() {
    val socketIp = NativeLibWrapper.testGetsockname()
    AssertionResult("Socket IP via 'getsockname'", socketIp, "10.111.222.1")
}

@Composable
private fun FilesystemAssertions() {
    CodeTitle("statx()", Color.Magenta)
    val statxTest = NativeLibWrapper.testStatx()

    AssertionResult("'statx'", statxTest, "Function not implemented")
    CodeTitle("statfs()", Color.Magenta)

    val statfsToHosts = NativeLibWrapper.testStatfsToHosts()
    statfsToHosts
        .split("\n")
        .take(2) // /system/etc/hosts and /etc/hosts
        .forEach {
            AssertionResult("'statfs' to hosts file", it, "Function not implemented")
        }
    CodeTitle("faccessat()", Color.Magenta)

    val rootNodes = arrayOf(
       "/system/lib/libzygisk.so",
       "/system/lib64/libzygisk.so",

       "/product/bin/magisk",
       "/product/bin/magiskpolicy",
       "/product/bin/resetprop",
       "/product/bin/su",
       "/product/bin/supolicy",

       "/debug_ramdisk/.magisk",
       "/debug_ramdisk/magisk",
       "/debug_ramdisk/magisk32",

        "/debug_ramdisk/magiskinit",
        "/debug_ramdisk/magiskpolicy",
        "/debug_ramdisk/resetprop",
        "/debug_ramdisk/su",
        "/debug_ramdisk/supolicy",
    )

    val faccessatRootPoints = NativeLibWrapper.testFaccessat(rootNodes).split("\n")
    faccessatRootPoints
        .forEachIndexed { idx, f ->
            if (idx != faccessatRootPoints.lastIndex) {
                AssertionResultContains("faccessat", f, "No such file or directory")
            }
        }

    CodeTitle("fstat()", Color.Magenta)

    val hostsNodes1 = arrayOf(
        "/etc",
        "/etc/hosts",
    )

    val fstatEtc = NativeLibWrapper.testFstat(hostsNodes1[0])
    val fstatEtcHosts = NativeLibWrapper.testFstat(hostsNodes1[1])

    AssertionResult("/etc and /etc/hosts devices should match", fstatEtc.dev, fstatEtcHosts.dev)
    AssertionResultNotEqualLongs("/etc and /etc/hosts inodes shouldn't match", fstatEtc.ino, fstatEtcHosts.ino)

    AssertionResult("/etc/hosts size (in bytes)", fstatEtcHosts.size, 46)
    AssertionResult("/etc/hosts block size (in bytes)", fstatEtcHosts.blkSiz, 4096)
    AssertionResult("/etc/hosts allocated blocks", fstatEtcHosts.blksAllocated, 8)

    AssertionResult("/etc/hosts and /etc access time should match", fstatEtc.accessTime, fstatEtcHosts.accessTime)
    AssertionResult("/etc/hosts and /etc modification time should match", fstatEtc.modTime, fstatEtcHosts.modTime)
    AssertionResult("/etc/hosts and /etc status change time should match", fstatEtc.modTime, fstatEtcHosts.modTime)

    CodeTitle("newfstatat()", Color.Magenta)

    val hostsNodes2 = arrayOf(
        "/system/etc",
        "/system/etc/hosts",
    )

    val newfstatatSystemEtc = NativeLibWrapper.testNewfstatat(hostsNodes2[0])
    val newfstatatSystemEtcHosts = NativeLibWrapper.testNewfstatat(hostsNodes2[1])

    AssertionResult("/system/etc and /system/etc/hosts devices should match", newfstatatSystemEtc.dev, newfstatatSystemEtcHosts.dev)
    AssertionResultNotEqualLongs("/system/etc and /system/etc/hosts inodes shouldn't match", newfstatatSystemEtc.ino, newfstatatSystemEtcHosts.ino)

    AssertionResult("/system/etc/hosts size (in bytes)", newfstatatSystemEtcHosts.size, 46)
    AssertionResult("/system/etc/hosts block size (in bytes)", newfstatatSystemEtcHosts.blkSiz, 4096)
    AssertionResult("/system/etc/hosts allocated blocks", newfstatatSystemEtcHosts.blksAllocated, 8)

    AssertionResult("/system/etc/hosts and /system/etc access time should match", newfstatatSystemEtc.accessTime, newfstatatSystemEtcHosts.accessTime)
    AssertionResult("/system/etc/hosts and /system/etc modification time should match", newfstatatSystemEtc.modTime, newfstatatSystemEtcHosts.modTime)
    AssertionResult("/system/etc/hosts and /system/etc status change time should match", newfstatatSystemEtc.modTime, newfstatatSystemEtcHosts.modTime)

    Text(
        text = "Sensitive file read",
        color = Color.Magenta
    )

    val senstiveFiles = arrayOf(
        "/proc/self/mountstats",
        "/proc/sys/kernel/version",
        "/proc/sys/kernel/osrelease",
        "/proc/version",
        "/proc/asound/version"
    )
    senstiveFiles.forEach { file ->
        AssertionResultContains("open", openFileKt(file), "Permission denied")
    }
}

@Composable
private fun SystemPropsReflectionAssertions() {
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
//    AssertionResult("ro.build.version.release", getSystemProperty("ro.build.version.release"), "16")
//    AssertionResult("ro.product.build.version.release", getSystemProperty("ro.product.build.version.release"), "16")
//    AssertionResult("ro.vendor_dlkm.build.version.release", getSystemProperty("ro.vendor_dlkm.build.version.release"), "16")
//    AssertionResult("ro.vendor.build.version.release", getSystemProperty("ro.vendor.build.version.release"), "16")
//    AssertionResult("ro.system_ext.build.version.release", getSystemProperty("ro.system_ext.build.version.release"), "16")
//    AssertionResult("ro.system.build.version.release", getSystemProperty("ro.system.build.version.release"), "16")

    // release_or_codename
//    AssertionResult("ro.build.version.release_or_codename", getSystemProperty("ro.build.version.release_or_codename"), "16")
//    AssertionResult("ro.vendor.build.version.release_or_codename", getSystemProperty("ro.vendor.build.version.release_or_codename"), "16")
//    AssertionResult("ro.product.build.version.release_or_codename", getSystemProperty("ro.product.build.version.release_or_codename"), "16")
//    AssertionResult("ro.vendor_dlkm.build.version.release_or_codename", getSystemProperty("ro.vendor_dlkm.build.version.release_or_codename"), "16")
//    AssertionResult("ro.system.build.version.release_or_codename", getSystemProperty("ro.system.build.version.release_or_codename"), "16")
//    AssertionResult("ro.system_ext.build.version.release_or_codename", getSystemProperty("ro.system_ext.build.version.release_or_codename"), "16")

//    AssertionResult("ro.build.version.release_or_preview_display", getSystemProperty("ro.build.version.release_or_preview_display"), "16")

    // SDK
//    AssertionResult("ro.build.version.sdk", getSystemProperty("ro.build.version.sdk"), "36")
//    AssertionResult("ro.product.build.version.sdk", getSystemProperty("ro.product.build.version.sdk"), "36")
//    AssertionResult("ro.vendor.build.version.sdk", getSystemProperty("ro.vendor.build.version.sdk"), "36")
//    AssertionResult("ro.vendor_dlkm.build.version.sdk", getSystemProperty("ro.vendor_dlkm.build.version.sdk"), "36")
//    AssertionResult("ro.system_ext.build.version.sdk", getSystemProperty("ro.system_ext.build.version.sdk"), "36")
//    AssertionResult("ro.system.build.version.sdk", getSystemProperty("ro.system.build.version.sdk"), "36")
//
//    AssertionResult("ro.build.version.sdk_full", getSystemProperty("ro.build.version.sdk_full"), "36.1")
//    AssertionResult("ro.product.build.version.sdk_full", getSystemProperty("ro.product.build.version.sdk_full"), "36.1")
//    AssertionResult("ro.system_ext.build.version.sdk_full", getSystemProperty("ro.system_ext.build.version.sdk_full"), "36.1")
//    AssertionResult("ro.system.build.version.sdk_full", getSystemProperty("ro.system.build.version.sdk_full"), "36.1")

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
    AssertionResult("bluetooth.device.default_name", getSystemProperty("bluetooth.device.default_name"), "Pixel 8 Pro")

    // User-set
    AssertionResult("debug.debuggerd.wait_for_debugger", getSystemProperty("debug.debuggerd.wait_for_debugger"), defaultValue)

    // General tuning
    AssertionResult("nfc.initialized", getSystemProperty("nfc.initialized"), "false")
    AssertionResult("ro.support_one_handed_mode", getSystemProperty("ro.support_one_handed_mode"), "false")

    // OEM/ROM specific
    AssertionResult("init.svc.vaultkeeper", getSystemProperty("init.svc.vaultkeeper"), defaultValue)
    AssertionResult("init.svc.vendor_flash_recovery", getSystemProperty("init.svc.vendor_flash_recovery"), defaultValue)
    AssertionResult("ro.board.api_frozen", getSystemProperty("ro.board.api_frozen"), defaultValue)

    // AOSP
    AssertionResult("init.svc.adb_root", getSystemProperty("init.svc.adb_root"), defaultValue)
    AssertionResult("persist.sys.usb.config", getSystemProperty("persist.sys.usb.config"), "mtp")
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

    // AssertionResult("ro.sf.lcd_density", getSystemProperty("ro.sf.lcd_density"), "400")
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

@Composable
private fun SystemPropsNativeAssertions() {
    val defaultValue = "(empty)"
    val propInfoNull = "prop_info* is NULL"

    val buildDate = "Fri Dec 05 12:00:00 UTC 2025"
    val fingerprint = "google/husky/husky:16/BP4A.251205.006/14401865:user/release-keys"
    val bootloader = "ripcurrent-15.0-12455211"

    AssertionResult("ro.serialno", NativeLibWrapper.sysPropsGet("ro.serialno"), defaultValue)
    AssertionResult("ro.serialno", NativeLibWrapper.sysPropsReadWithNullName("ro.serialno"), propInfoNull)
    AssertionResult("ro.serialno", NativeLibWrapper.sysPropsRead("ro.serialno"), propInfoNull)
    AssertionResult("ro.serialno", NativeLibWrapper.sysPropsReadCb("ro.serialno"), propInfoNull)

    AssertionResult("ro.bootimage.build.fingerprint", NativeLibWrapper.sysPropsGet("ro.bootimage.build.fingerprint"), defaultValue)
    AssertionResult("ro.bootimage.build.fingerprint", NativeLibWrapper.sysPropsReadWithNullName("ro.bootimage.build.fingerprint"), propInfoNull)
    AssertionResult("ro.bootimage.build.fingerprint", NativeLibWrapper.sysPropsRead("ro.bootimage.build.fingerprint"), propInfoNull)
    AssertionResult("ro.bootimage.build.fingerprint", NativeLibWrapper.sysPropsReadCb("ro.bootimage.build.fingerprint"), propInfoNull)

    AssertionResult("ro.bootimage.build.type", NativeLibWrapper.sysPropsGet("ro.bootimage.build.type"), defaultValue)
    AssertionResult("ro.bootimage.build.type", NativeLibWrapper.sysPropsReadWithNullName("ro.bootimage.build.type"), propInfoNull)
    AssertionResult("ro.bootimage.build.type", NativeLibWrapper.sysPropsRead("ro.bootimage.build.type"), propInfoNull)
    AssertionResult("ro.bootimage.build.type", NativeLibWrapper.sysPropsReadCb("ro.bootimage.build.type"), propInfoNull)

    AssertionResult("ro.bootimage.build.tags", NativeLibWrapper.sysPropsGet("ro.bootimage.build.tags"), defaultValue)
    AssertionResult("ro.bootimage.build.tags", NativeLibWrapper.sysPropsReadWithNullName("ro.bootimage.build.tags"), propInfoNull)
    AssertionResult("ro.bootimage.build.tags", NativeLibWrapper.sysPropsRead("ro.bootimage.build.tags"), propInfoNull)
    AssertionResult("ro.bootimage.build.tags", NativeLibWrapper.sysPropsReadCb("ro.bootimage.build.tags"), propInfoNull)

    AssertionResult("ro.debuggable", NativeLibWrapper.sysPropsGet("ro.debuggable"), defaultValue)
    AssertionResult("ro.debuggable", NativeLibWrapper.sysPropsReadWithNullName("ro.debuggable"), propInfoNull)
    AssertionResult("ro.debuggable", NativeLibWrapper.sysPropsRead("ro.debuggable"), propInfoNull)
    AssertionResult("ro.debuggable", NativeLibWrapper.sysPropsReadCb("ro.debuggable"), propInfoNull)

    AssertionResult("ro.secure", NativeLibWrapper.sysPropsGet("ro.secure"), defaultValue)
    AssertionResult("ro.secure", NativeLibWrapper.sysPropsReadWithNullName("ro.secure"), propInfoNull)
    AssertionResult("ro.secure", NativeLibWrapper.sysPropsRead("ro.secure"), propInfoNull)
    AssertionResult("ro.secure", NativeLibWrapper.sysPropsReadCb("ro.secure"), propInfoNull)

    AssertionResult("ro.force.debuggable", NativeLibWrapper.sysPropsGet("ro.force.debuggable"), "0")
    AssertionResult("ro.force.debuggable", NativeLibWrapper.sysPropsReadWithNullName("ro.force.debuggable"), "0")
    AssertionResult("ro.force.debuggable", NativeLibWrapper.sysPropsRead("ro.force.debuggable"), "0")
    AssertionResult("ro.force.debuggable", NativeLibWrapper.sysPropsReadCb("ro.force.debuggable"), "0")

    AssertionResult("ro.product.board", NativeLibWrapper.sysPropsGet("ro.product.board"), "husky")
    AssertionResult("ro.product.board", NativeLibWrapper.sysPropsReadWithNullName("ro.product.board"), "husky")
    AssertionResult("ro.product.board", NativeLibWrapper.sysPropsRead("ro.product.board"), "husky")
    AssertionResult("ro.product.board", NativeLibWrapper.sysPropsReadCb("ro.product.board"), "husky")

    AssertionResult("ro.product.brand", NativeLibWrapper.sysPropsGet("ro.product.brand"), "google")
    AssertionResult("ro.product.brand", NativeLibWrapper.sysPropsReadWithNullName("ro.product.brand"), "google")
    AssertionResult("ro.product.brand", NativeLibWrapper.sysPropsRead("ro.product.brand"), "google")
    AssertionResult("ro.product.brand", NativeLibWrapper.sysPropsReadCb("ro.product.brand"), "google")

    AssertionResult("ro.product.device", NativeLibWrapper.sysPropsGet("ro.product.device"), "husky")
    AssertionResult("ro.product.device", NativeLibWrapper.sysPropsReadWithNullName("ro.product.device"), "husky")
    AssertionResult("ro.product.device", NativeLibWrapper.sysPropsRead("ro.product.device"), "husky")
    AssertionResult("ro.product.device", NativeLibWrapper.sysPropsReadCb("ro.product.device"), "husky")

    AssertionResult("ro.product.manufacturer", NativeLibWrapper.sysPropsGet("ro.product.manufacturer"), "google")
    AssertionResult("ro.product.manufacturer", NativeLibWrapper.sysPropsReadWithNullName("ro.product.manufacturer"), "google")
    AssertionResult("ro.product.manufacturer", NativeLibWrapper.sysPropsRead("ro.product.manufacturer"), "google")
    AssertionResult("ro.product.manufacturer", NativeLibWrapper.sysPropsReadCb("ro.product.manufacturer"), "google")

    AssertionResult("ro.product.model", NativeLibWrapper.sysPropsGet("ro.product.model"), "Pixel 8 Pro")
    AssertionResult("ro.product.model", NativeLibWrapper.sysPropsReadWithNullName("ro.product.model"), "Pixel 8 Pro")
    AssertionResult("ro.product.model", NativeLibWrapper.sysPropsRead("ro.product.model"), "Pixel 8 Pro")
    AssertionResult("ro.product.model", NativeLibWrapper.sysPropsReadCb("ro.product.model"), "Pixel 8 Pro")

    AssertionResult("ro.product.name", NativeLibWrapper.sysPropsGet("ro.product.name"), "husky")
    AssertionResult("ro.product.name", NativeLibWrapper.sysPropsReadWithNullName("ro.product.name"), "husky")
    AssertionResult("ro.product.name", NativeLibWrapper.sysPropsRead("ro.product.name"), "husky")
    AssertionResult("ro.product.name", NativeLibWrapper.sysPropsReadCb("ro.product.name"), "husky")

    AssertionResult("ro.product.odm.brand", NativeLibWrapper.sysPropsGet("ro.product.odm.brand"), "google")
    AssertionResult("ro.product.odm.brand", NativeLibWrapper.sysPropsReadWithNullName("ro.product.odm.brand"), "google")
    AssertionResult("ro.product.odm.brand", NativeLibWrapper.sysPropsRead("ro.product.odm.brand"), "google")
    AssertionResult("ro.product.odm.brand", NativeLibWrapper.sysPropsReadCb("ro.product.odm.brand"), "google")

    AssertionResult("ro.product.odm.device", NativeLibWrapper.sysPropsGet("ro.product.odm.device"), "husky")
    AssertionResult("ro.product.odm.device", NativeLibWrapper.sysPropsReadWithNullName("ro.product.odm.device"), "husky")
    AssertionResult("ro.product.odm.device", NativeLibWrapper.sysPropsRead("ro.product.odm.device"), "husky")
    AssertionResult("ro.product.odm.device", NativeLibWrapper.sysPropsReadCb("ro.product.odm.device"), "husky")

    AssertionResult("ro.product.odm.manufacturer", NativeLibWrapper.sysPropsGet("ro.product.odm.manufacturer"), "google")
    AssertionResult("ro.product.odm.manufacturer", NativeLibWrapper.sysPropsReadWithNullName("ro.product.odm.manufacturer"), "google")
    AssertionResult("ro.product.odm.manufacturer", NativeLibWrapper.sysPropsRead("ro.product.odm.manufacturer"), "google")
    AssertionResult("ro.product.odm.manufacturer", NativeLibWrapper.sysPropsReadCb("ro.product.odm.manufacturer"), "google")

    AssertionResult("ro.product.odm.model", NativeLibWrapper.sysPropsGet("ro.product.odm.model"), "Pixel 8 Pro")
    AssertionResult("ro.product.odm.model", NativeLibWrapper.sysPropsReadWithNullName("ro.product.odm.model"), "Pixel 8 Pro")
    AssertionResult("ro.product.odm.model", NativeLibWrapper.sysPropsRead("ro.product.odm.model"), "Pixel 8 Pro")
    AssertionResult("ro.product.odm.model", NativeLibWrapper.sysPropsReadCb("ro.product.odm.model"), "Pixel 8 Pro")

    AssertionResult("ro.product.odm.name", NativeLibWrapper.sysPropsGet("ro.product.odm.name"), "husky")
    AssertionResult("ro.product.odm.name", NativeLibWrapper.sysPropsReadWithNullName("ro.product.odm.name"), "husky")
    AssertionResult("ro.product.odm.name", NativeLibWrapper.sysPropsRead("ro.product.odm.name"), "husky")
    AssertionResult("ro.product.odm.name", NativeLibWrapper.sysPropsReadCb("ro.product.odm.name"), "husky")

    AssertionResult("ro.product.product.brand", NativeLibWrapper.sysPropsGet("ro.product.product.brand"), "google")
    AssertionResult("ro.product.product.brand", NativeLibWrapper.sysPropsReadWithNullName("ro.product.product.brand"), "google")
    AssertionResult("ro.product.product.brand", NativeLibWrapper.sysPropsRead("ro.product.product.brand"), "google")
    AssertionResult("ro.product.product.brand", NativeLibWrapper.sysPropsReadCb("ro.product.product.brand"), "google")

    AssertionResult("ro.product.product.device", NativeLibWrapper.sysPropsGet("ro.product.product.device"), "husky")
    AssertionResult("ro.product.product.device", NativeLibWrapper.sysPropsReadWithNullName("ro.product.product.device"), "husky")
    AssertionResult("ro.product.product.device", NativeLibWrapper.sysPropsRead("ro.product.product.device"), "husky")
    AssertionResult("ro.product.product.device", NativeLibWrapper.sysPropsReadCb("ro.product.product.device"), "husky")

    AssertionResult("ro.product.product.manufacturer", NativeLibWrapper.sysPropsGet("ro.product.product.manufacturer"), "google")
    AssertionResult("ro.product.product.manufacturer", NativeLibWrapper.sysPropsReadWithNullName("ro.product.product.manufacturer"), "google")
    AssertionResult("ro.product.product.manufacturer", NativeLibWrapper.sysPropsRead("ro.product.product.manufacturer"), "google")
    AssertionResult("ro.product.product.manufacturer", NativeLibWrapper.sysPropsReadCb("ro.product.product.manufacturer"), "google")

    AssertionResult("ro.product.product.model", NativeLibWrapper.sysPropsGet("ro.product.product.model"), "Pixel 8 Pro")
    AssertionResult("ro.product.product.model", NativeLibWrapper.sysPropsReadWithNullName("ro.product.product.model"), "Pixel 8 Pro")
    AssertionResult("ro.product.product.model", NativeLibWrapper.sysPropsRead("ro.product.product.model"), "Pixel 8 Pro")
    AssertionResult("ro.product.product.model", NativeLibWrapper.sysPropsReadCb("ro.product.product.model"), "Pixel 8 Pro")

    AssertionResult("ro.product.product.name", NativeLibWrapper.sysPropsGet("ro.product.product.name"), "husky")
    AssertionResult("ro.product.product.name", NativeLibWrapper.sysPropsReadWithNullName("ro.product.product.name"), "husky")
    AssertionResult("ro.product.product.name", NativeLibWrapper.sysPropsRead("ro.product.product.name"), "husky")
    AssertionResult("ro.product.product.name", NativeLibWrapper.sysPropsReadCb("ro.product.product.name"), "husky")

    AssertionResult("ro.build.product", NativeLibWrapper.sysPropsGet("ro.build.product"), "husky")
    AssertionResult("ro.build.product", NativeLibWrapper.sysPropsReadWithNullName("ro.build.product"), "husky")
    AssertionResult("ro.build.product", NativeLibWrapper.sysPropsRead("ro.build.product"), "husky")
    AssertionResult("ro.build.product", NativeLibWrapper.sysPropsReadCb("ro.build.product"), "husky")

    AssertionResult("ro.product.system.brand", NativeLibWrapper.sysPropsGet("ro.product.system.brand"), "google")
    AssertionResult("ro.product.system.brand", NativeLibWrapper.sysPropsReadWithNullName("ro.product.system.brand"), "google")
    AssertionResult("ro.product.system.brand", NativeLibWrapper.sysPropsRead("ro.product.system.brand"), "google")
    AssertionResult("ro.product.system.brand", NativeLibWrapper.sysPropsReadCb("ro.product.system.brand"), "google")

    AssertionResult("ro.product.system.device", NativeLibWrapper.sysPropsGet("ro.product.system.device"), "husky")
    AssertionResult("ro.product.system.device", NativeLibWrapper.sysPropsReadWithNullName("ro.product.system.device"), "husky")
    AssertionResult("ro.product.system.device", NativeLibWrapper.sysPropsRead("ro.product.system.device"), "husky")
    AssertionResult("ro.product.system.device", NativeLibWrapper.sysPropsReadCb("ro.product.system.device"), "husky")

    AssertionResult("ro.product.system.manufacturer", NativeLibWrapper.sysPropsGet("ro.product.system.manufacturer"), "google")
    AssertionResult("ro.product.system.manufacturer", NativeLibWrapper.sysPropsReadWithNullName("ro.product.system.manufacturer"), "google")
    AssertionResult("ro.product.system.manufacturer", NativeLibWrapper.sysPropsRead("ro.product.system.manufacturer"), "google")
    AssertionResult("ro.product.system.manufacturer", NativeLibWrapper.sysPropsReadCb("ro.product.system.manufacturer"), "google")

    AssertionResult("ro.product.system.model", NativeLibWrapper.sysPropsGet("ro.product.system.model"), "Pixel 8 Pro")
    AssertionResult("ro.product.system.model", NativeLibWrapper.sysPropsReadWithNullName("ro.product.system.model"), "Pixel 8 Pro")
    AssertionResult("ro.product.system.model", NativeLibWrapper.sysPropsRead("ro.product.system.model"), "Pixel 8 Pro")
    AssertionResult("ro.product.system.model", NativeLibWrapper.sysPropsReadCb("ro.product.system.model"), "Pixel 8 Pro")

    AssertionResult("ro.product.system.name", NativeLibWrapper.sysPropsGet("ro.product.system.name"), "husky")
    AssertionResult("ro.product.system.name", NativeLibWrapper.sysPropsReadWithNullName("ro.product.system.name"), "husky")
    AssertionResult("ro.product.system.name", NativeLibWrapper.sysPropsRead("ro.product.system.name"), "husky")
    AssertionResult("ro.product.system.name", NativeLibWrapper.sysPropsReadCb("ro.product.system.name"), "husky")

    AssertionResult("ro.product.system_ext.brand", NativeLibWrapper.sysPropsGet("ro.product.system_ext.brand"), "google")
    AssertionResult("ro.product.system_ext.brand", NativeLibWrapper.sysPropsReadWithNullName("ro.product.system_ext.brand"), "google")
    AssertionResult("ro.product.system_ext.brand", NativeLibWrapper.sysPropsRead("ro.product.system_ext.brand"), "google")
    AssertionResult("ro.product.system_ext.brand", NativeLibWrapper.sysPropsReadCb("ro.product.system_ext.brand"), "google")

    AssertionResult("ro.product.system_ext.device", NativeLibWrapper.sysPropsGet("ro.product.system_ext.device"), "husky")
    AssertionResult("ro.product.system_ext.device", NativeLibWrapper.sysPropsReadWithNullName("ro.product.system_ext.device"), "husky")
    AssertionResult("ro.product.system_ext.device", NativeLibWrapper.sysPropsRead("ro.product.system_ext.device"), "husky")
    AssertionResult("ro.product.system_ext.device", NativeLibWrapper.sysPropsReadCb("ro.product.system_ext.device"), "husky")

    AssertionResult("ro.product.system_ext.manufacturer", NativeLibWrapper.sysPropsGet("ro.product.system_ext.manufacturer"), "google")
    AssertionResult("ro.product.system_ext.manufacturer", NativeLibWrapper.sysPropsReadWithNullName("ro.product.system_ext.manufacturer"), "google")
    AssertionResult("ro.product.system_ext.manufacturer", NativeLibWrapper.sysPropsRead("ro.product.system_ext.manufacturer"), "google")
    AssertionResult("ro.product.system_ext.manufacturer", NativeLibWrapper.sysPropsReadCb("ro.product.system_ext.manufacturer"), "google")

    AssertionResult("ro.product.system_ext.model", NativeLibWrapper.sysPropsGet("ro.product.system_ext.model"), "Pixel 8 Pro")
    AssertionResult("ro.product.system_ext.model", NativeLibWrapper.sysPropsReadWithNullName("ro.product.system_ext.model"), "Pixel 8 Pro")
    AssertionResult("ro.product.system_ext.model", NativeLibWrapper.sysPropsRead("ro.product.system_ext.model"), "Pixel 8 Pro")
    AssertionResult("ro.product.system_ext.model", NativeLibWrapper.sysPropsReadCb("ro.product.system_ext.model"), "Pixel 8 Pro")

    AssertionResult("ro.product.system_ext.name", NativeLibWrapper.sysPropsGet("ro.product.system_ext.name"), "husky")
    AssertionResult("ro.product.system_ext.name", NativeLibWrapper.sysPropsReadWithNullName("ro.product.system_ext.name"), "husky")
    AssertionResult("ro.product.system_ext.name", NativeLibWrapper.sysPropsRead("ro.product.system_ext.name"), "husky")
    AssertionResult("ro.product.system_ext.name", NativeLibWrapper.sysPropsReadCb("ro.product.system_ext.name"), "husky")

    AssertionResult("ro.product.vendor.brand", NativeLibWrapper.sysPropsGet("ro.product.vendor.brand"), "google")
    AssertionResult("ro.product.vendor.brand", NativeLibWrapper.sysPropsReadWithNullName("ro.product.vendor.brand"), "google")
    AssertionResult("ro.product.vendor.brand", NativeLibWrapper.sysPropsRead("ro.product.vendor.brand"), "google")
    AssertionResult("ro.product.vendor.brand", NativeLibWrapper.sysPropsReadCb("ro.product.vendor.brand"), "google")

    AssertionResult("ro.product.vendor.device", NativeLibWrapper.sysPropsGet("ro.product.vendor.device"), "husky")
    AssertionResult("ro.product.vendor.device", NativeLibWrapper.sysPropsReadWithNullName("ro.product.vendor.device"), "husky")
    AssertionResult("ro.product.vendor.device", NativeLibWrapper.sysPropsRead("ro.product.vendor.device"), "husky")
    AssertionResult("ro.product.vendor.device", NativeLibWrapper.sysPropsReadCb("ro.product.vendor.device"), "husky")

    AssertionResult("ro.product.vendor.manufacturer", NativeLibWrapper.sysPropsGet("ro.product.vendor.manufacturer"), "google")
    AssertionResult("ro.product.vendor.manufacturer", NativeLibWrapper.sysPropsReadWithNullName("ro.product.vendor.manufacturer"), "google")
    AssertionResult("ro.product.vendor.manufacturer", NativeLibWrapper.sysPropsRead("ro.product.vendor.manufacturer"), "google")
    AssertionResult("ro.product.vendor.manufacturer", NativeLibWrapper.sysPropsReadCb("ro.product.vendor.manufacturer"), "google")

    AssertionResult("ro.product.vendor.model", NativeLibWrapper.sysPropsGet("ro.product.vendor.model"), "Pixel 8 Pro")
    AssertionResult("ro.product.vendor.model", NativeLibWrapper.sysPropsReadWithNullName("ro.product.vendor.model"), "Pixel 8 Pro")
    AssertionResult("ro.product.vendor.model", NativeLibWrapper.sysPropsRead("ro.product.vendor.model"), "Pixel 8 Pro")
    AssertionResult("ro.product.vendor.model", NativeLibWrapper.sysPropsReadCb("ro.product.vendor.model"), "Pixel 8 Pro")

    AssertionResult("ro.product.vendor.name", NativeLibWrapper.sysPropsGet("ro.product.vendor.name"), "husky")
    AssertionResult("ro.product.vendor.name", NativeLibWrapper.sysPropsReadWithNullName("ro.product.vendor.name"), "husky")
    AssertionResult("ro.product.vendor.name", NativeLibWrapper.sysPropsRead("ro.product.vendor.name"), "husky")
    AssertionResult("ro.product.vendor.name", NativeLibWrapper.sysPropsReadCb("ro.product.vendor.name"), "husky")

    AssertionResult("ro.product.vendor_dlkm.brand", NativeLibWrapper.sysPropsGet("ro.product.vendor_dlkm.brand"), "google")
    AssertionResult("ro.product.vendor_dlkm.brand", NativeLibWrapper.sysPropsReadWithNullName("ro.product.vendor_dlkm.brand"), "google")
    AssertionResult("ro.product.vendor_dlkm.brand", NativeLibWrapper.sysPropsRead("ro.product.vendor_dlkm.brand"), "google")
    AssertionResult("ro.product.vendor_dlkm.brand", NativeLibWrapper.sysPropsReadCb("ro.product.vendor_dlkm.brand"), "google")

    AssertionResult("ro.product.vendor_dlkm.device", NativeLibWrapper.sysPropsGet("ro.product.vendor_dlkm.device"), "husky")
    AssertionResult("ro.product.vendor_dlkm.device", NativeLibWrapper.sysPropsReadWithNullName("ro.product.vendor_dlkm.device"), "husky")
    AssertionResult("ro.product.vendor_dlkm.device", NativeLibWrapper.sysPropsRead("ro.product.vendor_dlkm.device"), "husky")
    AssertionResult("ro.product.vendor_dlkm.device", NativeLibWrapper.sysPropsReadCb("ro.product.vendor_dlkm.device"), "husky")

    AssertionResult("ro.product.vendor_dlkm.manufacturer", NativeLibWrapper.sysPropsGet("ro.product.vendor_dlkm.manufacturer"), "google")
    AssertionResult("ro.product.vendor_dlkm.manufacturer", NativeLibWrapper.sysPropsReadWithNullName("ro.product.vendor_dlkm.manufacturer"), "google")
    AssertionResult("ro.product.vendor_dlkm.manufacturer", NativeLibWrapper.sysPropsRead("ro.product.vendor_dlkm.manufacturer"), "google")
    AssertionResult("ro.product.vendor_dlkm.manufacturer", NativeLibWrapper.sysPropsReadCb("ro.product.vendor_dlkm.manufacturer"), "google")

    AssertionResult("ro.product.vendor_dlkm.model", NativeLibWrapper.sysPropsGet("ro.product.vendor_dlkm.model"), "Pixel 8 Pro")
    AssertionResult("ro.product.vendor_dlkm.model", NativeLibWrapper.sysPropsReadWithNullName("ro.product.vendor_dlkm.model"), "Pixel 8 Pro")
    AssertionResult("ro.product.vendor_dlkm.model", NativeLibWrapper.sysPropsRead("ro.product.vendor_dlkm.model"), "Pixel 8 Pro")
    AssertionResult("ro.product.vendor_dlkm.model", NativeLibWrapper.sysPropsReadCb("ro.product.vendor_dlkm.model"), "Pixel 8 Pro")

    AssertionResult("ro.product.vendor_dlkm.name", NativeLibWrapper.sysPropsGet("ro.product.vendor_dlkm.name"), "husky")
    AssertionResult("ro.product.vendor_dlkm.name", NativeLibWrapper.sysPropsReadWithNullName("ro.product.vendor_dlkm.name"), "husky")
    AssertionResult("ro.product.vendor_dlkm.name", NativeLibWrapper.sysPropsRead("ro.product.vendor_dlkm.name"), "husky")
    AssertionResult("ro.product.vendor_dlkm.name", NativeLibWrapper.sysPropsReadCb("ro.product.vendor_dlkm.name"), "husky")

    AssertionResult("ro.build.host", NativeLibWrapper.sysPropsGet("ro.build.host"), "abfarm-20038")
    AssertionResult("ro.build.host", NativeLibWrapper.sysPropsReadWithNullName("ro.build.host"), "abfarm-20038")
    AssertionResult("ro.build.host", NativeLibWrapper.sysPropsRead("ro.build.host"), "abfarm-20038")
    AssertionResult("ro.build.host", NativeLibWrapper.sysPropsReadCb("ro.build.host"), "abfarm-20038")

    AssertionResult("ro.build.id", NativeLibWrapper.sysPropsGet("ro.build.id"), "BP4A.251205.006")
    AssertionResult("ro.build.id", NativeLibWrapper.sysPropsReadWithNullName("ro.build.id"), "BP4A.251205.006")
    AssertionResult("ro.build.id", NativeLibWrapper.sysPropsRead("ro.build.id"), "BP4A.251205.006")
    AssertionResult("ro.build.id", NativeLibWrapper.sysPropsReadCb("ro.build.id"), "BP4A.251205.006")

    AssertionResult("ro.vendor.build.id", NativeLibWrapper.sysPropsGet("ro.vendor.build.id"), "BP4A.251205.006")
    AssertionResult("ro.vendor.build.id", NativeLibWrapper.sysPropsReadWithNullName("ro.vendor.build.id"), "BP4A.251205.006")
    AssertionResult("ro.vendor.build.id", NativeLibWrapper.sysPropsRead("ro.vendor.build.id"), "BP4A.251205.006")
    AssertionResult("ro.vendor.build.id", NativeLibWrapper.sysPropsReadCb("ro.vendor.build.id"), "BP4A.251205.006")

    AssertionResult("ro.product.build.id", NativeLibWrapper.sysPropsGet("ro.product.build.id"), "BP4A.251205.006")
    AssertionResult("ro.product.build.id", NativeLibWrapper.sysPropsReadWithNullName("ro.product.build.id"), "BP4A.251205.006")
    AssertionResult("ro.product.build.id", NativeLibWrapper.sysPropsRead("ro.product.build.id"), "BP4A.251205.006")
    AssertionResult("ro.product.build.id", NativeLibWrapper.sysPropsReadCb("ro.product.build.id"), "BP4A.251205.006")

    AssertionResult("ro.system.build.id", NativeLibWrapper.sysPropsGet("ro.system.build.id"), "BP4A.251205.006")
    AssertionResult("ro.system.build.id", NativeLibWrapper.sysPropsReadWithNullName("ro.system.build.id"), "BP4A.251205.006")
    AssertionResult("ro.system.build.id", NativeLibWrapper.sysPropsRead("ro.system.build.id"), "BP4A.251205.006")
    AssertionResult("ro.system.build.id", NativeLibWrapper.sysPropsReadCb("ro.system.build.id"), "BP4A.251205.006")

    AssertionResult("ro.vendor_dlkm.build.id", NativeLibWrapper.sysPropsGet("ro.vendor_dlkm.build.id"), "BP4A.251205.006")
    AssertionResult("ro.vendor_dlkm.build.id", NativeLibWrapper.sysPropsReadWithNullName("ro.vendor_dlkm.build.id"), "BP4A.251205.006")
    AssertionResult("ro.vendor_dlkm.build.id", NativeLibWrapper.sysPropsRead("ro.vendor_dlkm.build.id"), "BP4A.251205.006")
    AssertionResult("ro.vendor_dlkm.build.id", NativeLibWrapper.sysPropsReadCb("ro.vendor_dlkm.build.id"), "BP4A.251205.006")

    AssertionResult("ro.system_ext.build.id", NativeLibWrapper.sysPropsGet("ro.system_ext.build.id"), "BP4A.251205.006")
    AssertionResult("ro.system_ext.build.id", NativeLibWrapper.sysPropsReadWithNullName("ro.system_ext.build.id"), "BP4A.251205.006")
    AssertionResult("ro.system_ext.build.id", NativeLibWrapper.sysPropsRead("ro.system_ext.build.id"), "BP4A.251205.006")
    AssertionResult("ro.system_ext.build.id", NativeLibWrapper.sysPropsReadCb("ro.system_ext.build.id"), "BP4A.251205.006")

    AssertionResult("ro.build.display.id", NativeLibWrapper.sysPropsGet("ro.build.display.id"), "BP4A.251205.006")
    AssertionResult("ro.build.display.id", NativeLibWrapper.sysPropsReadWithNullName("ro.build.display.id"), "BP4A.251205.006")
    AssertionResult("ro.build.display.id", NativeLibWrapper.sysPropsRead("ro.build.display.id"), "BP4A.251205.006")
    AssertionResult("ro.build.display.id", NativeLibWrapper.sysPropsReadCb("ro.build.display.id"), "BP4A.251205.006")

    AssertionResult("ro.build.tags", NativeLibWrapper.sysPropsGet("ro.build.tags"), "release-keys")
    AssertionResult("ro.build.tags", NativeLibWrapper.sysPropsReadWithNullName("ro.build.tags"), "release-keys")
    AssertionResult("ro.build.tags", NativeLibWrapper.sysPropsRead("ro.build.tags"), "release-keys")
    AssertionResult("ro.build.tags", NativeLibWrapper.sysPropsReadCb("ro.build.tags"), "release-keys")

    AssertionResult("ro.vendor.build.tags", NativeLibWrapper.sysPropsGet("ro.vendor.build.tags"), "release-keys")
    AssertionResult("ro.vendor.build.tags", NativeLibWrapper.sysPropsReadWithNullName("ro.vendor.build.tags"), "release-keys")
    AssertionResult("ro.vendor.build.tags", NativeLibWrapper.sysPropsRead("ro.vendor.build.tags"), "release-keys")
    AssertionResult("ro.vendor.build.tags", NativeLibWrapper.sysPropsReadCb("ro.vendor.build.tags"), "release-keys")

    AssertionResult("ro.product.build.tags", NativeLibWrapper.sysPropsGet("ro.product.build.tags"), "release-keys")
    AssertionResult("ro.product.build.tags", NativeLibWrapper.sysPropsReadWithNullName("ro.product.build.tags"), "release-keys")
    AssertionResult("ro.product.build.tags", NativeLibWrapper.sysPropsRead("ro.product.build.tags"), "release-keys")
    AssertionResult("ro.product.build.tags", NativeLibWrapper.sysPropsReadCb("ro.product.build.tags"), "release-keys")

    AssertionResult("ro.system.build.tags", NativeLibWrapper.sysPropsGet("ro.system.build.tags"), "release-keys")
    AssertionResult("ro.system.build.tags", NativeLibWrapper.sysPropsReadWithNullName("ro.system.build.tags"), "release-keys")
    AssertionResult("ro.system.build.tags", NativeLibWrapper.sysPropsRead("ro.system.build.tags"), "release-keys")
    AssertionResult("ro.system.build.tags", NativeLibWrapper.sysPropsReadCb("ro.system.build.tags"), "release-keys")

    AssertionResult("ro.vendor_dlkm.build.tags", NativeLibWrapper.sysPropsGet("ro.vendor_dlkm.build.tags"), "release-keys")
    AssertionResult("ro.vendor_dlkm.build.tags", NativeLibWrapper.sysPropsReadWithNullName("ro.vendor_dlkm.build.tags"), "release-keys")
    AssertionResult("ro.vendor_dlkm.build.tags", NativeLibWrapper.sysPropsRead("ro.vendor_dlkm.build.tags"), "release-keys")
    AssertionResult("ro.vendor_dlkm.build.tags", NativeLibWrapper.sysPropsReadCb("ro.vendor_dlkm.build.tags"), "release-keys")

    AssertionResult("ro.system_ext.build.tags", NativeLibWrapper.sysPropsGet("ro.system_ext.build.tags"), "release-keys")
    AssertionResult("ro.system_ext.build.tags", NativeLibWrapper.sysPropsReadWithNullName("ro.system_ext.build.tags"), "release-keys")
    AssertionResult("ro.system_ext.build.tags", NativeLibWrapper.sysPropsRead("ro.system_ext.build.tags"), "release-keys")
    AssertionResult("ro.system_ext.build.tags", NativeLibWrapper.sysPropsReadCb("ro.system_ext.build.tags"), "release-keys")

    AssertionResult("ro.build.type", NativeLibWrapper.sysPropsGet("ro.build.type"), "user")
    AssertionResult("ro.build.type", NativeLibWrapper.sysPropsReadWithNullName("ro.build.type"), "user")
    AssertionResult("ro.build.type", NativeLibWrapper.sysPropsRead("ro.build.type"), "user")
    AssertionResult("ro.build.type", NativeLibWrapper.sysPropsReadCb("ro.build.type"), "user")

    AssertionResult("ro.vendor.build.type", NativeLibWrapper.sysPropsGet("ro.vendor.build.type"), "user")
    AssertionResult("ro.vendor.build.type", NativeLibWrapper.sysPropsReadWithNullName("ro.vendor.build.type"), "user")
    AssertionResult("ro.vendor.build.type", NativeLibWrapper.sysPropsRead("ro.vendor.build.type"), "user")
    AssertionResult("ro.vendor.build.type", NativeLibWrapper.sysPropsReadCb("ro.vendor.build.type"), "user")

    AssertionResult("ro.product.build.type", NativeLibWrapper.sysPropsGet("ro.product.build.type"), "user")
    AssertionResult("ro.product.build.type", NativeLibWrapper.sysPropsReadWithNullName("ro.product.build.type"), "user")
    AssertionResult("ro.product.build.type", NativeLibWrapper.sysPropsRead("ro.product.build.type"), "user")
    AssertionResult("ro.product.build.type", NativeLibWrapper.sysPropsReadCb("ro.product.build.type"), "user")

    AssertionResult("ro.system.build.type", NativeLibWrapper.sysPropsGet("ro.system.build.type"), "user")
    AssertionResult("ro.system.build.type", NativeLibWrapper.sysPropsReadWithNullName("ro.system.build.type"), "user")
    AssertionResult("ro.system.build.type", NativeLibWrapper.sysPropsRead("ro.system.build.type"), "user")
    AssertionResult("ro.system.build.type", NativeLibWrapper.sysPropsReadCb("ro.system.build.type"), "user")

    AssertionResult("ro.vendor_dlkm.build.type", NativeLibWrapper.sysPropsGet("ro.vendor_dlkm.build.type"), "user")
    AssertionResult("ro.vendor_dlkm.build.type", NativeLibWrapper.sysPropsReadWithNullName("ro.vendor_dlkm.build.type"), "user")
    AssertionResult("ro.vendor_dlkm.build.type", NativeLibWrapper.sysPropsRead("ro.vendor_dlkm.build.type"), "user")
    AssertionResult("ro.vendor_dlkm.build.type", NativeLibWrapper.sysPropsReadCb("ro.vendor_dlkm.build.type"), "user")

    AssertionResult("ro.system_ext.build.type", NativeLibWrapper.sysPropsGet("ro.system_ext.build.type"), "user")
    AssertionResult("ro.system_ext.build.type", NativeLibWrapper.sysPropsReadWithNullName("ro.system_ext.build.type"), "user")
    AssertionResult("ro.system_ext.build.type", NativeLibWrapper.sysPropsRead("ro.system_ext.build.type"), "user")
    AssertionResult("ro.system_ext.build.type", NativeLibWrapper.sysPropsReadCb("ro.system_ext.build.type"), "user")

    AssertionResult("ro.build.user", NativeLibWrapper.sysPropsGet("ro.build.user"), "android-build")
    AssertionResult("ro.build.user", NativeLibWrapper.sysPropsReadWithNullName("ro.build.user"), "android-build")
    AssertionResult("ro.build.user", NativeLibWrapper.sysPropsRead("ro.build.user"), "android-build")
    AssertionResult("ro.build.user", NativeLibWrapper.sysPropsReadCb("ro.build.user"), "android-build")

    AssertionResult("ro.build.date.utc", NativeLibWrapper.sysPropsGet("ro.build.date.utc"), "1764954000")
    AssertionResult("ro.build.date.utc", NativeLibWrapper.sysPropsReadWithNullName("ro.build.date.utc"), "1764954000")
    AssertionResult("ro.build.date.utc", NativeLibWrapper.sysPropsRead("ro.build.date.utc"), "1764954000")
    AssertionResult("ro.build.date.utc", NativeLibWrapper.sysPropsReadCb("ro.build.date.utc"), "1764954000")

    AssertionResult("ro.odm.build.date.utc", NativeLibWrapper.sysPropsGet("ro.odm.build.date.utc"), "1764954000")
    AssertionResult("ro.odm.build.date.utc", NativeLibWrapper.sysPropsReadWithNullName("ro.odm.build.date.utc"), "1764954000")
    AssertionResult("ro.odm.build.date.utc", NativeLibWrapper.sysPropsRead("ro.odm.build.date.utc"), "1764954000")
    AssertionResult("ro.odm.build.date.utc", NativeLibWrapper.sysPropsReadCb("ro.odm.build.date.utc"), "1764954000")

    AssertionResult("ro.product.build.date.utc", NativeLibWrapper.sysPropsGet("ro.product.build.date.utc"), "1764954000")
    AssertionResult("ro.product.build.date.utc", NativeLibWrapper.sysPropsReadWithNullName("ro.product.build.date.utc"), "1764954000")
    AssertionResult("ro.product.build.date.utc", NativeLibWrapper.sysPropsRead("ro.product.build.date.utc"), "1764954000")
    AssertionResult("ro.product.build.date.utc", NativeLibWrapper.sysPropsReadCb("ro.product.build.date.utc"), "1764954000")

    AssertionResult("ro.system.build.date.utc", NativeLibWrapper.sysPropsGet("ro.system.build.date.utc"), "1764954000")
    AssertionResult("ro.system.build.date.utc", NativeLibWrapper.sysPropsReadWithNullName("ro.system.build.date.utc"), "1764954000")
    AssertionResult("ro.system.build.date.utc", NativeLibWrapper.sysPropsRead("ro.system.build.date.utc"), "1764954000")
    AssertionResult("ro.system.build.date.utc", NativeLibWrapper.sysPropsReadCb("ro.system.build.date.utc"), "1764954000")

    AssertionResult("ro.system_ext.build.date.utc", NativeLibWrapper.sysPropsGet("ro.system_ext.build.date.utc"), "1764954000")
    AssertionResult("ro.system_ext.build.date.utc", NativeLibWrapper.sysPropsReadWithNullName("ro.system_ext.build.date.utc"), "1764954000")
    AssertionResult("ro.system_ext.build.date.utc", NativeLibWrapper.sysPropsRead("ro.system_ext.build.date.utc"), "1764954000")
    AssertionResult("ro.system_ext.build.date.utc", NativeLibWrapper.sysPropsReadCb("ro.system_ext.build.date.utc"), "1764954000")

    AssertionResult("ro.vendor_dlkm.build.date.utc", NativeLibWrapper.sysPropsGet("ro.vendor_dlkm.build.date.utc"), "1764954000")
    AssertionResult("ro.vendor_dlkm.build.date.utc", NativeLibWrapper.sysPropsReadWithNullName("ro.vendor_dlkm.build.date.utc"), "1764954000")
    AssertionResult("ro.vendor_dlkm.build.date.utc", NativeLibWrapper.sysPropsRead("ro.vendor_dlkm.build.date.utc"), "1764954000")
    AssertionResult("ro.vendor_dlkm.build.date.utc", NativeLibWrapper.sysPropsReadCb("ro.vendor_dlkm.build.date.utc"), "1764954000")

    AssertionResult("ro.vendor.build.date.utc", NativeLibWrapper.sysPropsGet("ro.vendor.build.date.utc"), "1764954000")
    AssertionResult("ro.vendor.build.date.utc", NativeLibWrapper.sysPropsReadWithNullName("ro.vendor.build.date.utc"), "1764954000")
    AssertionResult("ro.vendor.build.date.utc", NativeLibWrapper.sysPropsRead("ro.vendor.build.date.utc"), "1764954000")
    AssertionResult("ro.vendor.build.date.utc", NativeLibWrapper.sysPropsReadCb("ro.vendor.build.date.utc"), "1764954000")

    AssertionResult("ro.build.version.all_codenames", NativeLibWrapper.sysPropsGet("ro.build.version.all_codenames"), "REL")
    AssertionResult("ro.build.version.all_codenames", NativeLibWrapper.sysPropsReadWithNullName("ro.build.version.all_codenames"), "REL")
    AssertionResult("ro.build.version.all_codenames", NativeLibWrapper.sysPropsRead("ro.build.version.all_codenames"), "REL")
    AssertionResult("ro.build.version.all_codenames", NativeLibWrapper.sysPropsReadCb("ro.build.version.all_codenames"), "REL")

    AssertionResult("ro.build.version.preview_sdk_fingerprint", NativeLibWrapper.sysPropsGet("ro.build.version.preview_sdk_fingerprint"), "REL")
    AssertionResult("ro.build.version.preview_sdk_fingerprint", NativeLibWrapper.sysPropsReadWithNullName("ro.build.version.preview_sdk_fingerprint"), "REL")
    AssertionResult("ro.build.version.preview_sdk_fingerprint", NativeLibWrapper.sysPropsRead("ro.build.version.preview_sdk_fingerprint"), "REL")
    AssertionResult("ro.build.version.preview_sdk_fingerprint", NativeLibWrapper.sysPropsReadCb("ro.build.version.preview_sdk_fingerprint"), "REL")

    AssertionResult("ro.build.date", NativeLibWrapper.sysPropsGet("ro.build.date"), buildDate)
    AssertionResult("ro.build.date", NativeLibWrapper.sysPropsReadWithNullName("ro.build.date"), buildDate)
    AssertionResult("ro.build.date", NativeLibWrapper.sysPropsRead("ro.build.date"), buildDate)
    AssertionResult("ro.build.date", NativeLibWrapper.sysPropsReadCb("ro.build.date"), buildDate)

    AssertionResult("ro.odm.build.date", NativeLibWrapper.sysPropsGet("ro.odm.build.date"), buildDate)
    AssertionResult("ro.odm.build.date", NativeLibWrapper.sysPropsReadWithNullName("ro.odm.build.date"), buildDate)
    AssertionResult("ro.odm.build.date", NativeLibWrapper.sysPropsRead("ro.odm.build.date"), buildDate)
    AssertionResult("ro.odm.build.date", NativeLibWrapper.sysPropsReadCb("ro.odm.build.date"), buildDate)

    AssertionResult("ro.product.build.date", NativeLibWrapper.sysPropsGet("ro.product.build.date"), buildDate)
    AssertionResult("ro.product.build.date", NativeLibWrapper.sysPropsReadWithNullName("ro.product.build.date"), buildDate)
    AssertionResult("ro.product.build.date", NativeLibWrapper.sysPropsRead("ro.product.build.date"), buildDate)
    AssertionResult("ro.product.build.date", NativeLibWrapper.sysPropsReadCb("ro.product.build.date"), buildDate)

    AssertionResult("ro.system.build.date", NativeLibWrapper.sysPropsGet("ro.system.build.date"), buildDate)
    AssertionResult("ro.system.build.date", NativeLibWrapper.sysPropsReadWithNullName("ro.system.build.date"), buildDate)
    AssertionResult("ro.system.build.date", NativeLibWrapper.sysPropsRead("ro.system.build.date"), buildDate)
    AssertionResult("ro.system.build.date", NativeLibWrapper.sysPropsReadCb("ro.system.build.date"), buildDate)

    AssertionResult("ro.system_ext.build.date", NativeLibWrapper.sysPropsGet("ro.system_ext.build.date"), buildDate)
    AssertionResult("ro.system_ext.build.date", NativeLibWrapper.sysPropsReadWithNullName("ro.system_ext.build.date"), buildDate)
    AssertionResult("ro.system_ext.build.date", NativeLibWrapper.sysPropsRead("ro.system_ext.build.date"), buildDate)
    AssertionResult("ro.system_ext.build.date", NativeLibWrapper.sysPropsReadCb("ro.system_ext.build.date"), buildDate)

    AssertionResult("ro.vendor.build.date", NativeLibWrapper.sysPropsGet("ro.vendor.build.date"), buildDate)
    AssertionResult("ro.vendor.build.date", NativeLibWrapper.sysPropsReadWithNullName("ro.vendor.build.date"), buildDate)
    AssertionResult("ro.vendor.build.date", NativeLibWrapper.sysPropsRead("ro.vendor.build.date"), buildDate)
    AssertionResult("ro.vendor.build.date", NativeLibWrapper.sysPropsReadCb("ro.vendor.build.date"), buildDate)

    AssertionResult("ro.vendor_dlkm.build.date", NativeLibWrapper.sysPropsGet("ro.vendor_dlkm.build.date"), buildDate)
    AssertionResult("ro.vendor_dlkm.build.date", NativeLibWrapper.sysPropsReadWithNullName("ro.vendor_dlkm.build.date"), buildDate)
    AssertionResult("ro.vendor_dlkm.build.date", NativeLibWrapper.sysPropsRead("ro.vendor_dlkm.build.date"), buildDate)
    AssertionResult("ro.vendor_dlkm.build.date", NativeLibWrapper.sysPropsReadCb("ro.vendor_dlkm.build.date"), buildDate)

    AssertionResult("ro.build.description", NativeLibWrapper.sysPropsGet("ro.build.description"), "husky-user 16 BP4A.251205.006 release-keys")
    AssertionResult("ro.build.description", NativeLibWrapper.sysPropsReadWithNullName("ro.build.description"), "husky-user 16 BP4A.251205.006 release-keys")
    AssertionResult("ro.build.description", NativeLibWrapper.sysPropsRead("ro.build.description"), "husky-user 16 BP4A.251205.006 release-keys")
    AssertionResult("ro.build.description", NativeLibWrapper.sysPropsReadCb("ro.build.description"), "husky-user 16 BP4A.251205.006 release-keys")

    AssertionResult("ro.build.flavor", NativeLibWrapper.sysPropsGet("ro.build.flavor"), "husky-user")
    AssertionResult("ro.build.flavor", NativeLibWrapper.sysPropsReadWithNullName("ro.build.flavor"), "husky-user")
    AssertionResult("ro.build.flavor", NativeLibWrapper.sysPropsRead("ro.build.flavor"), "husky-user")
    AssertionResult("ro.build.flavor", NativeLibWrapper.sysPropsReadCb("ro.build.flavor"), "husky-user")

    AssertionResult("ro.build.version.incremental", NativeLibWrapper.sysPropsGet("ro.build.version.incremental"), "14401865")
    AssertionResult("ro.build.version.incremental", NativeLibWrapper.sysPropsReadWithNullName("ro.build.version.incremental"), "14401865")
    AssertionResult("ro.build.version.incremental", NativeLibWrapper.sysPropsRead("ro.build.version.incremental"), "14401865")
    AssertionResult("ro.build.version.incremental", NativeLibWrapper.sysPropsReadCb("ro.build.version.incremental"), "14401865")

    AssertionResult("ro.vendor.build.version.incremental", NativeLibWrapper.sysPropsGet("ro.vendor.build.version.incremental"), "14401865")
    AssertionResult("ro.vendor.build.version.incremental", NativeLibWrapper.sysPropsReadWithNullName("ro.vendor.build.version.incremental"), "14401865")
    AssertionResult("ro.vendor.build.version.incremental", NativeLibWrapper.sysPropsRead("ro.vendor.build.version.incremental"), "14401865")
    AssertionResult("ro.vendor.build.version.incremental", NativeLibWrapper.sysPropsReadCb("ro.vendor.build.version.incremental"), "14401865")

    AssertionResult("ro.odm.build.version.incremental", NativeLibWrapper.sysPropsGet("ro.odm.build.version.incremental"), "14401865")
    AssertionResult("ro.odm.build.version.incremental", NativeLibWrapper.sysPropsReadWithNullName("ro.odm.build.version.incremental"), "14401865")
    AssertionResult("ro.odm.build.version.incremental", NativeLibWrapper.sysPropsRead("ro.odm.build.version.incremental"), "14401865")
    AssertionResult("ro.odm.build.version.incremental", NativeLibWrapper.sysPropsReadCb("ro.odm.build.version.incremental"), "14401865")

    AssertionResult("ro.product.build.version.incremental", NativeLibWrapper.sysPropsGet("ro.product.build.version.incremental"), "14401865")
    AssertionResult("ro.product.build.version.incremental", NativeLibWrapper.sysPropsReadWithNullName("ro.product.build.version.incremental"), "14401865")
    AssertionResult("ro.product.build.version.incremental", NativeLibWrapper.sysPropsRead("ro.product.build.version.incremental"), "14401865")
    AssertionResult("ro.product.build.version.incremental", NativeLibWrapper.sysPropsReadCb("ro.product.build.version.incremental"), "14401865")

    AssertionResult("ro.system.build.version.incremental", NativeLibWrapper.sysPropsGet("ro.system.build.version.incremental"), "14401865")
    AssertionResult("ro.system.build.version.incremental", NativeLibWrapper.sysPropsReadWithNullName("ro.system.build.version.incremental"), "14401865")
    AssertionResult("ro.system.build.version.incremental", NativeLibWrapper.sysPropsRead("ro.system.build.version.incremental"), "14401865")
    AssertionResult("ro.system.build.version.incremental", NativeLibWrapper.sysPropsReadCb("ro.system.build.version.incremental"), "14401865")

    AssertionResult("ro.vendor_dlkm.build.version.incremental", NativeLibWrapper.sysPropsGet("ro.vendor_dlkm.build.version.incremental"), "14401865")
    AssertionResult("ro.vendor_dlkm.build.version.incremental", NativeLibWrapper.sysPropsReadWithNullName("ro.vendor_dlkm.build.version.incremental"), "14401865")
    AssertionResult("ro.vendor_dlkm.build.version.incremental", NativeLibWrapper.sysPropsRead("ro.vendor_dlkm.build.version.incremental"), "14401865")
    AssertionResult("ro.vendor_dlkm.build.version.incremental", NativeLibWrapper.sysPropsReadCb("ro.vendor_dlkm.build.version.incremental"), "14401865")

    AssertionResult("ro.system_ext.build.version.incremental", NativeLibWrapper.sysPropsGet("ro.system_ext.build.version.incremental"), "14401865")
    AssertionResult("ro.system_ext.build.version.incremental", NativeLibWrapper.sysPropsReadWithNullName("ro.system_ext.build.version.incremental"), "14401865")
    AssertionResult("ro.system_ext.build.version.incremental", NativeLibWrapper.sysPropsRead("ro.system_ext.build.version.incremental"), "14401865")
    AssertionResult("ro.system_ext.build.version.incremental", NativeLibWrapper.sysPropsReadCb("ro.system_ext.build.version.incremental"), "14401865")

//    AssertionResult("ro.build.version.release", NativeLibWrapper.sysPropsGet("ro.build.version.release"), "16")
//    AssertionResult("ro.build.version.release", NativeLibWrapper.sysPropsReadWithNullName("ro.build.version.release"), propInfoNull)
//    AssertionResult("ro.build.version.release", NativeLibWrapper.sysPropsRead("ro.build.version.release"), "16")
//    AssertionResult("ro.build.version.release", NativeLibWrapper.sysPropsReadCb("ro.build.version.release"), "16")

//    AssertionResult("ro.product.build.version.release", NativeLibWrapper.sysPropsGet("ro.product.build.version.release"), "16")
//    AssertionResult("ro.product.build.version.release", NativeLibWrapper.sysPropsReadWithNullName("ro.product.build.version.release"), propInfoNull)
//    AssertionResult("ro.product.build.version.release", NativeLibWrapper.sysPropsRead("ro.product.build.version.release"), "16")
//    AssertionResult("ro.product.build.version.release", NativeLibWrapper.sysPropsReadCb("ro.product.build.version.release"), "16")
//
//    AssertionResult("ro.vendor_dlkm.build.version.release", NativeLibWrapper.sysPropsGet("ro.vendor_dlkm.build.version.release"), "16")
//    AssertionResult("ro.vendor_dlkm.build.version.release", NativeLibWrapper.sysPropsReadWithNullName("ro.vendor_dlkm.build.version.release"), propInfoNull)
//    AssertionResult("ro.vendor_dlkm.build.version.release", NativeLibWrapper.sysPropsRead("ro.vendor_dlkm.build.version.release"), "16")
//    AssertionResult("ro.vendor_dlkm.build.version.release", NativeLibWrapper.sysPropsReadCb("ro.vendor_dlkm.build.version.release"), "16")
//
//    AssertionResult("ro.vendor.build.version.release", NativeLibWrapper.sysPropsGet("ro.vendor.build.version.release"), "16")
//    AssertionResult("ro.vendor.build.version.release", NativeLibWrapper.sysPropsReadWithNullName("ro.vendor.build.version.release"), propInfoNull)
//    AssertionResult("ro.vendor.build.version.release", NativeLibWrapper.sysPropsRead("ro.vendor.build.version.release"), "16")
//    AssertionResult("ro.vendor.build.version.release", NativeLibWrapper.sysPropsReadCb("ro.vendor.build.version.release"), "16")
//
//    AssertionResult("ro.system_ext.build.version.release", NativeLibWrapper.sysPropsGet("ro.system_ext.build.version.release"), "16")
//    AssertionResult("ro.system_ext.build.version.release", NativeLibWrapper.sysPropsReadWithNullName("ro.system_ext.build.version.release"), propInfoNull)
//    AssertionResult("ro.system_ext.build.version.release", NativeLibWrapper.sysPropsRead("ro.system_ext.build.version.release"), "16")
//    AssertionResult("ro.system_ext.build.version.release", NativeLibWrapper.sysPropsReadCb("ro.system_ext.build.version.release"), "16")
//
//    AssertionResult("ro.system.build.version.release", NativeLibWrapper.sysPropsGet("ro.system.build.version.release"), "16")
//    AssertionResult("ro.system.build.version.release", NativeLibWrapper.sysPropsReadWithNullName("ro.system.build.version.release"), propInfoNull)
//    AssertionResult("ro.system.build.version.release", NativeLibWrapper.sysPropsRead("ro.system.build.version.release"), "16")
//    AssertionResult("ro.system.build.version.release", NativeLibWrapper.sysPropsReadCb("ro.system.build.version.release"), "16")
//
//    AssertionResult("ro.build.version.release_or_codename", NativeLibWrapper.sysPropsGet("ro.build.version.release_or_codename"), "16")
//    AssertionResult("ro.build.version.release_or_codename", NativeLibWrapper.sysPropsReadWithNullName("ro.build.version.release_or_codename"), propInfoNull)
//    AssertionResult("ro.build.version.release_or_codename", NativeLibWrapper.sysPropsRead("ro.build.version.release_or_codename"), "16")
//    AssertionResult("ro.build.version.release_or_codename", NativeLibWrapper.sysPropsReadCb("ro.build.version.release_or_codename"), "16")
//
//    AssertionResult("ro.vendor.build.version.release_or_codename", NativeLibWrapper.sysPropsGet("ro.vendor.build.version.release_or_codename"), "16")
//    AssertionResult("ro.vendor.build.version.release_or_codename", NativeLibWrapper.sysPropsReadWithNullName("ro.vendor.build.version.release_or_codename"), propInfoNull)
//    AssertionResult("ro.vendor.build.version.release_or_codename", NativeLibWrapper.sysPropsRead("ro.vendor.build.version.release_or_codename"), "16")
//    AssertionResult("ro.vendor.build.version.release_or_codename", NativeLibWrapper.sysPropsReadCb("ro.vendor.build.version.release_or_codename"), "16")
//
//    AssertionResult("ro.product.build.version.release_or_codename", NativeLibWrapper.sysPropsGet("ro.product.build.version.release_or_codename"), "16")
//    AssertionResult("ro.product.build.version.release_or_codename", NativeLibWrapper.sysPropsReadWithNullName("ro.product.build.version.release_or_codename"), propInfoNull)
//    AssertionResult("ro.product.build.version.release_or_codename", NativeLibWrapper.sysPropsRead("ro.product.build.version.release_or_codename"), "16")
//    AssertionResult("ro.product.build.version.release_or_codename", NativeLibWrapper.sysPropsReadCb("ro.product.build.version.release_or_codename"), "16")
//
//    AssertionResult("ro.vendor_dlkm.build.version.release_or_codename", NativeLibWrapper.sysPropsGet("ro.vendor_dlkm.build.version.release_or_codename"), "16")
//    AssertionResult("ro.vendor_dlkm.build.version.release_or_codename", NativeLibWrapper.sysPropsReadWithNullName("ro.vendor_dlkm.build.version.release_or_codename"), propInfoNull)
//    AssertionResult("ro.vendor_dlkm.build.version.release_or_codename", NativeLibWrapper.sysPropsRead("ro.vendor_dlkm.build.version.release_or_codename"), "16")
//    AssertionResult("ro.vendor_dlkm.build.version.release_or_codename", NativeLibWrapper.sysPropsReadCb("ro.vendor_dlkm.build.version.release_or_codename"), "16")
//
//    AssertionResult("ro.system.build.version.release_or_codename", NativeLibWrapper.sysPropsGet("ro.system.build.version.release_or_codename"), "16")
//    AssertionResult("ro.system.build.version.release_or_codename", NativeLibWrapper.sysPropsReadWithNullName("ro.system.build.version.release_or_codename"), propInfoNull)
//    AssertionResult("ro.system.build.version.release_or_codename", NativeLibWrapper.sysPropsRead("ro.system.build.version.release_or_codename"), "16")
//    AssertionResult("ro.system.build.version.release_or_codename", NativeLibWrapper.sysPropsReadCb("ro.system.build.version.release_or_codename"), "16")
//
//    AssertionResult("ro.system_ext.build.version.release_or_codename", NativeLibWrapper.sysPropsGet("ro.system_ext.build.version.release_or_codename"), "16")
//    AssertionResult("ro.system_ext.build.version.release_or_codename", NativeLibWrapper.sysPropsReadWithNullName("ro.system_ext.build.version.release_or_codename"), propInfoNull)
//    AssertionResult("ro.system_ext.build.version.release_or_codename", NativeLibWrapper.sysPropsRead("ro.system_ext.build.version.release_or_codename"), "16")
//    AssertionResult("ro.system_ext.build.version.release_or_codename", NativeLibWrapper.sysPropsReadCb("ro.system_ext.build.version.release_or_codename"), "16")
//
//    AssertionResult("ro.build.version.release_or_preview_display", NativeLibWrapper.sysPropsGet("ro.build.version.release_or_preview_display"), "16")
//    AssertionResult("ro.build.version.release_or_preview_display", NativeLibWrapper.sysPropsReadWithNullName("ro.build.version.release_or_preview_display"), propInfoNull)
//    AssertionResult("ro.build.version.release_or_preview_display", NativeLibWrapper.sysPropsRead("ro.build.version.release_or_preview_display"), "16")
//    AssertionResult("ro.build.version.release_or_preview_display", NativeLibWrapper.sysPropsReadCb("ro.build.version.release_or_preview_display"), "16")

//    AssertionResult("ro.build.version.sdk", NativeLibWrapper.sysPropsGet("ro.build.version.sdk"), "36")
//    AssertionResult("ro.build.version.sdk", NativeLibWrapper.sysPropsReadWithNullName("ro.build.version.sdk"), propInfoNull)
//    AssertionResult("ro.build.version.sdk", NativeLibWrapper.sysPropsRead("ro.build.version.sdk"), "36")
//    AssertionResult("ro.build.version.sdk", NativeLibWrapper.sysPropsReadCb("ro.build.version.sdk"), "36")
//
//    AssertionResult("ro.product.build.version.sdk", NativeLibWrapper.sysPropsGet("ro.product.build.version.sdk"), "36")
//    AssertionResult("ro.product.build.version.sdk", NativeLibWrapper.sysPropsReadWithNullName("ro.product.build.version.sdk"), propInfoNull)
//    AssertionResult("ro.product.build.version.sdk", NativeLibWrapper.sysPropsRead("ro.product.build.version.sdk"), "36")
//    AssertionResult("ro.product.build.version.sdk", NativeLibWrapper.sysPropsReadCb("ro.product.build.version.sdk"), "36")
//
//    AssertionResult("ro.vendor.build.version.sdk", NativeLibWrapper.sysPropsGet("ro.vendor.build.version.sdk"), "36")
//    AssertionResult("ro.vendor.build.version.sdk", NativeLibWrapper.sysPropsReadWithNullName("ro.vendor.build.version.sdk"), propInfoNull)
//    AssertionResult("ro.vendor.build.version.sdk", NativeLibWrapper.sysPropsRead("ro.vendor.build.version.sdk"), "36")
//    AssertionResult("ro.vendor.build.version.sdk", NativeLibWrapper.sysPropsReadCb("ro.vendor.build.version.sdk"), "36")
//
//    AssertionResult("ro.vendor_dlkm.build.version.sdk", NativeLibWrapper.sysPropsGet("ro.vendor_dlkm.build.version.sdk"), "36")
//    AssertionResult("ro.vendor_dlkm.build.version.sdk", NativeLibWrapper.sysPropsReadWithNullName("ro.vendor_dlkm.build.version.sdk"), propInfoNull)
//    AssertionResult("ro.vendor_dlkm.build.version.sdk", NativeLibWrapper.sysPropsRead("ro.vendor_dlkm.build.version.sdk"), "36")
//    AssertionResult("ro.vendor_dlkm.build.version.sdk", NativeLibWrapper.sysPropsReadCb("ro.vendor_dlkm.build.version.sdk"), "36")
//
//    AssertionResult("ro.system_ext.build.version.sdk", NativeLibWrapper.sysPropsGet("ro.system_ext.build.version.sdk"), "36")
//    AssertionResult("ro.system_ext.build.version.sdk", NativeLibWrapper.sysPropsReadWithNullName("ro.system_ext.build.version.sdk"), propInfoNull)
//    AssertionResult("ro.system_ext.build.version.sdk", NativeLibWrapper.sysPropsRead("ro.system_ext.build.version.sdk"), "36")
//    AssertionResult("ro.system_ext.build.version.sdk", NativeLibWrapper.sysPropsReadCb("ro.system_ext.build.version.sdk"), "36")
//
//    AssertionResult("ro.system.build.version.sdk", NativeLibWrapper.sysPropsGet("ro.system.build.version.sdk"), "36")
//    AssertionResult("ro.system.build.version.sdk", NativeLibWrapper.sysPropsReadWithNullName("ro.system.build.version.sdk"), propInfoNull)
//    AssertionResult("ro.system.build.version.sdk", NativeLibWrapper.sysPropsRead("ro.system.build.version.sdk"), "36")
//    AssertionResult("ro.system.build.version.sdk", NativeLibWrapper.sysPropsReadCb("ro.system.build.version.sdk"), "36")

//    AssertionResult("ro.build.version.sdk_full", NativeLibWrapper.sysPropsGet("ro.build.version.sdk_full"), "36.1")
//    AssertionResult("ro.build.version.sdk_full", NativeLibWrapper.sysPropsReadWithNullName("ro.build.version.sdk_full"), propInfoNull)
//    AssertionResult("ro.build.version.sdk_full", NativeLibWrapper.sysPropsRead("ro.build.version.sdk_full"), "36.1")
//    AssertionResult("ro.build.version.sdk_full", NativeLibWrapper.sysPropsReadCb("ro.build.version.sdk_full"), "36.1")

//    AssertionResult("ro.product.build.version.sdk_full", NativeLibWrapper.sysPropsGet("ro.product.build.version.sdk_full"), "36.1")
//    AssertionResult("ro.product.build.version.sdk_full", NativeLibWrapper.sysPropsReadWithNullName("ro.product.build.version.sdk_full"), propInfoNull)
//    AssertionResult("ro.product.build.version.sdk_full", NativeLibWrapper.sysPropsRead("ro.product.build.version.sdk_full"), "36.1")
//    AssertionResult("ro.product.build.version.sdk_full", NativeLibWrapper.sysPropsReadCb("ro.product.build.version.sdk_full"), "36.1")
//
//    AssertionResult("ro.system_ext.build.version.sdk_full", NativeLibWrapper.sysPropsGet("ro.system_ext.build.version.sdk_full"), "36.1")
//    AssertionResult("ro.system_ext.build.version.sdk_full", NativeLibWrapper.sysPropsReadWithNullName("ro.system_ext.build.version.sdk_full"), propInfoNull)
//    AssertionResult("ro.system_ext.build.version.sdk_full", NativeLibWrapper.sysPropsRead("ro.system_ext.build.version.sdk_full"), "36.1")
//    AssertionResult("ro.system_ext.build.version.sdk_full", NativeLibWrapper.sysPropsReadCb("ro.system_ext.build.version.sdk_full"), "36.1")
//
//    AssertionResult("ro.system.build.version.sdk_full", NativeLibWrapper.sysPropsGet("ro.system.build.version.sdk_full"), "36.1")
//    AssertionResult("ro.system.build.version.sdk_full", NativeLibWrapper.sysPropsReadWithNullName("ro.system.build.version.sdk_full"), propInfoNull)
//    AssertionResult("ro.system.build.version.sdk_full", NativeLibWrapper.sysPropsRead("ro.system.build.version.sdk_full"), "36.1")
//    AssertionResult("ro.system.build.version.sdk_full", NativeLibWrapper.sysPropsReadCb("ro.system.build.version.sdk_full"), "36.1")

    AssertionResult("ro.build.version.security_patch", NativeLibWrapper.sysPropsGet("ro.build.version.security_patch"), "2025-12-05")
    AssertionResult("ro.build.version.security_patch", NativeLibWrapper.sysPropsReadWithNullName("ro.build.version.security_patch"), "2025-12-05")
    AssertionResult("ro.build.version.security_patch", NativeLibWrapper.sysPropsRead("ro.build.version.security_patch"), "2025-12-05")
    AssertionResult("ro.build.version.security_patch", NativeLibWrapper.sysPropsReadCb("ro.build.version.security_patch"), "2025-12-05")

    AssertionResult("ro.build.version.codename", NativeLibWrapper.sysPropsGet("ro.build.version.codename"), "REL")
    AssertionResult("ro.build.version.codename", NativeLibWrapper.sysPropsReadWithNullName("ro.build.version.codename"), "REL")
    AssertionResult("ro.build.version.codename", NativeLibWrapper.sysPropsRead("ro.build.version.codename"), "REL")
    AssertionResult("ro.build.version.codename", NativeLibWrapper.sysPropsReadCb("ro.build.version.codename"), "REL")

    AssertionResult("ro.build.version.base_os", NativeLibWrapper.sysPropsGet("ro.build.version.base_os"), defaultValue)
    AssertionResult("ro.build.version.base_os", NativeLibWrapper.sysPropsReadWithNullName("ro.build.version.base_os"), defaultValue)
    AssertionResult("ro.build.version.base_os", NativeLibWrapper.sysPropsRead("ro.build.version.base_os"), defaultValue)
    AssertionResult("ro.build.version.base_os", NativeLibWrapper.sysPropsReadCb("ro.build.version.base_os"), defaultValue)

    AssertionResult("ro.build.version.preview_sdk", NativeLibWrapper.sysPropsGet("ro.build.version.preview_sdk"), "0")
    AssertionResult("ro.build.version.preview_sdk", NativeLibWrapper.sysPropsReadWithNullName("ro.build.version.preview_sdk"), "0")
    AssertionResult("ro.build.version.preview_sdk", NativeLibWrapper.sysPropsRead("ro.build.version.preview_sdk"), "0")
    AssertionResult("ro.build.version.preview_sdk", NativeLibWrapper.sysPropsReadCb("ro.build.version.preview_sdk"), "0")

    AssertionResult("ro.build.fingerprint", NativeLibWrapper.sysPropsGet("ro.build.fingerprint"), fingerprint)
    AssertionResult("ro.build.fingerprint", NativeLibWrapper.sysPropsReadWithNullName("ro.build.fingerprint"), fingerprint)
    AssertionResult("ro.build.fingerprint", NativeLibWrapper.sysPropsRead("ro.build.fingerprint"), fingerprint)
    AssertionResult("ro.build.fingerprint", NativeLibWrapper.sysPropsReadCb("ro.build.fingerprint"), fingerprint)

    AssertionResult("ro.odm.build.fingerprint", NativeLibWrapper.sysPropsGet("ro.odm.build.fingerprint"), fingerprint)
    AssertionResult("ro.odm.build.fingerprint", NativeLibWrapper.sysPropsReadWithNullName("ro.odm.build.fingerprint"), fingerprint)
    AssertionResult("ro.odm.build.fingerprint", NativeLibWrapper.sysPropsRead("ro.odm.build.fingerprint"), fingerprint)
    AssertionResult("ro.odm.build.fingerprint", NativeLibWrapper.sysPropsReadCb("ro.odm.build.fingerprint"), fingerprint)

    AssertionResult("ro.product.build.fingerprint", NativeLibWrapper.sysPropsGet("ro.product.build.fingerprint"), fingerprint)
    AssertionResult("ro.product.build.fingerprint", NativeLibWrapper.sysPropsReadWithNullName("ro.product.build.fingerprint"), fingerprint)
    AssertionResult("ro.product.build.fingerprint", NativeLibWrapper.sysPropsRead("ro.product.build.fingerprint"), fingerprint)
    AssertionResult("ro.product.build.fingerprint", NativeLibWrapper.sysPropsReadCb("ro.product.build.fingerprint"), fingerprint)

    AssertionResult("ro.system.build.fingerprint", NativeLibWrapper.sysPropsGet("ro.system.build.fingerprint"), fingerprint)
    AssertionResult("ro.system.build.fingerprint", NativeLibWrapper.sysPropsReadWithNullName("ro.system.build.fingerprint"), fingerprint)
    AssertionResult("ro.system.build.fingerprint", NativeLibWrapper.sysPropsRead("ro.system.build.fingerprint"), fingerprint)
    AssertionResult("ro.system.build.fingerprint", NativeLibWrapper.sysPropsReadCb("ro.system.build.fingerprint"), fingerprint)

    AssertionResult("ro.system_ext.build.fingerprint", NativeLibWrapper.sysPropsGet("ro.system_ext.build.fingerprint"), fingerprint)
    AssertionResult("ro.system_ext.build.fingerprint", NativeLibWrapper.sysPropsReadWithNullName("ro.system_ext.build.fingerprint"), fingerprint)
    AssertionResult("ro.system_ext.build.fingerprint", NativeLibWrapper.sysPropsRead("ro.system_ext.build.fingerprint"), fingerprint)
    AssertionResult("ro.system_ext.build.fingerprint", NativeLibWrapper.sysPropsReadCb("ro.system_ext.build.fingerprint"), fingerprint)

    AssertionResult("ro.vendor.build.fingerprint", NativeLibWrapper.sysPropsGet("ro.vendor.build.fingerprint"), fingerprint)
    AssertionResult("ro.vendor.build.fingerprint", NativeLibWrapper.sysPropsReadWithNullName("ro.vendor.build.fingerprint"), fingerprint)
    AssertionResult("ro.vendor.build.fingerprint", NativeLibWrapper.sysPropsRead("ro.vendor.build.fingerprint"), fingerprint)
    AssertionResult("ro.vendor.build.fingerprint", NativeLibWrapper.sysPropsReadCb("ro.vendor.build.fingerprint"), fingerprint)

    AssertionResult("ro.vendor_dlkm.build.fingerprint", NativeLibWrapper.sysPropsGet("ro.vendor_dlkm.build.fingerprint"), fingerprint)
    AssertionResult("ro.vendor_dlkm.build.fingerprint", NativeLibWrapper.sysPropsReadWithNullName("ro.vendor_dlkm.build.fingerprint"), fingerprint)
    AssertionResult("ro.vendor_dlkm.build.fingerprint", NativeLibWrapper.sysPropsRead("ro.vendor_dlkm.build.fingerprint"), fingerprint)
    AssertionResult("ro.vendor_dlkm.build.fingerprint", NativeLibWrapper.sysPropsReadCb("ro.vendor_dlkm.build.fingerprint"), fingerprint)

    AssertionResult("gsm.version.baseband", NativeLibWrapper.sysPropsGet("gsm.version.baseband"), "g5300g-251108-251202-B-12876551")
    AssertionResult("gsm.version.baseband", NativeLibWrapper.sysPropsReadWithNullName("gsm.version.baseband"), "g5300g-251108-251202-B-12876551")
    AssertionResult("gsm.version.baseband", NativeLibWrapper.sysPropsRead("gsm.version.baseband"), "g5300g-251108-251202-B-12876551")
    AssertionResult("gsm.version.baseband", NativeLibWrapper.sysPropsReadCb("gsm.version.baseband"), "g5300g-251108-251202-B-12876551")

    AssertionResult("gsm.version.ril-impl", NativeLibWrapper.sysPropsGet("gsm.version.ril-impl"), "com.google.android.telephony.modem")
    AssertionResult("gsm.version.ril-impl", NativeLibWrapper.sysPropsReadWithNullName("gsm.version.ril-impl"), "com.google.android.telephony.modem")
    AssertionResult("gsm.version.ril-impl", NativeLibWrapper.sysPropsRead("gsm.version.ril-impl"), "com.google.android.telephony.modem")
    AssertionResult("gsm.version.ril-impl", NativeLibWrapper.sysPropsReadCb("gsm.version.ril-impl"), "com.google.android.telephony.modem")

    AssertionResult("ril.sw_ver", NativeLibWrapper.sysPropsGet("ril.sw_ver"), defaultValue)
    AssertionResult("ril.sw_ver", NativeLibWrapper.sysPropsReadWithNullName("ril.sw_ver"), defaultValue)
    AssertionResult("ril.sw_ver", NativeLibWrapper.sysPropsRead("ril.sw_ver"), defaultValue)
    AssertionResult("ril.sw_ver", NativeLibWrapper.sysPropsReadCb("ril.sw_ver"), defaultValue)

    AssertionResult("ril.sw_ver2", NativeLibWrapper.sysPropsGet("ril.sw_ver2"), defaultValue)
    AssertionResult("ril.sw_ver2", NativeLibWrapper.sysPropsReadWithNullName("ril.sw_ver2"), defaultValue)
    AssertionResult("ril.sw_ver2", NativeLibWrapper.sysPropsRead("ril.sw_ver2"), defaultValue)
    AssertionResult("ril.sw_ver2", NativeLibWrapper.sysPropsReadCb("ril.sw_ver2"), defaultValue)

    AssertionResult("ro.baseband", NativeLibWrapper.sysPropsGet("ro.baseband"), "g5300g-251108-251202-B-12876551")
    AssertionResult("ro.baseband", NativeLibWrapper.sysPropsReadWithNullName("ro.baseband"), "g5300g-251108-251202-B-12876551")
    AssertionResult("ro.baseband", NativeLibWrapper.sysPropsRead("ro.baseband"), "g5300g-251108-251202-B-12876551")
    AssertionResult("ro.baseband", NativeLibWrapper.sysPropsReadCb("ro.baseband"), "g5300g-251108-251202-B-12876551")

    AssertionResult("ro.config.alarm_alert", NativeLibWrapper.sysPropsGet("ro.config.alarm_alert"), "Hassium.ogg")
    AssertionResult("ro.config.alarm_alert", NativeLibWrapper.sysPropsReadWithNullName("ro.config.alarm_alert"), "Hassium.ogg")
    AssertionResult("ro.config.alarm_alert", NativeLibWrapper.sysPropsRead("ro.config.alarm_alert"), "Hassium.ogg")
    AssertionResult("ro.config.alarm_alert", NativeLibWrapper.sysPropsReadCb("ro.config.alarm_alert"), "Hassium.ogg")

    AssertionResult("ro.config.notification_sound", NativeLibWrapper.sysPropsGet("ro.config.notification_sound"), "Argon.ogg")
    AssertionResult("ro.config.notification_sound", NativeLibWrapper.sysPropsReadWithNullName("ro.config.notification_sound"), "Argon.ogg")
    AssertionResult("ro.config.notification_sound", NativeLibWrapper.sysPropsRead("ro.config.notification_sound"), "Argon.ogg")
    AssertionResult("ro.config.notification_sound", NativeLibWrapper.sysPropsReadCb("ro.config.notification_sound"), "Argon.ogg")

    AssertionResult("ro.config.ringtone", NativeLibWrapper.sysPropsGet("ro.config.ringtone"), "Orion.ogg")
    AssertionResult("ro.config.ringtone", NativeLibWrapper.sysPropsReadWithNullName("ro.config.ringtone"), "Orion.ogg")
    AssertionResult("ro.config.ringtone", NativeLibWrapper.sysPropsRead("ro.config.ringtone"), "Orion.ogg")
    AssertionResult("ro.config.ringtone", NativeLibWrapper.sysPropsReadCb("ro.config.ringtone"), "Orion.ogg")

    AssertionResult("ro.product.locale", NativeLibWrapper.sysPropsGet("ro.product.locale"), "en-US")
    AssertionResult("ro.product.locale", NativeLibWrapper.sysPropsReadWithNullName("ro.product.locale"), "en-US")
    AssertionResult("ro.product.locale", NativeLibWrapper.sysPropsRead("ro.product.locale"), "en-US")
    AssertionResult("ro.product.locale", NativeLibWrapper.sysPropsReadCb("ro.product.locale"), "en-US")

    AssertionResult("bluetooth.device.default_name", NativeLibWrapper.sysPropsGet("bluetooth.device.default_name"), "Pixel 8 Pro")
    AssertionResult("bluetooth.device.default_name", NativeLibWrapper.sysPropsReadWithNullName("bluetooth.device.default_name"), "Pixel 8 Pro")
    AssertionResult("bluetooth.device.default_name", NativeLibWrapper.sysPropsRead("bluetooth.device.default_name"), "Pixel 8 Pro")
    AssertionResult("bluetooth.device.default_name", NativeLibWrapper.sysPropsReadCb("bluetooth.device.default_name"), "Pixel 8 Pro")

    AssertionResult("debug.debuggerd.wait_for_debugger", NativeLibWrapper.sysPropsGet("debug.debuggerd.wait_for_debugger"), defaultValue)
    AssertionResult("debug.debuggerd.wait_for_debugger", NativeLibWrapper.sysPropsReadWithNullName("debug.debuggerd.wait_for_debugger"), defaultValue)
    AssertionResult("debug.debuggerd.wait_for_debugger", NativeLibWrapper.sysPropsRead("debug.debuggerd.wait_for_debugger"), defaultValue)
    AssertionResult("debug.debuggerd.wait_for_debugger", NativeLibWrapper.sysPropsReadCb("debug.debuggerd.wait_for_debugger"), defaultValue)

    AssertionResult("nfc.initialized", NativeLibWrapper.sysPropsGet("nfc.initialized"), "false")
    AssertionResult("nfc.initialized", NativeLibWrapper.sysPropsReadWithNullName("nfc.initialized"), "false")
    AssertionResult("nfc.initialized", NativeLibWrapper.sysPropsRead("nfc.initialized"), "false")
    AssertionResult("nfc.initialized", NativeLibWrapper.sysPropsReadCb("nfc.initialized"), "false")

    AssertionResult("ro.support_one_handed_mode", NativeLibWrapper.sysPropsGet("ro.support_one_handed_mode"), "false")
    AssertionResult("ro.support_one_handed_mode", NativeLibWrapper.sysPropsReadWithNullName("ro.support_one_handed_mode"), "false")
    AssertionResult("ro.support_one_handed_mode", NativeLibWrapper.sysPropsRead("ro.support_one_handed_mode"), "false")
    AssertionResult("ro.support_one_handed_mode", NativeLibWrapper.sysPropsReadCb("ro.support_one_handed_mode"), "false")

    AssertionResult("init.svc.vaultkeeper", NativeLibWrapper.sysPropsGet("init.svc.vaultkeeper"), defaultValue)
    AssertionResult("init.svc.vaultkeeper", NativeLibWrapper.sysPropsReadWithNullName("init.svc.vaultkeeper"), defaultValue)
    AssertionResult("init.svc.vaultkeeper", NativeLibWrapper.sysPropsRead("init.svc.vaultkeeper"), defaultValue)
    AssertionResult("init.svc.vaultkeeper", NativeLibWrapper.sysPropsReadCb("init.svc.vaultkeeper"), defaultValue)

    AssertionResult("init.svc.vendor_flash_recovery", NativeLibWrapper.sysPropsGet("init.svc.vendor_flash_recovery"), defaultValue)
    AssertionResult("init.svc.vendor_flash_recovery", NativeLibWrapper.sysPropsReadWithNullName("init.svc.vendor_flash_recovery"), defaultValue)
    AssertionResult("init.svc.vendor_flash_recovery", NativeLibWrapper.sysPropsRead("init.svc.vendor_flash_recovery"), defaultValue)
    AssertionResult("init.svc.vendor_flash_recovery", NativeLibWrapper.sysPropsReadCb("init.svc.vendor_flash_recovery"), defaultValue)

    AssertionResult("ro.board.api_frozen", NativeLibWrapper.sysPropsGet("ro.board.api_frozen"), defaultValue)
    AssertionResult("ro.board.api_frozen", NativeLibWrapper.sysPropsReadWithNullName("ro.board.api_frozen"), defaultValue)
    AssertionResult("ro.board.api_frozen", NativeLibWrapper.sysPropsRead("ro.board.api_frozen"), defaultValue)
    AssertionResult("ro.board.api_frozen", NativeLibWrapper.sysPropsReadCb("ro.board.api_frozen"), defaultValue)

    AssertionResult("init.svc.adb_root", NativeLibWrapper.sysPropsGet("init.svc.adb_root"), defaultValue)
    AssertionResult("init.svc.adb_root", NativeLibWrapper.sysPropsReadWithNullName("init.svc.adb_root"), defaultValue)
    AssertionResult("init.svc.adb_root", NativeLibWrapper.sysPropsRead("init.svc.adb_root"), defaultValue)
    AssertionResult("init.svc.adb_root", NativeLibWrapper.sysPropsReadCb("init.svc.adb_root"), defaultValue)

    AssertionResult("persist.sys.usb.config", NativeLibWrapper.sysPropsGet("persist.sys.usb.config"), "mtp")
    AssertionResult("persist.sys.usb.config", NativeLibWrapper.sysPropsReadWithNullName("persist.sys.usb.config"), "mtp")
    AssertionResult("persist.sys.usb.config", NativeLibWrapper.sysPropsRead("persist.sys.usb.config"), "mtp")
    AssertionResult("persist.sys.usb.config", NativeLibWrapper.sysPropsReadCb("persist.sys.usb.config"), "mtp")

    AssertionResult("sys.usb.config", NativeLibWrapper.sysPropsGet("sys.usb.config"), "mtp")
    AssertionResult("sys.usb.config", NativeLibWrapper.sysPropsReadWithNullName("sys.usb.config"), "mtp")
    AssertionResult("sys.usb.config", NativeLibWrapper.sysPropsRead("sys.usb.config"), "mtp")
    AssertionResult("sys.usb.config", NativeLibWrapper.sysPropsReadCb("sys.usb.config"), "mtp")

    AssertionResult("sys.usb.configfs", NativeLibWrapper.sysPropsGet("sys.usb.configfs"), "1")
    AssertionResult("sys.usb.configfs", NativeLibWrapper.sysPropsReadWithNullName("sys.usb.configfs"), "1")
    AssertionResult("sys.usb.configfs", NativeLibWrapper.sysPropsRead("sys.usb.configfs"), "1")
    AssertionResult("sys.usb.configfs", NativeLibWrapper.sysPropsReadCb("sys.usb.configfs"), "1")

    AssertionResult("init.svc.usbd", NativeLibWrapper.sysPropsGet("init.svc.usbd"), "stopped")
    AssertionResult("init.svc.usbd", NativeLibWrapper.sysPropsReadWithNullName("init.svc.usbd"), "stopped")
    AssertionResult("init.svc.usbd", NativeLibWrapper.sysPropsRead("init.svc.usbd"), "stopped")
    AssertionResult("init.svc.usbd", NativeLibWrapper.sysPropsReadCb("init.svc.usbd"), "stopped")

    AssertionResult("init.svc.adbd", NativeLibWrapper.sysPropsGet("init.svc.adbd"), "stopped")
    AssertionResult("init.svc.adbd", NativeLibWrapper.sysPropsReadWithNullName("init.svc.adbd"), "stopped")
    AssertionResult("init.svc.adbd", NativeLibWrapper.sysPropsRead("init.svc.adbd"), "stopped")
    AssertionResult("init.svc.adbd", NativeLibWrapper.sysPropsReadCb("init.svc.adbd"), "stopped")

    AssertionResult("sys.usb.controller", NativeLibWrapper.sysPropsGet("sys.usb.controller"), defaultValue)
    AssertionResult("sys.usb.controller", NativeLibWrapper.sysPropsReadWithNullName("sys.usb.controller"), defaultValue)
    AssertionResult("sys.usb.controller", NativeLibWrapper.sysPropsRead("sys.usb.controller"), defaultValue)
    AssertionResult("sys.usb.controller", NativeLibWrapper.sysPropsReadCb("sys.usb.controller"), defaultValue)

    AssertionResult("ro.kernel.version", NativeLibWrapper.sysPropsGet("ro.kernel.version"), "6.6")
    AssertionResult("ro.kernel.version", NativeLibWrapper.sysPropsReadWithNullName("ro.kernel.version"), "6.6")
    AssertionResult("ro.kernel.version", NativeLibWrapper.sysPropsRead("ro.kernel.version"), "6.6")
    AssertionResult("ro.kernel.version", NativeLibWrapper.sysPropsReadCb("ro.kernel.version"), "6.6")

    AssertionResult("ro.odm.product.cpu.abilist32", NativeLibWrapper.sysPropsGet("ro.odm.product.cpu.abilist32"), defaultValue)
    AssertionResult("ro.odm.product.cpu.abilist32", NativeLibWrapper.sysPropsReadWithNullName("ro.odm.product.cpu.abilist32"), propInfoNull)
    AssertionResult("ro.odm.product.cpu.abilist32", NativeLibWrapper.sysPropsRead("ro.odm.product.cpu.abilist32"), propInfoNull)
    AssertionResult("ro.odm.product.cpu.abilist32", NativeLibWrapper.sysPropsReadCb("ro.odm.product.cpu.abilist32"), propInfoNull)

    AssertionResult("ro.product.cpu.abilist32", NativeLibWrapper.sysPropsGet("ro.product.cpu.abilist32"), defaultValue)
    AssertionResult("ro.product.cpu.abilist32", NativeLibWrapper.sysPropsReadWithNullName("ro.product.cpu.abilist32"), defaultValue)
    AssertionResult("ro.product.cpu.abilist32", NativeLibWrapper.sysPropsRead("ro.product.cpu.abilist32"), defaultValue)
    AssertionResult("ro.product.cpu.abilist32", NativeLibWrapper.sysPropsReadCb("ro.product.cpu.abilist32"), defaultValue)

    AssertionResult("ro.system.product.cpu.abilist32", NativeLibWrapper.sysPropsGet("ro.system.product.cpu.abilist32"), defaultValue)
    AssertionResult("ro.system.product.cpu.abilist32", NativeLibWrapper.sysPropsReadWithNullName("ro.system.product.cpu.abilist32"), defaultValue)
    AssertionResult("ro.system.product.cpu.abilist32", NativeLibWrapper.sysPropsRead("ro.system.product.cpu.abilist32"), defaultValue)
    AssertionResult("ro.system.product.cpu.abilist32", NativeLibWrapper.sysPropsReadCb("ro.system.product.cpu.abilist32"), defaultValue)

    AssertionResult("ro.vendor.product.cpu.abilist32", NativeLibWrapper.sysPropsGet("ro.vendor.product.cpu.abilist32"), defaultValue)
    AssertionResult("ro.vendor.product.cpu.abilist32", NativeLibWrapper.sysPropsReadWithNullName("ro.vendor.product.cpu.abilist32"), defaultValue)
    AssertionResult("ro.vendor.product.cpu.abilist32", NativeLibWrapper.sysPropsRead("ro.vendor.product.cpu.abilist32"), defaultValue)
    AssertionResult("ro.vendor.product.cpu.abilist32", NativeLibWrapper.sysPropsReadCb("ro.vendor.product.cpu.abilist32"), defaultValue)

    AssertionResult("ro.odm.product.cpu.abilist", NativeLibWrapper.sysPropsGet("ro.odm.product.cpu.abilist"), defaultValue)
    AssertionResult("ro.odm.product.cpu.abilist", NativeLibWrapper.sysPropsReadWithNullName("ro.odm.product.cpu.abilist"), propInfoNull)
    AssertionResult("ro.odm.product.cpu.abilist", NativeLibWrapper.sysPropsRead("ro.odm.product.cpu.abilist"), propInfoNull)
    AssertionResult("ro.odm.product.cpu.abilist", NativeLibWrapper.sysPropsReadCb("ro.odm.product.cpu.abilist"), propInfoNull)

    AssertionResult("ro.product.cpu.abilist", NativeLibWrapper.sysPropsGet("ro.product.cpu.abilist"), "arm64-v8a")
    AssertionResult("ro.product.cpu.abilist", NativeLibWrapper.sysPropsReadWithNullName("ro.product.cpu.abilist"), "arm64-v8a")
    AssertionResult("ro.product.cpu.abilist", NativeLibWrapper.sysPropsRead("ro.product.cpu.abilist"), "arm64-v8a")
    AssertionResult("ro.product.cpu.abilist", NativeLibWrapper.sysPropsReadCb("ro.product.cpu.abilist"), "arm64-v8a")

    AssertionResult("ro.system.product.cpu.abilist", NativeLibWrapper.sysPropsGet("ro.system.product.cpu.abilist"), "arm64-v8a")
    AssertionResult("ro.system.product.cpu.abilist", NativeLibWrapper.sysPropsReadWithNullName("ro.system.product.cpu.abilist"), "arm64-v8a")
    AssertionResult("ro.system.product.cpu.abilist", NativeLibWrapper.sysPropsRead("ro.system.product.cpu.abilist"), "arm64-v8a")
    AssertionResult("ro.system.product.cpu.abilist", NativeLibWrapper.sysPropsReadCb("ro.system.product.cpu.abilist"), "arm64-v8a")

    AssertionResult("ro.vendor.product.cpu.abilist", NativeLibWrapper.sysPropsGet("ro.vendor.product.cpu.abilist"), "arm64-v8a")
    AssertionResult("ro.vendor.product.cpu.abilist", NativeLibWrapper.sysPropsReadWithNullName("ro.vendor.product.cpu.abilist"), "arm64-v8a")
    AssertionResult("ro.vendor.product.cpu.abilist", NativeLibWrapper.sysPropsRead("ro.vendor.product.cpu.abilist"), "arm64-v8a")
    AssertionResult("ro.vendor.product.cpu.abilist", NativeLibWrapper.sysPropsReadCb("ro.vendor.product.cpu.abilist"), "arm64-v8a")

    AssertionResult("ro.zygote", NativeLibWrapper.sysPropsGet("ro.zygote"), "zygote64")
    AssertionResult("ro.zygote", NativeLibWrapper.sysPropsReadWithNullName("ro.zygote"), "zygote64")
    AssertionResult("ro.zygote", NativeLibWrapper.sysPropsRead("ro.zygote"), "zygote64")
    AssertionResult("ro.zygote", NativeLibWrapper.sysPropsReadCb("ro.zygote"), "zygote64")

    AssertionResult("init.svc.zygote_secondary", NativeLibWrapper.sysPropsGet("init.svc.zygote_secondary"), defaultValue)
    AssertionResult("init.svc.zygote_secondary", NativeLibWrapper.sysPropsReadWithNullName("init.svc.zygote_secondary"), defaultValue)
    AssertionResult("init.svc.zygote_secondary", NativeLibWrapper.sysPropsRead("init.svc.zygote_secondary"), defaultValue)
    AssertionResult("init.svc.zygote_secondary", NativeLibWrapper.sysPropsReadCb("init.svc.zygote_secondary"), defaultValue)

    AssertionResult("ro.bootmode", NativeLibWrapper.sysPropsGet("ro.bootmode"), "normal")
    AssertionResult("ro.bootmode", NativeLibWrapper.sysPropsReadWithNullName("ro.bootmode"), "normal")
    AssertionResult("ro.bootmode", NativeLibWrapper.sysPropsRead("ro.bootmode"), "normal")
    AssertionResult("ro.bootmode", NativeLibWrapper.sysPropsReadCb("ro.bootmode"), "normal")

    AssertionResult("bootreceiver.enable", NativeLibWrapper.sysPropsGet("bootreceiver.enable"), "1")
    AssertionResult("bootreceiver.enable", NativeLibWrapper.sysPropsReadWithNullName("bootreceiver.enable"), "1")
    AssertionResult("bootreceiver.enable", NativeLibWrapper.sysPropsRead("bootreceiver.enable"), "1")
    AssertionResult("bootreceiver.enable", NativeLibWrapper.sysPropsReadCb("bootreceiver.enable"), "1")

    AssertionResult("ro.bootloader", NativeLibWrapper.sysPropsGet("ro.bootloader"), bootloader)
    AssertionResult("ro.bootloader", NativeLibWrapper.sysPropsReadWithNullName("ro.bootloader"), bootloader)
    AssertionResult("ro.bootloader", NativeLibWrapper.sysPropsRead("ro.bootloader"), bootloader)
    AssertionResult("ro.bootloader", NativeLibWrapper.sysPropsReadCb("ro.bootloader"), bootloader)

    AssertionResult("ro.soc.manufacturer", NativeLibWrapper.sysPropsGet("ro.soc.manufacturer"), "Google")
    AssertionResult("ro.soc.manufacturer", NativeLibWrapper.sysPropsReadWithNullName("ro.soc.manufacturer"), "Google")
    AssertionResult("ro.soc.manufacturer", NativeLibWrapper.sysPropsRead("ro.soc.manufacturer"), "Google")
    AssertionResult("ro.soc.manufacturer", NativeLibWrapper.sysPropsReadCb("ro.soc.manufacturer"), "Google")

    AssertionResult("ro.soc.model", NativeLibWrapper.sysPropsGet("ro.soc.model"), "Tensor G3")
    AssertionResult("ro.soc.model", NativeLibWrapper.sysPropsReadWithNullName("ro.soc.model"), "Tensor G3")
    AssertionResult("ro.soc.model", NativeLibWrapper.sysPropsRead("ro.soc.model"), "Tensor G3")
    AssertionResult("ro.soc.model", NativeLibWrapper.sysPropsReadCb("ro.soc.model"), "Tensor G3")

    AssertionResult("ro.boot.boot_devices", NativeLibWrapper.sysPropsGet("ro.boot.boot_devices"), "soc/1d84000.ufshc")
    AssertionResult("ro.boot.boot_devices", NativeLibWrapper.sysPropsReadWithNullName("ro.boot.boot_devices"), "soc/1d84000.ufshc")
    AssertionResult("ro.boot.boot_devices", NativeLibWrapper.sysPropsRead("ro.boot.boot_devices"), "soc/1d84000.ufshc")
    AssertionResult("ro.boot.boot_devices", NativeLibWrapper.sysPropsReadCb("ro.boot.boot_devices"), "soc/1d84000.ufshc")

    AssertionResult("ro.boot.bootloader", NativeLibWrapper.sysPropsGet("ro.boot.bootloader"), bootloader)
    AssertionResult("ro.boot.bootloader", NativeLibWrapper.sysPropsReadWithNullName("ro.boot.bootloader"), bootloader)
    AssertionResult("ro.boot.bootloader", NativeLibWrapper.sysPropsRead("ro.boot.bootloader"), bootloader)
    AssertionResult("ro.boot.bootloader", NativeLibWrapper.sysPropsReadCb("ro.boot.bootloader"), bootloader)

    AssertionResult("ro.boot.em.did", NativeLibWrapper.sysPropsGet("ro.boot.em.did"), defaultValue)
    AssertionResult("ro.boot.em.did", NativeLibWrapper.sysPropsReadWithNullName("ro.boot.em.did"), defaultValue)
    AssertionResult("ro.boot.em.did", NativeLibWrapper.sysPropsRead("ro.boot.em.did"), defaultValue)
    AssertionResult("ro.boot.em.did", NativeLibWrapper.sysPropsReadCb("ro.boot.em.did"), defaultValue)

    AssertionResult("ro.boot.em.model", NativeLibWrapper.sysPropsGet("ro.boot.em.model"), bootloader)
    AssertionResult("ro.boot.em.model", NativeLibWrapper.sysPropsReadWithNullName("ro.boot.em.model"), bootloader)
    AssertionResult("ro.boot.em.model", NativeLibWrapper.sysPropsRead("ro.boot.em.model"), bootloader)
    AssertionResult("ro.boot.em.model", NativeLibWrapper.sysPropsReadCb("ro.boot.em.model"), bootloader)

    AssertionResult("ro.boot.hardware", NativeLibWrapper.sysPropsGet("ro.boot.hardware"), "zuma")
    AssertionResult("ro.boot.hardware", NativeLibWrapper.sysPropsReadWithNullName("ro.boot.hardware"), "zuma")
    AssertionResult("ro.boot.hardware", NativeLibWrapper.sysPropsRead("ro.boot.hardware"), "zuma")
    AssertionResult("ro.boot.hardware", NativeLibWrapper.sysPropsReadCb("ro.boot.hardware"), "zuma")

    AssertionResult("ro.boot.odin_download", NativeLibWrapper.sysPropsGet("ro.boot.odin_download"), defaultValue)
    AssertionResult("ro.boot.odin_download", NativeLibWrapper.sysPropsReadWithNullName("ro.boot.odin_download"), defaultValue)
    AssertionResult("ro.boot.odin_download", NativeLibWrapper.sysPropsRead("ro.boot.odin_download"), defaultValue)
    AssertionResult("ro.boot.odin_download", NativeLibWrapper.sysPropsReadCb("ro.boot.odin_download"), defaultValue)

    AssertionResult("ro.boot.wb.snapQB", NativeLibWrapper.sysPropsGet("ro.boot.wb.snapQB"), defaultValue)
    AssertionResult("ro.boot.wb.snapQB", NativeLibWrapper.sysPropsReadWithNullName("ro.boot.wb.snapQB"), defaultValue)
    AssertionResult("ro.boot.wb.snapQB", NativeLibWrapper.sysPropsRead("ro.boot.wb.snapQB"), defaultValue)
    AssertionResult("ro.boot.wb.snapQB", NativeLibWrapper.sysPropsReadCb("ro.boot.wb.snapQB"), defaultValue)

    AssertionResult("ro.com.google.clientidbase", NativeLibWrapper.sysPropsGet("ro.com.google.clientidbase"), "android-google")
    AssertionResult("ro.com.google.clientidbase", NativeLibWrapper.sysPropsReadWithNullName("ro.com.google.clientidbase"), "android-google")
    AssertionResult("ro.com.google.clientidbase", NativeLibWrapper.sysPropsRead("ro.com.google.clientidbase"), "android-google")
    AssertionResult("ro.com.google.clientidbase", NativeLibWrapper.sysPropsReadCb("ro.com.google.clientidbase"), "android-google")

    AssertionResult("ro.hardware", NativeLibWrapper.sysPropsGet("ro.hardware"), "zuma")
    AssertionResult("ro.hardware", NativeLibWrapper.sysPropsReadWithNullName("ro.hardware"), "zuma")
    AssertionResult("ro.hardware", NativeLibWrapper.sysPropsRead("ro.hardware"), "zuma")
    AssertionResult("ro.hardware", NativeLibWrapper.sysPropsReadCb("ro.hardware"), "zuma")

    AssertionResult("ro.boot.ap_serial", NativeLibWrapper.sysPropsGet("ro.boot.ap_serial"), defaultValue)
    AssertionResult("ro.boot.ap_serial", NativeLibWrapper.sysPropsReadWithNullName("ro.boot.ap_serial"), defaultValue)
    AssertionResult("ro.boot.ap_serial", NativeLibWrapper.sysPropsRead("ro.boot.ap_serial"), defaultValue)
    AssertionResult("ro.boot.ap_serial", NativeLibWrapper.sysPropsReadCb("ro.boot.ap_serial"), defaultValue)

    AssertionResult("ro.boot.verifiedbootstate", NativeLibWrapper.sysPropsGet("ro.boot.verifiedbootstate"), "green")
    AssertionResult("ro.boot.verifiedbootstate", NativeLibWrapper.sysPropsReadWithNullName("ro.boot.verifiedbootstate"), "green")
    AssertionResult("ro.boot.verifiedbootstate", NativeLibWrapper.sysPropsRead("ro.boot.verifiedbootstate"), "green")
    AssertionResult("ro.boot.verifiedbootstate", NativeLibWrapper.sysPropsReadCb("ro.boot.verifiedbootstate"), "green")

    AssertionResult("ro.boot.warranty_bit", NativeLibWrapper.sysPropsGet("ro.boot.warranty_bit"), defaultValue)
    AssertionResult("ro.boot.warranty_bit", NativeLibWrapper.sysPropsReadWithNullName("ro.boot.warranty_bit"), defaultValue)
    AssertionResult("ro.boot.warranty_bit", NativeLibWrapper.sysPropsRead("ro.boot.warranty_bit"), defaultValue)
    AssertionResult("ro.boot.warranty_bit", NativeLibWrapper.sysPropsReadCb("ro.boot.warranty_bit"), defaultValue)

    AssertionResult("ro.boot.force_upload", NativeLibWrapper.sysPropsGet("ro.boot.force_upload"), defaultValue)
    AssertionResult("ro.boot.force_upload", NativeLibWrapper.sysPropsReadWithNullName("ro.boot.force_upload"), defaultValue)
    AssertionResult("ro.boot.force_upload", NativeLibWrapper.sysPropsRead("ro.boot.force_upload"), defaultValue)
    AssertionResult("ro.boot.force_upload", NativeLibWrapper.sysPropsReadCb("ro.boot.force_upload"), defaultValue)

    AssertionResult("sys.oem_unlock_allowed", NativeLibWrapper.sysPropsGet("sys.oem_unlock_allowed"), "0")
    AssertionResult("sys.oem_unlock_allowed", NativeLibWrapper.sysPropsReadWithNullName("sys.oem_unlock_allowed"), "0")
    AssertionResult("sys.oem_unlock_allowed", NativeLibWrapper.sysPropsRead("sys.oem_unlock_allowed"), "0")
    AssertionResult("sys.oem_unlock_allowed", NativeLibWrapper.sysPropsReadCb("sys.oem_unlock_allowed"), "0")

    AssertionResult("ro.boot.write_protect", NativeLibWrapper.sysPropsGet("ro.boot.write_protect"), "1")
    AssertionResult("ro.boot.write_protect", NativeLibWrapper.sysPropsReadWithNullName("ro.boot.write_protect"), "1")
    AssertionResult("ro.boot.write_protect", NativeLibWrapper.sysPropsRead("ro.boot.write_protect"), "1")
    AssertionResult("ro.boot.write_protect", NativeLibWrapper.sysPropsReadCb("ro.boot.write_protect"), "1")

    AssertionResult("ro.boot.veritymode.managed", NativeLibWrapper.sysPropsGet("ro.boot.veritymode.managed"), "yes")
    AssertionResult("ro.boot.veritymode.managed", NativeLibWrapper.sysPropsReadWithNullName("ro.boot.veritymode.managed"), "yes")
    AssertionResult("ro.boot.veritymode.managed", NativeLibWrapper.sysPropsRead("ro.boot.veritymode.managed"), "yes")
    AssertionResult("ro.boot.veritymode.managed", NativeLibWrapper.sysPropsReadCb("ro.boot.veritymode.managed"), "yes")

    AssertionResult("ro.boot.veritymode", NativeLibWrapper.sysPropsGet("ro.boot.veritymode"), "enforcing")
    AssertionResult("ro.boot.veritymode", NativeLibWrapper.sysPropsReadWithNullName("ro.boot.veritymode"), "enforcing")
    AssertionResult("ro.boot.veritymode", NativeLibWrapper.sysPropsRead("ro.boot.veritymode"), "enforcing")
    AssertionResult("ro.boot.veritymode", NativeLibWrapper.sysPropsReadCb("ro.boot.veritymode"), "enforcing")

    AssertionResult("ro.boot.vbmeta.hash_alg", NativeLibWrapper.sysPropsGet("ro.boot.vbmeta.hash_alg"), "sha256")
    AssertionResult("ro.boot.vbmeta.hash_alg", NativeLibWrapper.sysPropsReadWithNullName("ro.boot.vbmeta.hash_alg"), "sha256")
    AssertionResult("ro.boot.vbmeta.hash_alg", NativeLibWrapper.sysPropsRead("ro.boot.vbmeta.hash_alg"), "sha256")
    AssertionResult("ro.boot.vbmeta.hash_alg", NativeLibWrapper.sysPropsReadCb("ro.boot.vbmeta.hash_alg"), "sha256")

    AssertionResult("ro.boot.vbmeta.device_state", NativeLibWrapper.sysPropsGet("ro.boot.vbmeta.device_state"), "locked")
    AssertionResult("ro.boot.vbmeta.device_state", NativeLibWrapper.sysPropsReadWithNullName("ro.boot.vbmeta.device_state"), "locked")
    AssertionResult("ro.boot.vbmeta.device_state", NativeLibWrapper.sysPropsRead("ro.boot.vbmeta.device_state"), "locked")
    AssertionResult("ro.boot.vbmeta.device_state", NativeLibWrapper.sysPropsReadCb("ro.boot.vbmeta.device_state"), "locked")

    AssertionResult("ro.boot.vbmeta.avb_version", NativeLibWrapper.sysPropsGet("ro.boot.vbmeta.avb_version"), "1.2")
    AssertionResult("ro.boot.vbmeta.avb_version", NativeLibWrapper.sysPropsReadWithNullName("ro.boot.vbmeta.avb_version"), "1.2")
    AssertionResult("ro.boot.vbmeta.avb_version", NativeLibWrapper.sysPropsRead("ro.boot.vbmeta.avb_version"), "1.2")
    AssertionResult("ro.boot.vbmeta.avb_version", NativeLibWrapper.sysPropsReadCb("ro.boot.vbmeta.avb_version"), "1.2")

    AssertionResult("ro.boot.secure_hardware", NativeLibWrapper.sysPropsGet("ro.boot.secure_hardware"), "1")
    AssertionResult("ro.boot.secure_hardware", NativeLibWrapper.sysPropsReadWithNullName("ro.boot.secure_hardware"), "1")
    AssertionResult("ro.boot.secure_hardware", NativeLibWrapper.sysPropsRead("ro.boot.secure_hardware"), "1")
    AssertionResult("ro.boot.secure_hardware", NativeLibWrapper.sysPropsReadCb("ro.boot.secure_hardware"), "1")

    AssertionResult("ro.boot.mode", NativeLibWrapper.sysPropsGet("ro.boot.mode"), "normal")
    AssertionResult("ro.boot.mode", NativeLibWrapper.sysPropsReadWithNullName("ro.boot.mode"), "normal")
    AssertionResult("ro.boot.mode", NativeLibWrapper.sysPropsRead("ro.boot.mode"), "normal")
    AssertionResult("ro.boot.mode", NativeLibWrapper.sysPropsReadCb("ro.boot.mode"), "normal")

    AssertionResult("ro.boot.force_normal_boot", NativeLibWrapper.sysPropsGet("ro.boot.force_normal_boot"), "1")
    AssertionResult("ro.boot.force_normal_boot", NativeLibWrapper.sysPropsReadWithNullName("ro.boot.force_normal_boot"), "1")
    AssertionResult("ro.boot.force_normal_boot", NativeLibWrapper.sysPropsRead("ro.boot.force_normal_boot"), "1")
    AssertionResult("ro.boot.force_normal_boot", NativeLibWrapper.sysPropsReadCb("ro.boot.force_normal_boot"), "1")

    AssertionResult("ro.boot.flash.locked", NativeLibWrapper.sysPropsGet("ro.boot.flash.locked"), "1")
    AssertionResult("ro.boot.flash.locked", NativeLibWrapper.sysPropsReadWithNullName("ro.boot.flash.locked"), "1")
    AssertionResult("ro.boot.flash.locked", NativeLibWrapper.sysPropsRead("ro.boot.flash.locked"), "1")
    AssertionResult("ro.boot.flash.locked", NativeLibWrapper.sysPropsReadCb("ro.boot.flash.locked"), "1")

    AssertionResult("ro.boot.avb_version", NativeLibWrapper.sysPropsGet("ro.boot.avb_version"), "1.2")
    AssertionResult("ro.boot.avb_version", NativeLibWrapper.sysPropsReadWithNullName("ro.boot.avb_version"), "1.2")
    AssertionResult("ro.boot.avb_version", NativeLibWrapper.sysPropsRead("ro.boot.avb_version"), "1.2")
    AssertionResult("ro.boot.avb_version", NativeLibWrapper.sysPropsReadCb("ro.boot.avb_version"), "1.2")

    AssertionResult("ro.carrier", NativeLibWrapper.sysPropsGet("ro.carrier"), "retbr")
    AssertionResult("ro.carrier", NativeLibWrapper.sysPropsReadWithNullName("ro.carrier"), "retbr")
    AssertionResult("ro.carrier", NativeLibWrapper.sysPropsRead("ro.carrier"), "retbr")
    AssertionResult("ro.carrier", NativeLibWrapper.sysPropsReadCb("ro.carrier"), "retbr")

    AssertionResult("ro.boot.carrierid", NativeLibWrapper.sysPropsGet("ro.boot.carrierid"), defaultValue)
    AssertionResult("ro.boot.carrierid", NativeLibWrapper.sysPropsReadWithNullName("ro.boot.carrierid"), defaultValue)
    AssertionResult("ro.boot.carrierid", NativeLibWrapper.sysPropsRead("ro.boot.carrierid"), defaultValue)
    AssertionResult("ro.boot.carrierid", NativeLibWrapper.sysPropsReadCb("ro.boot.carrierid"), defaultValue)

    AssertionResult("gsm.sim.state", NativeLibWrapper.sysPropsGet("gsm.sim.state"), "READY,")
    AssertionResult("gsm.sim.state", NativeLibWrapper.sysPropsReadWithNullName("gsm.sim.state"), "READY,")
    AssertionResult("gsm.sim.state", NativeLibWrapper.sysPropsRead("gsm.sim.state"), "READY,")
    AssertionResult("gsm.sim.state", NativeLibWrapper.sysPropsReadCb("gsm.sim.state"), "READY,")

    AssertionResult("gsm.sim.eventList", NativeLibWrapper.sysPropsGet("gsm.sim.eventList"), defaultValue)
    AssertionResult("gsm.sim.eventList", NativeLibWrapper.sysPropsReadWithNullName("gsm.sim.eventList"), defaultValue)
    AssertionResult("gsm.sim.eventList", NativeLibWrapper.sysPropsRead("gsm.sim.eventList"), defaultValue)
    AssertionResult("gsm.sim.eventList", NativeLibWrapper.sysPropsReadCb("gsm.sim.eventList"), defaultValue)

    AssertionResult("ril.simoperator", NativeLibWrapper.sysPropsGet("ril.simoperator"), ",")
    AssertionResult("ril.simoperator", NativeLibWrapper.sysPropsReadWithNullName("ril.simoperator"), ",")
    AssertionResult("ril.simoperator", NativeLibWrapper.sysPropsRead("ril.simoperator"), ",")
    AssertionResult("ril.simoperator", NativeLibWrapper.sysPropsReadCb("ril.simoperator"), ",")

    AssertionResult("ril.cidManager.initiated", NativeLibWrapper.sysPropsGet("ril.cidManager.initiated"), "1")
    AssertionResult("ril.cidManager.initiated", NativeLibWrapper.sysPropsReadWithNullName("ril.cidManager.initiated"), "1")
    AssertionResult("ril.cidManager.initiated", NativeLibWrapper.sysPropsRead("ril.cidManager.initiated"), "1")
    AssertionResult("ril.cidManager.initiated", NativeLibWrapper.sysPropsReadCb("ril.cidManager.initiated"), "1")

    AssertionResult("ril.dds.call.ongoing0", NativeLibWrapper.sysPropsGet("ril.dds.call.ongoing0"), "0")
    AssertionResult("ril.dds.call.ongoing0", NativeLibWrapper.sysPropsReadWithNullName("ril.dds.call.ongoing0"), "0")
    AssertionResult("ril.dds.call.ongoing0", NativeLibWrapper.sysPropsRead("ril.dds.call.ongoing0"), "0")
    AssertionResult("ril.dds.call.ongoing0", NativeLibWrapper.sysPropsReadCb("ril.dds.call.ongoing0"), "0")

    AssertionResult("ril.dds.call.ongoing1", NativeLibWrapper.sysPropsGet("ril.dds.call.ongoing1"), "0")
    AssertionResult("ril.dds.call.ongoing1", NativeLibWrapper.sysPropsReadWithNullName("ril.dds.call.ongoing1"), "0")
    AssertionResult("ril.dds.call.ongoing1", NativeLibWrapper.sysPropsRead("ril.dds.call.ongoing1"), "0")
    AssertionResult("ril.dds.call.ongoing1", NativeLibWrapper.sysPropsReadCb("ril.dds.call.ongoing1"), "0")

    AssertionResult("ril.modem.board", NativeLibWrapper.sysPropsGet("ril.modem.board"), defaultValue)
    AssertionResult("ril.modem.board", NativeLibWrapper.sysPropsReadWithNullName("ril.modem.board"), defaultValue)
    AssertionResult("ril.modem.board", NativeLibWrapper.sysPropsRead("ril.modem.board"), defaultValue)
    AssertionResult("ril.modem.board", NativeLibWrapper.sysPropsReadCb("ril.modem.board"), defaultValue)

    AssertionResult("ril.modem.board2", NativeLibWrapper.sysPropsGet("ril.modem.board2"), defaultValue)
    AssertionResult("ril.modem.board2", NativeLibWrapper.sysPropsReadWithNullName("ril.modem.board2"), defaultValue)
    AssertionResult("ril.modem.board2", NativeLibWrapper.sysPropsRead("ril.modem.board2"), defaultValue)
    AssertionResult("ril.modem.board2", NativeLibWrapper.sysPropsReadCb("ril.modem.board2"), defaultValue)

    AssertionResult("ril.attach.apn0", NativeLibWrapper.sysPropsGet("ril.attach.apn0"), defaultValue)
    AssertionResult("ril.attach.apn0", NativeLibWrapper.sysPropsReadWithNullName("ril.attach.apn0"), defaultValue)
    AssertionResult("ril.attach.apn0", NativeLibWrapper.sysPropsRead("ril.attach.apn0"), defaultValue)
    AssertionResult("ril.attach.apn0", NativeLibWrapper.sysPropsReadCb("ril.attach.apn0"), defaultValue)

    AssertionResult("ril.hw_ver", NativeLibWrapper.sysPropsGet("ril.hw_ver"), defaultValue)
    AssertionResult("ril.hw_ver", NativeLibWrapper.sysPropsReadWithNullName("ril.hw_ver"), defaultValue)
    AssertionResult("ril.hw_ver", NativeLibWrapper.sysPropsRead("ril.hw_ver"), defaultValue)
    AssertionResult("ril.hw_ver", NativeLibWrapper.sysPropsReadCb("ril.hw_ver"), defaultValue)

    AssertionResult("ril.hw_ver2", NativeLibWrapper.sysPropsGet("ril.hw_ver2"), defaultValue)
    AssertionResult("ril.hw_ver2", NativeLibWrapper.sysPropsReadWithNullName("ril.hw_ver2"), defaultValue)
    AssertionResult("ril.hw_ver2", NativeLibWrapper.sysPropsRead("ril.hw_ver2"), defaultValue)
    AssertionResult("ril.hw_ver2", NativeLibWrapper.sysPropsReadCb("ril.hw_ver2"), defaultValue)

    AssertionResult("ril.model_id", NativeLibWrapper.sysPropsGet("ril.model_id"), defaultValue)
    AssertionResult("ril.model_id", NativeLibWrapper.sysPropsReadWithNullName("ril.model_id"), defaultValue)
    AssertionResult("ril.model_id", NativeLibWrapper.sysPropsRead("ril.model_id"), defaultValue)
    AssertionResult("ril.model_id", NativeLibWrapper.sysPropsReadCb("ril.model_id"), defaultValue)

    AssertionResult("ril.model_id2", NativeLibWrapper.sysPropsGet("ril.model_id2"), defaultValue)
    AssertionResult("ril.model_id2", NativeLibWrapper.sysPropsReadWithNullName("ril.model_id2"), defaultValue)
    AssertionResult("ril.model_id2", NativeLibWrapper.sysPropsRead("ril.model_id2"), defaultValue)
    AssertionResult("ril.model_id2", NativeLibWrapper.sysPropsReadCb("ril.model_id2"), defaultValue)

    AssertionResult("ril.rfcal_date", NativeLibWrapper.sysPropsGet("ril.rfcal_date"), defaultValue)
    AssertionResult("ril.rfcal_date", NativeLibWrapper.sysPropsReadWithNullName("ril.rfcal_date"), defaultValue)
    AssertionResult("ril.rfcal_date", NativeLibWrapper.sysPropsRead("ril.rfcal_date"), defaultValue)
    AssertionResult("ril.rfcal_date", NativeLibWrapper.sysPropsReadCb("ril.rfcal_date"), defaultValue)

    AssertionResult("ril.rfcal_date2", NativeLibWrapper.sysPropsGet("ril.rfcal_date2"), defaultValue)
    AssertionResult("ril.rfcal_date2", NativeLibWrapper.sysPropsReadWithNullName("ril.rfcal_date2"), defaultValue)
    AssertionResult("ril.rfcal_date2", NativeLibWrapper.sysPropsRead("ril.rfcal_date2"), defaultValue)
    AssertionResult("ril.rfcal_date2", NativeLibWrapper.sysPropsReadCb("ril.rfcal_date2"), defaultValue)

    AssertionResult("ril.product_code", NativeLibWrapper.sysPropsGet("ril.product_code"), defaultValue)
    AssertionResult("ril.product_code", NativeLibWrapper.sysPropsReadWithNullName("ril.product_code"), defaultValue)
    AssertionResult("ril.product_code", NativeLibWrapper.sysPropsRead("ril.product_code"), defaultValue)
    AssertionResult("ril.product_code", NativeLibWrapper.sysPropsReadCb("ril.product_code"), defaultValue)

    AssertionResult("ril.product_code2", NativeLibWrapper.sysPropsGet("ril.product_code2"), defaultValue)
    AssertionResult("ril.product_code2", NativeLibWrapper.sysPropsReadWithNullName("ril.product_code2"), defaultValue)
    AssertionResult("ril.product_code2", NativeLibWrapper.sysPropsRead("ril.product_code2"), defaultValue)
    AssertionResult("ril.product_code2", NativeLibWrapper.sysPropsReadCb("ril.product_code2"), defaultValue)

    AssertionResult("gsm.operator.iso-country", NativeLibWrapper.sysPropsGet("gsm.operator.iso-country"), "br,")
    AssertionResult("gsm.operator.iso-country", NativeLibWrapper.sysPropsReadWithNullName("gsm.operator.iso-country"), "br,")
    AssertionResult("gsm.operator.iso-country", NativeLibWrapper.sysPropsRead("gsm.operator.iso-country"), "br,")
    AssertionResult("gsm.operator.iso-country", NativeLibWrapper.sysPropsReadCb("gsm.operator.iso-country"), "br,")

    AssertionResult("gsm.sim.operator.iso-country", NativeLibWrapper.sysPropsGet("gsm.sim.operator.iso-country"), "br,")
    AssertionResult("gsm.sim.operator.iso-country", NativeLibWrapper.sysPropsReadWithNullName("gsm.sim.operator.iso-country"), "br,")
    AssertionResult("gsm.sim.operator.iso-country", NativeLibWrapper.sysPropsRead("gsm.sim.operator.iso-country"), "br,")
    AssertionResult("gsm.sim.operator.iso-country", NativeLibWrapper.sysPropsReadCb("gsm.sim.operator.iso-country"), "br,")

    AssertionResult("gsm.sim.operator.numeric", NativeLibWrapper.sysPropsGet("gsm.sim.operator.numeric"), "72406,")
    AssertionResult("gsm.sim.operator.numeric", NativeLibWrapper.sysPropsReadWithNullName("gsm.sim.operator.numeric"), "72406,")
    AssertionResult("gsm.sim.operator.numeric", NativeLibWrapper.sysPropsRead("gsm.sim.operator.numeric"), "72406,")
    AssertionResult("gsm.sim.operator.numeric", NativeLibWrapper.sysPropsReadCb("gsm.sim.operator.numeric"), "72406,")

    AssertionResult("gsm.operator.numeric", NativeLibWrapper.sysPropsGet("gsm.operator.numeric"), "72406,")
    AssertionResult("gsm.operator.numeric", NativeLibWrapper.sysPropsReadWithNullName("gsm.operator.numeric"), "72406,")
    AssertionResult("gsm.operator.numeric", NativeLibWrapper.sysPropsRead("gsm.operator.numeric"), "72406,")
    AssertionResult("gsm.operator.numeric", NativeLibWrapper.sysPropsReadCb("gsm.operator.numeric"), "72406,")

    AssertionResult("gsm.sim.operator.alpha", NativeLibWrapper.sysPropsGet("gsm.sim.operator.alpha"), "Vivo,")
    AssertionResult("gsm.sim.operator.alpha", NativeLibWrapper.sysPropsReadWithNullName("gsm.sim.operator.alpha"), "Vivo,")
    AssertionResult("gsm.sim.operator.alpha", NativeLibWrapper.sysPropsRead("gsm.sim.operator.alpha"), "Vivo,")
    AssertionResult("gsm.sim.operator.alpha", NativeLibWrapper.sysPropsReadCb("gsm.sim.operator.alpha"), "Vivo,")

    AssertionResult("gsm.operator.alpha", NativeLibWrapper.sysPropsGet("gsm.operator.alpha"), "Vivo,")
    AssertionResult("gsm.operator.alpha", NativeLibWrapper.sysPropsReadWithNullName("gsm.operator.alpha"),"Vivo,")
    AssertionResult("gsm.operator.alpha", NativeLibWrapper.sysPropsRead("gsm.operator.alpha"), "Vivo,")
    AssertionResult("gsm.operator.alpha", NativeLibWrapper.sysPropsReadCb("gsm.operator.alpha"), "Vivo,")

    AssertionResult("debug.tracing.mnc", NativeLibWrapper.sysPropsGet("debug.tracing.mnc"), "6")
    AssertionResult("debug.tracing.mnc", NativeLibWrapper.sysPropsReadWithNullName("debug.tracing.mnc"), "6")
    AssertionResult("debug.tracing.mnc", NativeLibWrapper.sysPropsRead("debug.tracing.mnc"), "6")
    AssertionResult("debug.tracing.mnc", NativeLibWrapper.sysPropsReadCb("debug.tracing.mnc"), "6")

//    AssertionResult("ro.sf.lcd_density", NativeLibWrapper.sysPropsGet("ro.sf.lcd_density"), "400")
//    AssertionResult("ro.sf.lcd_density", NativeLibWrapper.sysPropsReadWithNullName("ro.sf.lcd_density"), "400")
//    AssertionResult("ro.sf.lcd_density", NativeLibWrapper.sysPropsRead("ro.sf.lcd_density"), "400")
//    AssertionResult("ro.sf.lcd_density", NativeLibWrapper.sysPropsReadCb("ro.sf.lcd_density"), "400")

    AssertionResult("ro.boot.selinux", NativeLibWrapper.sysPropsGet("ro.boot.selinux"), "enforcing")
    AssertionResult("ro.boot.selinux", NativeLibWrapper.sysPropsReadWithNullName("ro.boot.selinux"), "enforcing")
    AssertionResult("ro.boot.selinux", NativeLibWrapper.sysPropsRead("ro.boot.selinux"), "enforcing")
    AssertionResult("ro.boot.selinux", NativeLibWrapper.sysPropsReadCb("ro.boot.selinux"), "enforcing")

    AssertionResult("ro.adb.secure", NativeLibWrapper.sysPropsGet("ro.adb.secure"), "1")
    AssertionResult("ro.adb.secure", NativeLibWrapper.sysPropsReadWithNullName("ro.adb.secure"), "1")
    AssertionResult("ro.adb.secure", NativeLibWrapper.sysPropsRead("ro.adb.secure"), "1")
    AssertionResult("ro.adb.secure", NativeLibWrapper.sysPropsReadCb("ro.adb.secure"), "1")

    AssertionResult("ro.allow.mock.location", NativeLibWrapper.sysPropsGet("ro.allow.mock.location"), "0")
    AssertionResult("ro.allow.mock.location", NativeLibWrapper.sysPropsReadWithNullName("ro.allow.mock.location"), "0")
    AssertionResult("ro.allow.mock.location", NativeLibWrapper.sysPropsRead("ro.allow.mock.location"), "0")
    AssertionResult("ro.allow.mock.location", NativeLibWrapper.sysPropsReadCb("ro.allow.mock.location"), "0")

    AssertionResult("persist.sys.strictmode.disable", NativeLibWrapper.sysPropsGet("persist.sys.strictmode.disable"), "true")
    AssertionResult("persist.sys.strictmode.disable", NativeLibWrapper.sysPropsReadWithNullName("persist.sys.strictmode.disable"), "true")
    AssertionResult("persist.sys.strictmode.disable", NativeLibWrapper.sysPropsRead("persist.sys.strictmode.disable"), "true")
    AssertionResult("persist.sys.strictmode.disable", NativeLibWrapper.sysPropsReadCb("persist.sys.strictmode.disable"), "true")

    AssertionResult("ro.control_privapp_permissions", NativeLibWrapper.sysPropsGet("ro.control_privapp_permissions"), "enforce")
    AssertionResult("ro.control_privapp_permissions", NativeLibWrapper.sysPropsReadWithNullName("ro.control_privapp_permissions"), "enforce")
    AssertionResult("ro.control_privapp_permissions", NativeLibWrapper.sysPropsRead("ro.control_privapp_permissions"), "enforce")
    AssertionResult("ro.control_privapp_permissions", NativeLibWrapper.sysPropsReadCb("ro.control_privapp_permissions"), "enforce")

    AssertionResult("ro.build.characteristics", NativeLibWrapper.sysPropsGet("ro.build.characteristics"), "default")
    AssertionResult("ro.build.characteristics", NativeLibWrapper.sysPropsReadWithNullName("ro.build.characteristics"), "default")
    AssertionResult("ro.build.characteristics", NativeLibWrapper.sysPropsRead("ro.build.characteristics"), "default")
    AssertionResult("ro.build.characteristics", NativeLibWrapper.sysPropsReadCb("ro.build.characteristics"), "default")

//    AssertionResult("ro.surface_flinger.enable_frame_rate_override", NativeLibWrapper.sysPropsGet("ro.surface_flinger.enable_frame_rate_override"), "false")
//    AssertionResult("ro.surface_flinger.enable_frame_rate_override", NativeLibWrapper.sysPropsReadWithNullName("ro.surface_flinger.enable_frame_rate_override"), propInfoNull)
//    AssertionResult("ro.surface_flinger.enable_frame_rate_override", NativeLibWrapper.sysPropsRead("ro.surface_flinger.enable_frame_rate_override"), "false")
//    AssertionResult("ro.surface_flinger.enable_frame_rate_override", NativeLibWrapper.sysPropsReadCb("ro.surface_flinger.enable_frame_rate_override"), "false")

//    AssertionResult("ro.surface_flinger.game_default_frame_rate_override", NativeLibWrapper.sysPropsGet("ro.surface_flinger.game_default_frame_rate_override"), "60")
//    AssertionResult("ro.surface_flinger.game_default_frame_rate_override", NativeLibWrapper.sysPropsReadWithNullName("ro.surface_flinger.game_default_frame_rate_override"), propInfoNull)
//    AssertionResult("ro.surface_flinger.game_default_frame_rate_override", NativeLibWrapper.sysPropsRead("ro.surface_flinger.game_default_frame_rate_override"), "60")
//    AssertionResult("ro.surface_flinger.game_default_frame_rate_override", NativeLibWrapper.sysPropsReadCb("ro.surface_flinger.game_default_frame_rate_override"), "60")

    AssertionResult("security.perf_harden", NativeLibWrapper.sysPropsGet("security.perf_harden"), "1")
    AssertionResult("security.perf_harden", NativeLibWrapper.sysPropsReadWithNullName("security.perf_harden"), "1")
    AssertionResult("security.perf_harden", NativeLibWrapper.sysPropsRead("security.perf_harden"), "1")
    AssertionResult("security.perf_harden", NativeLibWrapper.sysPropsReadCb("security.perf_harden"), "1")

    AssertionResult("ril.halservice.registered.slot1", NativeLibWrapper.sysPropsGet("ril.halservice.registered.slot1"), "true")
    AssertionResult("ril.halservice.registered.slot1", NativeLibWrapper.sysPropsReadWithNullName("ril.halservice.registered.slot1"), "true")
    AssertionResult("ril.halservice.registered.slot1", NativeLibWrapper.sysPropsRead("ril.halservice.registered.slot1"), "true")
    AssertionResult("ril.halservice.registered.slot1", NativeLibWrapper.sysPropsReadCb("ril.halservice.registered.slot1"), "true")

    AssertionResult("ril.halservice.registered.slot2", NativeLibWrapper.sysPropsGet("ril.halservice.registered.slot2"), "true")
    AssertionResult("ril.halservice.registered.slot2", NativeLibWrapper.sysPropsReadWithNullName("ril.halservice.registered.slot2"), "true")
    AssertionResult("ril.halservice.registered.slot2", NativeLibWrapper.sysPropsRead("ril.halservice.registered.slot2"), "true")
    AssertionResult("ril.halservice.registered.slot2", NativeLibWrapper.sysPropsReadCb("ril.halservice.registered.slot2"), "true")

    AssertionResult("ril.rejectedPlmn", NativeLibWrapper.sysPropsGet("ril.rejectedPlmn"), ",")
    AssertionResult("ril.rejectedPlmn", NativeLibWrapper.sysPropsReadWithNullName("ril.rejectedPlmn"), ",")
    AssertionResult("ril.rejectedPlmn", NativeLibWrapper.sysPropsRead("ril.rejectedPlmn"), ",")
    AssertionResult("ril.rejectedPlmn", NativeLibWrapper.sysPropsReadCb("ril.rejectedPlmn"), ",")
}

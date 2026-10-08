package com.omarmesqq.grunfeld.ui.screens

import android.Manifest
import android.annotation.SuppressLint
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import android.os.Process
import android.os.Process.myUserHandle
import android.telephony.TelephonyManager
import android.text.format.Formatter
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.core.net.toUri
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.omarmesqq.grunfeld.data.DeviceIdState
import com.omarmesqq.grunfeld.data.RootCheckResult
import com.omarmesqq.grunfeld.ui.MainActivity
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
import com.omarmesqq.grunfeld.utils.NativeLibWrapper
import com.omarmesqq.grunfeld.utils.findActivity
import com.omarmesqq.grunfeld.utils.getNetworkInterfaces
import com.omarmesqq.grunfeld.utils.getSensorsInfo
import com.omarmesqq.grunfeld.utils.getSystemProperty
import com.omarmesqq.grunfeld.utils.getWifiManagerInfo
import com.omarmesqq.grunfeld.utils.hasPermission
import com.omarmesqq.grunfeld.utils.openFileKt
import com.omarmesqq.grunfeld.utils.runtimeExecWithCmd
import com.omarmesqq.grunfeld.utils.runtimeExecWithCmdArray
import com.omarmesqq.grunfeld.viewmodel.MainViewModel
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.NetworkInterface

private const val FAKE_IP = "10.111.222.1"
private const val PLAY_STORE_PKG_NAME = "com.android.vending"

@Composable
fun TestsScreen(mvm: MainViewModel) {
    val context = LocalContext.current

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .safeDrawingPadding()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        item {
            Text(
                text = "Java and native tests",
                style = MaterialTheme.typography.headlineMedium
            )
        }

        item {
            SectionHeader("BUILD AND SETTINGS TESTS")
            Card(
                modifier = Modifier.fillMaxWidth(),
                elevation = CardDefaults.cardElevation(defaultElevation = 4.dp)
            ) {
                BuildAssertions()
                HorizontalDivider()
                SettingsAssertions(mvm)
                HorizontalDivider()
                SystemPropertiesAssertions()
            }
        }

        item {
            SectionHeader("EXEC TESTS")
            Column(
                modifier = Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                RuntimeAssertions()
            }
        }

        item {
            SectionHeader("SENSORS TESTS (JAVA/NDK)")
            Column(
                modifier = Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                SensorsAssertions(context)
            }
        }

        item {
            SectionHeader("NETWORKING TESTS")
            NetworkingAssertions(context)
        }

        item {
            SectionHeader("APP INSTALLER TESTS")
            AppInstallerAssertions(context)
        }

        item {
            SectionHeader("APP INSPECTION TESTS")
            Column(
                modifier = Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                QueryIntentActivitiesAssertions(context)
                TestResolveActivity()
                InstalledApplicationsAssertions(context)
                InstalledPackagesAssertions(context)
                TestLauncherApps()
            }
        }

        item {
            SectionHeader("TELEPHONY TESTS")
            TelephonyAssertions(context)
        }

        item {
            SectionHeader("ROOTBER ROOT CHECK")
            RootCheckAssertions(mvm)
        }

        item {
            SectionHeader("DEVICE IDENTIFIERS")
            DeviceIdAssertions(mvm)
        }

        item {
            SectionHeader("STEALTH TESTS")
            StealthAssertions()
        }

        item {
            SectionHeader("FILESYSTEM TESTS")
            FilesystemAssertions()
        }

        item {
            SectionHeader("SYSTEM PROPERTIES TESTS")
            SystemPropsReflectionAssertions()
        }
    }
}


@Composable
private fun TestLauncherApps() {
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.VANILLA_ICE_CREAM) {
        Text(
            text = "Unsupported API level",
            color = Color.Yellow
        )
    } else {
        val context = LocalContext.current
        val activity = context.findActivity() as MainActivity

        val launcherAcInfos = activity.launcherApps.getActivityList(null, myUserHandle())
        val launcherUserInfo = activity.launcherApps.getLauncherUserInfo(myUserHandle())
        val preInstalledSystemPkgs =
            activity.launcherApps.getPreInstalledSystemPackages(myUserHandle())
        val allPackageInstallerSessions = activity.launcherApps.allPackageInstallerSessions
        val profiles = activity.launcherApps.profiles

        AssertionResultEmpty("(Launcher Apps) LauncherActivityInfo", launcherAcInfos)
        AssertionResultNull("(Launcher Apps) LauncherUserInfo", launcherUserInfo)
        AssertionResultEmpty("(Launcher Apps) Preinstalled system packages", preInstalledSystemPkgs)
        AssertionResultEmpty("(Launcher Apps) Package installer sessions", allPackageInstallerSessions)
        AssertionResultEmpty("(Launcher Apps) Profiles", profiles)
    }
}

@Composable
private fun TestResolveActivity() {
    val context = LocalContext.current
    val pm = context.packageManager
    val i = Intent(Intent.ACTION_VIEW).apply {
        data = "http://example.com".toUri()
        addCategory(Intent.CATEGORY_BROWSABLE)
    }

    val resolveInfo = pm.resolveActivity(i, PackageManager.MATCH_DEFAULT_ONLY)
    AssertionResultNull("resolveActivity/resolveIntent", resolveInfo)
}

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
    AssertionResultSingleSpecificValueInIterable(
        "SUPPORTED_64_BIT_ABIS",
        abis64.toList(),
        "arm64-v8a"
    )

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
        AssertionResult(
            "PARTITION FINGERPRINT",
            partition.fingerprint,
            "google/husky/husky:16/BP4A.251205.006/14401865:user/release-keys"
        )
        AssertionResult("PARTITION BUILD TIME", partition.buildTimeMillis, "1764954000000")
    }
}

@Composable
private fun SettingsAssertions(mvm: MainViewModel) {
    val fields = mvm.settingsGlobalFields.collectAsState().value
    if (fields.isEmpty()) {
        Text(
            text = "Failed to retrieve Settings.Global fields!",
            color = Color.Red
        )
    }

    fields.forEach {
        AssertionResult(it.label, it.value, it.expectedValue)
    }
}

@Composable
private fun SystemPropertiesAssertions() {
    val version = System.getProperty("os.version")
    AssertionResult("os.version", version ?: "(NULL!)", "6.6.56-android16-11-g8a3e2b1c4d5f")
}

@Composable
private fun RuntimeAssertions() {
    AssertionResult(
        "Runtime.exec(which, su)",
        runtimeExecWithCmdArray(arrayOf("which", "su")),
        ""
    )
    AssertionResult("Runtime.exec(getprop)", runtimeExecWithCmd("getprop"), "null")
    AssertionResult("fork()/exec(uname)", NativeLibWrapper.testForkExec(""), "")
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
private fun SensorsAssertions(ctx: Context) {
    AssertionResult("Sensors", getSensorsInfo(ctx), "")
}


@Composable
private fun NetworkingAssertions(ctx: Context) {
    Text(
        text = "Network interface enumeration",
        color = Color.Magenta
    )
    var ifaceList by remember { mutableStateOf<List<NetworkInterface>?>(null) }

    LaunchedEffect(Unit) {
        // already does its own withContext(IO) internally
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

    Text(
        text = "Link Properties via Connectivity Manager",
        color = Color.Magenta
    )

    val cm = ctx.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager

    @Suppress("DEPRECATION")
    if (cm.activeNetworkInfo != null) {
        val activeNetworkInfo = cm.activeNetworkInfo
        AssertionResultNotContains(
            "Is active network VPN?",
            activeNetworkInfo?.typeName ?: "NO_TYPE_NAME_THATS_ODD",
            "VPN"
        )
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
    AssertionResult("Network has VPN transport ?", hasTransportVpn, false)
    AssertionResult("Network has cap NOT_VPN ?", hasCapNotVpn, true)

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

    Text(
        text = "Wifi Manager (deprecated)",
        color = Color.Magenta
    )

    val wifiInfo = try {
        getWifiManagerInfo(ctx)
    } catch (e: Exception) {
        Text(
            text = "dumpWifiManagerInfo failed: ${e.message}",
            color = Color.Red
        )
        return
    }

    val isOnWifi = caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)

    @Suppress("DEPRECATION")
    if (isOnWifi) {
        AssertionResult(
            "(Connected to Wi-Fi) IPv4 address",
            Formatter.formatIpAddress(wifiInfo.ipAddress),
            FAKE_IP
        )
    } else {
        AssertionResult(
            "(Not on Wi-Fi) IPv4 address",
            Formatter.formatIpAddress(wifiInfo.ipAddress),
            FAKE_IP
        )
    }

    if (wifiInfo.bssid != null) {
        AssertionResult("BSSID", wifiInfo.bssid, "02:00:00:00:00:00")
    }
    AssertionResultContains("SSID", wifiInfo.ssid, "<unknown ssid>")

    Text(
        text = "LAN leak tests",
        color = Color.Magenta
    )

    val socketIp4 = NativeLibWrapper.testGetsocknameV4()
    AssertionResult("IPv4 via 'getsockname'", socketIp4, "10.111.222.1")
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
private fun TelephonyAssertions(ctx: Context) {
    val tm = ctx.getSystemService(Context.TELEPHONY_SERVICE) as TelephonyManager

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
private fun RootCheckAssertions(mvm: MainViewModel) {
    when (val isRooted = mvm.isRooted.collectAsState().value) {
        RootCheckResult.LOADING -> {
            Text("Loading...")
        }

        else -> {
            AssertionResult(
                // LOADING guards against null in current contract, safe to force cast
                "Is rooted?", isRooted.actualValue!!, false
            )
        }
    }
}

@Composable
private fun DeviceIdAssertions(mvm: MainViewModel) {
    val deviceIdsState by mvm.deviceIdsState.collectAsStateWithLifecycle()

    when (val state = deviceIdsState) {
        DeviceIdState.Loading -> Text("Loading...")
        DeviceIdState.FirstLaunch -> Text(
            "First app launch: collected device IDs to check in next launch",
            color = Color.Yellow
        )

        is DeviceIdState.Compared -> state.rows.forEach {
            AssertionResultNotEqualStrings(it.label, it.current, it.previous)
        }
    }
}

@Composable
private fun StealthAssertions() {
    val defaultValue = ""

    CodeTitle("Traces of injection in VFS", Color.Magenta)
    val procSelfMaps = NativeLibWrapper.scanProcSelfMaps("/proc/self/maps")
    val procPidMaps = NativeLibWrapper.scanProcSelfMaps("/proc/${Process.myPid()}/maps")
    val procSelfSmaps = NativeLibWrapper.scanProcSelfSmaps("/proc/self/smaps")
    val procPidSmaps = NativeLibWrapper.scanProcSelfMaps("/proc/${Process.myPid()}/smaps")
    val procSelfMountinfo = NativeLibWrapper.scanMountPoint("/proc/self/mountinfo")
    val procPidMountinfo = NativeLibWrapper.scanMountPoint("/proc/${Process.myPid()}/mountinfo")
    val procMounts = NativeLibWrapper.scanMountPoint("/proc/mounts")
    val procSelfMounts = NativeLibWrapper.scanMountPoint("/proc/self/mounts")
    val procPidMounts = NativeLibWrapper.scanMountPoint("/proc/${Process.myPid()}/mounts")

    AssertionResult("/proc/self/maps", procSelfMaps, defaultValue)
    AssertionResult("/proc/<PID>/maps", procPidMaps, defaultValue)
    AssertionResult("/proc/self/smaps", procSelfSmaps, defaultValue)
    AssertionResult("/proc/<PID>/smaps", procPidSmaps, defaultValue)
    AssertionResult("/proc/self/mountinfo", procSelfMountinfo, defaultValue)
    AssertionResult("/proc/<PID>/mountinfo", procPidMountinfo, defaultValue)
    AssertionResult("/proc/mounts", procMounts, defaultValue)
    AssertionResult("/proc/self/mounts", procSelfMounts, defaultValue)
    AssertionResult("/proc/<PID>/mounts", procPidMounts, defaultValue)

    CodeTitle("Traces of injection in linker's soinfo", Color.Magenta)
    val dlIteratePhdr = NativeLibWrapper.testDlIteratePhdr()
    AssertionResult("dl_iterate_phdr", dlIteratePhdr, defaultValue)

    CodeTitle("Correct symlinks of spoofed files", Color.Magenta)
    val procSelfMapsFd = NativeLibWrapper.openFileNative("/proc/self/maps")
    val procPidMapsFd = NativeLibWrapper.openFileNative("/proc/${Process.myPid()}/maps")
    val procSelfSmapsFd = NativeLibWrapper.openFileNative("/proc/self/smaps")
    val procPidSmapsFd = NativeLibWrapper.openFileNative("/proc/${Process.myPid()}/smaps")
    val etcHostsFd = NativeLibWrapper.openFileNative("/etc/hosts")
    val systemEtcHostsFd = NativeLibWrapper.openFileNative("/system/etc/hosts")
    val procSelfMountinfoFd = NativeLibWrapper.openFileNative("/proc/self/mountinfo")
    val procPidMountinfoFd = NativeLibWrapper.openFileNative("/proc/${Process.myPid()}/mountinfo")

    AssertionResult(
        "/proc/self/maps -> /proc/<PID>/maps",
        NativeLibWrapper.getFdSymlink(procSelfMapsFd),
        "/proc/${Process.myPid()}/maps"
    )
    AssertionResult(
        "/proc/<PID>/maps -> /proc/<PID>/maps",
        NativeLibWrapper.getFdSymlink(procPidMapsFd),
        "/proc/${Process.myPid()}/maps"
    )
    AssertionResult(
        "/proc/self/smaps -> /proc/<PID>/smaps",
        NativeLibWrapper.getFdSymlink(procSelfSmapsFd),
        "/proc/${Process.myPid()}/smaps"
    )
    AssertionResult(
        "/proc/<PID>/smaps -> /proc/<PID>/smaps",
        NativeLibWrapper.getFdSymlink(procPidSmapsFd),
        "/proc/${Process.myPid()}/smaps"
    )
    AssertionResult(
        "/proc/self/mountinfo -> /proc/<PID>/mountinfo",
        NativeLibWrapper.getFdSymlink(procSelfMountinfoFd),
        "/proc/${Process.myPid()}/mountinfo"
    )
    AssertionResult(
        "/proc/<PID>/mountinfo -> /proc/<PID>/mountinfo",
        NativeLibWrapper.getFdSymlink(procPidMountinfoFd),
        "/proc/${Process.myPid()}/mountinfo"
    )
    AssertionResult(
        "/etc/hosts -> /system/etc/hosts",
        NativeLibWrapper.getFdSymlink(etcHostsFd),
        "/system/etc/hosts"
    )
    AssertionResult(
        "/system/etc/hosts -> /system/etc/hosts",
        NativeLibWrapper.getFdSymlink(systemEtcHostsFd),
        "/system/etc/hosts"
    )
}

@Composable
private fun FilesystemAssertions() {
    CodeTitle("statx()", Color.Magenta)

    val statxTest = NativeLibWrapper.testStatx()
    AssertionResult("'statx'", statxTest, "Function not implemented")

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
    AssertionResultNotEqualLongs(
        "/etc and /etc/hosts inodes shouldn't match",
        fstatEtc.ino,
        fstatEtcHosts.ino
    )

    val hostsExpectedSize = 46
    val hostsExpectedBlockSize = 4096
    val hostsExpectedAllocatedBlocks = 8

    AssertionResult("/etc/hosts size (in bytes)", fstatEtcHosts.size, hostsExpectedSize.toLong())
    AssertionResult(
        "/etc/hosts block size (in bytes)",
        fstatEtcHosts.blkSiz,
        hostsExpectedBlockSize.toLong()
    )
    AssertionResult(
        "/etc/hosts allocated blocks",
        fstatEtcHosts.blksAllocated,
        hostsExpectedAllocatedBlocks.toLong()
    )

    AssertionResult(
        "/etc/hosts and /etc access time should match",
        fstatEtc.accessTime,
        fstatEtcHosts.accessTime
    )
    AssertionResult(
        "/etc/hosts and /etc modification time should match",
        fstatEtc.modTime,
        fstatEtcHosts.modTime
    )
    AssertionResult(
        "/etc/hosts and /etc status change time should match",
        fstatEtc.modTime,
        fstatEtcHosts.modTime
    )

    CodeTitle("newfstatat()", Color.Magenta)

    val hostsNodes2 = arrayOf(
        "/system/etc",
        "/system/etc/hosts",
    )

    val newfstatatSystemEtc = NativeLibWrapper.testNewfstatat(hostsNodes2[0])
    val newfstatatSystemEtcHosts = NativeLibWrapper.testNewfstatat(hostsNodes2[1])

    AssertionResult(
        "/system/etc and /system/etc/hosts devices should match",
        newfstatatSystemEtc.dev,
        newfstatatSystemEtcHosts.dev
    )
    AssertionResultNotEqualLongs(
        "/system/etc and /system/etc/hosts inodes shouldn't match",
        newfstatatSystemEtc.ino,
        newfstatatSystemEtcHosts.ino
    )

    AssertionResult(
        "/system/etc/hosts size (in bytes)",
        newfstatatSystemEtcHosts.size,
        hostsExpectedSize.toLong()
    )
    AssertionResult(
        "/system/etc/hosts block size (in bytes)",
        newfstatatSystemEtcHosts.blkSiz,
        hostsExpectedBlockSize.toLong()
    )
    AssertionResult(
        "/system/etc/hosts allocated blocks",
        newfstatatSystemEtcHosts.blksAllocated,
        hostsExpectedAllocatedBlocks.toLong()
    )

    AssertionResult(
        "/system/etc/hosts and /system/etc access time should match",
        newfstatatSystemEtc.accessTime,
        newfstatatSystemEtcHosts.accessTime
    )
    AssertionResult(
        "/system/etc/hosts and /system/etc modification time should match",
        newfstatatSystemEtc.modTime,
        newfstatatSystemEtcHosts.modTime
    )
    AssertionResult(
        "/system/etc/hosts and /system/etc status change time should match",
        newfstatatSystemEtc.modTime,
        newfstatatSystemEtcHosts.modTime
    )

    Text(
        text = "Sensitive file read (should be blocked by SELinux)",
        color = Color.Magenta
    )

    val senstiveFiles = arrayOf(
        "/proc/self/mountstats",
        "/proc/${Process.myPid()}/mountstats",
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
    AssertionResult(
        "ro.bootimage.build.fingerprint",
        getSystemProperty("ro.bootimage.build.fingerprint"),
        defaultValue
    )
    AssertionResult(
        "ro.bootimage.build.type",
        getSystemProperty("ro.bootimage.build.type"),
        defaultValue
    )
    AssertionResult(
        "ro.bootimage.build.tags",
        getSystemProperty("ro.bootimage.build.tags"),
        defaultValue
    )

    AssertionResult("ro.debuggable", getSystemProperty("ro.debuggable"), defaultValue)
    AssertionResult("ro.secure", getSystemProperty("ro.secure"), defaultValue)
    AssertionResult("ro.force.debuggable", getSystemProperty("ro.force.debuggable"), "0")

    AssertionResult("ro.product.board", getSystemProperty("ro.product.board"), "husky")
    AssertionResult("ro.product.brand", getSystemProperty("ro.product.brand"), "google")
    AssertionResult("ro.product.device", getSystemProperty("ro.product.device"), "husky")
    AssertionResult(
        "ro.product.manufacturer",
        getSystemProperty("ro.product.manufacturer"),
        "google"
    )
    AssertionResult("ro.product.model", getSystemProperty("ro.product.model"), "Pixel 8 Pro")
    AssertionResult("ro.product.name", getSystemProperty("ro.product.name"), "husky")

    // ro.product.odm.*
    AssertionResult("ro.product.odm.brand", getSystemProperty("ro.product.odm.brand"), "google")
    AssertionResult("ro.product.odm.device", getSystemProperty("ro.product.odm.device"), "husky")
    AssertionResult(
        "ro.product.odm.manufacturer",
        getSystemProperty("ro.product.odm.manufacturer"),
        "google"
    )
    AssertionResult(
        "ro.product.odm.model",
        getSystemProperty("ro.product.odm.model"),
        "Pixel 8 Pro"
    )
    AssertionResult("ro.product.odm.name", getSystemProperty("ro.product.odm.name"), "husky")

    // ro.product.product.*
    AssertionResult(
        "ro.product.product.brand",
        getSystemProperty("ro.product.product.brand"),
        "google"
    )
    AssertionResult(
        "ro.product.product.device",
        getSystemProperty("ro.product.product.device"),
        "husky"
    )
    AssertionResult(
        "ro.product.product.manufacturer",
        getSystemProperty("ro.product.product.manufacturer"),
        "google"
    )
    AssertionResult(
        "ro.product.product.model",
        getSystemProperty("ro.product.product.model"),
        "Pixel 8 Pro"
    )
    AssertionResult(
        "ro.product.product.name",
        getSystemProperty("ro.product.product.name"),
        "husky"
    )

    AssertionResult("ro.build.product", getSystemProperty("ro.build.product"), "husky")

    // ro.product.system.*
    AssertionResult(
        "ro.product.system.brand",
        getSystemProperty("ro.product.system.brand"),
        "google"
    )
    AssertionResult(
        "ro.product.system.device",
        getSystemProperty("ro.product.system.device"),
        "husky"
    )
    AssertionResult(
        "ro.product.system.manufacturer",
        getSystemProperty("ro.product.system.manufacturer"),
        "google"
    )
    AssertionResult(
        "ro.product.system.model",
        getSystemProperty("ro.product.system.model"),
        "Pixel 8 Pro"
    )
    AssertionResult("ro.product.system.name", getSystemProperty("ro.product.system.name"), "husky")

    // ro.product.system_ext.*
    AssertionResult(
        "ro.product.system_ext.brand",
        getSystemProperty("ro.product.system_ext.brand"),
        "google"
    )
    AssertionResult(
        "ro.product.system_ext.device",
        getSystemProperty("ro.product.system_ext.device"),
        "husky"
    )
    AssertionResult(
        "ro.product.system_ext.manufacturer",
        getSystemProperty("ro.product.system_ext.manufacturer"),
        "google"
    )
    AssertionResult(
        "ro.product.system_ext.model",
        getSystemProperty("ro.product.system_ext.model"),
        "Pixel 8 Pro"
    )
    AssertionResult(
        "ro.product.system_ext.name",
        getSystemProperty("ro.product.system_ext.name"),
        "husky"
    )

    // ro.product.vendor.*
    AssertionResult(
        "ro.product.vendor.brand",
        getSystemProperty("ro.product.vendor.brand"),
        "google"
    )
    AssertionResult(
        "ro.product.vendor.device",
        getSystemProperty("ro.product.vendor.device"),
        "husky"
    )
    AssertionResult(
        "ro.product.vendor.manufacturer",
        getSystemProperty("ro.product.vendor.manufacturer"),
        "google"
    )
    AssertionResult(
        "ro.product.vendor.model",
        getSystemProperty("ro.product.vendor.model"),
        "Pixel 8 Pro"
    )
    AssertionResult("ro.product.vendor.name", getSystemProperty("ro.product.vendor.name"), "husky")

    // ro.product.vendor_dlkm.*
    AssertionResult(
        "ro.product.vendor_dlkm.brand",
        getSystemProperty("ro.product.vendor_dlkm.brand"),
        "google"
    )
    AssertionResult(
        "ro.product.vendor_dlkm.device",
        getSystemProperty("ro.product.vendor_dlkm.device"),
        "husky"
    )
    AssertionResult(
        "ro.product.vendor_dlkm.manufacturer",
        getSystemProperty("ro.product.vendor_dlkm.manufacturer"),
        "google"
    )
    AssertionResult(
        "ro.product.vendor_dlkm.model",
        getSystemProperty("ro.product.vendor_dlkm.model"),
        "Pixel 8 Pro"
    )
    AssertionResult(
        "ro.product.vendor_dlkm.name",
        getSystemProperty("ro.product.vendor_dlkm.name"),
        "husky"
    )

    // Build host / id
    AssertionResult("ro.build.host", getSystemProperty("ro.build.host"), "abfarm-20038")
    AssertionResult("ro.build.id", getSystemProperty("ro.build.id"), "BP4A.251205.006")
    AssertionResult(
        "ro.vendor.build.id",
        getSystemProperty("ro.vendor.build.id"),
        "BP4A.251205.006"
    )
    AssertionResult(
        "ro.product.build.id",
        getSystemProperty("ro.product.build.id"),
        "BP4A.251205.006"
    )
    AssertionResult(
        "ro.system.build.id",
        getSystemProperty("ro.system.build.id"),
        "BP4A.251205.006"
    )
    AssertionResult(
        "ro.vendor_dlkm.build.id",
        getSystemProperty("ro.vendor_dlkm.build.id"),
        "BP4A.251205.006"
    )
    AssertionResult(
        "ro.system_ext.build.id",
        getSystemProperty("ro.system_ext.build.id"),
        "BP4A.251205.006"
    )
    AssertionResult(
        "ro.build.display.id",
        getSystemProperty("ro.build.display.id"),
        "BP4A.251205.006"
    )

    // Tags
    AssertionResult("ro.build.tags", getSystemProperty("ro.build.tags"), "release-keys")
    AssertionResult(
        "ro.vendor.build.tags",
        getSystemProperty("ro.vendor.build.tags"),
        "release-keys"
    )
    AssertionResult(
        "ro.product.build.tags",
        getSystemProperty("ro.product.build.tags"),
        "release-keys"
    )
    AssertionResult(
        "ro.system.build.tags",
        getSystemProperty("ro.system.build.tags"),
        "release-keys"
    )
    AssertionResult(
        "ro.vendor_dlkm.build.tags",
        getSystemProperty("ro.vendor_dlkm.build.tags"),
        "release-keys"
    )
    AssertionResult(
        "ro.system_ext.build.tags",
        getSystemProperty("ro.system_ext.build.tags"),
        "release-keys"
    )

    // Type
    AssertionResult("ro.build.type", getSystemProperty("ro.build.type"), "user")
    AssertionResult("ro.vendor.build.type", getSystemProperty("ro.vendor.build.type"), "user")
    AssertionResult("ro.product.build.type", getSystemProperty("ro.product.build.type"), "user")
    AssertionResult("ro.system.build.type", getSystemProperty("ro.system.build.type"), "user")
    AssertionResult(
        "ro.vendor_dlkm.build.type",
        getSystemProperty("ro.vendor_dlkm.build.type"),
        "user"
    )
    AssertionResult(
        "ro.system_ext.build.type",
        getSystemProperty("ro.system_ext.build.type"),
        "user"
    )
    AssertionResult("ro.build.user", getSystemProperty("ro.build.user"), "android-build")

    // Date UTC
    AssertionResult("ro.build.date.utc", getSystemProperty("ro.build.date.utc"), "1764954000")
    AssertionResult(
        "ro.odm.build.date.utc",
        getSystemProperty("ro.odm.build.date.utc"),
        "1764954000"
    )
    AssertionResult(
        "ro.product.build.date.utc",
        getSystemProperty("ro.product.build.date.utc"),
        "1764954000"
    )
    AssertionResult(
        "ro.system.build.date.utc",
        getSystemProperty("ro.system.build.date.utc"),
        "1764954000"
    )
    AssertionResult(
        "ro.system_ext.build.date.utc",
        getSystemProperty("ro.system_ext.build.date.utc"),
        "1764954000"
    )
    AssertionResult(
        "ro.vendor_dlkm.build.date.utc",
        getSystemProperty("ro.vendor_dlkm.build.date.utc"),
        "1764954000"
    )
    AssertionResult(
        "ro.vendor.build.date.utc",
        getSystemProperty("ro.vendor.build.date.utc"),
        "1764954000"
    )

    AssertionResult(
        "ro.build.version.all_codenames",
        getSystemProperty("ro.build.version.all_codenames"),
        "REL"
    )
    AssertionResult(
        "ro.build.version.preview_sdk_fingerprint",
        getSystemProperty("ro.build.version.preview_sdk_fingerprint"),
        "REL"
    )

    // Build date
    val buildDate = "Fri Dec 05 12:00:00 UTC 2025"
    AssertionResult("ro.build.date", getSystemProperty("ro.build.date"), buildDate)
    AssertionResult("ro.odm.build.date", getSystemProperty("ro.odm.build.date"), buildDate)
    AssertionResult("ro.product.build.date", getSystemProperty("ro.product.build.date"), buildDate)
    AssertionResult("ro.system.build.date", getSystemProperty("ro.system.build.date"), buildDate)
    AssertionResult(
        "ro.system_ext.build.date",
        getSystemProperty("ro.system_ext.build.date"),
        buildDate
    )
    AssertionResult("ro.vendor.build.date", getSystemProperty("ro.vendor.build.date"), buildDate)
    AssertionResult(
        "ro.vendor_dlkm.build.date",
        getSystemProperty("ro.vendor_dlkm.build.date"),
        buildDate
    )

    AssertionResult(
        "ro.build.description",
        getSystemProperty("ro.build.description"),
        "husky-user 16 BP4A.251205.006 release-keys"
    )
    AssertionResult("ro.build.flavor", getSystemProperty("ro.build.flavor"), "husky-user")

    // Version incremental
    AssertionResult(
        "ro.build.version.incremental",
        getSystemProperty("ro.build.version.incremental"),
        "14401865"
    )
    AssertionResult(
        "ro.vendor.build.version.incremental",
        getSystemProperty("ro.vendor.build.version.incremental"),
        "14401865"
    )
    AssertionResult(
        "ro.odm.build.version.incremental",
        getSystemProperty("ro.odm.build.version.incremental"),
        "14401865"
    )
    AssertionResult(
        "ro.product.build.version.incremental",
        getSystemProperty("ro.product.build.version.incremental"),
        "14401865"
    )
    AssertionResult(
        "ro.system.build.version.incremental",
        getSystemProperty("ro.system.build.version.incremental"),
        "14401865"
    )
    AssertionResult(
        "ro.vendor_dlkm.build.version.incremental",
        getSystemProperty("ro.vendor_dlkm.build.version.incremental"),
        "14401865"
    )
    AssertionResult(
        "ro.system_ext.build.version.incremental",
        getSystemProperty("ro.system_ext.build.version.incremental"),
        "14401865"
    )

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

    AssertionResult(
        "ro.build.version.security_patch",
        getSystemProperty("ro.build.version.security_patch"),
        "2025-12-05"
    )
    AssertionResult(
        "ro.build.version.codename",
        getSystemProperty("ro.build.version.codename"),
        "REL"
    )
    AssertionResult(
        "ro.build.version.base_os",
        getSystemProperty("ro.build.version.base_os"),
        defaultValue
    )
    AssertionResult(
        "ro.build.version.preview_sdk",
        getSystemProperty("ro.build.version.preview_sdk"),
        "0"
    )

    // Fingerprint
    val fingerprint = "google/husky/husky:16/BP4A.251205.006/14401865:user/release-keys"
    AssertionResult("ro.build.fingerprint", getSystemProperty("ro.build.fingerprint"), fingerprint)
    AssertionResult(
        "ro.odm.build.fingerprint",
        getSystemProperty("ro.odm.build.fingerprint"),
        fingerprint
    )
    AssertionResult(
        "ro.product.build.fingerprint",
        getSystemProperty("ro.product.build.fingerprint"),
        fingerprint
    )
    AssertionResult(
        "ro.system.build.fingerprint",
        getSystemProperty("ro.system.build.fingerprint"),
        fingerprint
    )
    AssertionResult(
        "ro.system_ext.build.fingerprint",
        getSystemProperty("ro.system_ext.build.fingerprint"),
        fingerprint
    )
    AssertionResult(
        "ro.vendor.build.fingerprint",
        getSystemProperty("ro.vendor.build.fingerprint"),
        fingerprint
    )
    AssertionResult(
        "ro.vendor_dlkm.build.fingerprint",
        getSystemProperty("ro.vendor_dlkm.build.fingerprint"),
        fingerprint
    )

    // RADIO
    AssertionResult(
        "gsm.version.baseband",
        getSystemProperty("gsm.version.baseband"),
        "g5300g-251108-251202-B-12876551"
    )
    AssertionResult(
        "gsm.version.ril-impl",
        getSystemProperty("gsm.version.ril-impl"),
        "com.google.android.telephony.modem"
    )
    AssertionResult("ril.sw_ver", getSystemProperty("ril.sw_ver"), defaultValue)
    AssertionResult("ril.sw_ver2", getSystemProperty("ril.sw_ver2"), defaultValue)
    AssertionResult(
        "ro.baseband",
        getSystemProperty("ro.baseband"),
        "g5300g-251108-251202-B-12876551"
    )

    // Fingerprinting vectors
    AssertionResult(
        "ro.config.alarm_alert",
        getSystemProperty("ro.config.alarm_alert"),
        "Hassium.ogg"
    )
    AssertionResult(
        "ro.config.notification_sound",
        getSystemProperty("ro.config.notification_sound"),
        "Argon.ogg"
    )
    AssertionResult("ro.config.ringtone", getSystemProperty("ro.config.ringtone"), "Orion.ogg")
    AssertionResult("ro.product.locale", getSystemProperty("ro.product.locale"), "en-US")
    AssertionResult(
        "bluetooth.device.default_name",
        getSystemProperty("bluetooth.device.default_name"),
        "Pixel 8 Pro"
    )

    // User-set
    AssertionResult(
        "debug.debuggerd.wait_for_debugger",
        getSystemProperty("debug.debuggerd.wait_for_debugger"),
        defaultValue
    )

    // General tuning
    AssertionResult("nfc.initialized", getSystemProperty("nfc.initialized"), "false")
    AssertionResult(
        "ro.support_one_handed_mode",
        getSystemProperty("ro.support_one_handed_mode"),
        "false"
    )

    // OEM/ROM specific
    AssertionResult("init.svc.vaultkeeper", getSystemProperty("init.svc.vaultkeeper"), defaultValue)
    AssertionResult(
        "init.svc.vendor_flash_recovery",
        getSystemProperty("init.svc.vendor_flash_recovery"),
        defaultValue
    )
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
    AssertionResult(
        "ro.odm.product.cpu.abilist32",
        getSystemProperty("ro.odm.product.cpu.abilist32"),
        defaultValue
    )
    AssertionResult(
        "ro.product.cpu.abilist32",
        getSystemProperty("ro.product.cpu.abilist32"),
        defaultValue
    )
    AssertionResult(
        "ro.system.product.cpu.abilist32",
        getSystemProperty("ro.system.product.cpu.abilist32"),
        defaultValue
    )
    AssertionResult(
        "ro.vendor.product.cpu.abilist32",
        getSystemProperty("ro.vendor.product.cpu.abilist32"),
        defaultValue
    )
    AssertionResult(
        "ro.odm.product.cpu.abilist",
        getSystemProperty("ro.odm.product.cpu.abilist"),
        defaultValue
    )
    AssertionResult(
        "ro.product.cpu.abilist",
        getSystemProperty("ro.product.cpu.abilist"),
        "arm64-v8a"
    )
    AssertionResult(
        "ro.system.product.cpu.abilist",
        getSystemProperty("ro.system.product.cpu.abilist"),
        "arm64-v8a"
    )
    AssertionResult(
        "ro.vendor.product.cpu.abilist",
        getSystemProperty("ro.vendor.product.cpu.abilist"),
        "arm64-v8a"
    )
    AssertionResult("ro.zygote", getSystemProperty("ro.zygote"), "zygote64")
    AssertionResult(
        "init.svc.zygote_secondary",
        getSystemProperty("init.svc.zygote_secondary"),
        defaultValue
    )

    // Hardware fingerprinting
    AssertionResult("ro.bootmode", getSystemProperty("ro.bootmode"), "normal")
    AssertionResult("bootreceiver.enable", getSystemProperty("bootreceiver.enable"), "1")

    val bootloader = "ripcurrent-15.0-12455211"
    AssertionResult("ro.bootloader", getSystemProperty("ro.bootloader"), bootloader)
    AssertionResult("ro.soc.manufacturer", getSystemProperty("ro.soc.manufacturer"), "Google")
    AssertionResult("ro.soc.model", getSystemProperty("ro.soc.model"), "Tensor G3")
    AssertionResult(
        "ro.boot.boot_devices",
        getSystemProperty("ro.boot.boot_devices"),
        "soc/1d84000.ufshc"
    )
    AssertionResult("ro.boot.bootloader", getSystemProperty("ro.boot.bootloader"), bootloader)
    AssertionResult("ro.boot.em.did", getSystemProperty("ro.boot.em.did"), defaultValue)
    AssertionResult("ro.boot.em.model", getSystemProperty("ro.boot.em.model"), bootloader)
    AssertionResult("ro.boot.hardware", getSystemProperty("ro.boot.hardware"), "zuma")
    AssertionResult(
        "ro.boot.odin_download",
        getSystemProperty("ro.boot.odin_download"),
        defaultValue
    )
    AssertionResult("ro.boot.wb.snapQB", getSystemProperty("ro.boot.wb.snapQB"), defaultValue)
    AssertionResult(
        "ro.com.google.clientidbase",
        getSystemProperty("ro.com.google.clientidbase"),
        "android-google"
    )
    AssertionResult("ro.hardware", getSystemProperty("ro.hardware"), "zuma")
    AssertionResult("ro.boot.ap_serial", getSystemProperty("ro.boot.ap_serial"), defaultValue)
    AssertionResult(
        "ro.boot.verifiedbootstate",
        getSystemProperty("ro.boot.verifiedbootstate"),
        "green"
    )
    AssertionResult("ro.boot.warranty_bit", getSystemProperty("ro.boot.warranty_bit"), defaultValue)
    AssertionResult("ro.boot.force_upload", getSystemProperty("ro.boot.force_upload"), defaultValue)

    AssertionResult("sys.oem_unlock_allowed", getSystemProperty("sys.oem_unlock_allowed"), "0")
    AssertionResult("ro.boot.write_protect", getSystemProperty("ro.boot.write_protect"), "1")
    AssertionResult(
        "ro.boot.veritymode.managed",
        getSystemProperty("ro.boot.veritymode.managed"),
        "yes"
    )
    AssertionResult("ro.boot.veritymode", getSystemProperty("ro.boot.veritymode"), "enforcing")
    AssertionResult(
        "ro.boot.vbmeta.hash_alg",
        getSystemProperty("ro.boot.vbmeta.hash_alg"),
        "sha256"
    )
    AssertionResult(
        "ro.boot.vbmeta.device_state",
        getSystemProperty("ro.boot.vbmeta.device_state"),
        "locked"
    )
    AssertionResult(
        "ro.boot.vbmeta.avb_version",
        getSystemProperty("ro.boot.vbmeta.avb_version"),
        "1.2"
    )
    AssertionResult("ro.boot.secure_hardware", getSystemProperty("ro.boot.secure_hardware"), "1")
    AssertionResult("ro.boot.mode", getSystemProperty("ro.boot.mode"), "normal")
    AssertionResult(
        "ro.boot.force_normal_boot",
        getSystemProperty("ro.boot.force_normal_boot"),
        "1"
    )
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

    AssertionResult(
        "gsm.operator.iso-country",
        getSystemProperty("gsm.operator.iso-country"),
        "br,"
    )
    AssertionResult(
        "gsm.sim.operator.iso-country",
        getSystemProperty("gsm.sim.operator.iso-country"),
        "br,"
    )

    AssertionResult(
        "gsm.sim.operator.numeric",
        getSystemProperty("gsm.sim.operator.numeric"),
        "72406,"
    )
    AssertionResult("gsm.operator.numeric", getSystemProperty("gsm.operator.numeric"), "72406,")

    AssertionResult("gsm.sim.operator.alpha", getSystemProperty("gsm.sim.operator.alpha"), "Vivo,")
    AssertionResult("gsm.operator.alpha", getSystemProperty("gsm.operator.alpha"), "Vivo,")

    AssertionResult("debug.tracing.mnc", getSystemProperty("debug.tracing.mnc"), "6")

    AssertionResult("ro.boot.selinux", getSystemProperty("ro.boot.selinux"), "enforcing")
    AssertionResult("ro.adb.secure", getSystemProperty("ro.adb.secure"), "1")
    AssertionResult("ro.allow.mock.location", getSystemProperty("ro.allow.mock.location"), "0")
    AssertionResult(
        "persist.sys.strictmode.disable",
        getSystemProperty("persist.sys.strictmode.disable"),
        "true"
    )
    AssertionResult(
        "ro.control_privapp_permissions",
        getSystemProperty("ro.control_privapp_permissions"),
        "enforce"
    )
    AssertionResult(
        "ro.build.characteristics",
        getSystemProperty("ro.build.characteristics"),
        "default"
    )
    AssertionResult("security.perf_harden", getSystemProperty("security.perf_harden"), "1")
}

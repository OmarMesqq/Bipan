package com.omarmesqq.grunfeld.utils

import android.Manifest
import android.annotation.SuppressLint
import android.app.ActivityManager
import android.content.Context
import android.hardware.Sensor
import android.hardware.SensorManager
import android.os.Build
import android.provider.Settings
import android.provider.Settings.Global
import android.content.pm.PackageInstaller
import androidx.annotation.RequiresApi
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import java.net.NetworkInterface
import android.net.wifi.WifiManager
import android.text.format.Formatter
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.PackageInfo
import android.content.pm.PackageManager.NameNotFoundException
import androidx.core.net.toUri
import android.media.MediaDrm
import java.security.MessageDigest
import java.util.UUID
import java.io.File
import java.util.Scanner
import android.telephony.TelephonyManager
import java.lang.reflect.Method
import android.content.pm.ApplicationInfo;
import android.provider.Telephony
import android.telecom.TelecomManager
import androidx.annotation.RequiresPermission

fun DumpJavaInfo(context: Context): String {
    val buildInfo = dumpBuildInfo()
    val settingsInfo = dumpSettingsInfo(context)
    return "$buildInfo\n\n$settingsInfo"
}

fun dumpJavaSensorInfo(ctx: Context): String {
    val sensorManager = ctx.getSystemService(Context.SENSOR_SERVICE) as SensorManager
    val deviceSensors: List<Sensor> = sensorManager.getSensorList(Sensor.TYPE_ALL)

    return if (deviceSensors.isEmpty()) {
        "No sensors detected"
    } else {
        deviceSensors.joinToString(separator = "\n\n") { sensor ->
            """
        Name: ${sensor.name}
        Vendor: ${sensor.vendor}
        Version: ${sensor.version}
        Type: ${sensor.type}
        Power: ${sensor.power} mA
        Resolution: ${sensor.resolution}
        Max Range: ${sensor.maximumRange}
        """.trimIndent()
        }
    }
}

@RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
fun dumpInstallerInfo(ctx: Context): String {
    val pm = ctx.packageManager
    val packageName = ctx.packageName
    val info = pm.getInstallSourceInfo(packageName)

    val originator = info.originatingPackageName // The "Source" (e.g., Chrome)
    val initiator = info.initiatingPackageName   // Who called the install
    val installer = info.installingPackageName   // Who did the work (e.g., Play Store)
    val updateOwner = info.updateOwnerPackageName   // Package responsible for managing updates

    val packageSource = when (info.packageSource) {
        PackageInstaller.PACKAGE_SOURCE_STORE -> "Some App Store"
        PackageInstaller.PACKAGE_SOURCE_LOCAL_FILE -> "Local File"
        PackageInstaller.PACKAGE_SOURCE_DOWNLOADED_FILE -> "Downloaded File"
        PackageInstaller.PACKAGE_SOURCE_OTHER -> "Other"
        PackageInstaller.PACKAGE_SOURCE_UNSPECIFIED -> "Installer did not call PackageInstaller.SessionParams.setPackageSource(int) to specify the package source."
        else -> "Unknown Value: ${info.packageSource}"
    }

    @Suppress("DEPRECATION")
    val legacyInstaller = pm.getInstallerPackageName(packageName)

    return """
        Originator:   $originator
        Initiator:    $initiator
        Installer:    $installer
        Update Owner: $updateOwner
        Package Source: $packageSource
        [Legacy API] Installer: $legacyInstaller
    """.trimIndent()
}


fun dumpNetworkInfo(context: Context): String {
    val sb = StringBuilder()

    sb.append("[NETWORK INTERFACES (via getNetworkInterfaces)]\n")
    try {
        // TODO: evaluate allowing this
        val interfaces = NetworkInterface.getNetworkInterfaces()
        if (interfaces == null) {
            sb.append("No interfaces found.\n")
        } else {
            for (intf in interfaces.asSequence()) {
                sb.append(formatInterfaceDetails(intf))
                sb.append("\n")
            }
        }
    } catch (e: Exception) {
        sb.append("Failed to get interfaces: ${e.message}\n")
    }

    sb.append("\n[WIFI MANAGER INFO]\n")
    val wifiManager = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager

    @Suppress("DEPRECATION")
    val info = wifiManager.connectionInfo

    val ipv4Address = Formatter.formatIpAddress(info.ipAddress)
    val bssid = info.bssid
    val ssid = info.ssid
    val linkSpeed = info.linkSpeed
    val maxrx = info.maxSupportedRxLinkSpeedMbps
    val mxtx = info.maxSupportedTxLinkSpeedMbps
    val tx = info.txLinkSpeedMbps
    val rx = info.rxLinkSpeedMbps
    val netid = info.networkId
    val ppfqdn = info.passpointFqdn
    val ppfriendly = info.passpointProviderFriendlyName
    val ppUniqueId = info.passpointUniqueId
    val subId = info.subscriptionId

    sb.append("IPv4 address: $ipv4Address\n")
    sb.append("BSSID: $bssid\n")
    sb.append("SSID: $ssid\n")
    sb.append("Link speed: $linkSpeed Mbps\n")
    sb.append("Max RX: $maxrx Mbps\n")
    sb.append("Max TX: $mxtx Mbps\n")
    sb.append("TX: $tx Mbps\n")
    sb.append("RX: $rx Mbps\n")
    sb.append("Network ID: $netid\n")
    sb.append("Passpoint FQDN: $ppfqdn\n")
    sb.append("Passpoint Friendly name: $ppfriendly\n")
    sb.append("Passpoint Unique ID: $ppUniqueId\n")
    sb.append("Subscription ID: $subId\n")

    sb.append("\n[LINK PROPERTIES INFO]\n")
    val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
    val activeNetwork = cm.activeNetwork
    val caps = cm.getNetworkCapabilities(cm.activeNetwork)

    val isVpnTransport = caps?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) ?: false
    val hasNotVpnCap = caps?.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN) ?: true
    sb.append("TRANSPORT_VPN: $isVpnTransport\n")
    sb.append("HAS_NOT_VPN_CAP: $hasNotVpnCap\n\n")

    if (activeNetwork == null) {
        sb.append("No active network to query.\n")
    } else {
        val linkProperties = cm.getLinkProperties(activeNetwork)
        if (linkProperties == null) {
            sb.append("LinkProperties is null.\n")
        } else {
            val dhcpServerAdddr= linkProperties.dhcpServerAddress
            val dnsServers = linkProperties.dnsServers
            val dnsDomains = linkProperties.domains
            val proxy = linkProperties.httpProxy
            val ifaceName = linkProperties.interfaceName
            val addresses = linkProperties.linkAddresses
            val nat64prefix = linkProperties.nat64Prefix
            val privateDnsServerName = linkProperties.privateDnsServerName
            val routes = linkProperties.routes
            val isPrivateDnsActive = linkProperties.isPrivateDnsActive
            val mtu = linkProperties.mtu

            sb.append("DHCP Server: $dhcpServerAdddr \n")
            dnsServers.forEach {
                sb.append("DNS server: ${it.hostAddress}\n")
            }

            sb.append("Interface name: $ifaceName \n")

            if (addresses.isEmpty()) {
                sb.append("No IP address found!\n")
            } else {
                addresses.forEach { addr ->
                    sb.append("Address: ${addr.address.hostAddress}\n")
                }
            }

            routes.forEach { r ->
                sb.append("Route: $r\n")
            }
            sb.append("mtu: $mtu\n\n")

            sb.append("nat64prefix: $nat64prefix \n")
            sb.append("isPrivateDnsActive: $isPrivateDnsActive\n")
            sb.append("privateDnsServerName: $privateDnsServerName \n")
            sb.append("HTTP Proxy: $proxy \n")
            sb.append(
                "DNS domains search path: ${dnsDomains?.takeIf { it.isNotEmpty() } ?: "None"}\n"
            )
        }
    }


    return sb.toString()
}

private fun formatInterfaceDetails(intf: NetworkInterface): String {
    val details = StringBuilder()

    // 1. Basic Metadata
    details.append("--- Interface: ${intf.name} ---\n")
    details.append("| Display Name: ${intf.displayName}\n")
    details.append("| Index: ${intf.index}\n")
    details.append("| MTU: ${intf.mtu}\n")

    // 2. State & Capabilities (Crucial for Bipan)
    details.append("| Flags: ")
    if (intf.isUp) details.append("[UP] ")
    if (intf.isLoopback) details.append("[LOOPBACK] ")
    if (intf.isPointToPoint) details.append("[P2P/TUNNEL] ") // High signal for VPNs
    if (intf.supportsMulticast()) details.append("[MULTICAST] ")
    if (intf.isVirtual) details.append("[VIRTUAL] ")
    details.append("\n")

    // 3. Hardware Address (MAC)
    // Note: On modern Android, this returns null for non-system apps
    val mac = intf.hardwareAddress
    val macString = mac?.joinToString(":") { "%02x".format(it) } ?: "Hidden/Null"
    details.append("| MAC: $macString\n")

    // 4. IP Addresses (The "Leak" data)
    val addrList = intf.interfaceAddresses
    if (addrList.isEmpty()) {
        details.append("| Addresses: None\n")
    } else {
        for (addr in addrList) {
            val ip = addr.address.hostAddress
            val prefix = addr.networkPrefixLength
            val broadcast = addr.broadcast?.hostAddress ?: "N/A"
            details.append("| -> IP: $ip/$prefix (Broadcast: $broadcast)\n")
        }
    }

    // 5. Hierarchy (Sub-interfaces/VLANs)
    val parent = intf.parent
    if (parent != null) {
        details.append("| Parent: ${parent.name}\n")
    }

    val subs = intf.subInterfaces.asSequence().toList()
    if (subs.isNotEmpty()) {
        details.append("| Children: ${subs.joinToString { it.name }}\n")
    }

    return details.toString()
}

private fun dumpBuildInfo(): String {
    return """
            BOARD: ${Build.BOARD}
            BOOTLOADER: ${Build.BOOTLOADER}
            BRAND: ${Build.BRAND}
            DEVICE: ${Build.DEVICE}
            DISPLAY: ${Build.DISPLAY}
            FINGERPRINT: ${Build.FINGERPRINT}
            HARDWARE: ${Build.HARDWARE}
            HOST: ${Build.HOST}
            ID: ${Build.ID}
            MANUFACTURER: ${Build.MANUFACTURER}
            MODEL: ${Build.MODEL}
            ODM_SKU: ${Build.ODM_SKU}
            PRODUCT: ${Build.PRODUCT}
            SKU: ${Build.SKU}
            SOC_MANUFACTURER: ${Build.SOC_MANUFACTURER}
            SOC_MODEL: ${Build.SOC_MODEL}
            SUPPORTED_CPU_ABIs: ${Build.SUPPORTED_ABIS?.joinToString()}
            TAGS: ${Build.TAGS}
            TIME: ${Build.TIME}
            TYPE: ${Build.TYPE}
            USER: ${Build.USER}
            RADIO: ${Build.getRadioVersion()}
            MAJOR_SDK: ${Build.getMajorSdkVersion(Build.VERSION.SDK_INT_FULL)}
            MINOR_SDK: ${Build.getMinorSdkVersion(Build.VERSION.SDK_INT_FULL)}
            PARTITIONS: ${Build.getFingerprintedPartitions().joinToString { "${it.name}:${it.fingerprint}" }}
            BASE_OS: ${Build.VERSION.BASE_OS}
            CODENAME: ${Build.VERSION.CODENAME}
            INCREMENTAL: ${Build.VERSION.INCREMENTAL}
            MEDIA_PERFORMANCE_CLASS: ${Build.VERSION.MEDIA_PERFORMANCE_CLASS}
            PREVIEW_SDK_INT: ${Build.VERSION.PREVIEW_SDK_INT}
            RELEASE: ${Build.VERSION.RELEASE}
            RELEASE_OR_CODENAME: ${Build.VERSION.RELEASE_OR_CODENAME}
            RELEASE_OR_PREVIEW_DISPLAY: ${Build.VERSION.RELEASE_OR_PREVIEW_DISPLAY}
            SDK_INT: ${Build.VERSION.SDK_INT}
            SDK_INT_FULL: ${Build.VERSION.SDK_INT_FULL}
            SECURITY_PATCH: ${Build.VERSION.SECURITY_PATCH}
            """.trimIndent()
}

private fun dumpSettingsInfo(ctx: Context): String {
    val cr = ctx.contentResolver
    val NOT_FOUND = -999

    val deviceName = Global.getString(cr, Global.DEVICE_NAME) ?: "Unknown"
    @SuppressLint("HardwareIds")
    val ssaid = Settings.Secure.getString(cr, Settings.Secure.ANDROID_ID)

    val devSettingsOn = Global.getInt(cr, Global.DEVELOPMENT_SETTINGS_ENABLED, NOT_FOUND)
    val adbEnabled = Global.getInt(cr, Global.ADB_ENABLED, NOT_FOUND)
    val bootCount = Global.getInt(cr, Global.BOOT_COUNT, NOT_FOUND)
    val waitForDebugger = Global.getInt(cr, Global.WAIT_FOR_DEBUGGER, NOT_FOUND)

    return """
       DEVICE_NAME: $deviceName
       SSAID: $ssaid
       DEV_SETTINGS_ON: ${if (devSettingsOn == NOT_FOUND) "Could not extract value" else devSettingsOn}
       ADB_ENABLED: ${if (adbEnabled == NOT_FOUND) "Could not extract value" else adbEnabled}
       BOOT_COUNT: ${if (bootCount == NOT_FOUND) "Could not extract value" else bootCount}
       WAIT_FOR_DEBUGGER: ${if (waitForDebugger == NOT_FOUND) "Could not extract value" else waitForDebugger}
    """.trimIndent()
}

fun dumpQueryIntentActivities(context: Context): String {
    val pm = context.packageManager
    val sb = StringBuilder()

    // 1. Broad sweep — every app with a launcher icon
    val launcherIntent = Intent(Intent.ACTION_MAIN).apply {
        addCategory(Intent.CATEGORY_LAUNCHER)
    }
    val allApps = pm.queryIntentActivities(launcherIntent, 0)
    allApps.forEach { info ->
        sb.appendLine("Apps with Launcher: ${info.activityInfo.packageName}")
    }

    val arbitraryPackages = listOf(
        "com.spotify.music",
        "com.topjohnwu.magisk"
    )
    allApps.filter { app ->
        arbitraryPackages.any { prefix ->
            app.activityInfo.packageName.startsWith(prefix)
        }
    }.forEach { app ->
        sb.appendLine("Desired app found: ${app.activityInfo.packageName}")
    }

    return sb.toString()
}

fun dumpGetPackageInfo(context: Context, targetPackage: String): String {
    val pm = context.packageManager
    val sb = StringBuilder()

    val flags = (
            PackageManager.GET_PERMISSIONS or
                    PackageManager.GET_ACTIVITIES or
                    PackageManager.GET_SERVICES or
                    PackageManager.GET_RECEIVERS or
                    PackageManager.GET_PROVIDERS or
                    PackageManager.GET_SIGNING_CERTIFICATES
            )

    val info: PackageInfo = try {
        pm.getPackageInfo(targetPackage, flags)
    } catch (_: NameNotFoundException) {
        return "Package not found: $targetPackage"
    }

    // Basic info
    sb.appendLine("=== $targetPackage ===")
    sb.appendLine("Version: ${info.versionName} (${info.longVersionCode})")
    sb.appendLine("Installed: ${java.util.Date(info.firstInstallTime)}")
    sb.appendLine("Updated:   ${java.util.Date(info.lastUpdateTime)}")
    sb.appendLine("UID: ${info.applicationInfo?.uid}")

    // Permissions
    sb.appendLine("\n-- Declared Permissions --")
    info.requestedPermissions?.forEach { perm ->
        val granted = (info.requestedPermissionsFlags
            ?.getOrNull(info.requestedPermissions!!.indexOf(perm))
            ?: 0) and PackageInfo.REQUESTED_PERMISSION_GRANTED != 0
        sb.appendLine("  [${ if (granted) "GRANTED" else "DENIED " }] $perm")
    }

    // Components
    sb.appendLine("\n-- Activities --")
    info.activities?.forEach { sb.appendLine("  ${it.name}") }

    sb.appendLine("\n-- Services --")
    info.services?.forEach { sb.appendLine("  ${it.name}") }

    sb.appendLine("\n-- Receivers --")
    info.receivers?.forEach { sb.appendLine("  ${it.name}") }

    sb.appendLine("\n-- Providers --")
    info.providers?.forEach { sb.appendLine("  ${it.name}") }

    // Signing certs
    sb.appendLine("\n-- Signing Certificates --")
    info.signingInfo?.apkContentsSigners?.forEach { sig ->
        val md = java.security.MessageDigest.getInstance("SHA-256")
        val fingerprint = md.digest(sig.toByteArray())
            .joinToString(":") { "%02X".format(it) }
        sb.appendLine("  SHA-256: $fingerprint")
    }

    return sb.toString()
}

fun dumpGetInstalledApplications(context: Context): String {
    val pm = context.packageManager
    val sb = StringBuilder()

    // getInstalledApplications: Lighter: runtime info only, no components/permissions
    val apps: List<ApplicationInfo> =
        pm.getInstalledApplications(PackageManager.GET_META_DATA)

    sb.appendLine("\n=== getInstalledApplications (${apps.size} packages) ===")
    apps.forEach { app: ApplicationInfo ->
        val isSystem = (app.flags and ApplicationInfo.FLAG_SYSTEM) != 0
        val isDebuggable = (app.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0
        sb.appendLine("${app.packageName} | system: $isSystem | debuggable: $isDebuggable")
    }

    // getInstalledPackages: heavier: full PackageInfo per app — components + permissions in one shot
    val flags = (
            PackageManager.GET_PERMISSIONS or
                    PackageManager.GET_ACTIVITIES or
                    PackageManager.GET_SERVICES or
                    PackageManager.GET_RECEIVERS or
                    PackageManager.GET_PROVIDERS
            )
    val packages: List<PackageInfo> = pm.getInstalledPackages(flags)

    sb.appendLine("\n=== getInstalledPackages (${packages.size} packages) ===")
    packages.forEach { pkg: PackageInfo ->
        sb.appendLine("\n${pkg.packageName} v${pkg.versionName}")
        sb.appendLine("  Activities : ${pkg.activities?.size ?: 0}")
        sb.appendLine("  Services   : ${pkg.services?.size ?: 0}")
        sb.appendLine("  Receivers  : ${pkg.receivers?.size ?: 0}")
        sb.appendLine("  Providers  : ${pkg.providers?.size ?: 0}")

        val perms: Array<String> = pkg.requestedPermissions ?: emptyArray()
        val permFlags: IntArray = pkg.requestedPermissionsFlags ?: IntArray(0)
        perms.forEachIndexed { i, perm: String ->
            val granted = (permFlags.getOrElse(i) { 0 } and PackageInfo.REQUESTED_PERMISSION_GRANTED) != 0
            sb.appendLine("  [${if (granted) "GRANTED" else "DENIED "}] $perm")
        }
    }

    return sb.toString()
}

@RequiresApi(Build.VERSION_CODES.VANILLA_ICE_CREAM)
fun dumpGetApplicationInfo(context: Context) : String {
    val pm = context.packageManager
    val packageName = "com.whatsapp"

    val res = try {
        pm.getApplicationInfo(packageName, 0)
    } catch (e: Exception) {
        e.cause
    }

    return res.toString()
}

fun dumpGetSystemAvailableFeaturesInfo(context: Context) : String {
    val pm = context.packageManager
    val sb = StringBuilder()

    val res = pm.systemAvailableFeatures;
    res.forEach { fi ->
        sb.appendLine(fi.name)
    }
    return sb.toString()
}


fun getMemoryInfo(context: Context): String {
    val am  = context.getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
    val info = ActivityManager.MemoryInfo()
    am.getMemoryInfo(info)

    return """
        === [ActivityManager MemoryInfo] ===
        totalMem:         ${info.totalMem  / 1024 / 1024} MB
        availMem:         ${info.availMem  / 1024 / 1024} MB
        threshold:        ${info.threshold / 1024 / 1024} MB
        lowMemory:        ${info.lowMemory}
    """.trimIndent()
}

// Credits to https://github.com/fingerprintjs/fingerprintjs-android
fun dumpGpuInfo(context: Context) : String {
    val am  = context.getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
    val glesVersion = am.deviceConfigurationInfo.glEsVersion
    return "OpenGL ES version: $glesVersion"
}

// Credits to https://github.com/fingerprintjs/fingerprintjs-android
fun dumpCpuInfo() : String {
    val sb = StringBuilder()
    val jvmNproc = Runtime.getRuntime().availableProcessors()
    sb.appendLine("=== [Android Runtime info] ===")
    sb.appendLine(" Available processors to the JVM: $jvmNproc\n")

    val CPU_INFO_PATH = "/proc/cpuinfo"
    val KEY_VALUE_DELIMITER = ": "


    val cpuInfoMap: MutableMap<String, String> = HashMap()
    Scanner(File(CPU_INFO_PATH)).use { s ->
        while (s.hasNextLine()) {
            val cpuInfoValues = s.nextLine()!!.split(KEY_VALUE_DELIMITER)
            if (cpuInfoValues.size > 1) cpuInfoMap[cpuInfoValues[0].trim { it <= ' ' }] =
                cpuInfoValues[1].trim { it <= ' ' }
        }
    }

    sb.appendLine("=== [CPU Breakdown] ===")
    cpuInfoMap.forEach { (key, value) ->
        sb.appendLine("$key: $value")
    }

    return sb.toString()
}


fun getSystemProps(): String {
    val arch = System.getProperty("os.arch")
    val name = System.getProperty("os.name")
    val version = System.getProperty("os.version")

    return """
        os.arch:         $arch
        os.name:         $name
        os.name:         $version
    """.trimIndent()
}

// Credits to https://github.com/fingerprintjs/fingerprintjs-android
fun dumpGsfId(ctx: Context) : String {
    val cr = ctx.contentResolver
    val URI_GSF_CONTENT_PROVIDER = "content://com.google.android.gsf.gservices"
    val ID_KEY = "android_id"

    val uri = URI_GSF_CONTENT_PROVIDER.toUri()
    val params = arrayOf(ID_KEY)

    val gsfId = try {
        cr!!.query(uri, null, null, params, null)!!.use { cursor ->
            check(cursor.moveToFirst() && cursor.columnCount >= 2)
            java.lang.Long.toHexString(cursor.getString(1).toLong())
        }
    } catch (e: Exception) {
        "Failed to get GSF ID: ${e.message}"
    }
    return gsfId
}

// Credits to https://github.com/fingerprintjs/fingerprintjs-android
fun dumpMediaDrmId() : String {
    val WIDEWINE_UUID_MOST_SIG_BITS = -0x121074568629b532L
    val WIDEWINE_UUID_LEAST_SIG_BITS = -0x5c37d8232ae2de13L

    val widevineUUID = UUID(WIDEWINE_UUID_MOST_SIG_BITS, WIDEWINE_UUID_LEAST_SIG_BITS)

    val wvDrm = MediaDrm(widevineUUID)
    val mivevineId = wvDrm.getPropertyByteArray(MediaDrm.PROPERTY_DEVICE_UNIQUE_ID)
    wvDrm.close()
    val md: MessageDigest = MessageDigest.getInstance("SHA-256")
    md.update(mivevineId)

    return md.digest().toHexString()
}
private fun ByteArray.toHexString(): String {
    return this.joinToString("") {
        java.lang.String.format("%02x", it)
    }
}


@SuppressLint("PrivateApi")
fun dumpDevProperties(context: Context): String {
    val sysPropClass = Class.forName("android.os.SystemProperties")
    val getMethod: Method = sysPropClass.getMethod("get", String::class.java, String::class.java)
    fun prop(key: String, default: String = "<empty>"): String =
        (getMethod.invoke(null, key, default) as? String)
            ?.takeIf { it.isNotEmpty() } ?: default

    val tm = context.getSystemService(Context.TELEPHONY_SERVICE) as? TelephonyManager
    val sb = StringBuilder()

    fun section(name: String, block: StringBuilder.() -> Unit) {
        sb.appendLine("\n══ $name ══")
        sb.block()
    }
    fun row(label: String, value: Any?) =
        sb.appendLine("  %-45s %s".format("$label:", value ?: "<null>"))


    section("vendor_default_prop (?)") {
        row("vendor.secureos.kernel.version", prop("vendor.secureos.kernel.version"))
        row("ro.vendor.product.cpu.abilist", prop("ro.vendor.product.cpu.abilist"))
        row("ro.vendor.multisim.simslotcount", prop("ro.vendor.multisim.simslotcount"))
        row("ro.vendor.radio.default_network", prop("ro.vendor.radio.default_network"))
        row("ro.vendor.build.version.sdk_full", prop("ro.vendor.build.version.sdk_full"))
        row("ro.vendor.build.version.sdk", prop("ro.vendor.build.version.sdk"))
        row("ro.vendor.build.version.release_or_codename", prop("ro.vendor.build.version.release_or_codename"))
        row("ro.vendor.build.version.release", prop("ro.vendor.build.version.release"))
        row("ro.vendor.build.version.incremental", prop("ro.vendor.build.version.incremental"))
        row("ro.vendor.build.type", prop("ro.vendor.build.type"))
        row("ro.vendor.build.tags", prop("ro.vendor.build.tags"))
        row("[!] ro.vendor.build.security_patch", prop("ro.vendor.build.security_patch"))
        row("ro.vendor.build.id", prop("ro.vendor.build.id"))
        row("ro.vendor.build.fingerprint", prop("ro.vendor.build.fingerprint"))
        row("ro.vendor.build.date.utc", prop("ro.vendor.build.date.utc"))
        row("ro.vendor.build.date", prop("ro.vendor.build.date"))
        row("ro.vendor.api_level", prop("ro.vendor.api_level"))
        row("ro.product.vendor.name", prop("ro.product.vendor.name"))
        row("ro.product.vendor.model", prop("ro.product.vendor.model"))
        row("ro.product.vendor.manufacturer", prop("ro.product.vendor.manufacturer"))
        row("ro.product.vendor.device", prop("ro.product.vendor.device"))
        row("ro.product.vendor.brand", prop("ro.product.vendor.brand"))

    }

    section("binder_cache_telephony_server_prop (?)") {
        val activeDataSub   = runCatching { tm?.let {
            val m = TelephonyManager::class.java.getMethod("getActiveDataSubscriptionId")
            m.invoke(it)
        }}.getOrNull()
        val phoneCount      = runCatching { tm?.let {
            val m = TelephonyManager::class.java.getMethod("getPhoneCount")
            m.invoke(it)
        }}.getOrNull()

        row("[TelephonyManager (reflection)] activeDataSubscriptionId",                   activeDataSub)
        row("[TelephonyManager (reflection)] phoneCount",                                 phoneCount)
    }


    section("telephony_config_prop (?)") {
        row("ro.telephony.default_network",              prop("ro.telephony.default_network"))
        row("ro.telephony.sim_slots.count",              prop("ro.telephony.sim_slots.count"))
        row("ro.com.android.dataroaming",                prop("ro.com.android.dataroaming"))
    }

    section("telephony_status_prop (?)") {
        row("gsm.version.baseband",              prop("gsm.version.baseband"))
        row("gsm.version.ril-impl",              prop("gsm.version.ril-impl"))
        row("ril.sw_ver",              prop("ril.sw_ver"))
        // TODO: should be empty?
        row("ril.sw_ver2",              prop("ril.sw_ver2"))
        row("gsm.operator.alpha",                prop("gsm.operator.alpha"))
        row("gsm.operator.numeric",              prop("gsm.operator.numeric"))
        row("gsm.operator.iso-country",          prop("gsm.operator.iso-country"))
        row("gsm.sim.state",                     prop("gsm.sim.state"))
        row("gsm.network.type",                  prop("gsm.network.type"))
        // Crossrefing with Java
        row("[TelephonyManager] networkOperatorName",          tm?.networkOperatorName)
        row("[TelephonyManager] simOperatorName",              tm?.simOperatorName)
        row("[TelephonyManager] networkCountryIso",            tm?.networkCountryIso)
    }

    section("userdebug_or_eng_prop (?)") {
        row("[PROTECTED?] ro.debuggable",                     prop("ro.debuggable"))
        row("[PROTECTED?] ro.secure",                     prop("ro.secure"))
        row("[PROTECTED?] init.svc_debug_pid.adbd",           prop("init.svc_debug_pid.adbd"))
        row("[PROTECTED?] init.svc_debug_pid.tombstoned",     prop("init.svc_debug_pid.tombstoned"))
        row("ro.build.type",                     prop("ro.build.type"))
    }

    // ── radio_control_prop ────────────────────────────────────────────────
    // This one fires reliably already. Keep the same keys.
    section("radio_control_prop (?)") {
        row("persist.radio.multisim.config",     prop("persist.radio.multisim.config"))
        row("persist.radio.def_network",     prop("persist.radio.def_network"))
        row("persist.radio.latest-modeltype",     prop("persist.radio.latest-modeltype"))
    }

    section("fingerprint_prop (?)") {
        row("ro.system.build.fingerprint",       prop("ro.system.build.fingerprint"))
        row("ro.vendor.build.fingerprint",       prop("ro.vendor.build.fingerprint"))
        row("ro.product.build.fingerprint",      prop("ro.product.build.fingerprint"))
        row("ro.system_ext.build.fingerprint",   prop("ro.system_ext.build.fingerprint"))
        row("ro.odm.build.fingerprint",          prop("ro.odm.build.fingerprint"))
    }

    section("bootloader_prop") {
        row("ro.bootloader",                     prop("ro.bootloader"))
        row("ro.boot.verifiedbootstate",         prop("ro.boot.verifiedbootstate"))
        row("ro.boot.veritymode",                prop("ro.boot.veritymode"))
        row("ro.boot.vbmeta.digest",             prop("ro.boot.vbmeta.digest"))
        row("ro.boot.vbmeta.device_state",       prop("ro.boot.vbmeta.device_state"))
        row("ro.boot.avb_version",               prop("ro.boot.avb_version"))
        row("ro.boot.slot_suffix",               prop("ro.boot.slot_suffix"))
    }

    return sb.toString()
}

@RequiresApi(Build.VERSION_CODES.VANILLA_ICE_CREAM)
@RequiresPermission(allOf = [Manifest.permission.READ_PHONE_STATE, Manifest.permission.ACCESS_FINE_LOCATION, Manifest.permission.ACCESS_COARSE_LOCATION])
fun dumpTelephonyInfo(context: Context): String {
    /**
     *     public static final String TELEPHONY_IMS_SERVICE = "telephony_ims";
     *     public static final String TELEPHONY_PHONE_NUMBER_SERVICE = "telephony_phone_number";
     *     public static final String TELEPHONY_SUBSCRIPTION_SERVICE = "telephony_subscription_service";
     */

    // public static final String TELECOM_SERVICE = "telecom";
    val telecomManager  = context.getSystemService(Context.TELECOM_SERVICE) as TelecomManager

    // public static final String TELEPHONY_SERVICE = "phone";
    val telephonyManager  = context.getSystemService(Context.TELEPHONY_SERVICE) as TelephonyManager

    val sb = StringBuilder()
    sb.appendLine("=== [TelecomManager] ===")

    val simCallMgr = telecomManager.simCallManager
    if (simCallMgr != null) {
        val simCallComponentName = simCallMgr.componentName

        val simCallMgrId = simCallMgr.id
        val simCallComponentNamePkgName =  simCallComponentName.packageName
        val simCallComponentNameClassName = simCallComponentName.className
        val simCallComponentShortNameClassName =simCallComponentName.shortClassName

        sb.appendLine("simCallMgrId: $simCallMgrId")
        sb.appendLine("simCallComponentNamePkgName: $simCallComponentNamePkgName")
        sb.appendLine("simCallComponentNameClassName: $simCallComponentNameClassName")
        sb.appendLine("simCallComponentShortNameClassName: $simCallComponentShortNameClassName")
    }

    val defaultDialerPackage = telecomManager.defaultDialerPackage
    sb.appendLine("defaultDialerPackage ID: $defaultDialerPackage")


    sb.appendLine("=== [TelephonyManager] ===")

    sb.appendLine("[LEGACY] phoneCount: ${telephonyManager.phoneCount}")
    sb.appendLine("[MODERN] activeModemCount: ${telephonyManager.activeModemCount}")
    sb.appendLine("supportedModemCount: ${telephonyManager.supportedModemCount}")
    sb.appendLine("isMultiSimSupported: ${telephonyManager.isMultiSimSupported}")

    sb.appendLine("[LEGACY] allCellInfo: ${telephonyManager.allCellInfo}\n")
    sb.appendLine("[MODERN] cellLocation: ${telephonyManager.cellLocation}\n")



    sb.appendLine("carrierConfig: ${telephonyManager.carrierConfig}\n")
    sb.appendLine("carrierIdFromSimMccMnc: ${telephonyManager.carrierIdFromSimMccMnc}")
    sb.appendLine("networkOperator: ${telephonyManager.networkOperator}")
    sb.appendLine("networkOperatorName: ${telephonyManager.networkOperatorName}")
    sb.appendLine("simOperator: ${telephonyManager.simOperator}")
    sb.appendLine("simOperatorName: ${telephonyManager.simOperatorName}")
    sb.appendLine("networkCountryIso: ${telephonyManager.networkCountryIso}")
    sb.appendLine("simCountryIso: ${telephonyManager.simCountryIso}")
    sb.appendLine("simCarrierId: ${telephonyManager.simCarrierId}")
    sb.appendLine("simCarrierIdName: ${telephonyManager.simCarrierIdName}")
    sb.appendLine("simSpecificCarrierId: ${telephonyManager.simSpecificCarrierId}")

    sb.appendLine("serviceState: ${telephonyManager.serviceState}\n")

    sb.appendLine("visualVoicemailPackageName: ${telephonyManager.visualVoicemailPackageName}")
    sb.appendLine("hasCarrierPrivileges(): ${telephonyManager.hasCarrierPrivileges()}")
    sb.appendLine("preferredOpportunisticDataSubscription: ${telephonyManager.preferredOpportunisticDataSubscription}")

    return sb.toString()
}
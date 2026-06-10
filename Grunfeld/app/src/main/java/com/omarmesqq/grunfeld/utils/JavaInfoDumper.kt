package com.omarmesqq.grunfeld.utils

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
import java.net.Inet4Address
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.PackageInfo
import android.content.pm.SigningInfo

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
    val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
    val activeNetwork = cm.activeNetwork
    val caps = cm.getNetworkCapabilities(cm.activeNetwork)

    val isVpnTransport = caps?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) ?: false
    val hasNotVpnCap = caps?.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN) ?: true

    val sb = StringBuilder()
    sb.append("[SYSTEM CONNECTIVITY]\n")
    sb.append("TRANSPORT_VPN: $isVpnTransport\n")
    sb.append("HAS_NOT_VPN_CAP: $hasNotVpnCap\n\n")

    try {
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

    val wifiManager = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
    val info = wifiManager.connectionInfo
    val ipAddress = Formatter.formatIpAddress(info.ipAddress)
    val bssid = info.bssid ?: "Hidden"
    val ssid = info.ssid ?: "Hidden"
    val mac = info.macAddress ?: "Hidden"
    val linkSpeed = info.linkSpeed // Mbps
    sb.append("\n[LEGACY WIFI MANAGER LEAK TEST]\n")
    sb.append("IP Address: $ipAddress\n")
    sb.append("BSSID: $bssid\n")
    sb.append("SSID: $ssid\n")
    sb.append("MAC address: $mac\n")
    sb.append("Link Speed: $linkSpeed Mbps\n")

    sb.append("\n[MODERN LINK PROPERTIES LEAK TEST]\n")
    if (activeNetwork != null) {
        val linkProperties = cm.getLinkProperties(activeNetwork)
        if (linkProperties != null) {
            val addresses = linkProperties.linkAddresses
            if (addresses.isNotEmpty()) {
                addresses.forEach { linkAddr ->
                    val addr = linkAddr.address
                    sb.append("IP Address: ${addr.hostAddress}")
                    if (addr is Inet4Address) {
                        sb.append(" (IPv4)\n")
                    }
                }
            } else {
                sb.append("No addresses found in LinkProperties.\n")
            }
        } else {
            sb.append("LinkProperties is null.\n")
        }
    } else {
        sb.append("No active network to query.\n")
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
        "com.celzero.bravedns"
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
    } catch (e: PackageManager.NameNotFoundException) {
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

/**
 * TODO:
 * - Hook all overloads
 * - Hide custom ROM packages
 * - Make MicroG packages system
 */
fun dumpGetInstalledApplications(context: Context): String {
    val pm = context.packageManager
    val sb = StringBuilder()

    // --- getInstalledApplications ---
    // Lighter: runtime info only, no components/permissions
    val apps: List<android.content.pm.ApplicationInfo> =
        pm.getInstalledApplications(PackageManager.GET_META_DATA)

    sb.appendLine("=== getInstalledApplications (${apps.size} apps) ===")
    apps.forEach { app: android.content.pm.ApplicationInfo ->
        val isSystem = (app.flags and android.content.pm.ApplicationInfo.FLAG_SYSTEM) != 0
//        val isDebuggable = (app.flags and android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) != 0
        sb.appendLine("${app.packageName} | system: $isSystem")
//        sb.appendLine("  UID: ${app.uid} | system: $isSystem | debuggable: $isDebuggable")
//        sb.appendLine("  dataDir: ${app.dataDir}")
//        sb.appendLine("  nativeLibraryDir: ${app.nativeLibraryDir}")
    }

    // --- getInstalledPackages ---
    // Heavier: full PackageInfo per app — components + permissions in one shot
//    val flags = (
//            PackageManager.GET_PERMISSIONS or
//                    PackageManager.GET_ACTIVITIES or
//                    PackageManager.GET_SERVICES or
//                    PackageManager.GET_RECEIVERS or
//                    PackageManager.GET_PROVIDERS
//            )
//    val packages: List<PackageInfo> = pm.getInstalledPackages(flags)

//    sb.appendLine("\n=== getInstalledPackages (${packages.size} packages) ===")
//    packages.forEach { pkg: PackageInfo ->
//        sb.appendLine("\n${pkg.packageName} v${pkg.versionName}")
//        sb.appendLine("  Activities : ${pkg.activities?.size ?: 0}")
//        sb.appendLine("  Services   : ${pkg.services?.size ?: 0}")
//        sb.appendLine("  Receivers  : ${pkg.receivers?.size ?: 0}")
//        sb.appendLine("  Providers  : ${pkg.providers?.size ?: 0}")
//
//        val perms: Array<String> = pkg.requestedPermissions ?: emptyArray()
//        val permFlags: IntArray = pkg.requestedPermissionsFlags ?: IntArray(0)
//        perms.forEachIndexed { i, perm: String ->
//            val granted = (permFlags.getOrElse(i) { 0 } and PackageInfo.REQUESTED_PERMISSION_GRANTED) != 0
//            sb.appendLine("  [${if (granted) "GRANTED" else "DENIED "}] $perm")
//        }
//    }

    return sb.toString()
}
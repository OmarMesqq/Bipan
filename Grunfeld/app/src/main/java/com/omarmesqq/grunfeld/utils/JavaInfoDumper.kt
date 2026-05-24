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

fun DumpJavaInfo(context: Context): String {
    val buildInfo = dumpBuildInfo()
    val settingsInfo = dumpSettingsInfo(context)
    return "$buildInfo\n\n$settingsInfo"
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
        sb.append("[!] ERROR: ${e.message}\n")
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

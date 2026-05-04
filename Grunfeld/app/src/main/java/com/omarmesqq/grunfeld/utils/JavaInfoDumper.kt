package com.omarmesqq.grunfeld.utils

import android.content.Context
import android.hardware.Sensor
import android.hardware.SensorManager
import android.os.Build
import android.provider.Settings
import android.provider.Settings.Global

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

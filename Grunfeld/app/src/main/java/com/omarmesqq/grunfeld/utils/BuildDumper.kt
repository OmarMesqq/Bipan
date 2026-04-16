package com.omarmesqq.grunfeld.utils

import android.annotation.SuppressLint
import android.os.Build
import android.provider.Settings.Global
import android.provider.Settings
import android.content.Context


fun DumpJavaInfo(context: Context): String {
    val buildInfo = dumpBuildInfo()
    val settingsInfo = dumpSettingsInfo(context)
    return "$buildInfo\n\n$settingsInfo"
}

@SuppressLint("WrongConstant")
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

    val devSettingsOn = Global.getInt(cr, Global.DEVELOPMENT_SETTINGS_ENABLED)
    val adbEnabled = Global.getInt(cr, Global.ADB_ENABLED)
    val bootCount = Global.getInt(cr, Global.BOOT_COUNT)

    val deviceName = Global.getString(cr, Global.DEVICE_NAME) ?: "Unknown"
    val waitForDebugger = Global.getInt(cr, Global.WAIT_FOR_DEBUGGER)

    val ssaid = Settings.Secure.getString(cr, Settings.Secure.ANDROID_ID)

    return """
       DEV_SETTINGS_ON: $devSettingsOn
       ADB_ENABLED: $adbEnabled
       BOOT_COUNT: $bootCount
       DEVICE_NAME: $deviceName
       WAIT_FOR_DEBUGGER: $waitForDebugger
       SSAID: $ssaid
    """.trimIndent()
}

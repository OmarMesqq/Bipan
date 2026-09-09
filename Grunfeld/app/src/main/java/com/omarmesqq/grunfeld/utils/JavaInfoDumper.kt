package com.omarmesqq.grunfeld.utils

import android.annotation.SuppressLint
import android.content.ContentResolver
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.content.pm.PackageManager.NameNotFoundException
import android.hardware.Sensor
import android.hardware.SensorManager
import android.media.MediaDrm
import android.net.wifi.WifiInfo
import android.net.wifi.WifiManager
import android.os.Build
import android.provider.Settings
import android.telephony.TelephonyManager
import androidx.annotation.RequiresApi
import androidx.core.net.toUri
import com.omarmesqq.grunfeld.utils.Avocado.avocadoLog
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.async
import java.io.BufferedReader
import java.io.InputStreamReader
import java.lang.Long.toHexString
import java.lang.String.format
import java.lang.reflect.Method
import java.net.NetworkInterface
import java.util.Enumeration
import java.util.UUID

private val deferredInterfaces = GlobalScope.async {
    try {
        return@async NetworkInterface.getNetworkInterfaces()
    } catch (e: Exception) {
        throw e
    }
}


fun dumpSensorInfo(ctx: Context): String {
    val sb = StringBuilder()

    val sensorManager = ctx.getSystemService(Context.SENSOR_SERVICE) as SensorManager
    val sensorList = sensorManager.getSensorList(Sensor.TYPE_ALL)

    if (sensorList.isNotEmpty()) {
        sb.appendLine("SensorList(ALL) size: ${sensorList.size}")
    }

    val defaultSensorAll = sensorManager.getDefaultSensor(Sensor.TYPE_ALL)
    if (defaultSensorAll != null) {
        sb.appendLine("getDefaultSensor(ALL): ${defaultSensorAll.name}")
    }

    return sb.toString()
}


@Suppress("DEPRECATION")
fun dumpWifiManagerInfo(ctx: Context): WifiInfo {
    try {
        val wifiManager = ctx.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
        return wifiManager.connectionInfo
    } catch (e: Exception) {
        throw e
    }
}

fun dumpNetworkInterfaces(): Enumeration<NetworkInterface> {
    try {
        return deferredInterfaces.getCompleted()
    } catch (e: Exception) {
        avocadoLog(AVOCADO_LOG_LEVEL.AVOCADO_ERROR, msg = "getNetworkInterfaces Exception", tr = e)
        throw e
    }
}


@RequiresApi(Build.VERSION_CODES.VANILLA_ICE_CREAM)
@Suppress("DEPRECATION")
fun dumpGetPackageInfo(context: Context, targetPackage: String): String {
    val pm = context.packageManager
    val sb = StringBuilder()

    val flags = (
            PackageManager.GET_PERMISSIONS or
                    PackageManager.GET_ACTIVITIES or
                    PackageManager.GET_SERVICES or
                    PackageManager.GET_RECEIVERS or
                    PackageManager.GET_PROVIDERS or
                    PackageManager.GET_SIGNING_CERTIFICATES or
                    PackageManager.GET_META_DATA or
                    PackageManager.GET_URI_PERMISSION_PATTERNS or
                    PackageManager.GET_INTENT_FILTERS
            )

    val info: PackageInfo = try {
        pm.getPackageInfo(targetPackage, flags)
    } catch (_: NameNotFoundException) {
        return "Package not found: $targetPackage"
    }

    sb.appendLine("=== $targetPackage ===")
    sb.appendLine("Version: ${info.versionName} (${info.longVersionCode})")
    sb.appendLine("Installed: ${java.util.Date(info.firstInstallTime)}")
    sb.appendLine("Updated:   ${java.util.Date(info.lastUpdateTime)}")
    sb.appendLine("UID: ${info.applicationInfo?.uid}")

    val appInfoFlags = info.applicationInfo?.flags ?: 0
    val isSystemApp = (appInfoFlags and ApplicationInfo.FLAG_SYSTEM) != 0
    val isUpdatedSystemApp = (appInfoFlags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0

    sb.appendLine("isSystemApp: $isSystemApp")
    sb.appendLine("isUpdatedSystemApp: $isUpdatedSystemApp")

    sb.appendLine("metaData: ${info.applicationInfo?.metaData}")
    sb.appendLine("appComponentFactory: ${info.applicationInfo?.appComponentFactory}")
    sb.appendLine("backupAgentName: ${info.applicationInfo?.backupAgentName}")
    sb.appendLine("category: ${info.applicationInfo?.category}")
    sb.appendLine("className: ${info.applicationInfo?.className}")

    if (info.applicationInfo != null) {
        val label = pm.getApplicationLabel(info.applicationInfo!!)
        sb.appendLine("label: $label")
    }

    return sb.toString()
}


@RequiresApi(Build.VERSION_CODES.VANILLA_ICE_CREAM)
fun dumpGetApplicationInfo(context: Context, packageName: String) : String {
    val pm = context.packageManager

    val res = try {
        val appInfo = pm.getApplicationInfo(packageName, 0)
        val sb = StringBuilder()
        sb.appendLine("App Component Factory: ${appInfo.appComponentFactory}")
        sb.appendLine("Class name: ${appInfo.className}")
        sb.appendLine("Enabled ?: ${appInfo.enabled}")
        sb.appendLine("Minimum SDK: ${appInfo.minSdkVersion}")
        sb.appendLine("UID: ${appInfo.uid}")

        sb.toString()
    } catch (e: Exception) {
        e.cause
    }

    return res.toString()
}

fun dumpDeviceIds(ctx: Context, cr: ContentResolver): String {
    val ssaid = dumpSsaid(cr)
    val gsfId = dumpGsfId(ctx)
    val mediaDrmId = dumpMediaDrmId()

    val sb = StringBuilder()
    sb.appendLine("SSAID: $ssaid")
    sb.appendLine("GSF ID: $gsfId")
    sb.appendLine("DRM ID: $mediaDrmId")
    sb.appendLine("\nNow relaunch the app and note Bipan's work on these IDs!")

    return sb.toString()
}


@SuppressLint("PrivateApi")
fun dumpDevProperties(): String {
    val sysPropClass = Class.forName("android.os.SystemProperties")
    val getMethod: Method = sysPropClass.getMethod("get", String::class.java, String::class.java)
    fun prop(key: String, default: String = "<empty>"): String =
        (getMethod.invoke(null, key, default) as? String)
            ?.takeIf { it.isNotEmpty() } ?: default
    
    val sb = StringBuilder()

    fun section(name: String, block: StringBuilder.() -> Unit) {
        sb.appendLine("\n══ $name ══")
        sb.block()
    }
    fun row(label: String, value: Any?) =
        sb.appendLine("%s\n%s\n".format("$label:", value ?: "<null>"))

    section("Telephony and Radio - SELinux allowed") {
        row("gsm.version.baseband",              prop("gsm.version.baseband"))
        row("gsm.version.ril-impl",              prop("gsm.version.ril-impl"))
        row("ril.sw_ver",              prop("ril.sw_ver"))
        row("ril.sw_ver2",              prop("ril.sw_ver2"))
        row("gsm.operator.alpha",                prop("gsm.operator.alpha"))
        row("gsm.operator.numeric",              prop("gsm.operator.numeric"))
        row("gsm.sim.state",                     prop("gsm.sim.state"))
        row("gsm.network.type",                  prop("gsm.network.type"))
        row("ro.telephony.default_network",              prop("ro.telephony.default_network"))
        row("ro.telephony.sim_slots.count",              prop("ro.telephony.sim_slots.count"))
        row("persist.radio.def_network",     prop("persist.radio.def_network"))
        row("persist.radio.latest-modeltype",     prop("persist.radio.latest-modeltype"))
    }

    section("Build props - SELinux allowed") {
        row("ro.system.build.fingerprint",       prop("ro.system.build.fingerprint"))
        row("ro.vendor.build.fingerprint",       prop("ro.vendor.build.fingerprint"))
        row("ro.product.build.fingerprint",      prop("ro.product.build.fingerprint"))
        row("ro.system_ext.build.fingerprint",   prop("ro.system_ext.build.fingerprint"))
        row("ro.odm.build.fingerprint",          prop("ro.odm.build.fingerprint"))
        row("ro.vendor.build.version.sdk", prop("ro.vendor.build.version.sdk"))
        row("ro.vendor.build.version.release_or_codename", prop("ro.vendor.build.version.release_or_codename"))
        row("ro.vendor.build.version.release", prop("ro.vendor.build.version.release"))
        row("ro.vendor.build.version.incremental", prop("ro.vendor.build.version.incremental"))
        row("ro.vendor.build.type", prop("ro.vendor.build.type"))
        row("ro.vendor.build.tags", prop("ro.vendor.build.tags"))
        row("ro.vendor.build.id", prop("ro.vendor.build.id"))
        row("ro.vendor.build.fingerprint", prop("ro.vendor.build.fingerprint"))
        row("ro.vendor.build.date.utc", prop("ro.vendor.build.date.utc"))
        row("ro.vendor.build.date", prop("ro.vendor.build.date"))
        row("ro.product.vendor.name", prop("ro.product.vendor.name"))
        row("ro.product.vendor.model", prop("ro.product.vendor.model"))
        row("ro.product.vendor.manufacturer", prop("ro.product.vendor.manufacturer"))
        row("ro.product.vendor.device", prop("ro.product.vendor.device"))
        row("ro.product.vendor.brand", prop("ro.product.vendor.brand"))
        row("ro.build.flavor", prop("ro.build.flavor"))
    }

    section("Bootloader/AVB/Verity - SELinux allowed") {
        row("ro.bootloader",                     prop("ro.bootloader"))
        row("ro.boot.verifiedbootstate",         prop("ro.boot.verifiedbootstate"))
        row("ro.com.google.clientidbase",         prop("ro.com.google.clientidbase"))
        row("ro.boot.selinux",         prop("ro.boot.selinux"))
        row("ro.boot.warranty_bit",         prop("ro.boot.warranty_bit"))
        row("ro.boot.hardware",         prop("ro.boot.hardware"))
        row("ro.boot.boot_devices",         prop("ro.boot.boot_devices"))
    }

    section("Persist/Init Section - SELinux allowed") {
        row("persist.sys.usb.config",         prop("persist.sys.usb.config"))
        row("init.svc.adbd",         prop("init.svc.adbd"))
    }

    section("telephony_status_prop") {
        row("gsm.operator.iso-country",          prop("gsm.operator.iso-country"))
        row("gsm.sim.operator.iso-country", prop("gsm.sim.operator.iso-country"))
        row("gsm.sim.operator.numeric", prop("gsm.sim.operator.numeric"))
    }

    section("radio_control_prop") {
        row("persist.radio.multisim.config",     prop("persist.radio.multisim.config"))
    }

    section("build_bootimage_prop") {
        row("ro.bootimage.build.fingerprint",         prop("ro.bootimage.build.fingerprint"))
        row("ro.bootimage.build.type",         prop("ro.bootimage.build.type"))
        row("ro.bootimage.build.tags",         prop("ro.bootimage.build.tags"))
    }


    section("userdebug_or_eng_prop") {
        row("ro.debuggable",         prop("ro.debuggable"))
        row("ro.secure",         prop("ro.secure"))
    }

    section("custom_version_prop") {
        row("ro.lineage.version",         prop("ro.lineage.version"))
        row("ro.lineage.releasetype",         prop("ro.lineage.releasetype"))
    }

    section("init_service_status_private_prop") {
        row("init.svc.adb_root",         prop("init.svc.adb_root"))
        row("init.svc.flash_recovery",         prop("init.svc.flash_recovery"))
        row("init.svc.usbd",         prop("init.svc.usbd"))
        row("init.svc.vaultkeeper",         prop("init.svc.vaultkeeper"))
    }

    section("serialno_prop") {
        row("ro.serialno",         prop("ro.serialno"))
    }

    section("bootloader_prop") {
        row("ro.boot.ap_serial",         prop("ro.boot.ap_serial"))
        row("ro.boot.em.did",         prop("ro.boot.em.did"))
    }


    return sb.toString()
}

@RequiresApi(Build.VERSION_CODES.VANILLA_ICE_CREAM)
@Suppress("DEPRECATION")
fun dumpTelephonyInfo(context: Context): String {
    val telephonyManager  = context.getSystemService(Context.TELEPHONY_SERVICE) as TelephonyManager

    val sb = StringBuilder()

    sb.appendLine("subscriptionId: ${telephonyManager.subscriptionId}")
    sb.appendLine("[LEGACY] phoneCount: ${telephonyManager.phoneCount}")
    sb.appendLine("[MODERN] activeModemCount: ${telephonyManager.activeModemCount}")
    sb.appendLine("supportedModemCount: ${telephonyManager.supportedModemCount}")

    sb.appendLine("carrierIdFromSimMccMnc: ${telephonyManager.carrierIdFromSimMccMnc}")
    sb.appendLine("networkOperator: ${telephonyManager.networkOperator}")
    sb.appendLine("networkOperatorName: ${telephonyManager.networkOperatorName}")
    sb.appendLine("simOperator: ${telephonyManager.simOperator}")
    sb.appendLine("simOperatorName: ${telephonyManager.simOperatorName}")
    sb.appendLine("networkCountryIso: ${telephonyManager.networkCountryIso}")
    sb.appendLine("simCountryIso: ${telephonyManager.simCountryIso}")
    sb.appendLine("simCarrierId: ${telephonyManager.simCarrierId}")
    sb.appendLine("simCarrierIdName: ${telephonyManager.simCarrierIdName}")
    sb.appendLine("simSpecificCarrierId: ${telephonyManager.simSpecificCarrierId}\n")

    sb.appendLine("hasCarrierPrivileges: ${telephonyManager.hasCarrierPrivileges()}")

    try {
        sb.appendLine("isMultiSimSupported: ${telephonyManager.isMultiSimSupported}")
        sb.appendLine("[LEGACY] allCellInfo: ${telephonyManager.allCellInfo}")
        sb.appendLine("[MODERN] cellLocation: ${telephonyManager.cellLocation}")
        sb.appendLine("visualVoicemailPackageName: ${telephonyManager.visualVoicemailPackageName}")
    } catch (e: SecurityException) {
        avocadoLog(AVOCADO_LOG_LEVEL.AVOCADO_ERROR, "dumpTelephonyInfo", "Exception: ", tr = e)

        sb.appendLine("Permission denied for grabbing some fields: ${e.message}")
        sb.appendLine("Stacktrace: ${e.stackTrace.contentToString()}")
    }

    return sb.toString()
}

fun runtimeExecWithCmdArray(cmdarray: Array<String>):String {
    val sb = StringBuilder()
    try {
        val process =  Runtime.getRuntime().exec(cmdarray)
        val bufferedReader = BufferedReader(InputStreamReader(process.inputStream))
        bufferedReader.forEachLine { line ->
            sb.appendLine(line)
        }
    } catch (tr: Throwable) {
        sb.appendLine("Throwable: ${tr.cause} | ${tr.message}")
    }
    return sb.toString()
}

fun runtimeExecWithCmd(cmd: String):String {
    val sb = StringBuilder()
    try {
        val process =  Runtime.getRuntime().exec(cmd)
        val bufferedReader = BufferedReader(InputStreamReader(process.inputStream))
        bufferedReader.forEachLine { line ->
            sb.appendLine(line)
        }

    } catch (tr: Throwable) {
        sb.appendLine("Throwable: ${tr.cause} | ${tr.message}")
    }
    return sb.toString()
}



// Credits to https://github.com/fingerprintjs/fingerprintjs-android
private fun dumpGsfId(ctx: Context) : String {
    val cr = ctx.contentResolver
    val gsfContentProviderUri = "content://com.google.android.gsf.gservices"
    val idKey = "android_id"

    val uri = gsfContentProviderUri.toUri()
    val params = arrayOf(idKey)

    val gsfId = try {
        cr!!.query(uri, null, null, params, null)!!.use { cursor ->
            check(cursor.moveToFirst() && cursor.columnCount >= 2)
            toHexString(cursor.getString(1).toLong())
        }
    } catch (e: Exception) {
        "Failed to get GSF ID: ${e.message}"
    }
    return gsfId
}

// Credits to https://github.com/fingerprintjs/fingerprintjs-android
private fun dumpMediaDrmId() : String {
    val widevineUUidMostSigBits = -0x121074568629b532L
    val widevineUUidLeastSigBits = -0x5c37d8232ae2de13L
    val widevineUUID = UUID(widevineUUidMostSigBits, widevineUUidLeastSigBits)

    val wvDrm = MediaDrm(widevineUUID)
    val widevineIdRaw = wvDrm.getPropertyByteArray(MediaDrm.PROPERTY_DEVICE_UNIQUE_ID)
    val widevineId = widevineIdRaw.toHexString()
    wvDrm.close()

    return widevineId
}
private fun ByteArray.toHexString(): String {
    return this.joinToString("") {
        format("%02x", it)
    }
}


private fun dumpSsaid(cr: ContentResolver): String {
    @SuppressLint("HardwareIds")
    val ssaid = Settings.Secure.getString(cr, Settings.Secure.ANDROID_ID)
    return ssaid
}
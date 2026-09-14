package com.omarmesqq.grunfeld.utils

import android.annotation.SuppressLint
import android.content.ContentResolver
import android.content.Context
import android.hardware.Sensor
import android.hardware.SensorManager
import android.media.MediaDrm
import android.net.wifi.WifiInfo
import android.net.wifi.WifiManager
import android.provider.Settings
import androidx.core.net.toUri
import com.omarmesqq.grunfeld.utils.Avocado.avocadoLog
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader
import java.lang.Long.toHexString
import java.lang.String.format
import java.lang.reflect.Method
import java.net.NetworkInterface
import java.util.UUID

suspend fun getNetworkInterfaces(): List<NetworkInterface>? {
    try {
        var ifaces: List<NetworkInterface>
        withContext(Dispatchers.IO) {
            ifaces = NetworkInterface.getNetworkInterfaces().toList()
        }
        return ifaces
    } catch (e: Exception) {
        avocadoLog(AVOCADO_LOG_LEVEL.AVOCADO_ERROR, msg = "getNetworkInterfaces Exception", tr = e)
        return null
    }
}

fun getSensorsInfo(ctx: Context): String {
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

    val sensorsInfoNativeLayer = NativeLibWrapper.testSensors()
    sb.append(sensorsInfoNativeLayer)

    return sb.toString()
}

@Suppress("DEPRECATION")
fun getWifiManagerInfo(ctx: Context): WifiInfo {
    try {
        val wifiManager = ctx.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
        return wifiManager.connectionInfo
    } catch (e: Exception) {
        throw e
    }
}

@SuppressLint("PrivateApi")
fun getSystemProperty(key: String, defaultValue: String = "<empty>"): String {
    val sysPropClass = Class.forName("android.os.SystemProperties")
    val getMethod: Method = sysPropClass.getMethod("get", String::class.java, String::class.java)

    return (getMethod.invoke(null, key, defaultValue) as? String)
        ?.takeIf { it.isNotEmpty() } ?: defaultValue
}

// Credits to https://github.com/fingerprintjs/fingerprintjs-android
fun getGsfId(ctx: Context) : String {
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
fun getMediaDrmId() : String {
    val widevineUUidMostSigBits = -0x121074568629b532L
    val widevineUUidLeastSigBits = -0x5c37d8232ae2de13L
    val widevineUUID = UUID(widevineUUidMostSigBits, widevineUUidLeastSigBits)

    val wvDrm = MediaDrm(widevineUUID)
    val widevineIdRaw = wvDrm.getPropertyByteArray(MediaDrm.PROPERTY_DEVICE_UNIQUE_ID)
    val widevineId = widevineIdRaw.toHexString()
    wvDrm.close()

    return widevineId
}

fun getSsaid(cr: ContentResolver): String {
    @SuppressLint("HardwareIds")
    val ssaid = Settings.Secure.getString(cr, Settings.Secure.ANDROID_ID)
    return ssaid
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
        sb.append(bufferedReader.readLine())
    } catch (tr: Throwable) {
        sb.appendLine("Throwable: ${tr.cause} | ${tr.message}")
    }
    return sb.toString()
}


fun openFileKt(filename: String): String {
    val sb = StringBuilder()
    try {
        val file = File(filename)
        val br = BufferedReader(InputStreamReader(file.inputStream()))
        val linesToShow = 5
        sb.appendLine("=== $linesToShow of $filename ===")
        repeat(linesToShow) {
            sb.append(br.readLine())
        }
        sb.append("\n")
    } catch (tr: Throwable) {
        sb.appendLine("${tr.message}")
    }
    return sb.toString()
}

private fun ByteArray.toHexString(): String {
    return this.joinToString("") {
        format("%02x", it)
    }
}
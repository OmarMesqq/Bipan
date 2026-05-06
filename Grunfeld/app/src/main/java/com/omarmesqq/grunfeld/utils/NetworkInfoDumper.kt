package com.omarmesqq.grunfeld.utils

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import com.omarmesqq.grunfeld.utils.Avocado.avocadoLog
import java.net.NetworkInterface

private  const val  TAG = "NetInfoDumper"
fun dumpNetworkInfo(context: Context): String {
    // ACCESS_NETWORK_STATE whatnots to get info on connectivity info of device
    val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
    val caps = cm.getNetworkCapabilities(cm.activeNetwork)

    // JVM Connectivity Flags
    val isVpnTransport = caps?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) ?: false
    val hasNotVpnCap = caps?.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN) ?: true

    // Interface Scan
    val interfaceList = mutableListOf<String>()
    var vpnInterfaceFound = false

    try {
        val interfaces = NetworkInterface.getNetworkInterfaces()
        for (intf in interfaces) {
            if (intf.isUp) {
                val name = intf.name.lowercase()
                // Check for common VPN/Tunnel prefixes
                val isSuspectedVpn = name.contains("tun") ||
                        name.contains("ppp") ||
                        name.contains("p2p") ||
                        name.contains("wg")

                if (isSuspectedVpn) vpnInterfaceFound = true

                val vpnTag = if (isSuspectedVpn) " [VPN_MATCH]" else ""
                interfaceList.add("${intf.name}$vpnTag [MTU: ${intf.mtu}]")
            }
        }
    } catch (e: Exception) {
        interfaceList.add("Error while scanning interfaces: ${e.message}")
        avocadoLog(AVOCADO_LOG_LEVEL.AVOCADO_ERROR , TAG, "Error scanning interfaces", tr = e,  shouldToast = true)
    }

    return """
    |[NETWORK CAPABILITIES]
    |TRANSPORT_VPN: $isVpnTransport
    |HAS_NOT_VPN_CAPABILITY: $hasNotVpnCap
    |
    |[INTERFACES]
    |VPN_INTERFACE_DETECTED: $vpnInterfaceFound
    |
    |[LIST OF INTERFACES]:
    |${interfaceList.joinToString("\n|")}
""".trimMargin()

}
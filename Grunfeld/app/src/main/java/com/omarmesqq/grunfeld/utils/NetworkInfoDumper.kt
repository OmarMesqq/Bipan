package com.omarmesqq.grunfeld.utils

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import com.omarmesqq.grunfeld.utils.Avocado.avocadoLog
import java.net.NetworkInterface

private  const val  TAG = "NetInfoDumper"
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
package com.omarmesqq.grunfeld.utils


import android.net.TrafficStats
import java.net.InetAddress
import java.net.Socket
import javax.net.SocketFactory

private const val OKHTTP_SOCKET_TAG = 8988

class TaggingSocketFactory(
    private val delegate: SocketFactory
) : SocketFactory() {

    private fun <T : Socket> tagAndCreate(block: () -> T): T {
        TrafficStats.setThreadStatsTag(OKHTTP_SOCKET_TAG)
        return block()
    }

    override fun createSocket(): Socket =
        tagAndCreate { delegate.createSocket() }

    override fun createSocket(host: String?, port: Int): Socket =
        tagAndCreate { delegate.createSocket(host, port) }

    override fun createSocket(host: String?, port: Int, localHost: InetAddress?, localPort: Int): Socket =
        tagAndCreate { delegate.createSocket(host, port, localHost, localPort) }

    override fun createSocket(host: InetAddress?, port: Int): Socket =
        tagAndCreate { delegate.createSocket(host, port) }

    override fun createSocket(address: InetAddress?, port: Int, localAddress: InetAddress?, localPort: Int): Socket =
        tagAndCreate { delegate.createSocket(address, port, localAddress, localPort) }
}


class TaggingSSLSocketFactory(
    private val delegate: javax.net.ssl.SSLSocketFactory
) : javax.net.ssl.SSLSocketFactory() {

    override fun getDefaultCipherSuites(): Array<String> = delegate.defaultCipherSuites
    override fun getSupportedCipherSuites(): Array<String> = delegate.supportedCipherSuites

    private fun <T : Socket> tagAndCreate(block: () -> T): T {
        TrafficStats.setThreadStatsTag(OKHTTP_SOCKET_TAG)
        val socket = block()
        TrafficStats.tagSocket(socket) // maybe unnecessary
        return socket
    }

    // Wraps an existing socket
    override fun createSocket(s: Socket?, host: String?, port: Int, autoClose: Boolean): Socket {
        TrafficStats.setThreadStatsTag(OKHTTP_SOCKET_TAG)
        val socket = delegate.createSocket(s, host, port, autoClose)
        TrafficStats.tagSocket(socket) // maybe unnecessary
        return socket
    }

    override fun createSocket(): Socket =
        tagAndCreate { delegate.createSocket() }

    override fun createSocket(host: String?, port: Int): Socket =
        tagAndCreate { delegate.createSocket(host, port) }

    override fun createSocket(host: String?, port: Int, localHost: InetAddress?, localPort: Int): Socket =
        tagAndCreate { delegate.createSocket(host, port, localHost, localPort) }

    override fun createSocket(host: InetAddress?, port: Int): Socket =
        tagAndCreate { delegate.createSocket(host, port) }

    override fun createSocket(address: InetAddress?, port: Int, localAddress: InetAddress?, localPort: Int): Socket =
        tagAndCreate { delegate.createSocket(address, port, localAddress, localPort) }
}
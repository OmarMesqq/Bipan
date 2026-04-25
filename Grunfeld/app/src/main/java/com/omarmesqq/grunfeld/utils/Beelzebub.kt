package com.omarmesqq.grunfeld.utils

import android.content.Context
import android.webkit.CookieManager
import android.webkit.MimeTypeMap
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import android.webkit.WebSettings
import com.omarmesqq.grunfeld.utils.Avocado.avocadoLog
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.io.FileOutputStream
import java.security.MessageDigest

private const val TAG = "Beelzebub"

/**
 * A very hungry cache manager
 */
object Beelzebub {

    private val cacheableExtensions = listOf(
        ".png", ".jpg", ".jpeg", ".gif", ".css", ".js", ".woff2", ".svg", ".ico"
    )

    /**
     * Attempt to serve cached version of a given resource
     * If HIT, serve it
     * Otherwise, cache it
     */
    fun feast(ctx: Context, request: WebResourceRequest): WebResourceResponse? {
        val url = request.url.toString()
        val isStaticAsset = cacheableExtensions.any { url.lowercase().contains(it) }
        if (!isStaticAsset) return null

        val extension = MimeTypeMap.getFileExtensionFromUrl(url)
        val fileName = url.toHash("MD5") + "." + extension
        val cacheFile = File(ctx.cacheDir, fileName)
        val mimeType = MimeTypeMap.getSingleton().getMimeTypeFromExtension(extension) ?: "application/octet-stream"

        // 1. HIT: Serve from disk
        if (cacheFile.exists()) {
            avocadoLog(AVOCADO_LOG_LEVEL.AVOCADO_INFO, TAG, "Cache HIT for: $fileName")
            return WebResourceResponse(mimeType, "UTF-8", cacheFile.inputStream()).apply {
                responseHeaders = mapOf("Access-Control-Allow-Origin" to "*")
            }
        }

        // 2. MISS: Hoard it for next time
        avocadoLog(AVOCADO_LOG_LEVEL.AVOCADO_DEBUG, TAG, "Cache MISS for: $fileName. Hoarding...")
        return hoard(ctx, request, cacheFile, mimeType)
    }

    /**
     * Downloads the resource, saves it to disk, and returns the response
     */
    private fun hoard(ctx: Context, request: WebResourceRequest, cacheFile: File, mimeType: String): WebResourceResponse? {
        val url = request.url.toString()
        return try {
            val connection = URL(url).openConnection() as HttpURLConnection

            // 1. Mirror the original Request Headers (Referer, Origin, etc.)
            request.requestHeaders.forEach { (key, value) ->
                connection.setRequestProperty(key, value)
            }

            // 2. Inject Cookies for this specific URL
            val cookies = CookieManager.getInstance().getCookie(url)
            if (cookies != null) {
                connection.setRequestProperty("Cookie", cookies)
            }

            // 3. Ensure User-Agent is present and matches the WebView
            if (connection.getRequestProperty("User-Agent") == null) {
                connection.setRequestProperty("User-Agent", WebSettings.getDefaultUserAgent(ctx))
            }

            connection.connectTimeout = 10000
            connection.readTimeout = 10000

            if (connection.responseCode == HttpURLConnection.HTTP_OK) {
                connection.inputStream.use { input ->
                    FileOutputStream(cacheFile).use { output ->
                        input.copyTo(output)
                    }
                }

                WebResourceResponse(mimeType, "UTF-8", cacheFile.inputStream()).apply {
                    // We can also mirror the response headers from the server if needed
                    responseHeaders = mapOf("Access-Control-Allow-Origin" to "*")
                }
            } else {
                null
            }
        } catch (e: Exception) {
            avocadoLog(AVOCADO_LOG_LEVEL.AVOCADO_ERROR, TAG, "Hoard failed: ${e.message}")
            null
        }
    }
    private fun String.toHash(algorithm: String = "MD5"): String {
        val bytes = MessageDigest.getInstance(algorithm).digest(this.toByteArray())
        return bytes.joinToString("") { "%02x".format(it) }
    }
}
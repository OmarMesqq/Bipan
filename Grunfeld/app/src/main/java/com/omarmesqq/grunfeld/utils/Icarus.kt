package com.omarmesqq.grunfeld.utils

import android.R.attr.mimeType
import android.content.Context
import android.webkit.CookieManager
import android.webkit.MimeTypeMap
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import androidx.core.net.toUri
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.io.File
import java.security.cert.X509Certificate
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager
import com.omarmesqq.grunfeld.BuildConfig
import com.omarmesqq.grunfeld.utils.Avocado.avocadoLog
import okhttp3.logging.HttpLoggingInterceptor
import java.net.UnknownHostException
import javax.net.SocketFactory

private const val TAG = "Icarus"
private const val REQUEST_LOGGING_TAG = "Icarus-Logger"

object Icarus {
    /**
     * Always allow Cross Origin Resource Sharing for any resource
     * in case origin forgot to set
     */
    private val CORS_HEADERS = mapOf("Access-Control-Allow-Origin" to "*")
    private const val TIMEOUT = 30L // seconds
    private const val OKHTTP_SOCKET_TAG = 8988
    private val okHttpClient = OkHttpClient.Builder()
        .followRedirects(true)
        .socketFactory(TaggingSocketFactory(SocketFactory.getDefault(), OKHTTP_SOCKET_TAG))
        .connectTimeout(TIMEOUT, TimeUnit.SECONDS)
        .readTimeout(TIMEOUT, TimeUnit.SECONDS)
        .writeTimeout(TIMEOUT, TimeUnit.SECONDS)
        .fastFallback(true)
        .cookieJar(object : okhttp3.CookieJar {
            private val cookieStore = mutableMapOf<String, List<okhttp3.Cookie>>()
            override fun saveFromResponse(url: okhttp3.HttpUrl, cookies: List<okhttp3.Cookie>) {
                cookieStore[url.host] = cookies
            }
            override fun loadForRequest(url: okhttp3.HttpUrl): List<okhttp3.Cookie> {
                return cookieStore[url.host] ?: listOf()
            }
        })
        .apply {
            if (BuildConfig.DEBUG) {
                val trustAllCerts = arrayOf<TrustManager>(object : X509TrustManager {
                    override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
                    override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}
                    override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
                })

                val sslContext = SSLContext.getInstance("TLS")
                sslContext.init(null, trustAllCerts, java.security.SecureRandom())
                sslSocketFactory(
                    TaggingSSLSocketFactory(sslContext.socketFactory, OKHTTP_SOCKET_TAG),
                    trustAllCerts[0] as X509TrustManager
                )
                hostnameVerifier { _, _ -> true }
            }
        }
        .addInterceptor(HttpLoggingInterceptor { message ->
            avocadoLog(AVOCADO_LOG_LEVEL.AVOCADO_WARNING, REQUEST_LOGGING_TAG, message)
        }.apply {
            level = HttpLoggingInterceptor.Level.HEADERS
        })
        .build()

    fun handleRequest(
        context: Context,
        request: WebResourceRequest,
        currentUrl: String,
        userAgent: String
    ): WebResourceResponse? {
        val uri = request.url
        val urlString = uri.toString()
        // Assume GET as default I guess
        val method = request.method?.uppercase() ?: "GET"

        if (!isHostAllowed(urlString, currentUrl)) {
            avocadoLog(AVOCADO_LOG_LEVEL.AVOCADO_WARNING, TAG, "Blocking 3rd Party: $urlString")
            return WebResourceResponse("text/plain", "UTF-8", 403, "Forbidden", null, "".byteInputStream())
        }

        if (method == "OPTIONS") {
            // Echo back whatever headers the browser is asking for
            val requestedHeaders = request.requestHeaders["Access-Control-Request-Headers"] ?: "*"

            val responseHeaders = mutableMapOf(
                "Access-Control-Allow-Origin" to "*",
                "Access-Control-Allow-Methods" to "GET, POST, OPTIONS, PUT, DELETE, PATCH",
                "Access-Control-Allow-Headers" to requestedHeaders, // Dynamic fix
                "Access-Control-Max-Age" to "3600"
            )
            return WebResourceResponse("text/plain", "UTF-8", 200, "OK", responseHeaders, "".byteInputStream())
        }

        // Network Fetch via OkHttp
        return try {
            val okRequestBuilder = if (method in listOf("GET", "HEAD", "OPTIONS")) {
                Request.Builder()
                    .url(urlString)
                    .header("User-Agent", userAgent)
                    .header("Priority", "u=0, i")
                    .method(method, null)
            } else {
                Request.Builder()
                    .url(urlString)
                    .header("User-Agent", userAgent)
                    .header("Priority", "u=0, i")
            }

            // Map WebView Headers to OkHttp
            request.requestHeaders.forEach { (key, value) ->
                if (!shouldStripHeader(key)) {
                    okRequestBuilder.addHeader(key, value)
                }
            }

            // Sync Cookies
            val cookies = CookieManager.getInstance().getCookie(urlString)
            if (!cookies.isNullOrEmpty()) {
                okRequestBuilder.addHeader("Cookie", cookies)
            }

            val response = okHttpClient.newCall(okRequestBuilder.build()).execute()

            if (response.isSuccessful) {
                // 1. FLATTEN HEADERS: Convert Map<String, List<String>> to Map<String, String>
                val flatHeaders = mutableMapOf<String, String>()
                for (name in response.headers.names()) {
                    // Standard HTTP behavior: multiple headers with same name are comma-separated
                    flatHeaders[name] = response.headers(name).joinToString(", ")
                }

                // 2. PERMISSIVE CORS: Force origin and headers to avoid preflight blocks
                flatHeaders["Access-Control-Allow-Origin"] = "*"
                flatHeaders["Access-Control-Allow-Headers"] = "*"

                val contentType = response.header("Content-Type", "text/html; charset=utf-8")
                val mimeType = contentType?.split(";")?.get(0) ?: "text/html"
                val encoding = if (contentType?.contains("charset=") == true)
                    contentType.split("charset=")[1].trim() else "UTF-8"

                var bodyStream = response.body.byteStream()

                // 3. SOURCE MAP SCRUBBING
                if (mimeType.contains("javascript") || mimeType.contains("css")) {
                    val content = response.body.string()
                    val scrubbed = content.replace(Regex("""[/#|*]\s*sourceMappingURL=.*"""), "")
                    bodyStream = scrubbed.byteInputStream(Charsets.UTF_8)
                }

                return WebResourceResponse(
                    mimeType,
                    encoding,
                    response.code,
                    response.message.ifEmpty { "OK" },
                    flatHeaders, // Use the correct flat Map here!
                    bodyStream
                )
            } else { // 400s and 500s
                avocadoLog(AVOCADO_LOG_LEVEL.AVOCADO_ERROR, TAG, "handleRequest: Response unsuccessful: code ${response.code}", shouldToast = true)
                return WebResourceResponse(
                    "text/plain",
                    "UTF-8",
                    response.code,
                    response.message.ifEmpty { "Error" },
                    CORS_HEADERS,
                    "".byteInputStream()
                )
            }
        } catch (e: UnknownHostException) {
            avocadoLog(AVOCADO_LOG_LEVEL.AVOCADO_ERROR, TAG, "handleRequest: DNS query failed for $urlString", shouldToast = true)
            return WebResourceResponse(
                "text/plain",
                "UTF-8",
                200,
                "OK",
                CORS_HEADERS,
                "".byteInputStream()
            )
        } catch (e: Exception) { // Catastrophic failure...
            avocadoLog(AVOCADO_LOG_LEVEL.AVOCADO_ERROR, TAG, "handleRequest: Exception\n${e.stackTraceToString()}", shouldToast = true)
            return WebResourceResponse(
                "text/plain",
                "UTF-8",
                504,
                "Icarus Timeout",
                CORS_HEADERS,
                "".byteInputStream()
            )
        }
    }

    fun executeManualBodyRequest(urlString: String, body: String, contentType: String, currentUrl: String, method: String, userAgent: String): String? {
        return try {
            if (!isHostAllowed(urlString, currentUrl)) {
                avocadoLog(AVOCADO_LOG_LEVEL.AVOCADO_WARNING, TAG, "Blocking 3rd Party: $urlString")
                return "<html><body>Host not allowed</body></html>"
            }

            val mediaType = contentType.toMediaTypeOrNull() ?: "application/x-www-form-urlencoded".toMediaType()
            val requestBody = body.toRequestBody(mediaType)

            val okRequestBuilder = Request.Builder()
                .url(urlString)
                .method(method.uppercase(), requestBody)
                .header("User-Agent", userAgent)
                .header("Priority", "u=0, i")

            val cookies = CookieManager.getInstance().getCookie(urlString)
            if (!cookies.isNullOrEmpty()) {
                okRequestBuilder.addHeader("Cookie", cookies)
            }

            val response = okHttpClient.newCall(okRequestBuilder.build()).execute()

            if (response.isSuccessful) {
                val latestCookies = response.headers("Set-Cookie")
                latestCookies.forEach { cookieStr ->
                    // Feed the new session cookie back to the system
                    CookieManager.getInstance().setCookie(urlString, cookieStr)
                }
                val body = response.body.string()
                return body
            } else {
                avocadoLog(AVOCADO_LOG_LEVEL.AVOCADO_ERROR, TAG, "executeManualBodyRequest: unsuccessful response: ${response.code}")
                "<html><body>${method.uppercase()} Failed: ${response.code}</body></html>"
            }
        } catch (e: Exception) {
            avocadoLog(AVOCADO_LOG_LEVEL.AVOCADO_ERROR, TAG, "executeManualBodyRequest: Exception", tr = e, shouldToast = true)
            "<html><body>Icarus Bridge Error: ${e.message}</body></html>"
        }
    }

    private fun isHostAllowed(requestUrl: String?, currentUrl: String?): Boolean {
        if (requestUrl.isNullOrBlank() || currentUrl.isNullOrBlank()) return false

        // Normalize both hosts (strip 'www.' and convert to lowercase)
        val getHost = { url: String ->
            // If it doesn't start with a scheme, Uri.parse won't find the host
            val formattedUrl = if (!url.contains("://")) "https://$url" else url
            val uri = formattedUrl.toUri()
            uri.host?.lowercase()?.removePrefix("www.")
        }

        val requestHost = getHost(requestUrl) ?: return false
        val allowedHost = getHost(currentUrl) ?: return false

        // Allow if exact match (site.com == site.com)
        // or if it's a subdomain (api.site.com ends with .site.com)
        return requestHost == allowedHost || requestHost.endsWith(".$allowedHost")
    }


    private fun shouldStripHeader(key: String): Boolean {
        val lowercaseKey = key.lowercase()

        // Client Hints
        if (lowercaseKey.startsWith("sec-ch-")) {
            return true
        }

        // Network Information
        val networkHeaders = listOf("downlink", "rtt", "ect", "dpr", "device-memory", "viewport-width")
        if (networkHeaders.contains(lowercaseKey)) {
            return true
        }

        val useless = listOf(
            "X-Requested-With",
            "Sec-Fetch-Site",
            "Sec-Fetch-Mode",
            "Sec-Fetch-Dest",
            "Sec-Fetch-User",
            "Referer",
            "Upgrade-Insecure-Requests",
            "Accept-Encoding", // we drop to let OkHttp handle compression
            "User-Agent"       // OkHttp will reinject the one we pass from WebViewUtils
        )
        return useless.any { it.equals(key, ignoreCase = true) }
    }
}
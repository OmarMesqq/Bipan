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

private const val TAG = "Icarus"
private const val REQUEST_LOGGING_TAG = "Icarus-Logger"

object Icarus {

    private val okHttpClient = OkHttpClient.Builder()
        .followRedirects(true)
        .connectTimeout(60, TimeUnit.SECONDS)
        .readTimeout(60, TimeUnit.SECONDS)
        .writeTimeout(60, TimeUnit.SECONDS)
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

                val sslContext = SSLContext.getInstance("SSL")
                sslContext.init(null, trustAllCerts, java.security.SecureRandom())
                sslSocketFactory(sslContext.socketFactory, trustAllCerts[0] as X509TrustManager)
                hostnameVerifier { _, _ -> true }
            }
        }
        .build()

    fun handleRequest(
        context: Context,
        request: WebResourceRequest,
    ): WebResourceResponse? {
        val uri = request.url
        val urlString = uri.toString()


        // Network Fetch via OkHttp
        return try {
            val okRequestBuilder = Request.Builder().url(urlString)

            // Map WebView Headers -> OkHttp (Stripping privacy leaks)
            request.requestHeaders.forEach { (key, value) ->
                if (!shouldStripHeader(key)) {
                    okRequestBuilder.addHeader(key, value)
                }
            }

            // Sync Cookies manually
            val cookies = CookieManager.getInstance().getCookie(urlString)
            if (!cookies.isNullOrEmpty()) {
                okRequestBuilder.addHeader("Cookie", cookies)
            }

            val response = okHttpClient.newCall(okRequestBuilder.build()).execute()

            if (response.isSuccessful) {
                val contentType = response.header("Content-Type", "text/html; charset=utf-8")
                val mimeType = contentType?.split(";")?.get(0) ?: "text/html"
                val encoding = if (contentType?.contains("charset=") == true)
                    contentType.split("charset=")[1].trim() else "UTF-8"

                var bodyStream = response.body.byteStream()

                // Apparently, V8 fetches source maps itself, let's kill it
                if (mimeType.contains("javascript") || mimeType.contains("css")) {
                    val content = response.body.string()
                    val scrubbedContent = content.replace(Regex("""[/#|*]\s*sourceMappingURL=.*"""), "")
                    bodyStream = scrubbedContent.byteInputStream(Charsets.UTF_8)
                }


                WebResourceResponse(
                    mimeType,
                    encoding,
                    response.code,
                    response.message.ifEmpty { "OK" },
                    mapOf("Access-Control-Allow-Origin" to "*"),
                    bodyStream
                )
            } else {
                avocadoLog(AVOCADO_LOG_LEVEL.AVOCADO_ERROR, TAG, "handleRequest: Response unsuccessful: code ${response.code}", shouldToast = true)
                return WebResourceResponse(
                    "text/plain",
                    "UTF-8",
                    response.code,
                    response.message.ifEmpty { "Error" },
                    mapOf("Access-Control-Allow-Origin" to "*"),
                    "".byteInputStream()
                )
            }
        } catch (e: Exception) {
            avocadoLog(AVOCADO_LOG_LEVEL.AVOCADO_ERROR, TAG, "handleRequest: Exception", tr = e, shouldToast = true)
            return WebResourceResponse(
                "text/plain",
                "UTF-8",
                504,
                "Icarus Timeout",
                mapOf("Access-Control-Allow-Origin" to "*"),
                "".byteInputStream()
            )
        }
    }

    fun executeManualPost(urlString: String, body: String, contentType: String, allowedHost: String): String? {
        return try {
            val uri = urlString.toUri()
            val host = uri.host ?: ""

            val baseAllowedHost = allowedHost.removePrefix("www.")
            val isPrimaryHost = host == baseAllowedHost || host.endsWith(".$baseAllowedHost")

            if (!isPrimaryHost) {
                avocadoLog(AVOCADO_LOG_LEVEL.AVOCADO_ERROR, TAG, "executeManualPost: $host not allowed")
                return null
            }

            val mediaType = contentType.toMediaTypeOrNull() ?: "application/x-www-form-urlencoded".toMediaType()
            val requestBody = body.toRequestBody(mediaType)

            val okRequestBuilder = Request.Builder()
                .url(urlString)
                .post(requestBody)

            val cookies = CookieManager.getInstance().getCookie(urlString)
            if (!cookies.isNullOrEmpty()) {
                okRequestBuilder.addHeader("Cookie", cookies)
            }

            val response = okHttpClient.newCall(okRequestBuilder.build()).execute()

            if (response.isSuccessful) {
                // Inside executeManualPost after response is successful:
                val latestCookies = response.headers("Set-Cookie")
                latestCookies.forEach { cookieStr ->
                    // Feed the new session cookie back to the system
                    CookieManager.getInstance().setCookie(urlString, cookieStr)
                }
                val body = response.body.string()
                return body
            } else {
                avocadoLog(AVOCADO_LOG_LEVEL.AVOCADO_ERROR, TAG, "executeManualPost: unsuccessful response: ${response.code}")
                "<html><body>POST Failed: ${response.code}</body></html>"
            }
        } catch (e: Exception) {
            avocadoLog(AVOCADO_LOG_LEVEL.AVOCADO_ERROR, TAG, "executeManualPost: Exception", tr = e, shouldToast = true)
            "<html><body>Icarus Bridge Error: ${e.message}</body></html>"
        }
    }



    private fun shouldStripHeader(key: String): Boolean {
        val useless = listOf(
            "Sec-CH-UA",
            "Sec-CH-UA-Mobile",
            "Sec-CH-UA-Platform",
            "X-Requested-With",
            "Sec-Fetch-Site",
            "Sec-Fetch-Mode",
            "Sec-Fetch-Dest",
            "Sec-Fetch-User",
            "Referer",
            "Upgrade-Insecure-Requests",
            "Accept-Encoding"
        )
        return useless.any { it.equals(key, ignoreCase = true) }
    }
}
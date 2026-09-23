package com.anglesgirl.echsdk

import android.content.Context
import okhttp3.OkHttpClient
import java.net.Proxy
import java.net.ProxySelector
import java.net.SocketAddress
import java.net.URI

/**
 * 通用 Android ECH 接入门面。
 *
 * 宿主只需在 Application 中 install，一次在自己的 OkHttp Builder 上 configure。
 * SDK 不替换宿主 CookieJar、拦截器、缓存或重定向策略。
 */
object EchSdk {
    data class Config(
        val protectedHosts: Set<String>,
        val dohUrl: String,
        val dohBootstrapIps: List<String> = emptyList(),
        val userAgent: String? = null,
        val logger: EchLogger = EchLogger { _, _ -> },
    )

    @Volatile private var config: Config? = null

    fun install(context: Context, config: Config) {
        this.config = config
        EchHosts.configure(config.protectedHosts)
        EchDoh.configure(config.dohUrl, config.dohBootstrapIps)
        EchDiagnostics.logger = config.logger
        ConscryptEch.install()
    }

    /**
     * 在宿主已有 Builder 上调用，必须保留宿主已有 CookieJar 和业务拦截器。
     * 返回同一个 Builder，便于链式接入。
     */
    fun configure(builder: OkHttpClient.Builder): OkHttpClient.Builder {
        check(config != null) { "EchSdk.install(context, config) must be called first" }
        val original = ProxySelector.getDefault()
        builder
            .proxy(null)
            .proxySelector(object : ProxySelector() {
                override fun select(uri: URI): List<Proxy> =
                    if (EchHosts.isProtected(uri.host.orEmpty())) listOf(Proxy.NO_PROXY)
                    else original?.select(uri) ?: listOf(Proxy.NO_PROXY)

                override fun connectFailed(uri: URI, sa: SocketAddress, ioe: java.io.IOException) {
                    original?.connectFailed(uri, sa, ioe)
                }
            })
            .sslSocketFactory(ConscryptEch.socketFactory, ConscryptEch.trustManager)
            .dns(EchDns())
            .hostnameVerifier { host, session ->
                javax.net.ssl.HttpsURLConnection.getDefaultHostnameVerifier().verify(host, session)
            }
        return builder
    }
}

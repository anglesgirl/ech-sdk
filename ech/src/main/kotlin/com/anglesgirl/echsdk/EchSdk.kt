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
        val dohUrl: String? = null,
        val dohBootstrapIps: List<String> = emptyList(),
        val userAgent: String? = null,
        val logger: EchLogger = EchLogger { _, _ -> },
        val gatewayPoolTxt: String = "doh.xn--pn1aul.eu.org",
        val preferredIpsTxt: String = "ip.xn--pn1aul.eu.org",
    )

    @Volatile private var config: Config? = null

    fun install(context: Context, config: Config) {
        require(config.protectedHosts.isNotEmpty()) { "At least one protected host is required" }
        require(config.gatewayPoolTxt.isNotBlank() && config.preferredIpsTxt.isNotBlank()) {
            "Gateway-pool and preferred-IP TXT names must be configured"
        }
        EchHosts.configure(config.protectedHosts)
        EchDoh.configure(config.dohUrl, config.dohBootstrapIps)
        EchDoh.configureTxtRecords(config.gatewayPoolTxt, config.preferredIpsTxt)
        EchDiagnostics.logger = config.logger
        EchState.attach(context.applicationContext)
        check(ConscryptEch.install()) { "Conscrypt ECH 初始化失败，拒绝继续创建客户端" }
        this.config = config
    }

    /** 当前网络下已判定被墙且只能使用 VPN 的域名，供宿主显示标记。 */
    fun blockedHosts(): Set<String> = EchState.blockedHosts()

    /** 用户切换到 VPN 或网络恢复后，可重新探测该域名。 */
    fun clearBlockedHost(host: String) = EchState.clearBlocked(host)

    /** ECH 失败后的域名降级/封禁状态，供 Mihon UI 显示。 */
    fun echUnavailableHosts(): Set<String> = EchState.echUnavailableHosts()

    /**
     * 在宿主已有 Builder 上调用，必须保留宿主已有 CookieJar 和业务拦截器。
     * 返回同一个 Builder，便于链式接入。
     */
    fun configure(builder: OkHttpClient.Builder): OkHttpClient.Builder {
        check(config != null) { "EchSdk.install(context, config) must be called first" }
        check(ConscryptEch.ready) { "Conscrypt ECH is not ready; refusing unprotected client setup" }
        val original = ProxySelector.getDefault()
        val originalDns = builder.build().dns
        val echDns = EchDns(originalDns)
        builder
            .proxy(null)
            .proxySelector(object : ProxySelector() {
                override fun select(uri: URI): List<Proxy> =
                    if (EchHosts.shouldTryEch(uri.host.orEmpty())) listOf(Proxy.NO_PROXY)
                    else original?.select(uri) ?: listOf(Proxy.NO_PROXY)

                override fun connectFailed(uri: URI, sa: SocketAddress, ioe: java.io.IOException) {
                    original?.connectFailed(uri, sa, ioe)
                }
            })
            .sslSocketFactory(ConscryptEch.socketFactory, ConscryptEch.trustManager)
            .dns(echDns)
            .addInterceptor(EchRetryInterceptor())
            .hostnameVerifier { host, session ->
                javax.net.ssl.HttpsURLConnection.getDefaultHostnameVerifier().verify(host, session)
            }
        return builder
    }
}

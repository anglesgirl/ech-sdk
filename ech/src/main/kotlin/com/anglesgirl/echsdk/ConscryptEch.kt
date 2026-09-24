package com.anglesgirl.echsdk

import android.util.Log
import com.anglesgirl.echsdk.EchDiagnostics
import okhttp3.Dns
import okhttp3.Interceptor
import okhttp3.Response
import org.conscrypt.Conscrypt
import org.conscrypt.DomainEncryptionMode
import org.conscrypt.NetworkSecurityPolicy
import org.conscrypt.metrics.CertificateTransparencyVerificationReason
import java.io.IOException
import java.net.InetAddress
import java.net.Socket
import java.net.UnknownHostException
import java.security.KeyStore
import java.security.SecureRandom
import java.security.cert.X509Certificate
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.TrustManager
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

/** ECH 的尝试范围与核心域名分离：普通域名也先尝试，失败后才降级。 */
object EchHosts {
    @Volatile private var coreHosts: Set<String> = emptySet()

    fun configure(values: Set<String>) {
        coreHosts = values.map { it.lowercase().trimEnd('.') }.toSet()
    }

    /** 所有 HTTPS 域名都尝试 ECH；是否允许降级由核心域名规则决定。 */
    fun shouldTryEch(host: String): Boolean = true

    fun isCoreDomain(host: String): Boolean {
        val h = host.lowercase().trimEnd('.')
        return coreHosts.any { h == it || h.endsWith(".$it") }
    }

    /** 兼容现有调用点：这里表示“参与 ECH 传输层”，不是“必须成功”。 */
    fun isProtected(host: String): Boolean = shouldTryEch(host)
}

/**
 * Conscrypt（BoringSSL 内核）承担的 ECH 传输层。
 *
 * 为什么这条路干净：它是标准 JSSE provider —— OkHttp 的重定向、Cookie、gzip、连接池
 * 全部走原生语义，不再需要 JNI 桥 / libcurl / 手写重定向处理。
 *
 * 【最容易踩的坑，必须保留注释】Conscrypt 用**反射**从 X509TrustManager 上取
 * `getNetworkSecurityPolicy()`；取不到就回落平台默认策略（Android API 36 = DISABLED），
 * 而 DISABLED 会让 `getEchOptions()` 返回 null、`enableEchBasedOnPolicy()` 首行就 return
 * —— 结果是 setEchConfigList 完全白设，ECH 扩展一个字节都不发（且完全静默）。
 * 所以 PolicyTrustManager 上那个方法就是整套 ECH 的开关，绝不能删。
 */
object ConscryptEch {

    private const val TAG = "CO-ECH"

    @Volatile
    var ready = false
        private set

    // 【必须 lazy】Conscrypt.newProvider() 会触发 native 库加载；若在 Application.onCreate
    // 早期（SoLoader 尚未初始化）执行会抛 Error，冒泡后中断 RN 的 loadReactNative
    // → Fresco 未初始化 → 渲染第一个 <Image> 直接崩（2026-09-11 真机实测）。
    // 懒加载后只有第一次真正发请求时才初始化，那时 SoLoader 早已就绪。
    private val provider: java.security.Provider by lazy { Conscrypt.newProvider() }

    private val systemTrustManager: X509TrustManager by lazy {
        val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
        tmf.init(null as KeyStore?)
        tmf.trustManagers.filterIsInstance<X509TrustManager>().firstOrNull()
            ?: throw IllegalStateException("系统 X509TrustManager 不可用")
    }

    /** 给 OkHttp 用的信任管理器（证书校验委托给系统，另挂 ECH 策略） */
    val trustManager: X509TrustManager by lazy { PolicyTrustManager(systemTrustManager) }

    private val sslContext: SSLContext by lazy {
        SSLContext.getInstance("TLSv1.3", provider).apply {
            // 必须把 PolicyTrustManager 传进 SSLContext，Conscrypt 才反射得到策略
            init(null, arrayOf<TrustManager>(trustManager), SecureRandom())
        }
    }

    val socketFactory: SSLSocketFactory by lazy { EchSocketFactory(sslContext.socketFactory) }

    /**
     * 幂等安装：触发惰性初始化并确认真的可用。
     * **绝不抛异常**（启动路径可能调到它），失败返回 false。
     */
    fun install(): Boolean {
        if (ready) return true
        return runCatching {
            provider      // 触发 Conscrypt native 加载
            sslContext    // 建好挂了 ECH 策略的 SSLContext
            socketFactory
            ready = true
            Log.i(TAG, "Conscrypt ECH 就绪，version=${Conscrypt.version()}")
            EchDiagnostics.trace("boot.conscrypt.ok", mapOf("version" to Conscrypt.version()))
            true
        }.getOrElse { t ->
            Log.e(TAG, "Conscrypt ECH 初始化失败: ${t.javaClass.simpleName} ${t.message}")
            EchDiagnostics.trace(
                "boot.conscrypt.fail",
                mapOf("err" to "${t.javaClass.simpleName}: ${t.message}")
            )
            false
        }
    }

    class PolicyTrustManager(private val delegate: X509TrustManager) : X509TrustManager {
        override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {
            delegate.checkClientTrusted(chain, authType)
        }

        override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {
            delegate.checkServerTrusted(chain, authType)
        }

        override fun getAcceptedIssuers(): Array<X509Certificate> = delegate.acceptedIssuers

        /** Conscrypt 反射找的就是这个方法 —— 整套 ECH 的开关 */
        @Suppress("unused")
        fun getNetworkSecurityPolicy(): NetworkSecurityPolicy = POLICY
    }

    private val POLICY = object : NetworkSecurityPolicy {
        override fun isCertificateTransparencyVerificationRequired(hostname: String?): Boolean = false

        override fun getCertificateTransparencyVerificationReason(hostname: String?):
            CertificateTransparencyVerificationReason = CertificateTransparencyVerificationReason.UNKNOWN

        override fun getDomainEncryptionMode(hostname: String?): DomainEncryptionMode =
            if (hostname != null && EchHosts.shouldTryEch(hostname) && !EchState.isEchUnavailable(hostname)) {
                DomainEncryptionMode.ENABLED
            } else {
                DomainEncryptionMode.DISABLED
            }
    }

    /**
     * 包装 Conscrypt 的 SSLSocketFactory：在返回 socket 前按 host 注入 ECHConfigList。
     * OkHttp 走的是 createSocket(Socket, String, int, boolean) 这个重载。
     * 拿不到配置时先记录 ECH 不可用并允许应用层降级；若降级连接仍失败，
     * [EchRetryInterceptor] 会把域名持久标记为“被墙且无法使用 ECH”。
     */
    private class EchSocketFactory(private val delegate: SSLSocketFactory) : SSLSocketFactory() {

        override fun getDefaultCipherSuites(): Array<String> = delegate.defaultCipherSuites

        override fun getSupportedCipherSuites(): Array<String> = delegate.supportedCipherSuites

        private fun prepare(s: Socket, host: String?): Socket {
            if (host == null || s !is SSLSocket || !EchHosts.shouldTryEch(host)) return s
            val core = EchHosts.isCoreDomain(host)
            if (EchState.isBlocked(host)) {
                throw IOException("域名已判定为被墙且无法使用 ECH，只能通过 VPN 访问：$host")
            }
            if (EchState.isEchUnavailable(host)) return s
            val t0 = System.currentTimeMillis()
            val cfg = EchDoh.echConfigList(host)
            if (cfg == null) {
                EchState.markEchUnavailable(host)
                EchDiagnostics.trace(
                    "tls.ech.unavailable",
                    mapOf("host" to host, "core" to core, "ms" to (System.currentTimeMillis() - t0))
                )
                return s
            }
            try {
                Conscrypt.setEchConfigList(s, cfg)
            } catch (t: Throwable) {
                EchState.markEchUnavailable(host)
                EchDiagnostics.trace(
                    "tls.ech.setFail",
                    mapOf("host" to host, "bytes" to cfg.size, "core" to core,
                          "err" to "${t.javaClass.simpleName}: ${t.message}")
                )
                if (core) throw IOException("setEchConfigList 失败，核心域名拒绝明文：${t.message}")
                return s
            }
            EchDiagnostics.trace(
                "tls.ech.inject",
                mapOf("host" to host, "bytes" to cfg.size, "ms" to (System.currentTimeMillis() - t0))
            )
            return s
        }

        override fun createSocket(s: Socket, host: String, port: Int, autoClose: Boolean): Socket =
            prepare(delegate.createSocket(s, host, port, autoClose), host)

        override fun createSocket(host: String, port: Int): Socket =
            prepare(delegate.createSocket(host, port), host)

        override fun createSocket(host: String, port: Int, localHost: InetAddress, localPort: Int): Socket =
            prepare(delegate.createSocket(host, port, localHost, localPort), host)

        // 只给到 IP、拿不到域名的那两个重载无法注入 ECH；保护域名不会走到这里（有 Dns 与 host 重载）
        override fun createSocket(host: InetAddress, port: Int): Socket = delegate.createSocket(host, port)

        override fun createSocket(address: InetAddress, port: Int, localAddress: InetAddress, localPort: Int): Socket =
            delegate.createSocket(address, port, localAddress, localPort)
    }
}

/**
 * 保护域名用 DoH 解析（系统 DNS 在大陆被污染，连到假 IP 会得出错误结论）。
 * 解析失败即抛异常：fail-closed，不回落系统 DNS。
 */
class EchDns(private val system: Dns = Dns.SYSTEM) : Dns {
    override fun lookup(hostname: String): List<InetAddress> {
        if (!EchHosts.shouldTryEch(hostname)) return system.lookup(hostname)
        val t0 = System.currentTimeMillis()
        EchDiagnostics.trace("net.doh.begin", mapOf("host" to hostname))
        val addrs = runCatching { EchDoh.resolve(hostname) }.getOrElse {
            if (!EchHosts.isCoreDomain(hostname)) {
                EchDiagnostics.trace("net.doh.fallback", mapOf("host" to hostname, "err" to it.javaClass.simpleName))
                return system.lookup(hostname)
            }
            throw it
        }
        val ms = System.currentTimeMillis() - t0
        if (addrs.isEmpty()) {
            EchDiagnostics.trace(
                "net.doh.fail",
                mapOf("host" to hostname, "ms" to ms, "core" to EchHosts.isCoreDomain(hostname))
            )
            if (!EchHosts.isCoreDomain(hostname)) return system.lookup(hostname)
            throw UnknownHostException("DoH 解析失败（核心域名拒绝系统 DNS）：$hostname")
        }
        EchDiagnostics.trace(
            "net.doh.ok",
            mapOf("host" to hostname, "n" to addrs.size, "ms" to ms,
                  "ips" to addrs.joinToString(",") { it.hostAddress ?: "?" })
        )
        return addrs
    }
}

/**
 * 任何失败 → 去权威源取新的 ECH 配置 → 重试一次。
 *
 * 用户定的规则（也是浏览器的语义）：**cloudflare-ech.com 永远是权威正确值；
 * 只要失败，不管缓存了多久，就立刻去那里取新值并缓存起来。**
 *
 * 旧实现只在异常名含 "EchRejected" 时才清缓存 —— 太窄了：握手超时、连接被重置、
 * 异常被包装后类名不再含 EchRejected 等情况都不会清，于是继续拿旧密钥撞墙，
 * 一直撞到缓存 TTL 自然过期（而旧 TTL 下限是 1 小时），表现为「功能一直坏着」。
 */
class EchRetryInterceptor : Interceptor {

    /** 请求标记：保证最多只重试一次，避免持续失败时打成风暴。 */
    private object Retried

    override fun intercept(chain: Interceptor.Chain): Response {
        val req = chain.request()
        val host = req.url.host
        return try {
            chain.proceed(req)
        } catch (t: Throwable) {
            if (!EchHosts.shouldTryEch(host)) throw t
            if (req.tag(Any::class.java) === Retried) {
                // ECH 已经失败并完成明文降级；明文仍失败，持久标记为当前网络被封。
                EchState.markBlocked(host)
                EchDiagnostics.trace(
                    "host.blocked",
                    mapOf("host" to host, "note" to "ECH 与明文降级均失败，只能使用 VPN")
                )
                throw t
            }

            val echRejected = generateSequence(t) { it.cause }
                .any {
                    it.javaClass.simpleName.contains("EchRejected", ignoreCase = true) ||
                        it.message?.contains("ECH_REJECTED", ignoreCase = true) == true
                }
            if (echRejected || !EchState.isEchUnavailable(host)) {
                EchState.markEchUnavailable(host)
                EchState.drop(host)
                EchDiagnostics.trace(
                    "ech.fallback",
                    mapOf("host" to host, "echRejected" to echRejected,
                          "note" to "ECH 失败，标记后降级明文重试一次")
                )
            }
            return chain.proceed(req.newBuilder().tag(Any::class.java, Retried).build())
        }
    }
}

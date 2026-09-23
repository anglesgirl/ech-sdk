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

/** 哪些域名必须走 ECH（与旧拦截器里的判定保持一致） */
object EchHosts {
    @Volatile private var hosts: Set<String> = emptySet()

    fun configure(values: Set<String>) {
        hosts = values.map { it.lowercase().trimEnd('.') }.toSet()
    }

    fun isProtected(host: String): Boolean {
        val h = host.lowercase().trimEnd('.')
        return hosts.any { h == it || h.endsWith(".$it") }
    }
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
            if (hostname != null && EchHosts.isProtected(hostname)) DomainEncryptionMode.ENABLED
            else DomainEncryptionMode.DISABLED
    }

    /**
     * 包装 Conscrypt 的 SSLSocketFactory：在返回 socket 前按 host 注入 ECHConfigList。
     * OkHttp 走的是 createSocket(Socket, String, int, boolean) 这个重载。
     * 拿不到配置时**抛异常**（fail-closed）—— 宁可不连，也绝不明文暴露被墙域名的 SNI。
     */
    private class EchSocketFactory(private val delegate: SSLSocketFactory) : SSLSocketFactory() {

        override fun getDefaultCipherSuites(): Array<String> = delegate.defaultCipherSuites

        override fun getSupportedCipherSuites(): Array<String> = delegate.supportedCipherSuites

        private fun prepare(s: Socket, host: String?): Socket {
            if (host == null || s !is SSLSocket || !EchHosts.isProtected(host)) return s
            val t0 = System.currentTimeMillis()
            val cfg = EchDoh.echConfigList(host)
            if (cfg == null) {
                EchDiagnostics.trace(
                    "tls.ech.noConfig",
                    mapOf(
                        "host" to host,
                        "ms" to (System.currentTimeMillis() - t0),
                        "note" to "拿不到 ECHConfigList → fail-closed 拒绝明文（UI 显示 ECH_FAIL_CLOSED）"
                    )
                )
                throw IOException("ECH 配置不可用（fail-closed）：拒绝以明文访问 $host")
            }
            try {
                Conscrypt.setEchConfigList(s, cfg)
            } catch (t: Throwable) {
                EchDiagnostics.trace(
                    "tls.ech.setFail",
                    mapOf(
                        "host" to host, "bytes" to cfg.size,
                        "err" to "${t.javaClass.simpleName}: ${t.message}"
                    )
                )
                throw IOException("setEchConfigList 失败（fail-closed）: ${t.message}")
            }
            EchDiagnostics.trace(
                "tls.ech.inject",
                mapOf(
                    "host" to host, "bytes" to cfg.size,
                    "ms" to (System.currentTimeMillis() - t0)
                )
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
        if (!EchHosts.isProtected(hostname)) return system.lookup(hostname)
        val t0 = System.currentTimeMillis()
        EchDiagnostics.trace("net.doh.begin", mapOf("host" to hostname))
        val addrs = EchDoh.resolve(hostname)
        val ms = System.currentTimeMillis() - t0
        if (addrs.isEmpty()) {
            EchDiagnostics.trace(
                "net.doh.fail",
                mapOf("host" to hostname, "ms" to ms, "note" to "0 个地址 → fail-closed")
            )
            throw UnknownHostException("DoH 解析失败（fail-closed）：$hostname")
        }
        EchDiagnostics.trace(
            "net.doh.ok",
            mapOf(
                "host" to hostname, "n" to addrs.size, "ms" to ms,
                "ips" to addrs.joinToString(",") { it.hostAddress ?: "?" }
            )
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
            if (!EchHosts.isProtected(host)) throw t
            if (req.tag(Any::class.java) === Retried) throw t // 已重试过，不再循环

            val echRejected = generateSequence(t) { it.cause }
                .any { it.javaClass.simpleName.contains("EchRejected", ignoreCase = true) }
            if (echRejected) {
                EchDiagnostics.trace(
                    "tls.ech.rejected",
                    mapOf("host" to host, "err" to "${t.javaClass.simpleName}: ${t.message}")
                )
            }
            EchDiagnostics.trace(
                "ech.refetch.begin",
                mapOf(
                    "host" to host,
                    "err" to "${t.javaClass.simpleName}: ${t.message}",
                    "echRejected" to echRejected,
                    "note" to "任何失败都去权威源取新值并缓存"
                )
            )
            val fresh = EchDoh.refetchNow(host)
            if (fresh == null) {
                EchDiagnostics.trace(
                    "ech.refetch.fail",
                    mapOf("host" to host, "note" to "权威源也没拿到 → fail-closed")
                )
                throw t
            }
            EchDiagnostics.trace(
                "ech.refetch.ok",
                mapOf("host" to host, "bytes" to fresh.size, "note" to "已缓存新值，重试一次")
            )
            return chain.proceed(req.newBuilder().tag(Any::class.java, Retried).build())
        }
    }
}

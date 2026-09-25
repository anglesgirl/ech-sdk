package com.anglesgirl.echsdk

import android.util.Log
import com.anglesgirl.echsdk.EchDiagnostics
import okhttp3.Dns
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.dnsoverhttps.DnsOverHttps
import java.net.InetAddress
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit

/**
 * DoH 层：拿目标域名的真实 IP（绕大陆 DNS 污染）+ 拿 ECHConfigList。
 *
 * - **A/AAAA 解析用 OkHttp 官方 `DnsOverHttps`**（自带 TTL 缓存、失败重试），
 *   并用 `bootstrapDnsHosts` 把 DoH 网关自己钉到 CF 边缘 IP，避免"解析 DoH 域名时又被污染"。
 * - **ECHConfigList 仍要自己查**：`DnsOverHttps` 只做 A/AAAA，而 ECH 配置在 HTTPS(65) 记录里，
 *   所以这里用同一个 bootstrap 客户端发 JSON 查询（application/dns-json）并手动解析 ech= 。
 *
 * 设计约束：所有失败都 fail-closed。拿不到 ECH 配置时上层宁可不连，
 * 绝不以明文 SNI 直连（那等于把被墙域名写在脸上）。
 */
object EchDoh {

    private const val TAG = "ECH-SDK-DOH"

    private var configuredBootstrapIps: List<String> = emptyList()
    @Volatile private var configuredDohUrl: String? = null
    @Volatile private var configuredGatewayPoolTxt = "doh.xn--pn1aul.eu.org"
    @Volatile private var configuredPreferredIpsTxt = "ip.xn--pn1aul.eu.org"

    fun configure(dohUrl: String?, bootstrapIps: List<String> = emptyList()) {
        if (dohUrl != null) require(dohUrl.startsWith("https://")) { "DoH URL must use HTTPS" }
        configuredDohUrl = dohUrl
        configuredBootstrapIps = bootstrapIps.filter { it.isNotBlank() }
        invalidateGatewayForSdk()
    }

    fun configureTxtRecords(gatewayPoolTxt: String, preferredIpsTxt: String) {
        require(gatewayPoolTxt.isNotBlank())
        require(preferredIpsTxt.isNotBlank())
        configuredGatewayPoolTxt = gatewayPoolTxt
        configuredPreferredIpsTxt = preferredIpsTxt
        invalidateGatewayForSdk()
    }

    private fun invalidateGatewayForSdk() {
        gatewayCache = null
        poolCache = null
        resolverCache = null
        addressCache.clear()
    }


    /** 可选的显式网关覆盖；默认只使用 TXT 网关池。 */
    private fun activeDohUrl(): String = configuredDohUrl.orEmpty()

    /**
     * 配置域名：TXT 记录里发布**网关池**（一行一个 DoH 端点 URL）。
     *
     * 这是「网关可换」那一环 —— 换网关只改这条 TXT，App 不用重新编译发版。
     * 只由国内种子 DoH 去读（纯 IP 直连，天然免疫污染）；实测六家国内 DoH
     * （阿里/腾讯/360 各两台）都能完整取到 4 条。
     *
     * 解析器同时兼容两种写法：
     *   · 纯 URL 列表        —— 当前用的形式
     *   · key=value          —— `doh=https://…` / `doh2=https://…,https://…`
     */
    private val CONFIG_TXT_DOMAIN: String get() = configuredGatewayPoolTxt
    /**
     * 优选 IP 的配置域名：TXT 里发布**用户自己实测最快的 IP**（自选，不是网关自带的那批）。
     *
     * 为什么要独立一条：网关自带/官方解析出的地址不一定快（实测 `162.159.36.x` 就是一例），
     * 而 CF 的边缘 IP 同一个网关域名在多个段都能服务（实测 `172.64.229.x` 段同样 200）。
     * 所以「用哪个 IP」应该由**实测过的人**决定，并且能随时改 —— 改 TXT 即可，不用发版。
     *
     * 这些 IP 会排在 bootstrap 候选的**最前面**（用户实测快 > 解析结果 > 内置兜底）。
     */
    private val CONFIG_IP_DOMAIN: String get() = configuredPreferredIpsTxt
    private const val GATEWAY_POOL_TTL_MS = 30 * 60 * 1000L
    private const val GATEWAY_IP_TTL_MS = 30 * 60 * 1000L

    /** Cloudflare 的 ASN。用它判定「这个域名在不在 CF 上」，见 isCloudflareHost。 */
    private const val CLOUDFLARE_ASN = 13335

    /** IP → 是否属于 Cloudflare。按地址缓存，避免每个新连接都查一次 ASN。 */
    private val asnCache = ConcurrentHashMap<String, Boolean>()

    /** 域名 → 是否解析到 CF 段。按域名缓存，供 ECH 保护判定。 */
    private val cfHostCache = ConcurrentHashMap<String, Boolean>()

    /** 保护域名的 ECH 判定缓存。 */

    /** 仅使用 ip TXT 下发的地址作为网关 bootstrap；不内置网关地址兜底。 */
    private val DOH_FALLBACK_IPS = emptyList<String>()

    private val bootstrapClient: OkHttpClient = OkHttpClient.Builder()
        // ⚠️ 禁用代理。默认的 proxySelector 是 ProxySelector.getDefault()（系统代理），
        // 手机上只要装过代理/VPN 类 App 或 APN 里配了代理，DoH 请求就会走它 ——
        // 而代理不通的表现是**卡死**，不是快速报错。bangumi-ech 显式禁用了两次，
        // 这正是"同一个套路、不同 App 效果不一样"的差别之一。
        .proxy(java.net.Proxy.NO_PROXY)
        // ⚠️ 关掉自动重试。OkHttp 默认 true 会静默重试，把一次超时放大成两倍 ——
        // CO3 日志里那个 21.45 秒正是「8s 超时 × 重试」的形状；bangumi 关掉后 10s 就快速失败。
        .retryOnConnectionFailure(false)
        .connectTimeout(4, TimeUnit.SECONDS)
        .readTimeout(4, TimeUnit.SECONDS)
        // ⚠️ 总时限兜底。DnsOverHttps 内部是 latch.await()（无超时参数），
        // 没有 callTimeout 就可能无限等；bangumi 给了 15s。
        .callTimeout(12, TimeUnit.SECONDS)
        .build()

    /**
     * 【种子层】用国内纯 IP DoH 解析一个域名的地址（A + AAAA）。
     *
     * 这是整套链路的地基。域名若交给系统 DNS 就会被污染（拿到假 IP → 连接超时），
     * 而写死 IP 又会随网关更换 / 地址段被封而失效。
     * 国内三家 DoH 是**纯 IP 直连** —— 查它们本身不需要任何解析，天然免疫污染 ——
     * 所以「网关在哪」交给它们回答。
     *
     * 任意一家成功即返回，失败换下一家。
     */
    private fun resolveHostIps(host: String): List<String> {
        val out = LinkedHashSet<String>()
        for (ip in ECH_DOH_IPS.shuffled()) {
            for (type in intArrayOf(1, 28)) {
                val wire = dohWire(ip, host, type) ?: continue
                out.addAll(parseAddresses(wire))
            }
            if (out.isNotEmpty()) {
                EchDiagnostics.trace(
                    "doh.hostres.ok",
                    mapOf("host" to host, "via" to ip, "n" to out.size, "ips" to out.joinToString(","))
                )
                break
            }
            EchDiagnostics.trace("doh.hostres.miss", mapOf("host" to host, "via" to ip))
        }
        return out.toList()
    }

    /** 解析 DNS 应答里的 TXT(16) 记录（rdata 是若干 character-string，需拼接）。 */
    private fun parseTxt(msg: ByteArray): List<String> {
        if (msg.size < 12) return emptyList()
        var i = 12
        while (i < msg.size && msg[i].toInt() != 0) i += (msg[i].toInt() and 0xFF) + 1
        i += 5
        val ancount = ((msg[6].toInt() and 0xFF) shl 8) or (msg[7].toInt() and 0xFF)
        val out = ArrayList<String>()
        for (n in 0 until ancount) {
            if (i + 12 > msg.size) break
            if ((msg[i].toInt() and 0xC0) == 0xC0) i += 2
            else { while (i < msg.size && msg[i].toInt() != 0) i += (msg[i].toInt() and 0xFF) + 1; i += 1 }
            val rtype = ((msg[i].toInt() and 0xFF) shl 8) or (msg[i + 1].toInt() and 0xFF)
            val rdlen = ((msg[i + 8].toInt() and 0xFF) shl 8) or (msg[i + 9].toInt() and 0xFF)
            val rdata = i + 10
            if (rtype == 16 && rdata + rdlen <= msg.size) {
                val sb = StringBuilder()
                var p = rdata
                while (p < rdata + rdlen) {
                    val ln = msg[p].toInt() and 0xFF
                    if (p + 1 + ln > rdata + rdlen) break
                    sb.append(String(msg, p + 1, ln, Charsets.UTF_8))
                    p += 1 + ln
                }
                if (sb.isNotEmpty()) out.add(sb.toString())
            }
            i = rdata + rdlen
        }
        return out
    }

    /** 网关条目：URL + 它自带的 bootstrap IP（可为空）。 */
    private class GatewaySpec(val url: String, val ips: List<String>)

    /**
     * 从 TXT 内容里解析网关条目。兼容三种写法：
     *   · `https://网关/dns-query|IP|IP`  —— **推荐**（bangumi 同款；自带 IP，免去解析那一步）
     *   · `https://网关/dns-query`        —— 纯 URL，地址由国内种子 DoH 解析
     *   · `doh=https://…` / `doh2=https://…,…` —— key=value 老写法
     *
     * 为什么自带 IP 更好：解析网关地址这一步本身也是可能出问题的环节
     * （污染、超时），而且在受污染网络里「解析网关域名」最不该依赖系统 DNS。
     * 直接给定 IP 就把这个环节整个省掉，也让「优选 IP」可以由 TXT 远程调整。
     */
    private fun extractGatewaySpecs(txt: String): List<GatewaySpec> =
        txt.split(',', ';', ' ', '\n')
            .map { it.trim() }
            .filter { it.isNotEmpty() }
            .map { seg -> if (seg.contains('=')) seg.substringAfter('=').trim() else seg }
            .flatMap { seg ->
                val parts = seg.split('|').map { it.trim() }
                val url = parts.firstOrNull().orEmpty()
                if (!url.startsWith("https://") || !url.contains("/dns-query")) {
                    emptyList()
                } else {
                    // IP 字面量校验：只收合法的 IPv4/IPv6，不合法就丢掉（宁可少一条候选）
                    val ips = parts.drop(1).filter { isIpLiteral(it) }
                    listOf(GatewaySpec(url, ips))
                }
            }

    /** 宽松校验：能被 InetAddress 解析成字面量的才算 IP（不走 DNS）。 */
    private fun isIpLiteral(s: String): Boolean {
        if (s.isEmpty()) return false
        val v4 = Regex("^\\d{1,3}(\\.\\d{1,3}){3}$")
        val v6 = Regex("^[0-9a-fA-F:]+$")
        if (!v4.matches(s) && !(v6.matches(s) && s.contains(':'))) return false
        return runCatching { InetAddress.getByName(s) }.isSuccess
    }

    /** 用国内种子 DoH 读配置域名的 TXT → 网关池。 */
    private fun fetchGatewayPool(): List<GatewaySpec> {
        val started = System.currentTimeMillis()
        for (ip in ECH_DOH_IPS.shuffled()) {
            val wire = dohWire(ip, CONFIG_TXT_DOMAIN, 16) ?: continue
            val specs = parseTxt(wire).flatMap { extractGatewaySpecs(it) }
                .distinctBy { it.url + "|" + it.ips.joinToString(",") }
            if (specs.isNotEmpty()) {
                EchDiagnostics.trace(
                    "doh.pool.ok",
                    mapOf(
                        "via" to ip, "n" to specs.size,
                        "selfIp" to specs.count { it.ips.isNotEmpty() },
                        "ms" to (System.currentTimeMillis() - started),
                        "urls" to specs.joinToString(",") { it.url },
                    )
                )
                return specs
            }
            EchDiagnostics.trace("doh.pool.miss", mapOf("via" to ip))
        }
        return emptyList()
    }

    @Volatile private var prefIpsCache: Pair<List<String>, Long>? = null

    /**
     * 读优选 IP 配置域名（[CONFIG_IP_DOMAIN]）的 TXT → 用户自选的 IP 列表。
     *
     * 解析做宽：整条 TXT 里凡是合法的 IP 字面量都收，非法项直接丢掉 ——
     * 这样用户写「一行一个」「逗号分隔」「带 key=」都能用。
     */
    private fun fetchPreferredIps(): List<String> {
        val started = System.currentTimeMillis()
        for (ip in ECH_DOH_IPS.shuffled()) {
            val wire = dohWire(ip, CONFIG_IP_DOMAIN, 16) ?: continue
            val found = parseTxt(wire)
                .flatMap { it.split(',', ';', ' ', '\n', '\t') }
                .map { it.trim().substringAfter('=').trim() }
                .filter { isIpLiteral(it) }
                .distinct()
            if (found.isNotEmpty()) {
                EchDiagnostics.trace(
                    "doh.prefip.ok",
                    mapOf("via" to ip, "n" to found.size, "ms" to (System.currentTimeMillis() - started), "ips" to found.joinToString(","))
                )
                return found
            }
            EchDiagnostics.trace("doh.prefip.miss", mapOf("via" to ip))
        }
        return emptyList()
    }

    /** 优选 IP（带 TTL 缓存）；读不到就是空列表 —— 那就退回到解析/内置兜底。 */
    private fun preferredIps(): List<String> {
        val now = System.currentTimeMillis()
        prefIpsCache?.let { (v, exp) -> if (exp > now) return v }
        val v = fetchPreferredIps()
        prefIpsCache = v to (now + GATEWAY_POOL_TTL_MS)
        return v
    }

    @Volatile private var poolCache: Pair<List<GatewaySpec>, Long>? = null

    /** 网关池（带 TTL 缓存）；TXT 与显式覆盖都不可用时返回空，调用方 fail-closed。 */
    private fun gatewayPool(): List<GatewaySpec> {
        val now = System.currentTimeMillis()
        poolCache?.let { (u, exp) -> if (exp > now && u.isNotEmpty()) return u }
        val specs = fetchGatewayPool()
        if (specs.isEmpty() && activeDohUrl().isNotBlank()) {
            EchDiagnostics.trace("doh.pool.fallback", mapOf("url" to activeDohUrl()))
            return listOf(GatewaySpec(activeDohUrl(), configuredBootstrapIps))
        }
        poolCache = specs to (now + GATEWAY_POOL_TTL_MS)
        return specs
    }

    /** 选定的网关：URL + 域名 + bootstrap 地址。 */
    private class Gateway(val url: String, val host: String, val ips: List<String>)

    @Volatile private var gatewayCache: Pair<Gateway, Long>? = null

    /** 网关选择 single-flight：预热、文章请求、重试只能共用一次初始化。 */
    private val gatewayInitLock = Any()

    /** 目标域名解析结果缓存；避免同一启动周期重复查询同一个受保护域名。 */
    private data class AddressEntry(val addresses: List<InetAddress>, val expireAt: Long)
    private val addressCache = ConcurrentHashMap<String, AddressEntry>()
    /** 单航班任务结果；用于合并并发的同 host DNS 查询，互不相关的 host 可并行。 */
    private val addressFlights = ConcurrentHashMap<String, java.util.concurrent.CompletableFuture<List<InetAddress>>>()
    private const val ADDRESS_CACHE_TTL_MS = 60_000L

    /** ECH 获取 single-flight：并发请求共享同一份实时配置。 */
    private val echFetchLock = Any()

    /**
     * 从网关池里挑第一个**能解析出地址**的端点。
     *
     * 换网关只要改 TXT —— 池里哪个能用就用哪个；没有可用端点则 fail-closed。
     */
    private fun currentGateway(): Gateway? {
        val now = System.currentTimeMillis()
        gatewayCache?.let { (g, exp) -> if (exp > now) return g }
        synchronized(gatewayInitLock) {
            val lockedNow = System.currentTimeMillis()
            gatewayCache?.let { (g, exp) -> if (exp > lockedNow) return g }
            return selectGatewayLocked(lockedNow)
        }
    }

    /** 只允许 currentGateway 在 single-flight 锁内调用。 */
    private fun selectGatewayLocked(now: Long): Gateway? {
        for (spec in gatewayPool()) {
            val host = runCatching { spec.url.toHttpUrl().host }.getOrNull() ?: continue
            // ★ TXT 自带 IP（`URL|IP|IP`）时**直接用它，不做解析** ——
            // 解析这一步本身也会失败（污染/超时），而「优选 IP」正是要由 TXT 远程控制的东西。
            val preferred = preferredIps()
            val base = if (spec.ips.isNotEmpty()) {
                EchDiagnostics.trace(
                    "doh.gateway.selfIp",
                    mapOf("url" to spec.url, "ips" to spec.ips.joinToString(","))
                )
                spec.ips
            } else {
                val resolved = resolveHostIps(host)
                if (resolved.isEmpty()) {
                    EchDiagnostics.trace("doh.gateway.unusable", mapOf("url" to spec.url))
                    continue
                }
                resolved
            }
            // bootstrap 候选顺序：用户 TXT 优选 IP > 网关配置提供的地址 > 显式配置地址。
            val ips = (preferred + base + configuredBootstrapIps).distinct()
            // ★ 可用性校验：池里可能有"域名能解析、但查询一律空应答"的坏端点
            //   （实测 v7e373e11t = Status:5 REFUSED）。不校验就会一直选它、
            //   一直 fail-closed，表现成"第一次打开失败、重试碰巧才好"。
            val pins = ips.mapNotNull { runCatching { InetAddress.getByName(it) }.getOrNull() }
            if (!gatewayAnswers(spec.url, pins)) {
                EchDiagnostics.trace("doh.gateway.dead", mapOf("url" to spec.url))
                continue
            }
            val g = Gateway(spec.url, host, ips)
            gatewayCache = g to (now + GATEWAY_IP_TTL_MS)
            EchDiagnostics.trace("doh.gateway.ok", mapOf("url" to spec.url, "ips" to ips.joinToString(","), "ms" to (System.currentTimeMillis() - now)))
            return g
        }
        return null
    }

    /** 网关不可达时调用：丢缓存，下次重新读 TXT 并重新解析（网关可能已换）。 */
    private fun invalidateGateway() {
        gatewayCache = null
        poolCache = null
        resolverCache = null
        addressCache.clear()
    }

    /** 当前已选网关的 DoH 地址；未初始化或网关不可用时返回 null。 */
    fun activeDohEndpoint(): String? = currentGateway()?.url ?: activeDohUrl().ifBlank { null }

    /**
     * 网关可用性校验：真的发一次查询，确认它**给得出答案**。
     *
     * 为什么必须校验：池里可能有已停用/未生效的端点 —— 实测 `v7e373e11t` 返回
     * `Status:5 REFUSED`（空应答 36 字节），但它的**域名照样解析得到 IP**，
     * 所以光判断"能解析"根本分辨不出来。曾被它害得很惨：
     * 每次选到它就 `net.doh.fail 0 个地址 → fail-closed`，
     * 失败后重挑、碰巧换到好的才通 —— 表现就是"第一次打开失败、等半分钟重试才好"。
     *
     * 验的是「能不能给出答案」，用 LIVE_SOURCE_HOST（cloudflare-ech.com，没被墙）做探针。
     */
    private fun gatewayAnswers(url: String, pins: List<InetAddress>): Boolean {
        val t0 = System.currentTimeMillis()
        val ok = runCatching {
            DnsOverHttps.Builder()
                .client(bootstrapClient)
                .url(url.toHttpUrl())
                .bootstrapDnsHosts(*pins.toTypedArray())
                .includeIPv6(false) // 只要一个答案即可，不必查 AAAA
                .build()
                .lookup(LIVE_SOURCE_HOST)
                .isNotEmpty()
        }.getOrDefault(false)
        EchDiagnostics.trace(
            "doh.gateway.check",
            mapOf("url" to url, "ok" to ok, "ms" to (System.currentTimeMillis() - t0))
        )
        return ok
    }

    @Volatile private var resolverCache: Pair<DnsOverHttps, String>? = null

    /**
     * 官方 DoH 解析器：A/AAAA + TTL 缓存，用于解析受保护域名（防污染 + 兜底）。
     *
     * 端点与 bootstrap 地址都来自 [currentGateway]（先读 TXT 拿网关池 → 再动态解析地址），
     * 任一变化就重建 —— 所以**换网关只要改配置域名的 TXT，不需要动代码**。
     */
    private fun dohResolver(): DnsOverHttps {
        val gw = currentGateway()
        val endpoint = gw ?: throw java.net.UnknownHostException("ECH DoH gateway pool unavailable")
        val url = endpoint.url.toHttpUrl()
        val ips = endpoint.ips
        val key = url.toString() + "|" + ips.joinToString(",")
        resolverCache?.let { (r, k) -> if (k == key) return r }
        val pins = ips.mapNotNull { runCatching { InetAddress.getByName(it) }.getOrNull() }
        val built = DnsOverHttps.Builder()
            .client(bootstrapClient)
            .url(url)
            .bootstrapDnsHosts(*pins.toTypedArray())
            // ⚠️ 必须 true。移动网络的 SNI 封锁**只针对 IPv4**，禁掉 IPv6 等于自断后路 ——
            // 这正是 Han1meViewer 上"Chrome 能开、App 打不开"的同一个根因
            // （Chrome 走 IPv6 绕过了封锁，App 只有 IPv4 就被掐）。
            .includeIPv6(true)
            .build()
        resolverCache = built to key
        return built
    }

    // ---------------- ECH 配置 ----------------

    private class EchEntry(val wire: ByteArray, val expireAt: Long)

    private val echCache = ConcurrentHashMap<String, EchEntry>()
    private val echFailed = ConcurrentHashMap<String, Long>()

    /** 被服务器拒过的域名：改用「它自己的记录」优先，别一直拿同一份撞。 */
    private val ownFirst = java.util.Collections.newSetFromMap(ConcurrentHashMap<String, Boolean>())

    /** 失败冷却：避免每个请求都去打一次注定失败的 DoH */
    private const val FAIL_COOLDOWN_MS = 30_000L
    private const val MIN_TTL_MS = 60_000L
    private const val MAX_TTL_MS = 3_600_000L

    /**
     * 配置的「活源」：CF 官方的 ECH 域名。与 iOS 侧 `echproxy.go` 保持同一套顺序
     * （缓存 → cloudflare-ech.com → 目标自身记录）。
     *
     * 手写/注入到别处的 `ech=` 记录一旦过期，**再拉还是那份旧的**（记录没变、里面的密钥轮换掉了），
     * 拿它去握手只会被服务器拒（Conscrypt 抛 EchRejected）。所以受保护域名一律先取这份实时配置：
     * 跨 zone 注入实测可行，内层 SNI 仍是目标域名，SNI 不外泄。
     */
    private const val LIVE_SOURCE_HOST = "cloudflare-ech.com"

    /**
     * 取 ECH 活值的候选：**国内三家的纯 IP 端点**。
     *
     * 为什么用纯 IP：不查 DNS、不被污染、证书直接对 IP 生效（实测均 200）。
     * 为什么不用 `Host` 头：阿里带 `Host` 会直接失败（实测 http=000），
     * 三家在"不带 Host + `?dns=`"下都正常 —— 所以一律用 URL 里的 IP 当 Host。
     * 为什么只认 wire：三家都不支持 JSON（阿里/360 回 400 no 'dns' query parameter，
     * 腾讯回 UrlParameterError），只能发二进制 dns-message。
     *
     * 策略：**随机挑一家试，失败换下一家**（不同时打、也不重复打同一家）。
     */
    private val ECH_DOH_IPS = listOf(
        "223.5.5.5",        // 阿里
        "223.6.6.6",        // 阿里备
        "1.12.12.12",       // 腾讯
        "120.53.53.53",     // 腾讯备
        "101.198.193.29",   // 360
        "101.198.192.33",   // 360 备
    )

    /** 单家超时：快失败快换下一家，避免首次启动干等。 */
    private const val ECH_ONE_TIMEOUT_MS = 2500L

    /**
     * ECH 配置缓存时长。
     *
     * ⚠️ **绝不能设大**。旧值曾是「下限 1 小时 / 上限 5 小时」，注释理由是
     * "公钥实测能稳定数天" —— 但密钥轮换时这个假设直接失效，结果是轮换后
     * 最长 1 小时都拿旧密钥去撞墙，功能看起来"一直坏着"。
     *
     * 规则（用户定的，也是浏览器语义）：
     *   cloudflare-ech.com 永远是权威正确值；**任何失败都立即去那里取新值**，
     *   不管缓存了多久。所以缓存只用于"省掉重复查询"，绝不能成为"用旧值硬扛"的理由。
     * 记录本身的 TTL 只有 ~198s，这里就跟着它走，最多 30 分钟。
     */
    private const val ECH_CACHE_MIN_MS = 60_000L              // 1 分钟
    private const val ECH_CACHE_MAX_MS = 30 * 60 * 1000L      // 30 分钟

    /**
     * HTTPS(65) 记录解析结果：**一次查询同时拿到 ECH 配置与地址提示**。
     *
     * 为什么合并：RFC 9460 的 HTTPS 记录本身就同时携带
     *   ech(key=5) + ipv4hint(key=4) + ipv6hint(key=6)
     * 实测国内三家 DoH 查 archiveofourown.org 全部完整返回：
     *   v4=104.20.8.2,104.20.9.2  v6=2606:4700:10::…  ech=71B  ttl=116~600s
     *
     * 而旧实现把这两件事拆成两条路：
     *   ① ECH 配置 → fetchLiveEch() 走国内三家纯 IP      → ✅ 158ms
     *   ② A/AAAA   → dohResolver 走自有网关(162.159.36.x) → ❌ 每次卡 17~21 秒后 0 地址
     * 用户网络下 ② 根本连不上，于是整个 ECH 链路 fail-closed。
     * 合并后只需要一次查询，且走的是国内可达的纯 IP。
     */
    private class HttpsRecord(
        val ech: ByteArray?,
        val ipv4: List<String>,
        val ipv6: List<String>,
        val ttlMs: Long,
    )

    /** 从随机一家纯 IP DoH 取官方活值（wire 格式，解析 SVCB 的 key=5）。 */
    private fun fetchLiveEch(): Pair<ByteArray, Long>? {
        return fetchLiveRecord(LIVE_SOURCE_HOST)?.let { rec ->
            rec.ech?.let { it to rec.ttlMs }
        }
    }

    /**
     * 走国内三家纯 IP DoH 取某个域名的完整 HTTPS 记录（ech + 地址提示）。
     * 随机挑一家、2.5s 超时、失败换下一家（与既有 fetchLiveEch 的策略一致）。
     */
    private fun fetchLiveRecord(host: String): HttpsRecord? {
        val order = ECH_DOH_IPS.shuffled()
        for (ip in order) {
            val rec = runCatching { queryHttpsRecord(ip, host) }.getOrNull()
            if (rec != null) {
                EchDiagnostics.trace(
                    "ech.record.ok",
                    mapOf(
                        "host" to host, "via" to ip,
                        "echBytes" to (rec.ech?.size ?: 0),
                        "v4" to rec.ipv4.joinToString(","), "v6n" to rec.ipv6.size,
                        "ttlMs" to rec.ttlMs,
                    )
                )
                return rec
            }
            EchDiagnostics.trace("ech.record.miss", mapOf("host" to host, "via" to ip))
        }
        return null
    }

    /** 建 DNS 查询。type: 1=A, 28=AAAA, 65=HTTPS。 */
    private fun buildQuery(name: String, type: Int = 65): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        out.write(byteArrayOf(0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
        name.split('.').forEach { lb -> out.write(lb.length); out.write(lb.toByteArray()) }
        out.write(0)
        out.write(byteArrayOf(0x00, type.toByte(), 0x00, 0x01))
        return out.toByteArray()
    }

    /** 纯 IP DoH 查询的公共通道（绝不加 Host 头；URL 的 host 就是 IP，证书对 IP 生效）。 */
    private fun dohWire(ip: String, name: String, type: Int): ByteArray? {
        val b64 = android.util.Base64.encodeToString(
            buildQuery(name, type), android.util.Base64.NO_WRAP or android.util.Base64.URL_SAFE,
        ).trimEnd('=')
        val req = okhttp3.Request.Builder()
            .url("https://$ip/dns-query?dns=$b64")
            .header("accept", "application/dns-message")
            .build()
        return runCatching {
            bootstrapClient.newBuilder()
                .connectTimeout(ECH_ONE_TIMEOUT_MS, TimeUnit.MILLISECONDS)
                .readTimeout(ECH_ONE_TIMEOUT_MS, TimeUnit.MILLISECONDS)
                .callTimeout(ECH_ONE_TIMEOUT_MS, TimeUnit.MILLISECONDS)
                .build()
                .newCall(req).execute().use { resp ->
                    if (!resp.isSuccessful) null else resp.body?.bytes()
                }
        }.getOrNull()
    }

    /** 从 DNS 应答里收集 A(1) / AAAA(28) 地址（顺带兼容 CNAME 链：应答里有什么就收什么）。 */
    private fun parseAddresses(msg: ByteArray): List<String> {
        if (msg.size < 12) return emptyList()
        var i = 12
        while (i < msg.size && msg[i].toInt() != 0) i += (msg[i].toInt() and 0xFF) + 1
        i += 5
        val ancount = ((msg[6].toInt() and 0xFF) shl 8) or (msg[7].toInt() and 0xFF)
        val out = ArrayList<String>()
        for (n in 0 until ancount) {
            if (i + 12 > msg.size) break
            if ((msg[i].toInt() and 0xC0) == 0xC0) i += 2
            else { while (i < msg.size && msg[i].toInt() != 0) i += (msg[i].toInt() and 0xFF) + 1; i += 1 }
            val rtype = ((msg[i].toInt() and 0xFF) shl 8) or (msg[i + 1].toInt() and 0xFF)
            val rdlen = ((msg[i + 8].toInt() and 0xFF) shl 8) or (msg[i + 9].toInt() and 0xFF)
            val rdata = i + 10
            if (rdata + rdlen <= msg.size) {
                if (rtype == 1 && rdlen == 4) {
                    out.add(
                        "${msg[rdata].toInt() and 0xFF}.${msg[rdata + 1].toInt() and 0xFF}." +
                            "${msg[rdata + 2].toInt() and 0xFF}.${msg[rdata + 3].toInt() and 0xFF}"
                    )
                } else if (rtype == 28 && rdlen == 16) {
                    runCatching {
                        out.add(java.net.InetAddress.getByAddress(msg.copyOfRange(rdata, rdata + 16)).hostAddress ?: "")
                    }
                }
            }
            i = rdata + rdlen
        }
        return out.filter { it.isNotEmpty() }
    }

    /** 纯 IP + wire 的 DoH 查询，解析完整 HTTPS 记录（ech + ipv4hint + ipv6hint）。 */
    private fun queryHttpsRecord(ip: String, name: String): HttpsRecord? {
        val b64 = android.util.Base64.encodeToString(
            buildQuery(name), android.util.Base64.NO_WRAP or android.util.Base64.URL_SAFE,
        ).trimEnd('=')
        val req = okhttp3.Request.Builder()
            .url("https://$ip/dns-query?dns=$b64")
            .header("accept", "application/dns-message")
            .build()
        // 注意：绝不加 Host 头（阿里带 Host 会失败）；URL 的 host 就是 IP，证书对 IP 生效
        val wire = bootstrapClient.newBuilder()
            .connectTimeout(ECH_ONE_TIMEOUT_MS, TimeUnit.MILLISECONDS)
            .readTimeout(ECH_ONE_TIMEOUT_MS, TimeUnit.MILLISECONDS)
            .callTimeout(ECH_ONE_TIMEOUT_MS, TimeUnit.MILLISECONDS)
            .build()
            .newCall(req).execute().use { resp ->
                if (!resp.isSuccessful) return null
                resp.body?.bytes() ?: return null
            }
        return parseHttpsRecord(wire)
    }

    /**
     * 解析 DNS 应答，找 type=65 的 HTTPS 记录，取出 SvcParams：
     *   key=5 ech（含 2 字节长度前缀，可直接喂 Conscrypt）
     *   key=4 ipv4hint（4 字节一个地址）
     *   key=6 ipv6hint（16 字节一个地址）
     * 三者一次拿全 —— 这样解析 IP 与取 ECH 配置走的是同一批国内可达的纯 IP。
     */
    private fun parseHttpsRecord(msg: ByteArray): HttpsRecord? {
        if (msg.size < 12) return null
        var i = 12
        // 跳过 question
        while (i < msg.size && msg[i].toInt() != 0) i += (msg[i].toInt() and 0xFF) + 1
        i += 5
        val ancount = ((msg[6].toInt() and 0xFF) shl 8) or (msg[7].toInt() and 0xFF)
        for (n in 0 until ancount) {
            if (i + 12 > msg.size) return null
            if ((msg[i].toInt() and 0xC0) == 0xC0) i += 2
            else { while (i < msg.size && msg[i].toInt() != 0) i += (msg[i].toInt() and 0xFF) + 1; i += 1 }
            val type = ((msg[i].toInt() and 0xFF) shl 8) or (msg[i + 1].toInt() and 0xFF)
            val ttl = (((msg[i + 4].toInt() and 0xFF).toLong() shl 24) or
                ((msg[i + 5].toInt() and 0xFF).toLong() shl 16) or
                ((msg[i + 6].toInt() and 0xFF).toLong() shl 8) or
                (msg[i + 7].toInt() and 0xFF).toLong())
            val rdlen = ((msg[i + 8].toInt() and 0xFF) shl 8) or (msg[i + 9].toInt() and 0xFF)
            val rdata = i + 10
            if (type == 65 && rdlen > 4 && rdata + rdlen <= msg.size) {
                // SVCB: priority(2) + target(域名) + SvcParams
                var j = rdata + 2
                while (j < rdata + rdlen && msg[j].toInt() != 0) j += (msg[j].toInt() and 0xFF) + 1
                j += 1
                var ech: ByteArray? = null
                val v4 = ArrayList<String>()
                val v6 = ArrayList<String>()
                while (j + 4 <= rdata + rdlen) {
                    val key = ((msg[j].toInt() and 0xFF) shl 8) or (msg[j + 1].toInt() and 0xFF)
                    val len = ((msg[j + 2].toInt() and 0xFF) shl 8) or (msg[j + 3].toInt() and 0xFF)
                    val vStart = j + 4
                    if (vStart + len <= rdata + rdlen) {
                        when (key) {
                            5 -> if (len > 0) ech = msg.copyOfRange(vStart, vStart + len)
                            4 -> {
                                var k = vStart
                                while (k + 3 < vStart + len) {
                                    v4.add("${msg[k].toInt() and 0xFF}.${msg[k+1].toInt() and 0xFF}.${msg[k+2].toInt() and 0xFF}.${msg[k+3].toInt() and 0xFF}")
                                    k += 4
                                }
                            }
                            6 -> {
                                var k = vStart
                                while (k + 15 < vStart + len) {
                                    runCatching {
                                        v6.add(java.net.InetAddress.getByAddress(msg.copyOfRange(k, k + 16)).hostAddress ?: "")
                                    }
                                    k += 16
                                }
                            }
                        }
                    }
                    j += 4 + len
                }
                val ttlMs = (ttl * 1000).coerceIn(ECH_CACHE_MIN_MS, ECH_CACHE_MAX_MS - 1) + 1
                return HttpsRecord(ech, v4, v6, ttlMs)
            }
            i = rdata + rdlen
        }
        return null
    }

    /**
     * 取 ECHConfigList（RFC 9460 的 wire 格式，含 2 字节长度前缀，可直接喂 Conscrypt）。
     * @return null 表示该域名没有 ECH 配置或 DoH 拿不到 —— 调用方据此 fail-closed
     */
    fun echConfigList(host: String): ByteArray? {
        synchronized(echFetchLock) {
            return echConfigListLocked(host)
        }
    }

    private fun echConfigListLocked(host: String): ByteArray? {
        val now = System.currentTimeMillis()
        echCache[host]?.let {
            if (it.expireAt > now) {
                EchDiagnostics.trace(
                    "ech.cache.hit",
                    mapOf("host" to host, "bytes" to it.wire.size, "ttlLeftMs" to (it.expireAt - now))
                )
                return it.wire
            }
        }
        // 落盘复用：冷启动不再等网关查询（首屏最明显的一段等待就在这）
        EchState.load(host)?.let {
            echCache[host] = EchEntry(it, now + MIN_TTL_MS)
            Log.i(TAG, "ech config for $host: ${it.size} bytes（源=落盘）")
            EchDiagnostics.trace(
                "ech.state.hit",
                mapOf("host" to host, "bytes" to it.size,
                      "note" to "冷启动读落盘；密钥轮换后这里会短暂用到旧值")
            )
            return it
        }
        val failedAt = echFailed[host]
        if (failedAt != null && now - failedAt < FAIL_COOLDOWN_MS) {
            EchDiagnostics.trace(
                "ech.cooldown",
                mapOf("host" to host, "ageMs" to (now - failedAt),
                      "cooldownMs" to FAIL_COOLDOWN_MS,
                      "note" to "上次失败后的冷却期内，直接放弃 → 上层 fail-closed")
            )
            return null
        }

        // 先走哪条路：默认官方活源；被翻过标志位的域名先用它自己的记录。
        val first = if (host != LIVE_SOURCE_HOST && !ownFirst.contains(host)) LIVE_SOURCE_HOST else host
        val second = if (first == host) LIVE_SOURCE_HOST else host
        EchDiagnostics.trace(
            "ech.fetch.begin",
            mapOf("host" to host, "first" to first, "second" to second,
                  "ownFirst" to ownFirst.contains(host))
        )
        val hit = try {
            // ⚠️ **不**用「目标域名自己的 HTTPS 记录」取 ECH。
            // 国内 DoH 查被墙域名会拿到投毒应答 —— 同一次应答里 echBytes=0、
            // 地址是 Twitter/Facebook 的段（实证见 resolve() 的注释）。
            //
            // ECH 一律向 cloudflare-ech.com 借权威活值（该域名没被墙，国内 DoH 拿到的是真答案）。
            EchDiagnostics.trace(
                "ech.fetch.borrow",
                mapOf("host" to host, "first" to first, "second" to second)
            )
            if (first == LIVE_SOURCE_HOST) fetchLiveEch() ?: fetchConfig(first, now)
            else fetchConfig(first, now) ?: (if (second == LIVE_SOURCE_HOST) fetchLiveEch() else fetchConfig(second, now))
        } catch (t: Throwable) {
            Log.w(TAG, "ech query failed for $host: ${t.message}")
            EchDiagnostics.trace(
                "ech.fetch.throw",
                mapOf("host" to host, "err" to "${t.javaClass.simpleName}: ${t.message}")
            )
            null
        }
        if (hit == null) {
            Log.i(TAG, "no ech config for $host（已试：$first / $second）")
            EchDiagnostics.trace(
                "ech.fetch.allFail",
                mapOf("host" to host, "tried" to "$first / $second",
                      "note" to "所有来源都拿不到 ECH 配置 → 进入 30s 冷却 → 上层 fail-closed")
            )
            echFailed[host] = now
            return null
        }
        val (wire, ttlMs) = hit
        echCache[host] = EchEntry(wire, now + ttlMs)
        EchState.save(host, wire, ttlMs)
        echFailed.remove(host)
        Log.i(TAG, "ech config for $host: ${wire.size} bytes（源=$first）")
        EchDiagnostics.trace(
            "ech.fetch.ok",
            mapOf("host" to host, "bytes" to wire.size, "ttlMs" to ttlMs, "src" to first)
        )
        return wire
    }

    /** 查某个域名的 HTTPS(65) 记录并解出配置：wire（含 2 字节长度前缀）+ 缓存时长。 */
    private fun fetchConfig(name: String, now: Long): Pair<ByteArray, Long>? {
        val body = query(name, "HTTPS") ?: return null
        val b64 = Regex("ech=([A-Za-z0-9+/=]+)").find(body)?.groupValues?.get(1)
        if (b64 == null) {
            Log.i(TAG, "no ech config in record of $name")
            return null
        }
        val ttl = Regex("\"TTL\"\\s*:\\s*(\\d+)").findAll(body)
            .mapNotNull { it.groupValues[1].toLongOrNull() }
            .minOrNull() ?: 300L
        val wire = android.util.Base64.decode(b64, android.util.Base64.DEFAULT)
        return wire to (ttl * 1000).coerceIn(MIN_TTL_MS, MAX_TTL_MS)
    }

    /**
     * 清掉这个域名的一切 ECH 缓存，逼下一次重新取。
     *
     * ⚠️ 必须清得**彻底** —— 任何一处残留都会让下一次取用又拿到旧值：
     *   echCache    内存缓存（按域名 + 权威源各一份）
     *   EchState    落盘
     *   echFailed   失败冷却（不清就被 30s 冷却挡住，无法立刻重取）
     *   ownFirst    "优先用自己记录"的偏好
     *
     * 规则（用户定的，也是浏览器语义）：**cloudflare-ech.com 永远是权威正确值；
     * 只要失败，不管缓存了多久，就立刻去取新值** —— 缓存只用于省掉重复查询，
     * 绝不能成为"拿旧密钥硬扛"的理由。
     */
    fun invalidateEch(host: String) {
        echCache.remove(host)
        EchState.drop(host)
        echFailed.remove(host)
        echCache.remove(LIVE_SOURCE_HOST)
        // 旧实现这里是 ownFirst.add(host)，让该域名**永久**偏向"自己的记录"——
        // 但那份记录可能同样是旧的，等于换个地方继续撞墙，而且再也回不到权威源。
        // 改为清除：下次仍然优先权威源。
        ownFirst.remove(host)
    }

    /**
     * 失效并**立即**重取。用户规则：失败就去权威源拿正确值，并缓存起来。
     * @return 新拿到的配置；权威源也没拿到则返回 null（调用方继续 fail-closed）
     */
    fun refetchNow(host: String): ByteArray? {
        invalidateEch(host)
        return echConfigList(host)
    }

    // ---------------- DNS ----------------

    /**
     * 用 DoH 解析域名，失败返回空列表。
     *
     * **只走自有网关** —— 这是用户定的分工：
     *   · 国内种子 DoH → 只查**没被墙的**东西（cloudflare-ech.com 的 ECH、网关地址、配置 TXT）
     *   · 自有网关     → 解析**被墙的目标域名**（防污染，这是它存在的唯一理由）
     *
     * 曾经在这条路上加过「用国内 DoH 的 HTTPS 地址提示抄近路」，已删除 ——
     * 实测国内 DoH 查 archiveofourown.org 返回 Twitter/Facebook 段的**投毒地址**，
     * 且同一次应答里 echBytes=0。拿它去握手比慢一点糟得多。
     */
    fun resolve(host: String): List<InetAddress> {
        val startedAt = System.currentTimeMillis()
        val key = host.lowercase()
        val now = startedAt
        addressCache[key]?.let { if (it.expireAt > now) return it.addresses }
        val flight = java.util.concurrent.CompletableFuture<List<InetAddress>>()
        val active = addressFlights.putIfAbsent(key, flight)
        if (active != null) {
            val addresses = runCatching { active.get(15, TimeUnit.SECONDS) }.getOrDefault(emptyList())
            EchDiagnostics.trace("net.resolve.shared", mapOf("host" to host, "n" to addresses.size, "ms" to (System.currentTimeMillis() - startedAt)))
            return addresses
        }
        try {
            val lockedNow = System.currentTimeMillis()
            addressCache[key]?.let {
                if (it.expireAt > lockedNow) {
                    flight.complete(it.addresses)
                    return it.addresses
                }
            }
            val addresses = resolveUncached(host)
            if (addresses.isNotEmpty()) {
                addressCache[key] = AddressEntry(addresses, System.currentTimeMillis() + ADDRESS_CACHE_TTL_MS)
            }
            flight.complete(addresses)
            return addresses
        } catch (t: Throwable) {
            flight.completeExceptionally(t)
            throw t
        } finally {
            addressFlights.remove(key, flight)
        }
    }

    private fun resolveUncached(host: String): List<InetAddress> {
        val startedAt = System.currentTimeMillis()
        // ⚠️ 这里**不再**用国内 DoH 的 HTTPS 地址提示抄近路 —— 实测那是投毒地址。
        //
        // 2026-09-22 真机日志（14:20 那次）抓到确证：
        //   国内 DoH 查 archiveofourown.org 返回
        //     199.16.158.12                    → AS13414 = Twitter/X 的段
        //     2a03:2880:f111:83:face:b00c:...  → AS32934 = Facebook/Meta 的段
        //   而 AO3 真实地址是 104.20.8.2 / 104.20.9.2（Cloudflare）。
        //   而且同一次应答里 echBytes=0（连 ech 都是假的）。
        //
        // 机制：DoH 查询的 URL 里带着 base64 编码的域名，GFW 能解出来并注入假应答。
        // 这跟「阿里本身有没有污染」无关 —— 从境外查同一台阿里拿到的是干净结果。
        //
        // 所以职责必须分清：
        //   · 国内种子 DoH —— 只查**没被墙的**东西：cloudflare-ech.com 的 ECH、
        //     网关地址、配置 TXT。（这些域名不在封禁列表，拿到的就是真答案）
        //   · 自有网关     —— 解析**被墙的目标域名**（防污染，这是它存在的理由）
        //
        // 把目标域名交给国内 DoH，等于亲手把投毒结果喂给握手。

        // 自有网关（防污染）。bootstrap IP 由种子层动态解析而来。
        return try {
            val addrs = dohResolver().lookup(host)
            Log.i(TAG, "doh resolve $host -> ${addrs.joinToString { it.hostAddress ?: "?" }}")
            EchDiagnostics.trace(
                "net.resolve.gateway",
                mapOf("host" to host, "n" to addrs.size,
                      "ms" to (System.currentTimeMillis() - startedAt),
                      "ips" to addrs.joinToString(",") { it.hostAddress ?: "?" })
            )
            addrs
        } catch (t: Throwable) {
            Log.w(TAG, "doh resolve failed for $host: ${t.message}")
            EchDiagnostics.trace(
                "net.resolve.fail",
                mapOf("host" to host, "err" to "${t.javaClass.simpleName}: ${t.message}")
            )
            // 网关可能换了地址或当前 IP 不可达 —— 丢缓存，下次重新向国内 DoH 问「网关在哪」。
            invalidateGateway()
            emptyList()
        }
    }

    // ---------------- 底层 JSON 查询（仅用于 HTTPS(65) 记录） ----------------

    /**
     * 该 IP 是否属于 Cloudflare（**AS13335**）。
     *
     * 为什么用 ASN 而不是官方 IP 段表：段表要手工维护、而且**会漏** ——
     * 新增段、以及 CF「中国网络」的国内段都不在 `ips-v4` 里，漏判会让本该受保护的
     * 域名退回明文。ASN 归属由 IRRd 权威数据决定，一次查询覆盖它的全部段。
     * 实测：CF 站点（cloudflare-ech.com / bgm.tv / hanime1.me / javchu.com）全是 13335，
     * 而 CDN77 是 60068、站方自建 VPS 是 30058、**Google 是 15169**。
     *
     * 查询走 Team Cymru 的 DNS 反查（纯 DNS，与我们自己的网关 DoH 同一条路，
     * 手机上不需要任何额外依赖）：
     *
     *     <反转 IP>.origin.asn.cymru.com   TXT
     *     → "13335 | 104.26.0.0/20 | US | arin | 2014-03-28"
     *
     * IPv6 不参与判定（Cymru 的 v6 反查是另一套 nibble 形式），由调用方只看 IPv4。
     */
    private fun isCloudflareIp(ip: InetAddress): Boolean {
        if (ip.address.size != 4) return false
        val addr = ip.hostAddress ?: return false
        asnCache[addr]?.let { return it }
        val rev = addr.split(".").reversed().joinToString(".") + ".origin.asn.cymru.com"
        val body = try {
            query(rev, "TXT")
        } catch (t: Throwable) {
            null
        }
        val asn = body?.let {
            Regex("""(\d{2,6})\s*\|""").find(it)?.groupValues?.get(1)?.toIntOrNull()
        }
        // 查不到（网络或服务异常）时按「是 CF」处理：宁可白试一次，也不能误伤受保护域名
        if (asn == null) return true
        val cf = asn == CLOUDFLARE_ASN
        asnCache[addr] = cf
        return cf
    }

    /** 目标域名是否在 Cloudflare 上，用于决定是否启用 ECH。 */
    fun isCloudflareHost(host: String): Boolean {
        cfHostCache[host]?.let { return it }
        val addrs = try {
            resolve(host)
        } catch (t: Throwable) {
            emptyList()
        }
        if (addrs.isEmpty()) return true
        // 只看 IPv4 的归属：域名只要有一个 IPv4 判为 CF 就算 CF。
        // 只有 IPv6 的域名（罕见）不拦 —— 宁可白试一次，不能误伤。
        val v4 = addrs.filter { it.address.size == 4 }
        val cf = if (v4.isEmpty()) true else v4.any { isCloudflareIp(it) }
        cfHostCache[host] = cf
        EchDiagnostics.trace(
            if (cf) "cf.host.yes" else "cf.host.no",
            mapOf("host" to host, "v4" to v4.size.toString()),
        )
        return cf
    }

    private fun query(host: String, type: String): String? {
        // ⚠️ 必须走**当前生效的网关**，不能用写死的 DOH_URL ——
        // 网关池是远程 TXT 可调的，写死意味着换了网关这里还打旧地址（或打到一个被停用的端点）。
        val base = currentGateway()?.url ?: activeDohUrl().ifBlank { return null }
        val req = Request.Builder()
            .url("$base?name=$host&type=$type")
            .header("Accept", "application/dns-json")
            .build()
        bootstrapClient.newCall(req).execute().use { resp ->
            if (!resp.isSuccessful) {
                Log.w(TAG, "doh $type HTTP ${resp.code}")
                return null
            }
            return resp.body?.string()
        }
    }
}

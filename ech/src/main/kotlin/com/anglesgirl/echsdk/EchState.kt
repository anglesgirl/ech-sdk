package com.anglesgirl.echsdk

import android.content.Context
import android.util.Base64

/**
 * ECH 配置的落盘存储。
 *
 * 为什么需要：ECHConfigList 以前只放在内存里（ConcurrentHashMap），**每次冷启动都要重新
 * 去网关查一遍** —— 那是首屏最明显的一段等待。落盘后冷启动直接读本地，只要没过期就不查。
 *
 * 职责边界（与用户定下的架构一致）：
 *   - **DoH 只负责拿 IP**（干净 IP / 指定 IP）
 *   - ECH 配置由本类负责"记住上次拿到的活值"，失效时才让 [EchDoh] 去刷新一次
 *
 * 过期即视为没有（调用方据此 fail-closed，绝不回落明文 SNI）。
 */
object EchState {

    private const val PREF = "ech_state"
    private const val KEY_PREFIX = "ech:"

    @Volatile
    private var appContext: Context? = null

    fun attach(context: Context) {
        appContext = context.applicationContext
    }

    private fun prefs() = appContext?.getSharedPreferences(PREF, Context.MODE_PRIVATE)

    /** 读上次落盘的配置；不存在或已过期返回 null。 */
    fun load(host: String): ByteArray? {
        val p = prefs() ?: return null
        return try {
            val s = p.getString(KEY_PREFIX + host, null) ?: return null
            val parts = s.split('|', limit = 2)
            if (parts.size != 2) return null
            val expireAt = parts[0].toLongOrNull() ?: return null
            if (System.currentTimeMillis() >= expireAt) {
                p.edit().remove(KEY_PREFIX + host).apply()
                return null
            }
            Base64.decode(parts[1], Base64.DEFAULT)
        } catch (t: Throwable) {
            null
        }
    }

    /** 落盘一份配置（wire 格式，含 2 字节长度前缀）。 */
    fun save(host: String, wire: ByteArray, ttlMs: Long) {
        val p = prefs() ?: return
        try {
            val v = (System.currentTimeMillis() + ttlMs).toString() + "|" +
                Base64.encodeToString(wire, Base64.NO_WRAP)
            p.edit().putString(KEY_PREFIX + host, v).apply()
        } catch (_: Throwable) {
        }
    }

    /** 配置被服务端拒过：丢掉，逼下一次重新取。 */
    fun drop(host: String) {
        try {
            prefs()?.edit()?.remove(KEY_PREFIX + host)?.apply()
        } catch (_: Throwable) {
        }
    }
}

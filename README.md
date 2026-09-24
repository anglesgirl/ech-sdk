# ECH SDK

通用 Android `OkHttp + Conscrypt ECH` 组件，可与宿主已有 OkHttp、CookieJar、缓存和图片加载器共用。

## 使用方式

```kotlin
EchSdk.install(
    context = applicationContext,
    config = EchSdk.Config(
        protectedHosts = setOf("archiveofourown.org"),
        dohUrl = null, // 使用下面两个 TXT 动态配置
        gatewayPoolTxt = "doh.萝莉.eu.org",
        preferredIpsTxt = "ip.萝莉.eu.org",
        logger = EchLogger { name, fields -> /* 接入宿主日志 */ },
    ),
)

val builder = OkHttpClient.Builder()
    .cookieJar(hostCookieJar)
EchSdk.configure(builder)
val client = builder.build()
```

域名建议传入 IDN 转换后的 ASCII 名：`doh.xn--pn1aul.eu.org`、`ip.xn--pn1aul.eu.org`。SDK 通过国内纯 IP DNS-over-HTTPS 获取这两条 TXT：前者是 DoH 网关池，后者是优选 bootstrap IP。被保护的目标域名 A/AAAA 与 HTTPS/ECH 信息只经选中的自有网关查询；目标域名解析失败时 fail-closed，不回退系统 DNS。

## Mihon 接入点

Mihon API 与 Coil 3 图片请求共用 `NetworkHelper.client`。在它的 OkHttp Builder 上调用 `EchSdk.configure(builder)` 可共同覆盖；保留 Mihon CookieJar、缓存及已有拦截器。WebView 使用独立网络栈，本 SDK 不覆盖 WebView 子请求。

## 构建

GitHub Actions 构建 Android AAR。当前依赖目标 OkHttp 5.5.0。不要在本地编译 Android。
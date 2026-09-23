# ECH SDK

通用 Android `OkHttp + Conscrypt ECH` 组件，面向已有 OkHttp/图片加载器的应用。

## 接入接口

```kotlin
EchSdk.install(
    context = this,
    config = EchSdk.Config(
        protectedHosts = setOf("example.com"),
        dohUrl = "https://your-gateway.example/dns-query",
        dohBootstrapIps = listOf("203.0.113.10"),
    ),
)

val builder = OkHttpClient.Builder()
    // 宿主自己的 CookieJar、缓存、业务拦截器保持不动
EchSdk.configure(builder)
val client = builder.build()
```

`EchSdk.configure` 不替换宿主的 `CookieJar`，只为受保护域名挂载 ECH TLS、DoH DNS、直连策略和非默认主机名校验器。

## Mihon 接入点

Mihon 当前的共享客户端位于：

```text
core/common/src/main/kotlin/eu/kanade/tachiyomi/network/NetworkHelper.kt
```

初始化 `clientBuilder` 后、`build()` 前调用：

```kotlin
EchSdk.configure(builder)
```

Mihon 的 Coil 3 图片请求复用 `networkHelper.client`，因此 API 和图片会同时覆盖。WebView 是单独的浏览器网络栈，本 SDK 不宣称自动覆盖 WebView 子请求；需要时另接 WebView 适配器。

## 当前状态

- Android 核心源码已从 CO3 的实测 TCP/ECH 链路抽出；
- 已移除 React Native、H3/quiche、账号业务和诊断上传依赖；
- 版本兼容目标：OkHttp 5.5.0 API；
- AAR 必须通过 GitHub Actions 构建，当前环境没有 Android SDK，不能本地编译；
- 目前未宣称 Mihon 真机验证完成。

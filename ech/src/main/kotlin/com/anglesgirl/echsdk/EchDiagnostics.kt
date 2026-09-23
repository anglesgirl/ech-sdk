package com.anglesgirl.echsdk

/** SDK 诊断回调。默认空实现，不依赖宿主 App 的日志系统。 */
fun interface EchLogger {
    fun event(name: String, fields: Map<String, String>)
}

object EchDiagnostics {
    @Volatile
    var logger: EchLogger = EchLogger { _, _ -> }

    fun trace(name: String, fields: Map<String, Any?> = emptyMap()) {
        logger.event(name, fields.mapValues { it.value?.toString() ?: "" })
    }
}

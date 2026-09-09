# 反无人机监控 App - ProGuard 规则占位文件
# release 构建当前 minifyEnabled=false，无需额外规则。
# 若后续开启混淆，请保留 WebView 的 JavaScript 接口方法与类：
# -keepattributes JavascriptInterface
# -keep class com.example.dronemonitor.** { *; }
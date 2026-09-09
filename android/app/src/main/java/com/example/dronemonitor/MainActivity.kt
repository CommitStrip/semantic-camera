package com.example.dronemonitor

import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.os.Environment
import android.webkit.*
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * 反无人机监控 · Android 演示端
 *
 * 职责：
 *  1. 用 WebView 加载共享的 HTML5 检测核心（web/index.html）。
 *  2. 通过 JsBridge 接收核心遥测（性能采样/检出/确认事件），落盘为 CSV 便于追溯与改进。
 *  3. 相机依赖系统 WebView 的 getUserMedia（需 HTTPS 或本机 scheme 白名单）。
 */
class MainActivity : AppCompatActivity() {

    private lateinit var webView: WebView
    private val telemetryDir: File by lazy {
        File(getExternalFilesDir(Environment.DIRECTORY_DOCUMENTS), "telemetry").apply { mkdirs() }
    }
    private var telemetryWriter: java.io.FileWriter? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        requestCamera()
        setupWebView()
        setContentView(webView)
    }

    private fun requestCamera() {
        if (Build.VERSION.SDK_INT >= 23 &&
            checkSelfPermission(Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED) {
            ActivityCompat.requestPermissions(this, arrayOf(Manifest.permission.CAMERA), 100)
        }
    }

    private fun setupWebView() {
        webView = WebView(this)
        webView.settings.apply {
            javaScriptEnabled = true
            domStorageEnabled = true
            mediaPlaybackRequiresUserGesture = false
            allowFileAccess = true
            setSupportZoom(false)
        }
        webView.webChromeClient = object : WebChromeClient() {
            // WebView 默认拒绝网页 getUserMedia 请求：不重写此回调相机画面只会黑屏
            override fun onPermissionRequest(request: PermissionRequest) {
                if (checkSelfPermission(Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED) {
                    request.grant(request.resources)
                } else {
                    request.deny()
                }
            }
        }
        webView.webViewClient = WebViewClient()

        // 遥测桥：接收核心的遥测事件并落盘
        webView.addJavascriptInterface(object {
            @JavascriptInterface
            fun pushTelemetry(json: String) {
                runOnUiThread { saveTelemetry(json) }
            }
        }, "nativeBridge")

        webView.loadUrl("file:///android_asset/web/index.html")
        openTelemetryLog()
    }

    @Suppress("DEPRECATION")
    private fun saveTelemetry(json: String) {
        try {
            if (telemetryWriter == null) openTelemetryLog()
            telemetryWriter?.write(json + "\n")
            telemetryWriter?.flush()
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    private fun openTelemetryLog() {
        val ts = SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(Date())
        // 遥测事件是每行一个 JSON（JSONL），不是 CSV——扩展名据实修正
        val f = File(telemetryDir, "telemetry_$ts.jsonl")
        telemetryWriter?.close()
        telemetryWriter = f.writer()
    }

    override fun onBackPressed() {
        if (webView.canGoBack()) webView.goBack() else super.onBackPressed()
    }

    override fun onDestroy() {
        telemetryWriter?.close()
        super.onDestroy()
    }

    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
    }
}
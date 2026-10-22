// C161 用户数据路径（单一事实源）：
// WebView2 用户数据目录与全部用户数据都落在「用户应用数据根」
// （%LOCALAPPDATA%\semantic-camera，与安装器 UserDataDirName 一致），
// 绝不落在发布目录/安装目录——发布目录只含程序文件（C160 验收发现：
// 历史 profile 曾随包分发，根因即用户数据目录落点错误）。
using System;
using System.IO;

namespace SemanticCamera.Desktop;

internal static class UserPaths
{
    /// <summary>
    /// 用户数据根：默认 {localappdata}\semantic-camera（卸载保留）。
    /// SEMANTIC_CAMERA_USER_DATA_ROOT 仅用于**隔离测试**（重定向到独立
    /// 根，绝不触碰真实用户数据）；生产与安装版不设置该变量。
    /// </summary>
    public static string UserDataRoot =>
        Environment.GetEnvironmentVariable("SEMANTIC_CAMERA_USER_DATA_ROOT")
        ?? Path.Combine(Environment.GetFolderPath(
            Environment.SpecialFolder.LocalApplicationData),
            "semantic-camera");

    /// <summary>
    /// WebView2 用户数据目录：{用户数据根}\webview2。
    /// 由壳在初始化前显式指定（CreationProperties），使 WebView2 的
    /// EBWebView profile（Cookies/History/Cache…）只可能出现在这里，
    /// 结构上不可能出现在发布目录（不再依赖"发布后别运行"的纪律）。
    /// </summary>
    public static string WebView2DataFolder =>
        Path.Combine(UserDataRoot, "webview2");
}

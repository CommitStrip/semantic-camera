// C152 主窗口（R1 重写）：WebView2 宿主 + 导航白名单 + 状态显示 +
// 关闭三选一 + 托盘恢复/退出。停止只有**一条**实现（StopCoreAsync），
// 关闭「是」与托盘「停止值守并退出」共用；停止中重入直接返回。
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using Microsoft.Web.WebView2.Core;
using Microsoft.Web.WebView2.Wpf;
using Forms = System.Windows.Forms;

namespace SemanticCamera.Desktop;

public partial class MainWindow : Window
{
    private readonly WebView2 _view = new();
    private readonly TextBlock _status = new() { Text = "启动中…",
        Margin = new Thickness(8, 4, 8, 4) };
    private readonly HashSet<string> _allowed = new();
    private readonly BackendSession _session;
    private readonly Forms.NotifyIcon _tray = new();
    private bool _stopInProgress;          // 重入保护：停止中不重复进入
    private bool _exitRequested;           // 已完成正常收尾，允许真正关闭
    private bool _ready;
    private bool _navigationReady;         // 初始化 + 导航保护已装好
    private string? _pendingNavigate;      // 初始化前收到的 navigate
    private readonly Menu _applicationMenu = new();
    private readonly MenuItem _applicationOperationsMenuItem = new() { Header = "应用操作" };
    private readonly MenuItem _restartMenuItem = new() { Header = "重新启动后台" };
    private readonly MenuItem _recoveryMenuItem = new() { Header = "新建替代配置（仅本次）" };
    private readonly MenuItem _stopMenuItem = new() { Header = "停止值守并退出" };

    public MainWindow(BackendSession session)
    {
        _session = session;
        Title = "语义摄像头";
        Width = 1100; Height = 760;
        var dock = new DockPanel();
        _applicationOperationsMenuItem.Items.Add(_restartMenuItem);
        _applicationOperationsMenuItem.Items.Add(_recoveryMenuItem);
        _applicationOperationsMenuItem.Items.Add(_stopMenuItem);
        _applicationMenu.Items.Add(_applicationOperationsMenuItem);
        _restartMenuItem.Click += (_, _) => _ = RestartBackendFromTrayAsync();
        _recoveryMenuItem.Click += (_, _) => _ = RestartBackendFromTrayAsync(true);
        _stopMenuItem.Click += (_, _) => _ = StopFromTrayAsync();
        UpdateApplicationMenuState();
        DockPanel.SetDock(_applicationMenu, Dock.Top);
        dock.Children.Add(_applicationMenu);
        DockPanel.SetDock(_status, Dock.Top);
        dock.Children.Add(_status);
        dock.Children.Add(_view);
        Content = dock;

        // WebView2 用户数据目录固定在「用户应用数据根」（C161：绝不落在
        // 发布/安装目录——C160 验收发现历史 profile 曾随包分发，根因即
        // 用户数据目录落点）。目录由 WebView2 按需创建。
        try
        {
            _view.CreationProperties = new CoreWebView2CreationProperties
            {
                UserDataFolder = UserPaths.WebView2DataFolder,
            };
        }
        catch (Exception) { }
        // C161：显式初始化。隔离原生验证发现仅依赖控件的自动初始化时机
        // 在部分宿主时序下不触发（进程在、视图白板、Loader 未加载）。
        // EnsureCoreWebView2Async 必须在事件循环启动后调用——排队到
        // Dispatcher（app.Run() 启动后执行），不能在构造函数同步调用。
        _ = Dispatcher.InvokeAsync(EnsureViewAsync);
        _view.CoreWebView2InitializationCompleted += OnInit;

        _tray.Icon = System.Drawing.SystemIcons.Shield;
        _tray.Text = "语义摄像头";
        _tray.Visible = true;
        _tray.DoubleClick += (_, _) => RestoreWindow();
        _tray.MouseClick += (_, e) =>
        {
            if (e.Button == Forms.MouseButtons.Left) RestoreWindow();
        };
        var menu = new Forms.ContextMenuStrip();
        menu.Items.Add("显示窗口", null, (_, _) => RestoreWindow());
        menu.Items.Add("重新启动后台", null,
                       (_, _) => _ = RestartBackendFromTrayAsync());
        menu.Items.Add("新建替代配置（仅本次）", null,
                       (_, _) => _ = RestartBackendFromTrayAsync(true));
        menu.Items.Add("停止值守并退出", null,
                       (_, _) => _ = StopFromTrayAsync());
        _tray.ContextMenuStrip = menu;

        Closing += OnClosing;

        _session.Navigate += (url, page) => Dispatcher.Invoke(() =>
        {
            // 受信后台握手登记 setup/workbench 来源（不依赖 workbench ready）。
            if (TryOrigin(url, out string origin)) _allowed.Add(origin);
            if (!_navigationReady)
            {
                // 初始化与导航保护尚未装好：先缓冲，绝不抢先导航
                _pendingNavigate = url;
                _status.Text = page == "setup"
                    ? "正在打开首次配置向导…"
                    : "正在打开界面…";
                return;
            }
            _status.Text = page == "setup"
                ? "首次配置：请完成设置向导（完成后自动进入工作台）。"
                : "正在打开界面…";
            if (Uri.TryCreate(url, UriKind.Absolute, out var uri))
                _view.Source = uri;
        });
        _session.Ready += origin => Dispatcher.Invoke(() =>
        {
            _allowed.Add(origin.TrimEnd('/'));
            _ready = true;
            _status.Text = "HTTP 就绪（相机/模型状态见下方）";
        });
        _session.State += payload => Dispatcher.Invoke(() =>
        {
            string models = payload.TryGetProperty("models", out var m)
                ? m.GetString() ?? "unknown" : "unknown";
            string cams = payload.TryGetProperty("cameras", out var c)
                ? c.ToString() : "0";
            _status.Text = $"HTTP 就绪 · 相机 {cams} 路 · 模型状态：{models}";
        });
        // 收到 stopped 握手**只更新状态**：是否收尾完成由停止核心判定，
        // 不得凭事件关窗（进程可能仍在运行）。
        _session.Stopped += (exitCode, incomplete) => Dispatcher.Invoke(() =>
        {
            _status.Text = incomplete.Count == 0
                ? $"已收到停止握手（自报退出码 {exitCode}），正在等待进程退出…"
                : $"已收到停止握手（自报退出码 {exitCode}），但仍存在未完成收尾项："
                  + string.Join("；", incomplete);
        });
        _session.Faulted += () => Dispatcher.Invoke(() =>
        {
            _ready = false;
            var tail = string.Join(" | ", _session.Diagnostics.TakeLast(4));
            _status.Text = "后端通信异常或非正常退出：可从托盘菜单"
                + "「重新启动后台」恢复（未自动重启，避免打断可能的收尾）。"
                + (tail.Length > 0 ? " 诊断：" + tail : "");
            _tray.ShowBalloonTip(3000, "语义摄像头",
                "后台已异常退出：托盘菜单「重新启动后台」可恢复。",
                Forms.ToolTipIcon.Warning);
        });
    }

    // ---------------- 后台重启恢复（C161） ----------------
    /// <summary>
    /// 托盘「重新启动后台」：仍在运行先走正常停止合同（短超时，不强杀），
    /// 再重新启动；未运行则直接启动。任何失败都落在状态栏/对话框，
    /// 绝不让壳进入半死状态（窗口保留，可再次尝试）。
    /// </summary>
    internal async Task RestartBackendFromTrayAsync()
    {
        await RestartBackendFromTrayAsync(false);
    }

    private async Task RestartBackendFromTrayAsync(bool recoverConfig)
    {
        if (_stopInProgress) return;              // 与停止共用重入保护
        _stopInProgress = true;
        UpdateApplicationMenuState();
        try
        {
            RestoreWindow();
            if (!_session.HasExited)
            {
                _status.Text = "正在请求后台正常退出，以便重启…";
                var stop = await _session
                    .RequestStopAndWaitAsync(TimeSpan.FromSeconds(15))
                    .ConfigureAwait(true);
                if (stop != StopOutcome.NormalStopped
                    && stop != StopOutcome.NotRunning)
                {
                    ReportStopProblem("重启中止：后台未能正常退出（"
                        + stop + "）。未强制结束，可稍后重试或退出应用。");
                    return;
                }
            }
            _status.Text = "正在重新启动后台…";
            try
            {
                if (recoverConfig) _session.StartRecovery();
                else _session.Start();
            }
            catch (Exception)
            {
                ShowStartupFailure("后台重启失败：请检查 "
                    + "backend\\semantic-camera-backend.exe 是否存在后重试。");
                return;
            }
            _ready = false;
            // 导航保护（OnInit）已装好且 WebView2 不重初始化：保持
            // _navigationReady=true，仅清来源白名单——重启后新后台的
            // navigate 握手会先登记来源再导航（同一 UI 线程顺序执行）。
            _allowed.Clear();
            _pendingNavigate = null;
            _status.Text = "后台已重启，等待界面就绪…";
        }
        finally
        {
            _stopInProgress = false;
            UpdateApplicationMenuState();
        }
    }

    // ---------------- 停止：唯一实现 ----------------
    /// <summary>
    /// 停止核心：发送 stop → 等待「握手 + 进程退出」合同；超时/异常退出保留窗口。
    /// 关闭「是」与托盘「停止值守并退出」共用；停止中重入立即返回。
    /// </summary>
    private async Task<StopOutcome> StopCoreAsync()
    {
        if (_stopInProgress) return StopOutcome.Timeout;
        if (_exitRequested) return StopOutcome.NormalStopped;
        _stopInProgress = true;
        UpdateApplicationMenuState();
        try
        {
            _status.Text = "正在停止后台…";
            var outcome = await _session
                .RequestStopAndWaitAsync(TimeSpan.FromSeconds(20))
                .ConfigureAwait(true);
            switch (outcome)
            {
                case StopOutcome.NormalStopped:
                    _status.Text = $"后台已正常停止（退出码 {_session.ExitCode}）。";
                    _exitRequested = true;
                    DisposeNativeResources();
                    _ = Dispatcher.BeginInvoke(new Action(() =>
                    {
                        Close();
                        Application.Current.Shutdown();
                    }));
                    break;
                case StopOutcome.IncompleteFinalization:
                    ReportStopProblem("已收到停止握手，但存在未完成收尾项："
                        + string.Join("；", _session.HandshakeIncomplete)
                        + "。未强制结束，窗口保持打开。");
                    break;
                case StopOutcome.HandshakeExitFailure:
                    ReportStopProblem($"停止握手自报失败（退出码 "
                        + $"{_session.HandshakeExitCode}）：按异常处理，窗口保持打开。");
                    break;
                case StopOutcome.AbnormalExitCode:
                    ReportStopProblem($"后端实际退出码非 0（{_session.ExitCode}）："
                        + "按异常退出处理，未标记正常完成。");
                    break;
                case StopOutcome.StoppedButAlive:
                    ReportStopProblem("后端已回停止握手，但进程仍在运行："
                        + "未强制结束，窗口保持打开。");
                    break;
                case StopOutcome.ExitedWithoutHandshake:
                    ReportStopProblem("后端进程已退出，但未收到正常停止握手："
                        + "按非正常退出处理，未标记正常完成。");
                    break;
                case StopOutcome.StopRequestFailed:
                    ReportStopProblem("停止请求未能送达后端，且后端仍在运行："
                        + "未强制结束，窗口保持打开。");
                    break;
                case StopOutcome.NotRunning:
                    _status.Text = "没有后台在运行，正在退出界面。";
                    _exitRequested = true;
                    DisposeNativeResources();
                    _ = Dispatcher.BeginInvoke(new Action(() =>
                    {
                        Close();
                        Application.Current.Shutdown();
                    }));
                    break;
                default:
                    ReportStopProblem("停止超时：后端尚未确认停止，"
                        + "已保持窗口与后台运行（未强制结束进程）。");
                    break;
            }
            return outcome;
        }
        finally
        {
            _stopInProgress = false;
            UpdateApplicationMenuState();
        }
    }

    private void UpdateApplicationMenuState()
    {
        var enabled = !_stopInProgress;
        _restartMenuItem.IsEnabled = enabled;
        _recoveryMenuItem.IsEnabled = enabled;
        _stopMenuItem.IsEnabled = enabled;
    }

    private void ReportStopProblem(string message)
    {
        _status.Text = message;
        MessageBox.Show(message, "语义摄像头", MessageBoxButton.OK,
                        MessageBoxImage.Warning);
    }

    /// <summary>托盘菜单「停止值守并退出」绑定到这条路径。</summary>
    internal Task<StopOutcome> StopFromTrayAsync() => StopCoreAsync();

    /// <summary>关闭询问选「是」绑定到同一条路径。</summary>
    internal Task<StopOutcome> StopFromCloseDialogAsync() => StopCoreAsync();

    /// <summary>退出前显式释放原生资源（WebView2 宿主与托盘）。</summary>
    private void DisposeNativeResources()
    {
        try { _tray.Visible = false; _tray.Dispose(); } catch (Exception) { }
        try { _view.Dispose(); } catch (Exception) { }
    }

    /// <summary>托盘恢复：与第二实例唤起共用同一条恢复路径。</summary>
    internal void RestoreWindow()
    {
        Show();
        if (WindowState == WindowState.Minimized) WindowState = WindowState.Normal;
        Activate();
    }

    public void ShowStartupFailure(string message)
    {
        _ready = false;
        _status.Text = message;
        MessageBox.Show(message, "语义摄像头", MessageBoxButton.OK,
                        MessageBoxImage.Error);
    }

    /// <summary>显式初始化 WebView2（使用 CreationProperties 里的用户数据
    /// 目录）；失败给**带原因**的恢复指引（异常类型+消息，本机应用无凭据
    /// 面），不静默白板、不给"请重试"式不可诊断提示。</summary>
    private async Task EnsureViewAsync()
    {
        try
        {
            await _view.EnsureCoreWebView2Async().ConfigureAwait(true);
        }
        catch (Exception ex)
        {
            ShowStartupFailure("WebView2 初始化失败：" + ex.GetType().Name
                + " " + ex.Message + "\n请确认已安装 WebView2 Evergreen "
                + "Runtime，或从托盘「重新启动后台」/重开应用重试。");
        }
    }

    private async void OnInit(object? sender,
                              CoreWebView2InitializationCompletedEventArgs e)
    {
        if (!e.IsSuccess)
        {
            // WebView2 失败：桌面显示恢复指引；**不**自动开外部浏览器
            ShowStartupFailure("WebView2 运行时不可用：请安装 Evergreen Runtime 后重试。");
            await StopCoreAsync();
            return;
        }
        await _view.CoreWebView2.AddScriptToExecuteOnDocumentCreatedAsync(
            "window.__scDesktop = true;");
        var core = _view.CoreWebView2;
        core.NewWindowRequested += (_, args) =>
        {
            args.Handled = true;
            if (args.Uri.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            {
                var r = MessageBox.Show($"在系统浏览器中打开？\n{args.Uri}",
                                        "外部链接", MessageBoxButton.YesNo);
                if (r == MessageBoxResult.Yes)
                    System.Diagnostics.Process.Start(
                        new System.Diagnostics.ProcessStartInfo(args.Uri)
                        { UseShellExecute = true });
            }
        };
        core.NavigationStarting += (_, args) =>
        {
            if (!IsAllowed(args.Uri)) args.Cancel = true;
        };
        core.WebMessageReceived += (_, _) => { /* 页面消息不得触发 shell */ };
        _navigationReady = true;              // 保护已装好，之后才允许导航
        if (_pendingNavigate is { } pending &&
            Uri.TryCreate(pending, UriKind.Absolute, out var pendingUri))
        {
            _view.Source = pendingUri;
            _pendingNavigate = null;
        }
    }

    private static bool TryOrigin(string url, out string origin)
    {
        origin = "";
        if (!Uri.TryCreate(url, UriKind.Absolute, out var u)) return false;
        if (u.Scheme != "http") return false;
        if (u.Host != "127.0.0.1" && u.Host != "localhost") return false;
        if (u.Port <= 0 || !string.IsNullOrEmpty(u.UserInfo)) return false;
        origin = $"{u.Scheme}://{u.Host}:{u.Port}";
        return true;
    }

    private bool IsAllowed(string uri) =>
        Uri.TryCreate(uri, UriKind.Absolute, out var u)
        && u.Scheme == "http" && (u.Host == "127.0.0.1" || u.Host == "localhost")
        && _allowed.Contains($"{u.Scheme}://{u.Host}:{u.Port}");

    private async void OnClosing(object? sender,
                                 System.ComponentModel.CancelEventArgs e)
    {
        if (_exitRequested) return;      // 已按正常合同收尾，允许关闭
        e.Cancel = true;                 // 未决策前不改变运行状态
        var choice = MessageBox.Show(
            "关闭窗口后如何处理值守？\n\n「是」停止值守并退出\n"
            + "「否」继续后台值守（托盘可恢复）\n「取消」保持现状",
            "语义摄像头", MessageBoxButton.YesNoCancel);
        if (choice == MessageBoxResult.No)
        {
            Hide();                      // 取消/继续后台：**不进入停止核心**
            _tray.ShowBalloonTip(2000, "语义摄像头", "仍在后台值守，双击托盘恢复。",
                                 Forms.ToolTipIcon.Info);
            return;
        }
        if (choice == MessageBoxResult.Cancel) return;   // 同样不进入停止核心
        await StopFromCloseDialogAsync();
    }

    internal bool Ready => _ready;
}

// 桌面壳入口（基于官方 Microsoft.Web.WebView2）。
// 契约：不开外部浏览器兜底、页面不触发 shell、正常停止走协议、超时不强杀、
// HTTP 就绪不等于模型就绪。
using System;
using System.Threading;
using System.Windows;

namespace SemanticCamera.Desktop;

public static class Program
{
    private static Mutex? _single;

    [STAThread]
    public static int Main(string[] args)
    {
        bool first = true;
        _single = new Mutex(true, IpcChannelName(), out first);
        if (!first)
        {
            ActivationSignal.Request();      // 唤起原窗口；不新开后台
            return 0;
        }
        var session = new BackendSession();
        var app = new Application { ShutdownMode = ShutdownMode.OnExplicitShutdown };
        var window = new MainWindow(session);
        window.Show();
        // 主实例接收唤起信号：第二实例启动时恢复原窗口，不新开后台。
        var listener = new ActivationListener(() => app.Dispatcher.Invoke(() =>
        {
            window.Show();
            if (window.WindowState == WindowState.Minimized)
                window.WindowState = WindowState.Normal;
            window.Activate();
        }));
        listener.Start();
        try
        {
            session.Start();                 // 启动内部后端（失败在窗口内显示指引）
        }
        catch (Exception ex)
        {
            // C161：带原因的启动失败（异常类型+消息，本机应用无凭据面）。
            window.ShowStartupFailure(
                "后端不可用：" + ex.GetType().Name + " " + ex.Message
                + "\n请重新安装，或检查 backend\\semantic-camera-backend.exe。");
        }
        app.Run();
        listener.Dispose();
        _single.ReleaseMutex();
        // 正常收尾后自然返回：不使用 Environment.Exit 掩盖收尾问题；
        // WebView2 与托盘已在 StopCore 的正常分支里释放，线程均为后台线程。
        return 0;
    }

    internal static string IpcChannelName()
    {
        string root = BackendSession.InstallDir.ToLowerInvariant();
        string digest = Convert.ToHexString(
            System.Security.Cryptography.SHA256.HashData(
                System.Text.Encoding.UTF8.GetBytes(root)))[..12];
        return $"SemanticCamera.Desktop.{Environment.UserName}.{digest}";
    }
}

// 主实例侧：等待第二实例的唤起请求（当前用户 + 安装根限定命名事件）。
internal sealed class ActivationListener : IDisposable
{
    private readonly Action _onActivate;
    private IntPtr _handle;
    private volatile bool _stopped;

    [System.Runtime.InteropServices.DllImport("kernel32.dll",
        SetLastError = true,
        CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
    private static extern IntPtr CreateEventW(IntPtr attributes, bool manualReset,
                                              bool initialState, string name);

    [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);

    [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    public ActivationListener(Action onActivate) => _onActivate = onActivate;

    public void Start()
    {
        _handle = CreateEventW(IntPtr.Zero, false, false,
                               Program.IpcChannelName() + ".activate");
        if (_handle == IntPtr.Zero) return;      // 通道不可用：不假装可唤起
        var thread = new System.Threading.Thread(Loop) { IsBackground = true };
        thread.Start();
    }

    private void Loop()
    {
        while (!_stopped)
        {
            uint result = WaitForSingleObject(_handle, 200);
            if (result == 0) _onActivate();
        }
    }

    public void Dispose()
    {
        _stopped = true;
        if (_handle != IntPtr.Zero) CloseHandle(_handle);
        _handle = IntPtr.Zero;
    }
}

// 第二实例 → 主实例的唤起信号（命名事件，当前用户 + 安装根限定）。
internal static class ActivationSignal
{
    private const uint EVENT_MODIFY_STATE = 0x0002;

    [System.Runtime.InteropServices.DllImport("kernel32.dll",
        SetLastError = true,
        CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
    private static extern IntPtr OpenEventW(uint access, bool inherit, string name);

    [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetEvent(IntPtr handle);

    [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    public static void Request()
    {
        var handle = OpenEventW(EVENT_MODIFY_STATE, false,
            Program.IpcChannelName() + ".activate");
        if (handle == IntPtr.Zero) return;   // 主实例不在：诚实退出
        try { SetEvent(handle); } finally { CloseHandle(handle); }
    }
}

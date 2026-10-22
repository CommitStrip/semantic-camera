// C152 后端会话（R1 重写）：严格协议校验 + 有界行读取 + stderr 持续排空 +
// 停止结果模型（握手 / 进程退出 / 退出码 / 异常退出 / 超时 分开判定）。
// 不提供强杀接口；不以 Environment.Exit 代替后端收尾。
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace SemanticCamera.Desktop;

/// <summary>停止结果：只有 NormalStopped 才能宣称"正常完成"。</summary>
public enum StopOutcome
{
    NotRunning,
    /// <summary>握手成功 + 无未完成项 + 进程已退出 + 实际退出码成功。</summary>
    NormalStopped,
    /// <summary>握手到达但 incomplete 非空（收尾不完整）。</summary>
    IncompleteFinalization,
    /// <summary>握手自报退出码非 0。</summary>
    HandshakeExitFailure,
    /// <summary>进程实际退出码非 0。</summary>
    AbnormalExitCode,
    /// <summary>进程已退出但没有停止握手。</summary>
    ExitedWithoutHandshake,
    /// <summary>握手到达但进程仍存活。</summary>
    StoppedButAlive,
    /// <summary>超时：既无握手也未退出。</summary>
    Timeout,
    /// <summary>stop 命令未能发出且进程仍存活。</summary>
    StopRequestFailed,
}

public sealed class BackendSession
{
    public const string Schema = "scam.desktop/v1";
    /// <summary>内部后端的固定入口参数（桌面协议模式）。</summary>
    public const string DesktopArgument = "--desktop";
    /// <summary>协议单行上限（与冻结接口一致：16KiB）。</summary>
    public const int MaxLineBytes = 16 * 1024;
    private const int MaxDiagnosticLines = 64;
    private const int MaxDiagnosticLineChars = 200;

    private static readonly HashSet<string> KnownEvents = new(StringComparer.Ordinal)
    { "starting", "navigate", "ready", "stopping", "stopped", "failed", "state" };

    public event Action<string, string>? Navigate;   // (url, page)
    public event Action<string>? Ready;
    public event Action<JsonElement>? State;
    public event Action<int, IReadOnlyList<string>>? Stopped;
    public event Action? Faulted;

    private Process? _process;
    // Admission only: never hold across process launch, pipe IO, reader waits,
    // or subscriber callbacks. An in-progress launch owns the single slot.
    private readonly object _lifecycleGate = new();
    private sealed class StartAttempt
    {
        public bool StopRequested;
        public readonly TaskCompletionSource<GenState?> Completion =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
    }
    private StartAttempt? _startAttempt;
    // 代际隔离：每次启动对应独立 GenState；旧代 reader 回调与 finally 只写
    // 自己捕获的对象，事件经 IsCurrentGen 守卫后对外——旧代尾部不可能污染
    // 新代会话。
    private sealed class GenState
    {
        public Process? Process;
        public Task? ReaderTask;
        public volatile bool StopCommandSent;
        public volatile bool StoppedSeen;
        public volatile bool StdoutClosed;
        public volatile bool Faulted;
        public int? HandshakeExitCode;
        public IReadOnlyList<string> HandshakeIncomplete = Array.Empty<string>();
        // C161-R2 P2：诊断与协议错误**按代记录**（各 64 行上限、脱敏、
        // 排空不阻塞）——旧代 stderr/stdout 尾部与坏帧不得伪装当前代故障
        // （红例：new 代 Diagnostics 出现 old-*-tail-marker、ProtocolErrorCount
        // 被旧代坏 JSON +1）。
        public readonly Queue<string> Diagnostics = new Queue<string>();
        public int ProtocolErrorCount;
        public readonly object StopGate = new();
    }
    private volatile GenState? _genState;

    private bool IsCurrentGen(GenState? gen) =>
        ReferenceEquals(_genState, gen);

    public static string InstallDir =>
        Environment.GetEnvironmentVariable("SEMANTIC_CAMERA_INSTALL_DIR")
        ?? Path.Combine(Environment.GetFolderPath(
               Environment.SpecialFolder.LocalApplicationData),
           "Programs", "SemanticCamera");

    public static string BackendExePath =>
        Environment.GetEnvironmentVariable("SEMANTIC_CAMERA_BACKEND")
        ?? Path.Combine(InstallDir, "backend", "semantic-camera-backend.exe");

    public bool StoppedSeen => _genState?.StoppedSeen ?? false;
    /// <summary>握手自报的退出码（null = 未收到合法握手）。</summary>
    public int? HandshakeExitCode => _genState?.HandshakeExitCode;
    /// <summary>握手里的未完成收尾项。</summary>
    public IReadOnlyList<string> HandshakeIncomplete
        => _genState?.HandshakeIncomplete ?? Array.Empty<string>();
    /// <summary>握手成功 = 已收到 + 自报退出码 0 + 无未完成项。</summary>
    public bool HandshakeOk
        => _genState is { StoppedSeen: true, HandshakeExitCode: 0 } gen
           && gen.HandshakeIncomplete.Count == 0;
    public bool StdoutClosed => _genState?.StdoutClosed ?? false;
    public bool IsFaulted => _genState?.Faulted ?? false;
    public bool HasExited => _process?.HasExited ?? true;
    public int? ExitCode
    {
        get
        {
            try { return _process is { HasExited: true } p ? p.ExitCode : null; }
            catch (InvalidOperationException) { return null; }
        }
    }

    /// <summary>当前代的有界诊断（不含原始异常文本；URL 凭据已抹除）。
    /// C161-R2 P2：按代记录——旧代 stderr/stdout 尾部与坏帧不进当前代。</summary>
    public IReadOnlyList<string> Diagnostics
    {
        get
        {
            var gen = _genState;
            if (gen is null) return Array.Empty<string>();
            lock (gen.Diagnostics) return gen.Diagnostics.ToArray();
        }
    }

    /// <summary>当前代的协议错误计数（按代；旧代坏帧不计入当前代）。</summary>
    public int ProtocolErrorCount => _genState?.ProtocolErrorCount ?? 0;

    /// <summary>
    /// 启动。当前代进程仍存活时**拒绝**（C161-R2：重复启动会丢失第一进程
    /// 引用，红例 duplicate_start.rejected=false 即此缺陷）。
    /// </summary>
    public void Start()
    {
        StartInternal(false);
    }

    public void StartRecovery()
    {
        StartInternal(true);
    }

    private void StartInternal(bool recoverConfig)
    {
        var exe = BackendExePath;
        if (!File.Exists(exe))
            throw new FileNotFoundException("后端不存在", exe);
        // 显式本地配置入口；不接受页面提供的任意后端参数。
        // 在创建进程前检查，避免路径错误时误进首次设置并新建配置。
        var configPath = Environment.GetEnvironmentVariable("SEMANTIC_CAMERA_CONFIG");
        if (configPath is not null)
        {
            if (string.IsNullOrWhiteSpace(configPath) || !Path.IsPathFullyQualified(configPath))
                throw new ArgumentException("配置文件必须是绝对路径");
            configPath = Path.GetFullPath(configPath);
            if (!File.Exists(configPath))
                throw new FileNotFoundException("配置文件不存在", configPath);
        }
        StartAttempt attempt;
        lock (_lifecycleGate)
        {
            if (_startAttempt is not null)
                throw new InvalidOperationException("backend start already in progress");
            var previous = _genState;
            if (previous is { Process: { HasExited: false } alive })
                throw new InvalidOperationException(
                    "backend already running (pid " + alive.Id
                    + ")；先正常停止再启动，避免丢失第一进程引用");
            attempt = new StartAttempt();
            _startAttempt = attempt;
        }
        try
        {
        var genState = new GenState();
        var info = new ProcessStartInfo(exe)
        {
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
        };
        // 内部后端固定使用桌面协议，仅额外传递显式配置文件路径。
        info.ArgumentList.Add(DesktopArgument);
        if (recoverConfig) info.ArgumentList.Add("--recover-config");
        if (configPath is not null)
        {
            info.ArgumentList.Add("--config");
            info.ArgumentList.Add(configPath);
        }
        var process = Process.Start(info)
            ?? throw new InvalidOperationException("后端启动失败");
        genState.Process = process;
        var published = new TaskCompletionSource<bool>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        // reader 任务句柄挂到本代：进程退出后等待其排干缓冲行再评估，
        // 消除"退出先于握手行被处理"的竞态（C161-R2）。
        // Publish handles before allowing a fast child to call subscribers.
        genState.ReaderTask = Task.Run(async () =>
        {
            await published.Task.ConfigureAwait(false);
            await ReadStdoutAsync(genState).ConfigureAwait(false);
        });
        _ = Task.Run(async () =>
        {
            await published.Task.ConfigureAwait(false);
            await DrainStderrAsync(genState).ConfigureAwait(false);
        });
        bool stopRequested;
        lock (_lifecycleGate)
        {
            _process = process;
            _genState = genState;
            stopRequested = attempt.StopRequested;
            _startAttempt = null;
        }
        published.TrySetResult(true);
        // A stop received during launch belongs to this attempt, not a future
        // restart. Delivery and all IO happen after releasing admission.
        if (stopRequested) RequestStop(genState);
        attempt.Completion.TrySetResult(genState);
        }
        catch
        {
            lock (_lifecycleGate)
            {
                if (ReferenceEquals(_startAttempt, attempt)) _startAttempt = null;
            }
            attempt.Completion.TrySetResult(null);
            throw;
        }
    }

    // ---------------- 有界行读取（全部状态只写本代） ----------------
    private async Task ReadStdoutAsync(GenState gen)
    {
        var process = gen.Process!;
        var reader = process.StandardOutput;
        var buffer = new char[1024];
        var line = new StringBuilder(256);
        int lineBytes = 0;              // 按 **UTF-8 字节** 计数（非 UTF-16 字符数）
        bool overlong = false;
        bool pendingHighSurrogate = false;
        try
        {
            while (true)
            {
                int read = await reader.ReadAsync(buffer, 0, buffer.Length);
                if (read <= 0) break;                    // EOF
                for (int i = 0; i < read; i++)
                {
                    char ch = buffer[i];
                    if (ch == '\n')
                    {
                        if (overlong) NoteProtocolError(gen, "line_too_long");
                        else HandleLine(gen, line.ToString().TrimEnd('\r'));
                        line.Clear();
                        lineBytes = 0;
                        overlong = false;
                        pendingHighSurrogate = false;
                        continue;
                    }
                    if (overlong) continue;              // 超长行：丢弃其余，不收内存
                    lineBytes += Utf8Bytes(ch, ref pendingHighSurrogate);
                    if (lineBytes > MaxLineBytes)
                    {
                        overlong = true;                 // 不读完整行即判定
                        line.Clear();
                        continue;
                    }
                    line.Append(ch);
                }
            }
            // EOF 结束的超长行同样必须记录协议错误（不得静默接受）
            if (overlong) NoteProtocolError(gen, "line_too_long");
            else if (line.Length > 0) HandleLine(gen, line.ToString().TrimEnd('\r'));
        }
        catch (Exception)
        {
            MarkFaulted(gen);
        }
        finally
        {
            // 本代尾部只写本代（C161-R2）：不可能污染后续代会话。
            gen.StdoutClosed = true;
            if (!gen.StoppedSeen && process.HasExited) MarkFaulted(gen);
        }
    }

    /// <summary>单个 UTF-16 单元的 UTF-8 字节数（代理对按 4 字节计）。</summary>
    private static int Utf8Bytes(char ch, ref bool pendingHigh)
    {
        if (pendingHigh)
        {
            pendingHigh = false;
            if (char.IsLowSurrogate(ch)) return 2;       // 代理对第二半
            return 3;                                    // 落单高代理（保守）
        }
        if (char.IsHighSurrogate(ch))
        {
            pendingHigh = true;
            return 2;                                    // 先记 2，另一半补 2 → 共 4
        }
        if (ch < 0x80) return 1;
        if (ch < 0x800) return 2;
        return 3;
    }

    private async Task DrainStderrAsync(GenState gen)
    {
        var process = gen.Process!;
        var reader = process.StandardError;
        try
        {
            var buffer = new char[1024];
            var line = new StringBuilder(128);
            while (true)
            {
                int read = await reader.ReadAsync(buffer, 0, buffer.Length);
                if (read <= 0) break;
                for (int i = 0; i < read; i++)
                {
                    char ch = buffer[i];
                    if (ch == '\n')
                    {
                        NoteDiagnostic(gen, line.ToString().TrimEnd('\r'));
                        line.Clear();
                        continue;
                    }
                    if (line.Length < MaxDiagnosticLineChars) line.Append(ch);
                }
            }
            if (line.Length > 0) NoteDiagnostic(gen, line.ToString().TrimEnd('\r'));
        }
        catch (Exception)
        {
            NoteDiagnostic(gen, "stderr 读取中断");
        }
    }

    // ---------------- 协议校验（事件仅当前代对外分发） ----------------
    private void HandleLine(GenState gen, string line)
    {
        if (string.IsNullOrWhiteSpace(line)) return;
        if (!line.StartsWith('{'))
        {
            NoteDiagnostic(gen, line);                        // 非协议输出：只进诊断
            return;
        }
        JsonDocument doc;
        try { doc = JsonDocument.Parse(line); }
        catch (JsonException) { NoteProtocolError(gen, "bad_json"); return; }
        using (doc)
        {
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                NoteProtocolError(gen, "bad_frame");
                return;
            }
            if (!root.TryGetProperty("schema", out var schema)
                || schema.ValueKind != JsonValueKind.String
                || schema.GetString() != Schema)
            {
                NoteProtocolError(gen, "bad_schema");         // 缺/错 schema：状态不变
                return;
            }
            if (!root.TryGetProperty("event", out var evt)
                || evt.ValueKind != JsonValueKind.String)
            {
                NoteProtocolError(gen, "bad_frame");
                return;
            }
            string name = evt.GetString()!;
            if (!KnownEvents.Contains(name))
            {
                NoteProtocolError(gen, "unknown_event");      // 未知事件：状态不变
                return;
            }
            switch (name)
            {
                case "navigate":
                    if (TryGetLocalUrl(root, "url", out var navUrl)
                        && TryGetPage(root, out var page)
                        && IsCurrentGen(gen))
                        Navigate?.Invoke(navUrl, page);
                    break;
                case "ready":
                    if (TryGetLocalUrl(root, "origin", out var origin)
                        && IsCurrentGen(gen))
                        Ready?.Invoke(origin);
                    break;
                case "state":
                    if (root.TryGetProperty("cameras", out var cams)
                        && cams.ValueKind == JsonValueKind.Number
                        && root.TryGetProperty("models", out var models)
                        && models.ValueKind == JsonValueKind.String
                        && IsCurrentGen(gen))
                        State?.Invoke(root.Clone());
                    else
                        NoteProtocolError(gen, "bad_state_fields");
                    break;
                case "stopped":
                {
                    int? exitCode = null;
                    if (root.TryGetProperty("exit_code", out var code)
                        && code.ValueKind == JsonValueKind.Number
                        && code.TryGetInt32(out int parsed))
                        exitCode = parsed;
                    if (exitCode is null)
                    {
                        NoteProtocolError(gen, "bad_exit_code");
                        break;
                    }
                    // incomplete 必填：数组、成员为非空字符串；非法不得静默当 []
                    if (!root.TryGetProperty("incomplete", out var inc)
                        || inc.ValueKind != JsonValueKind.Array)
                    {
                        NoteProtocolError(gen, "bad_incomplete");
                        break;
                    }
                    var incomplete = new List<string>();
                    bool bad = false;
                    foreach (var item in inc.EnumerateArray())
                    {
                        if (item.ValueKind != JsonValueKind.String
                            || string.IsNullOrWhiteSpace(item.GetString()))
                        {
                            bad = true;
                            break;
                        }
                        incomplete.Add(item.GetString()!);
                    }
                    if (bad)
                    {
                        NoteProtocolError(gen, "bad_incomplete");   // 结构错误不确认停止
                        break;
                    }
                    gen.StoppedSeen = true;
                    gen.HandshakeExitCode = exitCode;
                    gen.HandshakeIncomplete = incomplete;
                    if (IsCurrentGen(gen))
                        Stopped?.Invoke(exitCode.Value, incomplete);
                    break;
                }
                case "failed":
                    NoteProtocolError(gen, root.TryGetProperty("code", out var fc)
                        && fc.ValueKind == JsonValueKind.String
                        ? "backend_failed" : "bad_failure_code");
                    break;
                // starting / stopping：状态不变（只表示阶段）
            }
        }
    }

    private static bool TryGetPage(JsonElement root, out string page)
    {
        page = "";
        if (!root.TryGetProperty("page", out var p)
            || p.ValueKind != JsonValueKind.String) return false;
        page = p.GetString()!;
        return page is "setup" or "workbench";
    }

    private static bool TryGetLocalUrl(JsonElement root, string name,
                                       out string url)
    {
        url = "";
        if (!root.TryGetProperty(name, out var value)
            || value.ValueKind != JsonValueKind.String) return false;
        string raw = value.GetString()!;
        if (!Uri.TryCreate(raw, UriKind.Absolute, out var uri)) return false;
        if (uri.Scheme != "http") return false;
        if (uri.Host != "127.0.0.1" && uri.Host != "localhost") return false;
        if (uri.Port <= 0) return false;
        if (!string.IsNullOrEmpty(uri.UserInfo)) return false;
        url = uri.GetLeftPart(UriPartial.Path).TrimEnd('/');
        return true;
    }

    // ---------------- 诊断与故障 ----------------
    private void NoteProtocolError(GenState gen, string code)
    {
        gen.ProtocolErrorCount++;                 // 按代计数：旧代坏帧不进当前代
        NoteDiagnostic(gen, "protocol:" + code);
    }

    private void NoteDiagnostic(GenState gen, string text)
    {
        string safe = Redact(text);
        lock (gen.Diagnostics)
        {
            if (gen.Diagnostics.Count >= MaxDiagnosticLines) gen.Diagnostics.Dequeue();
            gen.Diagnostics.Enqueue(safe.Length > MaxDiagnosticLineChars
                ? safe[..MaxDiagnosticLineChars] : safe);
        }
    }

    private static string Redact(string text)
    {
        // 不把凭据/URL 全文回显：去掉 user:pass@ 与 query
        string s = text;
        int at = s.IndexOf('@');
        if (at > 0 && s.Contains("://"))
        {
            int scheme = s.IndexOf("://", StringComparison.Ordinal) + 3;
            if (at > scheme) s = s[..scheme] + "***@" + s[(at + 1)..];
        }
        int q = s.IndexOf('?');
        if (q >= 0) s = s[..q] + "?…";
        return s;
    }

    private void MarkFaulted(GenState gen)
    {
        if (gen.Faulted) return;
        gen.Faulted = true;
        if (IsCurrentGen(gen)) Faulted?.Invoke();
    }

    // ---------------- 停止（唯一实现；无强杀；只作用当前代） ----------------
    /// <summary>发送一次 stop（幂等）；不提供 kill/terminate。</summary>
    public bool RequestStop()
    {
        GenState? gen;
        lock (_lifecycleGate)
        {
            if (_startAttempt is { } attempt)
            {
                attempt.StopRequested = true;
                return true; // accepted for this launch; not stopped confirmation
            }
            gen = _genState;
        }
        return gen is not null && RequestStop(gen);
    }

    private bool RequestStop(GenState gen)
    {
        var process = gen.Process;                  // 本代进程快照
        if (process is null) return false;
        lock (gen.StopGate)
        {
        if (gen.StoppedSeen || process.HasExited) return true;
        if (gen.StopCommandSent) return true;               // 重入保护
        try
        {
            process.StandardInput.WriteLine(
                "{\"schema\":\"scam.desktop/v1\",\"command\":\"stop\"}");
            process.StandardInput.Flush();
            gen.StopCommandSent = true;
            return true;
        }
        catch (Exception)
        {
            NoteDiagnostic(gen, "stop_write_failed");
            return false;
        }
        }
    }

    /// <summary>
    /// 正常停止合同：**收到 stopped 握手 且 子进程实际退出** 才算 NormalStopped。
    /// 其余情况分别返回 StoppedButAlive / ExitedWithoutHandshake / Timeout。
    /// 本代快照（进程+状态）在进入时捕获——重启不会让旧等待误判新代。
    /// </summary>
    public async Task<StopOutcome> RequestStopAndWaitAsync(TimeSpan timeout)
    {
        var deadline = DateTime.UtcNow + timeout;
        GenState? gen;
        StartAttempt? attempt;
        lock (_lifecycleGate)
        {
            attempt = _startAttempt;
            if (attempt is not null) attempt.StopRequested = true;
            gen = _genState;
        }
        if (attempt is not null)
        {
            var remaining = deadline - DateTime.UtcNow;
            if (remaining <= TimeSpan.Zero) return StopOutcome.Timeout;
            if (await Task.WhenAny(attempt.Completion.Task, Task.Delay(remaining))
                    .ConfigureAwait(false) != attempt.Completion.Task)
                return StopOutcome.Timeout;
            gen = await attempt.Completion.Task.ConfigureAwait(false);
        }
        if (gen is null) return StopOutcome.NotRunning;
        var process = gen.Process;
        if (process is null) return StopOutcome.NotRunning;
        bool sent = RequestStop(gen);
        var drained = false;
        while (DateTime.UtcNow < deadline)
        {
            // 进程退出后先等本代 reader 排干缓冲行（有界一次），再评估
            // ——否则握手行还在管道里就被误判 ExitedWithoutHandshake。
            if (!drained && process.HasExited)
            {
                await DrainReaderWithinDeadline(gen, deadline).ConfigureAwait(false);
                drained = true;
            }
            var settled = Evaluate(gen, process);
            if (settled is { } value) return value;
            await Task.Delay(50).ConfigureAwait(false);
        }
        if (!drained && process.HasExited)
        {
            await DrainReaderWithinDeadline(gen, deadline).ConfigureAwait(false);
        }
        var final = Evaluate(gen, process);
        if (final is { } done) return done;
        if (!sent) return StopOutcome.StopRequestFailed;   // 命令没发出且仍存活
        return gen.StoppedSeen ? StopOutcome.StoppedButAlive : StopOutcome.Timeout;
    }

    private static async Task DrainReaderWithinDeadline(GenState gen, DateTime deadline)
    {
        var remaining = deadline - DateTime.UtcNow;
        if (gen.ReaderTask is null || remaining <= TimeSpan.Zero) return;
        var bounded = remaining < TimeSpan.FromMilliseconds(1200)
            ? remaining : TimeSpan.FromMilliseconds(1200);
        // Async wait: UI subscribers may require the dispatcher to make progress.
        await Task.WhenAny(gen.ReaderTask, Task.Delay(bounded)).ConfigureAwait(false);
    }

    /// <summary>可判定则返回结果；进程仍在运行返回 null。</summary>
    private static StopOutcome? Evaluate(GenState gen, Process process)
    {
        bool exited;
        try { exited = process.HasExited; }
        catch (InvalidOperationException) { exited = true; }
        if (!exited) return null;
        if (!gen.StoppedSeen) return StopOutcome.ExitedWithoutHandshake;
        if (gen.HandshakeIncomplete.Count > 0)
            return StopOutcome.IncompleteFinalization;
        if (gen.HandshakeExitCode is not 0) return StopOutcome.HandshakeExitFailure;
        int? code = null;
        try { code = process is { HasExited: true } p ? p.ExitCode : null; }
        catch (InvalidOperationException) { }
        if (code is int actual && actual != 0) return StopOutcome.AbnormalExitCode;
        return StopOutcome.NormalStopped;
    }

    /// <summary>等待进程退出（仅观察，不干预）。</summary>
    public bool WaitForExit(TimeSpan timeout)
    {
        var process = _process;
        if (process is null) return true;
        try { return process.WaitForExit((int)timeout.TotalMilliseconds); }
        catch (Exception) { return HasExited; }
    }
}

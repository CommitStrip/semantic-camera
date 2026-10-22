; semantic-camera.iss — Inno Setup 安装器骨架（C152-Z 轻量包）
;
; 构建（需 Inno Setup 6 编译器，本批不安装/不验证编译器）：
;   iscc /DAppVersion=<version> /DAppSource=<publish_dir> packaging\windows\semantic-camera.iss
;
; 版本唯一源：pyproject.toml 项目 version；AppVersion 编译时显式传入。
; AppSource：桌面壳 publish 输出目录（须含 语义摄像头.exe 和
;   backend\semantic-camera-backend.exe），由宿主工程 publish 产出。
; AppId 固定：升级沿用同一 GUID，不每批重新生成。

#define AppExeName "语义摄像头.exe"
#define BackendExeName "semantic-camera-backend.exe"
#define BackendSubDir "backend"
#define AppPublisher "SemanticCamera"

; ---- Production identity is immutable; TestMode is compile-only isolation ----
#define AppIdDefault "{{BBA9D479-0BB1-4AF0-961A-CE9D645639B9}"
#define AppIdTest "{{C292D0D0-7C37-4C6B-8AF0-1B2C3D4E5F60}"
#define AppNameDefault "语义摄像头"
#define AppNameTest "SemanticCamera C292 Test"
#define UserDataDirNameDefault "semantic-camera"
#define UserDataDirNameTest "semantic-camera-c292-test"
#define DefaultDirNameDefault "{localappdata}\Programs\SemanticCamera"
#define DefaultDirNameTest "{localappdata}\Programs\SemanticCamera-C292-Test"
#define OutputBaseFilenameDefault "SemanticCamera-Setup"
#define OutputBaseFilenameTest "SemanticCamera-Test-Setup"
#define TestModeActive 0
#ifdef TestMode
  #if TestMode != "1"
    #error TestMode requires the fixed isolated identity
  #endif
  #define TestModeActive 1
  #ifdef AppId
    #error TestMode requires the fixed isolated identity
  #endif
  #ifdef AppName
    #error TestMode requires the fixed isolated identity
  #endif
  #ifdef DefaultDirName
    #error TestMode requires the fixed isolated identity
  #endif
#else
  #ifdef AppId
    #error normal compile must keep the production identity
  #endif
  #ifdef AppName
    #error normal compile must keep the production identity
  #endif
  #ifdef DefaultDirName
    #error normal compile must keep the production identity
  #endif
#endif
#if TestModeActive == 1
  #define SelectedAppIdEscaped AppIdTest
  #define SelectedAppName AppNameTest
  #define AppName AppNameTest
  #define UserDataDirName UserDataDirNameTest
  #define SelectedDefaultDirName DefaultDirNameTest
  #define SelectedOutputBaseFilename OutputBaseFilenameTest
#else
  #define SelectedAppIdEscaped AppIdDefault
  #define SelectedAppName AppNameDefault
  #define AppName AppNameDefault
  #define UserDataDirName UserDataDirNameDefault
  #define SelectedDefaultDirName DefaultDirNameDefault
  #define SelectedOutputBaseFilename OutputBaseFilenameDefault
#endif

; ---- 版本（编译时显式传入，不导入运行时读取） ----
#ifndef AppVersion
  #error AppVersion must be passed via /DAppVersion=<version> (source: pyproject.toml)
#endif

; ---- 应用目录（publish 输出，须含必需桌面文件） ----
#ifndef AppSource
  #error AppSource must be passed via /DAppSource=<publish_dir>
#endif

; ---- 编译前置检查（不满足即编译失败，不产出"看似可用"的安装器） ----
#if FileExists(AppSource + "\" + AppExeName) == 0
  #error "必需桌面文件不存在: " + AppSource + "\" + AppExeName
#endif
#if FileExists(AppSource + "\" + BackendSubDir + "\" + BackendExeName) == 0
  #error "必需后端文件不存在: " + AppSource + "\" + BackendSubDir + "\" + BackendExeName
#endif
; ---- 版本格式校验：三段数字 MAJOR.MINOR.PATCH（与项目版本 0.1.0 对应） ----
; 仅使用 ISPP 库函数（Pos/Copy/Length）与参数化宏；宏展开为单层（无递归）。
; 数字白名单：段内字符必须属于 0-9——同时拒绝段内空白、路径字符、字母
; 等一切非数字内容；每段显式限 1-4 位（避免无界展开）。
; 本环境无法执行 ISPP 编译验证 → 静态检查通过、编译未验证。
#define ScVerDigitAt(S, I) ((I > Len(S)) || (Pos(Copy(S, I, 1), "0123456789") > 0))
#define ScVerIsDigits(S) ((Len(S) >= 1) && (Len(S) <= 4) && (ScVerDigitAt(S, 1)) && (ScVerDigitAt(S, 2)) && (ScVerDigitAt(S, 3)) && (ScVerDigitAt(S, 4)))

#if AppVersion == ""
  #error "AppVersion 无效：不能为空（须为 MAJOR.MINOR.PATCH 三段数字）"
#endif
#if Pos("\", AppVersion) > 0
  #error "AppVersion 无效：不能包含路径字符"
#endif
#if Pos("/", AppVersion) > 0
  #error "AppVersion 无效：不能包含路径字符"
#endif
#define ScVerDot1 Pos(".", AppVersion)
#if ScVerDot1 == 0
  #error "AppVersion 无效：须为 MAJOR.MINOR.PATCH 三段数字格式"
#endif
#if ScVerDot1 == 1
  #error "AppVersion 无效：第一段不能为空"
#endif
#define ScVerPart1 Copy(AppVersion, 1, ScVerDot1 - 1)
#define ScVerRestA Copy(AppVersion, ScVerDot1 + 1, 999)
#define ScVerDot2 Pos(".", ScVerRestA)
#if ScVerDot2 == 0
  #error "AppVersion 无效：缺少第二段或第二个分隔符（须为三段）"
#endif
#if ScVerDot2 == 1
  #error "AppVersion 无效：第二段不能为空"
#endif
#define ScVerPart2 Copy(ScVerRestA, 1, ScVerDot2 - 1)
#define ScVerPart3 Copy(ScVerRestA, ScVerDot2 + 1, 999)
#if Pos(".", ScVerPart3) > 0
  #error "AppVersion 无效：不得超过三段（额外分段）"
#endif
#if (ScVerIsDigits(ScVerPart1)) == 0
  #error "AppVersion 无效：第一段须为 1-4 位数字"
#endif
#if (ScVerIsDigits(ScVerPart2)) == 0
  #error "AppVersion 无效：第二段须为 1-4 位数字"
#endif
#if (ScVerIsDigits(ScVerPart3)) == 0
  #error "AppVersion 无效：第三段须为 1-4 位数字"
#endif

[Setup]
AppId={#SelectedAppIdEscaped}
AppName={#SelectedAppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
; 当前用户安装：不写 Program Files，不请求 UAC 提升
PrivilegesRequired=lowest
DefaultDirName={#SelectedDefaultDirName}
; 卸载登记：名称/版本/图标由上述字段自动写入 Windows"已安装的应用"
UninstallDisplayName={#AppName}
UninstallDisplayIcon={app}\{#AppExeName}
; 不开机自启、不装 Windows 服务、不开放远程访问
; （无 [Run] {autostart}、无服务条目、无防火墙命令）
; 中文安装界面
ShowLanguageDialog=no
OutputDir={#AppSource}\..
OutputBaseFilename={#SelectedOutputBaseFilename}-{#AppVersion}
; 不创建桌面快捷方式（由 [Tasks] 可选项控制）
DisableDirPage=yes
DisableProgramGroupPage=yes
; 用户数据目录 {localappdata}\semantic-camera 不在安装/卸载范围内
; （无 [InstallDelete] / [UninstallDelete] 条目涉及用户数据）

[Languages]
Name: "chinesesimplified"; MessagesFile: "compiler:Languages\ChineseSimplified.isl"

[Tasks]
; 桌面快捷方式可选（默认不勾选）
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; \
  GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
; 发布候选目录的全部文件→应用目录。C161 双保险：即使历史 profile 曾落在
; publish 目录（旧版 WebView2 默认落点或旧 InstallDir\webview2），安装器
; 也不携带——与 csproj 的 StripWebView2ProfileFromPublish 目标互为冗余。
Source: "{#AppSource}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs; \
  Excludes: "SemanticCamera.Desktop.exe.WebView2,webview2,.mimosa"

[Icons]
; 开始菜单"语义摄像头"→用户桌面 EXE（非浏览器/BAT）
Name: "{autoprograms}\{#AppName}"; Filename: "{app}\{#AppExeName}"
; 卸载入口（开始菜单）
Name: "{autoprograms}\{#AppName}\{cm:UninstallProgram,{#AppName}}"; \
  Filename: "{uninstallexe}"
; 桌面快捷方式（Tasks: desktopicon 绑定；用户勾选才创建）
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExeName}"; \
  Tasks: desktopicon

#if TestModeActive == 0
[Run]
; 安装完成后的"启动应用"由用户选择；本批不真正运行它
Filename: "{app}\{#AppExeName}"; Description: "{cm:LaunchProgram,{#AppName}}"; \
  Flags: nowait postinstall skipifsilent
#endif

[UninstallRun]
; 无：运行中卸载依赖 Codex 正常停止协议（INTERFACE-C152.md stdio JSONL
; stop 握手），协议未完成前列为阻塞，不强杀进程冒充正常退出。

; [UninstallDelete] 无条目：默认仅删除安装器管理的应用文件与快捷方式
; （Inno 自身行为），不使用递归通配删除用户数据；彻底清理用户数据
; 不在本包实现。

[Code]
// ---- C161 运行时检测（实装；绝不自动下载/静默安装） ----
// 检测① .NET 8 Desktop Runtime（Microsoft.WindowsDesktop.App 8.*）：
//   目录证据 {ProgramW6432}\dotnet\shared\Microsoft.WindowsDesktop.App\8.*
//   （机器级目录，当前用户可读；不执行 dotnet 子进程）。
// 检测② WebView2 Evergreen Runtime：EdgeUpdate Clients 固定 GUID 的 pv 值
//   （HKLM/WOW6432Node 与 HKCU 双查，任一非空即视为已装）。
// 缺失时：可理解提示 + 询问是否打开官方下载页——只有用户明确同意才打开
//   浏览器；安装器自身不下载、不静默安装（用户未同意不得下载）。
// 缺运行时仍允许继续安装：壳在运行时会显示恢复指引（不冒充完整体验）。

const
  DotNetDesktopSharedDir = 'dotnet\shared\Microsoft.WindowsDesktop.App';
  WebView2Guid = '{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}';
  Net8DownloadUrl = 'https://dotnet.microsoft.com/download/dotnet/8.0';
  WebView2DownloadUrl = 'https://developer.microsoft.com/microsoft-edge/webview2/';

function DirHasChildStartingWith(const dir, prefix: String): Boolean;
var
  find: TFindRec;
  full: String;
begin
  Result := False;
  full := AddBackslash(dir);
  if not DirExists(dir) then Exit;
  if FindFirst(full + '*', find) then
  try
    repeat
      if (find.Name <> '.') and (find.Name <> '..') and
         (find.Attributes and FILE_ATTRIBUTE_DIRECTORY <> 0) and
         (Copy(find.Name, 1, Length(prefix)) = prefix) then
      begin
        Result := True;
        Exit;
      end;
    until not FindNext(find);
  finally
    FindClose(find);
  end;
end;

function DotNetDesktopRuntime8Present(): Boolean;
var
  root: String;
begin
  root := AddBackslash(GetEnv('ProgramW6432')) + DotNetDesktopSharedDir;
  Result := DirHasChildStartingWith(root, '8.');
end;

function WebView2PvUsableAt(const root: Integer; const key: String): Boolean;
var
  pv: String;
begin
  Result := False;
  // C161-R2：逐处验证——查询成功不足为凭；pv 空/'0.0.0.0'（已下载未注册/
  // 被禁用）不可用。HKLM 与 HKCU 各自验证后 OR，避免空机器项短路遮蔽
  // 有效的用户级安装。
  if RegQueryStringValue(root, key, 'pv', pv) then
    Result := (pv <> '') and (pv <> '0.0.0.0');
end;

function WebView2RuntimePresent(): Boolean;
begin
  Result :=
    WebView2PvUsableAt(HKLM,
      'SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\' + WebView2Guid)
    or WebView2PvUsableAt(HKCU,
      'SOFTWARE\Microsoft\EdgeUpdate\Clients\' + WebView2Guid);
end;

function OfferOfficialDownload(const title, url: String): Boolean;
var
  agreed: Boolean;
  ErrorCode: Integer;
begin
  Result := False;
  // 未同意不下载：只询问是否打开官方页面；用户拒绝则不打开、不下载。
  agreed := (MsgBox(title + #13#10 + #13#10 +
      '是否现在打开官方下载页？（安装器不会自动下载或安装）',
      mbConfirmation, MB_YESNO) = IDYES);
  if not agreed then Exit;
  // ShellExec 末参为 var Integer（官方文档 topic_isxfunc_shellexec），
  // 需要独立 ErrorCode 接收错误码，不得复用函数返回值。
  ErrorCode := 0;
  if ShellExec('open', url, '', '', SW_SHOWNORMAL, ewNoWait, ErrorCode) then
    Result := True
  else
    MsgBox('浏览器打开失败（错误码 ' + IntToStr(ErrorCode) + '）。' + #13#10
        + '请手动访问：' + url, mbError, MB_OK);
end;

function InitializeSetup(): Boolean;
var
  missing, offer: String;
begin
  Result := True;
  missing := '';
  if not DotNetDesktopRuntime8Present() then
    missing := missing + '· .NET 8 Desktop Runtime（Microsoft.WindowsDesktop.App 8.x）'
      + #13#10;
  if not WebView2RuntimePresent() then
    missing := missing + '· Microsoft Edge WebView2 Evergreen Runtime' + #13#10;
  if missing = '' then Exit;
  offer := missing + #13#10
    + '缺少上述运行时，应用可能无法启动或无法显示界面。' + #13#10
    + '你可以先继续安装（应用启动时会再次给出指引）。';
  MsgBox(offer, mbInformation, MB_OK);
  if Pos('.NET 8', missing) > 0 then
    OfferOfficialDownload('获取 .NET 8 Desktop Runtime（官方页面）',
      Net8DownloadUrl);
  if Pos('WebView2', missing) > 0 then
    OfferOfficialDownload('获取 WebView2 Runtime（官方页面）',
      WebView2DownloadUrl);
  Result := True;
end;

// ---- C161 礼貌卸载（不强杀） ----
// 检测应用窗口存在 → 请求用户在应用内选择正常退出（WM_CLOSE 走应用
// 自身的关闭合同：停止握手+进程退出），轮询等待；仍运行则取消卸载，
// 绝不 taskkill/TerminateProcess。用户数据 {localappdata}\semantic-camera
// 与 WebView2 profile 一律保留（无 UninstallDelete 条目涉及它们）。

const
  WM_CLOSE = $0010;
  TH32CS_SNAPPROCESS = 2;

// C161-R2：类名传 Longint 0 = NULL 语义（空字符串'' 是"匹配空类名"，
// 不是 NULL），按窗口标题可靠查任意类窗口。
function FindWindowW(lpClassName: Longint; lpWindowName: String): Longint;
  external 'FindWindowW@user32.dll stdcall';
function PostMessageW(hWnd: Longint; Msg: Longint; wParam: Longint;
  lParam: Longint): Boolean;
  external 'PostMessageW@user32.dll stdcall';
procedure KernelSleep(milliseconds: Longint);
  external 'Sleep@kernel32.dll stdcall';

// ---- 进程级存在性检查（Toolhelp32；窗口消失≠进程退出） ----
// 卸载闸以**进程**为准：托盘隐藏（无窗口）/用户取消/仅后端存活等情形，
// 只看窗口会错误放行。进程仍在 = 未确认停止 = 阻止卸载，绝不强杀。
type
  TProcessEntryW = record
    dwSize: Longword;
    cntUsage: Longword;
    th32ProcessID: Longword;
    th32DefaultHeapID: Longword;
    th32ModuleID: Longword;
    cntThreads: Longword;
    th32ParentProcessID: Longword;
    pcPriClassBase: Longint;
    dwFlags: Longword;
    szExeFile: array[0..259] of WideChar;
  end;

function CreateToolhelp32Snapshot(flags: Longword;
  processId: Longword): Longword;
  external 'CreateToolhelp32Snapshot@kernel32.dll stdcall';
function Process32FirstW(snapshot: Longword;
  var entry: TProcessEntryW): Boolean;
  external 'Process32FirstW@kernel32.dll stdcall';
function Process32NextW(snapshot: Longword;
  var entry: TProcessEntryW): Boolean;
  external 'Process32NextW@kernel32.dll stdcall';
procedure KernelCloseHandle(handle: Longint);
  external 'CloseHandle@kernel32.dll stdcall';

function ProcessRunningByName(const exeName: String): Boolean;
var
  snapshot: Longword;
  entry: TProcessEntryW;
  i: Integer;
  processName: String;
begin
  Result := True;   // 无法枚举时保守视为"仍在运行"（宁可阻止卸载不放行）
  snapshot := CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snapshot = 0) or (snapshot = $FFFFFFFF) then Exit;
  try
    entry.dwSize := SizeOf(entry);
    if Process32FirstW(snapshot, entry) then
    begin
      repeat
        processName := '';
        for i := 0 to 259 do
        begin
          if entry.szExeFile[i] = #0 then
            break;
          processName := processName + entry.szExeFile[i];
        end;
        if CompareText(processName, exeName) = 0 then
        begin
          Result := True;
          Exit;
        end;
      until not Process32NextW(snapshot, entry);
      Result := False;   // 枚举完成且未命中：确实未运行
    end;
  finally
    KernelCloseHandle(snapshot);
  end;
end;

function AppProcessesRunning(): Boolean;
begin
  Result := ProcessRunningByName('{#BackendExeName}')
            or ProcessRunningByName('{#AppExeName}');
end;

function InitializeUninstall(): Boolean;
var
  hwnd, waited: Longint;
  stillRunning: Boolean;
begin
  Result := True;
  // 进程级闸：窗口消失（托盘隐藏/已取消）不代表后端退出。
  if not AppProcessesRunning() then Exit;   // 双进程均已退出：直接卸载
  if MsgBox('检测到{#AppName}可能正在运行（后台值守进程存在）。' + #13#10 +
      '点击「是」将请求应用正常退出：应用内会出现确认对话框，'
      + '请在其中选择「是（停止值守并退出）」。' + #13#10 +
      '点击「否」取消卸载（不会强制结束进程）。',
      mbConfirmation, MB_YESNO) <> IDYES then
  begin
    Result := False;       // 用户选择不退出：取消卸载，不强杀
    Exit;
  end;
  stillRunning := True;
  hwnd := FindWindowW(0, '{#AppName}');   // 类名=NULL：按标题可靠查窗
  if hwnd <> 0 then
  begin
    PostMessageW(hwnd, WM_CLOSE, 0, 0);
    waited := 0;
    while waited < 45000 do
    begin
      if not AppProcessesRunning() then
      begin
        stillRunning := False;
        break;
      end;
      KernelSleep(500);
      waited := waited + 500;
    end;
  end
  else
  begin
    // 窗口不可见（托盘隐藏等）：无法礼貌请求——给明确指引并取消卸载。
    MsgBox('应用窗口未找到但后台进程仍在运行。请通过托盘图标菜单'
      + '「停止值守并退出」正常退出后重试卸载。', mbError, MB_OK);
    Result := False;
    Exit;
  end;
  if stillRunning then
  begin
    MsgBox('后端/应用仍在运行（未确认停止，未强制结束）。'
      + '请正常退出{#AppName}后重试卸载。', mbError, MB_OK);
    Result := False;
  end;
end;

// ---- 备用：卸载时保留用户数据（Inno 默认不删 app 外文件；
//      {localappdata}\semantic-camera 不在 {app} 内，天然保留，
//      含其中的 webview2 profile——重装/升级不丢配置与缓存） ----
// 彻底清理用户数据不在本包实现；如未来需要，须经主协调批准并
// 显式列出路径（不使用递归通配删除）。

#Requires -Version 5.1
# Win11 R3 two-phase native acceptance operator wrapper.
# Compatible with Windows PowerShell 5.1 and PowerShell 7.
#
# SOURCE IS DELIBERATELY PURE ASCII, NO UTF-8 BOM:
#   Windows PowerShell 5.1 decodes a BOM-less script with the machine ANSI code page
#   (cp936 / cp932 / cp1252 / cp437 ...). Non-ASCII source text would therefore be
#   mangled, and a swallowed quote byte can break parsing outright. Keeping the whole
#   file ASCII makes code and messages identical on every host, in both editions of
#   PowerShell. Keep it ASCII, or re-add a UTF-8 BOM in the same change.
#   Chinese operator guidance lives in deploy/README.md.
#
# This wrapper only wraps the existing production command
# `python -m scam.win11_r3_acceptance` and its two explicit phases:
#   Before - collect pre-restart facts, then exclusively write the state file (no clobber).
#   After  - after a HUMAN restart of the Win11 app, re-check the facts and atomically
#            publish the final report (no clobber).
#
# Usage:
#   powershell -NoProfile -ExecutionPolicy Bypass -File deploy\run-win11-r3-acceptance.ps1 -Phase Before
#   (restart the Win11 workstation app by hand, wait until the workbench is online again)
#   powershell -NoProfile -ExecutionPolicy Bypass -File deploy\run-win11-r3-acceptance.ps1 -Phase After
#
# Parameters:
#   -Phase         Before | After. Required. Case-insensitive.
#   -BaseUrl       Before only. Default http://127.0.0.1:8600.
#   -EvidenceRoot  Evidence directory. Default %LOCALAPPDATA%\semantic-camera\acceptance.
#   -StateFile     State file. Default <EvidenceRoot>\win11-r3-state.json
#                  (Before writes it, After consumes exactly that file).
#   -ReportFile    After only. Report file. Default <EvidenceRoot>\win11-r3-report.json.
#   -PythonCommand Python interpreter. Default <repo>\.venv\Scripts\python.exe, else python on PATH.
#
# Boundaries of this wrapper (never more than the driver does):
#   - never starts, stops, restarts, kills or probes any process, never waits for the
#     workbench; the restart is a manual human step;
#   - never performs an HTTP request itself (only the Python driver reads the workbench,
#     over loopback);
#   - only ever creates the evidence directory; never creates or rewrites configuration
#     (cameras.json), environment profiles or zones;
#   - never reads or echoes configuration, RTSP source, credential, model path, frame
#     bytes or environment/zone text;
#   - invokes the module with an argument array (& $python @argumentList); it never
#     assembles a command string out of inputs and never evaluates one;
#   - refuses to overwrite an existing artifact before invoking Python, while the driver's
#     own exclusive no-clobber write stays the final boundary for concurrent races.
#
# Exit code contract:
#   0 / 1 / 2 - exit code of the Python driver, passed through unchanged
#               (0 pass / 1 gate not met / 2 precondition failure);
#   3         - refused by this wrapper before Python was invoked (invalid phase,
#               unsafe workbench URL, missing LOCALAPPDATA, artifact already exists,
#               interpreter unavailable, internal error).
#   3 never collides with 0/1/2, so "exit code is 0/1/2" proves the driver really ran.
#
# Evidence level: this wrapper only produces R3 native-restart CANDIDATE evidence.
# Real RTSP, real model quality, alert latency, clean installation and soak remain
# unverified and must be measured on the target host.

param(
    [string] $Phase,
    [string] $BaseUrl,
    [string] $EvidenceRoot,
    [string] $StateFile,
    [string] $ReportFile,
    [string] $PythonCommand
)

$ErrorActionPreference = 'Stop'

$script:R3RefusalExitCode = 3
$script:R3DefaultBaseUrl = 'http://127.0.0.1:8600'
$script:R3StateFileName = 'win11-r3-state.json'
$script:R3ReportFileName = 'win11-r3-report.json'
$script:R3ScriptPath = $PSCommandPath

$script:R3LocalAppDataRefusalMessage = 'LOCALAPPDATA is not set: the default evidence root is %LOCALAPPDATA%\semantic-camera\acceptance. Run this wrapper from a logged-in interactive user session (not a system account or a scheduled task), or pass -EvidenceRoot <dir> explicitly.'

$script:R3UrlRefusalMessage = 'Workbench URL must be http:// plus a loopback host (127.0.0.1, localhost, ::1) with an explicit port (1..65535), and must not carry user info, path, query or fragment. Non-loopback, private and reserved addresses are refused. Pass it as -BaseUrl, for example -BaseUrl http://127.0.0.1:8600 .'

$script:R3BaseUrlNotApplicableMessage = 'The After phase takes the workbench address from the state file written by Before and does not accept -BaseUrl. Re-run Before if you need to trust a different workbench.'

$script:R3BoundaryNotice = '[boundary] Boundary: R3 native-restart candidate evidence only. Real RTSP, real model quality, alert latency, clean installation and soak remain unverified.'

function Write-R3BoundaryNotice {
    Write-Host $script:R3BoundaryNotice
}

function Write-R3NextStep {
    # Printed only after a successful Before (exit code 0). The restart is manual by design.
    $scriptPath = $script:R3ScriptPath
    if ([string]::IsNullOrEmpty($scriptPath)) {
        $scriptPath = 'deploy\run-win11-r3-acceptance.ps1'
    }
    Write-Host '[next-step] restart the Win11 workstation app BY HAND now (this wrapper never restarts and never probes processes), wait until the runtime log says the workbench is online again, then run the After phase:'
    Write-Host ('            powershell -NoProfile -ExecutionPolicy Bypass -File "{0}" -Phase After' -f $scriptPath)
    Write-Host '[next-step] Before only proves the pre-restart facts; whether they still hold after the restart is decided by After.'
}

function Stop-R3Request {
    # Single refusal exit: every input rejected before Python is invoked ends here (exit code 3).
    param(
        [string] $Code,
        [string] $Message
    )
    Write-Host ''
    Write-Host ('[refuse] {0}' -f $Code) -ForegroundColor Red
    Write-Host ('        {0}' -f $Message)
    Write-R3BoundaryNotice
    exit $script:R3RefusalExitCode
}

function New-R3ArgumentList {
    # Pure function: the returned array depends on the parameters only (no script scope),
    # so tests can parse this definition and invoke it in isolation.
    param(
        [string] $ModuleName = 'scam.win11_r3_acceptance',
        [string] $Phase,
        [string] $StatePath,
        [string] $ReportPath,
        [string] $BaseUrl
    )

    $arguments = @('-m', $ModuleName, $Phase, '--state', $StatePath)
    if ($Phase -eq 'after') {
        $arguments += @('--report', $ReportPath)
    } else {
        $arguments += @('--base-url', $BaseUrl)
    }
    return $arguments
}

function Get-R3DefaultEvidenceRoot {
    # Pure function: the default evidence root depends on LOCALAPPDATA only.
    # Returns $null when it is absent, so the caller can emit the fixed refusal message.
    param(
        [string] $LocalAppData
    )

    if ([string]::IsNullOrWhiteSpace($LocalAppData)) {
        return $null
    }
    return (Join-Path (Join-Path $LocalAppData.Trim() 'semantic-camera') 'acceptance')
}

function ConvertTo-R3LoopbackHostText {
    # Pure function: canonical loopback host text ('127.0.0.1', 'localhost', '::1') or $null.
    # Windows PowerShell 5.1 keeps the IPv6 brackets in Uri.Host ('[::1]') while PowerShell 7
    # returns the compressed form without brackets ('::1'), and an IPv6 literal can also arrive
    # fully expanded ('0:0:0:0:0:0:0:1'). Normalize exactly one surrounding bracket pair and
    # canonicalize the IPv6 loopback literal to '::1', so every spelling that really denotes
    # loopback reaches the same allowlist entry and the same rebuilt address. Everything else
    # returns $null and is refused by the caller - in particular '::2', an IPv4-mapped literal
    # ('::ffff:127.0.0.1'), a zone id, a doubly bracketed text ('[[::1]]') and a bracketed
    # non-literal ('[localhost]').
    # No IP or network API is used: the group text is checked itself, so an unrecognized
    # spelling fails closed instead of being upgraded into loopback.
    param(
        [string] $HostText
    )

    if ([string]::IsNullOrWhiteSpace($HostText)) {
        return $null
    }
    $text = $HostText.Trim()
    if ($text -eq '127.0.0.1') {
        return '127.0.0.1'
    }
    if ($text -eq 'localhost') {
        return 'localhost'
    }
    if ($text.Length -ge 2 -and $text.StartsWith('[') -and $text.EndsWith(']')) {
        $text = $text.Substring(1, $text.Length - 2)
    }
    if ($text.Contains(':')) {
        # All-zero groups followed by a final 1 is exactly the IPv6 loopback literal; any
        # other group content is refused instead of comparing undecoded host text.
        $groups = $text.Split(':')
        if ($groups.Count -ge 2) {
            for ($index = 0; $index -lt $groups.Count; $index++) {
                $group = $groups[$index].TrimStart('0')
                if ($index -eq $groups.Count - 1) {
                    if ($group -ne '1') { return $null }
                } elseif ($group -ne '') {
                    return $null
                }
            }
            return '::1'
        }
    }
    return $null
}

function ConvertTo-R3LoopbackTarget {
    # Accepts http + loopback host + explicit port only.
    # Returns $null for everything else (the caller emits the fixed refusal message).
    param(
        [string] $Url
    )

    $allowedHosts = @('127.0.0.1', 'localhost', '::1')

    if ([string]::IsNullOrWhiteSpace($Url)) {
        return $null
    }
    $candidate = $Url.Trim()
    $uri = $null
    try {
        $uri = New-Object -TypeName System.Uri -ArgumentList @($candidate, [System.UriKind]::Absolute)
    } catch {
        return $null
    }
    if ($null -eq $uri) { return $null }
    if (-not $uri.IsAbsoluteUri) { return $null }
    if ($uri.Scheme -ne 'http') { return $null }
    if (-not [string]::IsNullOrEmpty($uri.UserInfo)) { return $null }

    # Windows PowerShell 5.1 keeps the IPv6 brackets in Uri.Host ('[::1]') while PowerShell 7
    # returns '::1', so one surrounding bracket pair is normalized before the allowed-host
    # comparison instead of comparing the raw text.
    $hostText = ConvertTo-R3LoopbackHostText -HostText $uri.Host
    if ($null -eq $hostText) { return $null }
    if ($allowedHosts -notcontains $hostText) { return $null }
    if ($uri.AbsolutePath -ne '/') { return $null }
    if (-not [string]::IsNullOrEmpty($uri.Query)) { return $null }
    if (-not [string]::IsNullOrEmpty($uri.Fragment)) { return $null }

    # The port must be written explicitly. Uri cannot tell an omitted port from an
    # explicitly written scheme-default port, so the authority text is read instead and
    # the same rule as the Python driver applies: port present and within 1..65535.
    $authorityText = $candidate.Substring($candidate.IndexOf('://') + 3)
    foreach ($terminator in @('/', '?', '#')) {
        $cut = $authorityText.IndexOf($terminator)
        if ($cut -ge 0) {
            $authorityText = $authorityText.Substring(0, $cut)
        }
    }
    $portText = $null
    if ($authorityText.StartsWith('[')) {
        $closing = $authorityText.IndexOf(']')
        if ($closing -lt 0) { return $null }
        $remainder = $authorityText.Substring($closing + 1)
        if ($remainder.StartsWith(':')) { $portText = $remainder.Substring(1) }
    } elseif ($authorityText.Contains(':')) {
        $portText = $authorityText.Substring($authorityText.LastIndexOf(':') + 1)
    }
    if ([string]::IsNullOrEmpty($portText)) { return $null }
    if ($portText -notmatch '^[0-9]{1,5}$') { return $null }
    $port = [int] $portText
    if ($port -lt 1 -or $port -gt 65535) { return $null }

    # Rebuild canonical IPv6 with exactly one bracket pair (never '[[::1]]'), and hand the
    # driver the normalized address rather than the operator's original text.
    $canonicalHost = $hostText
    if ($canonicalHost.Contains(':')) {
        $canonicalHost = '[' + $canonicalHost + ']'
    }
    return @{
        Host = $hostText
        Port = $port
        Text = ('{0}://{1}:{2}' -f $uri.Scheme, $canonicalHost, $port)
    }
}

function Resolve-R3Python {
    # Interpreter precedence: explicit -PythonCommand, then <repo>\.venv, then python on PATH.
    param(
        [string] $PythonCommand,
        [string] $RepoRoot
    )

    if (-not [string]::IsNullOrWhiteSpace($PythonCommand)) {
        return $PythonCommand.Trim()
    }
    if (-not [string]::IsNullOrWhiteSpace($RepoRoot)) {
        $venvPython = Join-Path (Join-Path $RepoRoot '.venv\Scripts') 'python.exe'
        if (Test-Path -LiteralPath $venvPython -PathType Leaf) {
            return $venvPython
        }
    }
    return 'python'
}

Write-Host '=== Win11 R3 two-phase native acceptance (read-only loopback workbench) ===' -ForegroundColor Cyan

try {
    # ---- 1. Phase: Before / After must be chosen explicitly ----
    if ([string]::IsNullOrEmpty($Phase) -or [string]::IsNullOrEmpty($Phase.Trim())) {
        Stop-R3Request -Code 'phase_invalid' -Message 'An explicit phase is required: -Phase Before or -Phase After.'
    }
    $phaseName = $Phase.Trim().ToLowerInvariant()
    if ($phaseName -ne 'before' -and $phaseName -ne 'after') {
        Stop-R3Request -Code 'phase_invalid' -Message 'The phase accepts Before or After only (case-insensitive).'
    }

    # ---- 2. Evidence directory: default %LOCALAPPDATA%\semantic-camera\acceptance ----
    $localAppData = [System.Environment]::GetEnvironmentVariable('LOCALAPPDATA')
    $resolvedEvidenceRoot = $EvidenceRoot
    if ([string]::IsNullOrWhiteSpace($resolvedEvidenceRoot)) {
        $resolvedEvidenceRoot = Get-R3DefaultEvidenceRoot -LocalAppData $localAppData
        if ($null -eq $resolvedEvidenceRoot) {
            Stop-R3Request -Code 'localappdata_missing' -Message $script:R3LocalAppDataRefusalMessage
        }
    }
    $resolvedEvidenceRoot = $resolvedEvidenceRoot.Trim()

    # ---- 3. Artifact paths: Before and After share one deterministic resolution ----
    $resolvedStatePath = $StateFile
    if ([string]::IsNullOrWhiteSpace($resolvedStatePath)) {
        $resolvedStatePath = Join-Path $resolvedEvidenceRoot $script:R3StateFileName
    }
    $resolvedReportPath = $ReportFile
    if ([string]::IsNullOrWhiteSpace($resolvedReportPath)) {
        $resolvedReportPath = Join-Path $resolvedEvidenceRoot $script:R3ReportFileName
    }

    Write-Host ('[phase]         phase={0}' -f $phaseName)
    Write-Host ('[evidence-root] {0}' -f $resolvedEvidenceRoot)
    Write-Host ('[state-file]    {0}' -f $resolvedStatePath)
    if ($phaseName -eq 'after') {
        Write-Host ('[report-file]   {0}' -f $resolvedReportPath)
    }

    # ---- 4. Workbench URL: meaningful for Before only, loopback only ----
    $normalizedBaseUrl = $null
    if ($phaseName -eq 'before') {
        $baseUrlText = $BaseUrl
        if ([string]::IsNullOrEmpty($baseUrlText)) {
            $baseUrlText = $script:R3DefaultBaseUrl
        }
        $target = ConvertTo-R3LoopbackTarget -Url $baseUrlText
        if ($null -eq $target) {
            Stop-R3Request -Code 'unsafe_workbench' -Message $script:R3UrlRefusalMessage
        }
        $normalizedBaseUrl = $target.Text
        Write-Host ('[base-url]      loopback-ok {0}' -f $normalizedBaseUrl)
    } else {
        if (-not [string]::IsNullOrWhiteSpace($BaseUrl)) {
            Stop-R3Request -Code 'base_url_not_applicable' -Message $script:R3BaseUrlNotApplicableMessage
        }
    }

    # ---- 5. Refuse overwrite before invoking Python; the driver keeps the final boundary ----
    if ($phaseName -eq 'before') {
        if (Test-Path -LiteralPath $resolvedStatePath) {
            Stop-R3Request -Code 'state_exists' -Message ('State file already exists, refusing to overwrite: {0}. Move the old artifact away after checking it by hand, or use -EvidenceRoot / -StateFile for a new location. The Python driver keeps its own no-clobber as the final boundary.' -f $resolvedStatePath)
        }
    } else {
        if (-not (Test-Path -LiteralPath $resolvedStatePath)) {
            Stop-R3Request -Code 'state_missing' -Message ('State file written by Before not found: {0}. Run -Phase Before first to collect the pre-restart facts.' -f $resolvedStatePath)
        }
        if (Test-Path -LiteralPath $resolvedReportPath) {
            Stop-R3Request -Code 'report_exists' -Message ('Report already exists, refusing to overwrite: {0}. Move the old report away after checking it by hand, or use -ReportFile for a new path. The Python driver keeps its own no-clobber as the final boundary.' -f $resolvedReportPath)
        }
    }

    # ---- 6. Interpreter and repository root (self-locating, independent of caller cwd) ----
    $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
    $python = Resolve-R3Python -PythonCommand $PythonCommand -RepoRoot $repoRoot
    if (-not (Get-Command -Name $python -ErrorAction SilentlyContinue)) {
        Stop-R3Request -Code 'python_missing' -Message ('Python interpreter not found: {0}. Run deploy\install-win11.ps1 first to create .venv, or point -PythonCommand at an interpreter.' -f $python)
    }

    # ---- 7. Create the evidence directory only; never config, profiles or zones ----
    # New-Item has no -LiteralPath parameter, and Windows PowerShell 5.1 fails binding it
    # outright (a legal After would turn into an internal error before Python is invoked), so
    # the form both 5.1 and 7 share is used: -Path is a named parameter and the path travels
    # as the value of a variable, which keeps an evidence directory whose name begins with
    # '-' a path value and never a parameter name.
    New-Item -Path $resolvedEvidenceRoot -ItemType Directory -Force | Out-Null

    # ---- 8. Invoke the existing production command with an argument array ----
    $argumentList = New-R3ArgumentList -Phase $phaseName -StatePath $resolvedStatePath -ReportPath $resolvedReportPath -BaseUrl $normalizedBaseUrl
    Write-Host ('[exec]          {0} -m scam.win11_r3_acceptance {1}' -f $python, $phaseName)

    # Native stderr must not become a terminating error under $ErrorActionPreference='Stop':
    # the driver writes its structured failure document to stderr and it has to pass through,
    # instead of being swallowed as an internal error of this wrapper.
    $savedErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $childExitCode = $null
    try {
        & $python @argumentList
        $childExitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $savedErrorActionPreference
    }
    if ($null -eq $childExitCode) {
        Stop-R3Request -Code 'internal_error' -Message 'Could not read the exit code of the Python driver; this run is not trustworthy.'
    }

    Write-Host ('[exit-code]     exit-code={0} returned by the Python driver, passed through unchanged' -f $childExitCode)
    if ($childExitCode -eq 0 -and $phaseName -eq 'before') {
        Write-R3NextStep
    }
    Write-R3BoundaryNotice
    exit $childExitCode
} catch {
    Write-Host ''
    Write-Host ('[refuse] internal_error - unexpected wrapper failure ({0})' -f $_.Exception.GetType().Name) -ForegroundColor Red
    Write-Host ('        {0}' -f $_.Exception.Message)
    Write-R3BoundaryNotice
    exit $script:R3RefusalExitCode
}

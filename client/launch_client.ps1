# launch_client.ps1 -- portable client launcher for Shining Force Cross Raid.
#
# What it does (and nothing else):
#   1. reads client.json (server_ip / game_dir / exe hash / pcp ports)
#   2. writes cfg\dnsmap.txt and the `forcenet` line of cfg\poke.cfg from server_ip
#   3. starts the LOCAL PCP server (the game always talks to 127.0.0.1:4010x)
#   4. checks that the remote ALL.Net (:80) and SIF (:52000) are reachable
#   5. stops an old game instance and injects bin\tpfake.dll + bin\probe.dll
#
# Everything the DLLs write goes to <this folder>\logs (no K:\debug).

param(
    [string]$ServerIP = '',
    [string]$GameDir = '',
    [switch]$NoPcp,
    [switch]$NoLaunch,
    [switch]$Debug,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
$Root   = $PSScriptRoot
$CfgDir = Join-Path $Root 'cfg'
$BinDir = Join-Path $Root 'bin'
$LogDir = Join-Path $Root 'logs'
$PcpDir = Join-Path $Root 'pcp'
New-Item -ItemType Directory -Force $LogDir | Out-Null

function Say($msg) { Write-Host $msg }

function Test-PortUp([int]$port) {
    return [bool](Get-NetTCPConnection -State Listen -LocalPort $port -ErrorAction SilentlyContinue)
}

function Test-RemoteTcp([string]$ip, [int]$port, [int]$ms = 1500) {
    $c = New-Object Net.Sockets.TcpClient
    try {
        $iar = $c.BeginConnect($ip, $port, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne($ms)) { return $false }
        $c.EndConnect($iar)
        return $true
    } catch { return $false } finally { $c.Close() }
}

# ------------------------------------------------------------------ config
$jsonPath = Join-Path $Root 'client.json'
if (-not (Test-Path $jsonPath)) { throw "missing client.json" }
# 2026-11-07: client.json 里现在有中文注释，必须显式按 UTF-8 读，
# 否则 PowerShell 5.1 会按 ANSI 解码 -> ConvertFrom-Json 直接失败。
$cfg = Get-Content $jsonPath -Raw -Encoding UTF8 | ConvertFrom-Json

if (-not $ServerIP) { $ServerIP = [string]$cfg.server_ip }
if (-not $GameDir)  { $GameDir  = [string]$cfg.game_dir }
if (-not $ServerIP) { throw "client.json: server_ip is empty" }
if (-not $GameDir)  { throw "client.json: game_dir is empty" }
if (-not [IO.Path]::IsPathRooted($GameDir)) { $GameDir = Join-Path $Root $GameDir }
$GameDir = [IO.Path]::GetFullPath($GameDir)   # accepts D:/... or D:\\...

$ExeName = [string]$cfg.exe
if (-not $ExeName) { $ExeName = 'project_f-ringedge-release.exe' }
$Exe = Join-Path $GameDir $ExeName
if (-not (Test-Path $Exe)) { throw "game exe not found: $Exe" }

if ($cfg.exe_sha256) {
    $hash = (Get-FileHash $Exe -Algorithm SHA256).Hash.ToUpper()
    if ($hash -ne ([string]$cfg.exe_sha256).ToUpper()) {
        $msg = "game exe SHA256 mismatch`n  expected $($cfg.exe_sha256)`n  actual   $hash"
        if (-not $Force) { throw "$msg`n(use -Force only if you know the build is compatible)" }
        Say "[!] $msg  (continuing because -Force)"
    }
}

Say "=== [1/5] config (server $ServerIP) ==="
$names = @('naominet.jp', 'ib.naominet.jp', 'bbrouter.loc', 'tenporouter.loc', 'aime.naominet.jp')
$dnsText = (($names | ForEach-Object { "$_=$ServerIP" }) -join "`r`n") + "`r`n"
[IO.File]::WriteAllText((Join-Path $CfgDir 'dnsmap.txt'), $dnsText, (New-Object System.Text.ASCIIEncoding))

$pokePath = Join-Path $CfgDir 'poke.cfg'
$poke = [IO.File]::ReadAllText($pokePath)
if ($poke -match '(?m)^forcenet\s+\S+') {
    $poke = [regex]::Replace($poke, '(?m)^forcenet\s+\S+', "forcenet $ServerIP")
} else {
    $poke += "`r`nforcenet $ServerIP`r`n"
}
[IO.File]::WriteAllText($pokePath, $poke, (New-Object System.Text.UTF8Encoding($false)))
Say "  dnsmap.txt -> $ServerIP (5 entries)"
Say "  poke.cfg   -> forcenet $ServerIP"

# ------------------------------------------------------------------ remote
Say "=== [2/5] remote server ==="
$ok80 = Test-RemoteTcp $ServerIP 80
$ok52 = Test-RemoteTcp $ServerIP 52000
Say ("  {0}:80    {1}" -f $ServerIP, $(if ($ok80) { 'UP' } else { 'DOWN' }))
Say ("  {0}:52000 {1}" -f $ServerIP, $(if ($ok52) { 'UP' } else { 'DOWN' }))
if (-not ($ok80 -and $ok52)) {
    Say '  [!] one of the remote services is down -- the three status lights will not all be green.'
}

# ------------------------------------------------------------------ PCP
Say "=== [3/5] local PCP (127.0.0.1:4010x) ==="
$pcpPorts = @(40100, 40102, 40104, 40106, 40110, 40113, 40114)
if ($cfg.pcp -and $cfg.pcp.ports) { $pcpPorts = @($cfg.pcp.ports | ForEach-Object { [int]$_ }) }

if ($NoPcp) {
    Say '  skipped (-NoPcp)'
} elseif ((Test-PortUp 40100) -and (Test-PortUp 40106)) {
    Say '  already up, reusing it'
} else {
    $py = Join-Path $Root 'python\python.exe'
    if (-not (Test-Path $py)) { $py = 'python' }
    $addr = 'auto'
    if ($cfg.pcp -and $cfg.pcp.networkaddr) { $addr = [string]$cfg.pcp.networkaddr }
    if (($addr -eq 'auto') -or (-not $addr)) {
        # 2026-11-01: 多机联机时 networkaddr 必须指向服务器。
        # 优先用 client.json 的 server_ip；没有才退回本机 IP。
        if ($cfg.server_ip) {
            $addr = [string]$cfg.server_ip
            Say ("  networkaddr auto -> server_ip {0}" -f $addr)
        } else {
            $addr = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                     Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' } |
                     Select-Object -First 1).IPAddress
        }
    }
    if (-not $addr) { $addr = '127.0.0.1' }
    $pcpPy = Join-Path $PcpDir 'pcp_server.py'
    if (-not (Test-Path $pcpPy)) { throw "missing pcp\pcp_server.py" }
    $pcpArgs = @($pcpPy, '--ports', ($pcpPorts -join ','), '--networkaddr', $addr,
                 '--log', (Join-Path $LogDir 'pcp.log'))
    $dsTable = Join-Path $GameDir 'SBVB_Table.dat'
    if (Test-Path $dsTable) {
        $pcpArgs += @('--ds-table', $dsTable)
    } else {
        Say '  [!] SBVB_Table.dat not found in game_dir -- keychip.ssd.proof will fail'
    }
    Say ("  starting: {0} --networkaddr {1}" -f $py, $addr)
    # 2026-11-03: 每台机台必须有不同的 keychip ID（档案里的基板标识由它决定）
    if ($cfg.pcp -and $cfg.pcp.keyid)  { $pcpArgs += @('--keyid',  [string]$cfg.pcp.keyid) }
    if ($cfg.pcp -and $cfg.pcp.mainid) { $pcpArgs += @('--mainid', [string]$cfg.pcp.mainid) }
    Start-Process -FilePath $py -ArgumentList $pcpArgs -WindowStyle Hidden `
        -RedirectStandardOutput (Join-Path $LogDir 'pcp.out.txt') `
        -RedirectStandardError  (Join-Path $LogDir 'pcp.err.txt') | Out-Null
    $up = $false
    for ($i = 0; $i -lt 20; $i++) {
        Start-Sleep -Milliseconds 250
        if (Test-PortUp 40100) { $up = $true; break }
    }
    if ($up) { Say '  PCP is up' } else { Say '  [!] PCP did not open 40100 -- see logs\pcp.err.txt' }
}

# ------------------------------------------------------------------ card
if (-not (Test-Path 'C:\iccard.bin')) {
    Say '  [!] C:\iccard.bin is missing -- insert a card (or run setup_card.ps1 once as admin).'
}

# ------------------------------------------------------------------ inject
Say "=== [4/5] stop old game + inject ==="
Get-Process project_f-ringedge-release -ErrorAction SilentlyContinue | ForEach-Object {
    Say ("  stopping old pid {0}" -f $_.Id)
    & taskkill /F /PID $_.Id *> $null
}
Start-Sleep -Seconds 2
if (Get-Process project_f-ringedge-release -ErrorAction SilentlyContinue) {
    throw 'old game process is still running; close it and retry'
}

if ($NoLaunch) {
    Say '  skipped injection (-NoLaunch)'
} else {
    $inj = Join-Path $BinDir 'inject_multi.exe'
    if (-not (Test-Path $inj)) { throw "missing bin\inject_multi.exe" }
    $core  = @('tpfake.dll', 'profiletx.dll')   # tpfake 自载 probe/windower/...；probe_focus 会撞车   # windower: 1296x759 窗口；profilepatch: 卡面6字段
    $extra = @('appdump12.dll', 'sendlog.dll', 'esctp_tap.dll', 'sifdump.dll',
               'filefail.dll', 'sessdump.dll', 'handump.dll', 'taildump.dll', 'recvlog.dll')
    $names = $core
    if ($Debug) { $names = $core + $extra }
    $dlls = @($names | ForEach-Object { Join-Path $BinDir $_ })
    $injArgs = @('--log', (Join-Path $LogDir 'game_out.txt'), $ExeName) + $dlls
    $p = Start-Process -FilePath $inj -ArgumentList $injArgs -WorkingDirectory $GameDir -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput (Join-Path $LogDir 'inject.out.txt') `
        -RedirectStandardError  (Join-Path $LogDir 'inject.err.txt')
    $p | Wait-Process -Timeout 90 -ErrorAction SilentlyContinue
    if ($p.HasExited -and $p.ExitCode -ne 0) {
        Say ("  [!] inject_multi rc={0}; see logs\inject.err.txt" -f $p.ExitCode)
    }
    Start-Sleep -Seconds 3
    $g = Get-Process project_f-ringedge-release -ErrorAction SilentlyContinue |
         Sort-Object StartTime | Select-Object -Last 1
    if ($g) { Say ("  game pid={0} start={1}" -f $g.Id, $g.StartTime) }
    else { Say '  [!] game process not found -- check logs\inject.err.txt' }
}

Say "=== [5/5] done ==="
Say ''
Say 'Hotkeys: F2 = insert IC card, F10 = eject, F1 = coin.'
Say 'Check: three status lights green on Game Mode Select;'
Say '       a card that has played at least one story quest shows the Online modes selectable.'
Say 'Logs:  logs\  (tpfake/connlog/probe/pcp/...)'

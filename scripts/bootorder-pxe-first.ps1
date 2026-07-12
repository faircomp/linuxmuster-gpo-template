# bootorder-pxe-first.ps1 — UEFI boot order: network/PXE first (-> LINBO), Windows Boot
# Manager last. Otherwise Windows pushes its boot manager back to the top after every start.
#
# WHY TWO-STAGE (scheduled task):
# The GPO startup/shutdown script does run as SYSTEM, but with a REDUCED token that lacks
# SeSystemEnvironmentPrivilege (client log: "a required privilege is not held by the client",
# also for {bootmgr}). So no bcdedit access to the UEFI NVRAM is possible. Solution:
#  - INSTALLER mode (default, called by the GPO): copies this script locally and registers a
#    scheduled task that runs it as SYSTEM with HIGHEST privileges (full token, incl.
#    SeSystemEnvironmentPrivilege) at system start — and starts it once immediately.
#  - WORKER mode (-Worker, called by the task): does the actual bcdedit reorder.
# Everything is logged to %SystemRoot%\Temp\lmgpo-bootorder.log.
param([switch]$Worker)
$ErrorActionPreference = 'SilentlyContinue'
$log = Join-Path $env:SystemRoot 'Temp\lmgpo-bootorder.log'
function Log($m) { try { ('{0}  {1}' -f (Get-Date -Format 's'), $m) | Out-File -LiteralPath $log -Append -Encoding utf8 } catch {} }

# --------------------------------------------------------------------------- #
# WORKER: the actual reorder (runs with full privileges via the scheduled task)
# --------------------------------------------------------------------------- #
function Invoke-Reorder {
    Log ('whoami /priv (SeSystemEnvironment): ' + ((& whoami /priv 2>&1 | Select-String 'SeSystemEnvironment') -join ' | '))

    # Enable SeSystemEnvironmentPrivilege (present in the full token, but possibly disabled).
    $csharp = @'
[DllImport("advapi32.dll", SetLastError=true)] static extern bool OpenProcessToken(IntPtr h, uint a, out IntPtr t);
[DllImport("advapi32.dll", SetLastError=true)] static extern bool LookupPrivilegeValue(string s, string n, out long l);
[DllImport("advapi32.dll", SetLastError=true)] static extern bool AdjustTokenPrivileges(IntPtr t, bool d, ref TP p, uint bl, IntPtr ps, IntPtr rl);
[DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
[StructLayout(LayoutKind.Sequential)] public struct TP { public uint Count; public long Luid; public uint Attr; }
public static string Enable(string priv) {
    IntPtr t;
    if (!OpenProcessToken(GetCurrentProcess(), 0x0028, out t)) return "OpenProcessToken error " + Marshal.GetLastWin32Error();
    long luid;
    if (!LookupPrivilegeValue(null, priv, out luid)) return "LookupPrivilegeValue error " + Marshal.GetLastWin32Error();
    TP tp = new TP(); tp.Count = 1; tp.Luid = luid; tp.Attr = 0x00000002;
    bool r = AdjustTokenPrivileges(t, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
    int err = Marshal.GetLastWin32Error();
    if (!r) return "AdjustTokenPrivileges error " + err;
    if (err == 1300) return "NOT in token (ERROR_NOT_ALL_ASSIGNED)";
    return "enabled";
}
'@
    try { Add-Type -Namespace LMGPO -Name Tok -MemberDefinition $csharp -ErrorAction Stop; Log ('SeSystemEnvironmentPrivilege: ' + [LMGPO.Tok]::Enable('SeSystemEnvironmentPrivilege')) } catch { Log ('privilege-enable exception: ' + $_.Exception.Message) }

    $bcd = Join-Path $env:SystemRoot 'System32\bcdedit.exe'
    if (-not [Environment]::Is64BitProcess -and [Environment]::Is64BitOperatingSystem) {
        $sn = Join-Path $env:SystemRoot 'Sysnative\bcdedit.exe'; if (Test-Path -LiteralPath $sn) { $bcd = $sn }
    }
    $fwEnum = (& $bcd /enum "{fwbootmgr}" 2>&1 | Out-String)
    Log ("bcdedit /enum {fwbootmgr} (raw):`n" + $fwEnum.Trim())
    if ($fwEnum -notmatch 'fwbootmgr') {
        # NOTE: the German 'erforderliches Recht' MUST stay — it matches localized bcdedit output.
        if ($fwEnum -match 'erforderliches Recht|required privilege|privilege is not held') { Log 'ABORT: still a privilege error — even the task context lacks the privilege (very unusual).' }
        else { Log 'ABORT: {fwbootmgr} not readable (maybe Legacy/BIOS) — check the raw output above.' }
        return
    }

    # Network/PXE pattern (case-insensitive). 'Netzwerk' MUST stay — it matches localized entries.
    $netPattern = '(?i)\bIPV?4\b|\bIPV?6\b|\bIP4\b|\bIP6\b|PXE|Network|Netzwerk|\bLAN\b|Ethernet'
    $curId = $null; $net = New-Object System.Collections.Generic.List[object]; $bootmgrId = $null
    foreach ($line in (& $bcd /enum firmware 2>$null)) {
        # 'Bezeichner'/'Beschreibung'/'Windows-Start-Manager' MUST stay (localized bcdedit output).
        $mi = [regex]::Match($line, '^\s*(?:identifier|Bezeichner)\s+(\{[^}]+\}|\S+)')
        if ($mi.Success) { $curId = $mi.Groups[1].Value; continue }
        $md = [regex]::Match($line, '^\s*(?:description|Beschreibung)\s+(.+?)\s*$')
        if (-not ($md.Success -and $curId)) { continue }
        $id = $curId; $desc = $md.Groups[1].Value; $curId = $null
        if ($id -eq '{fwbootmgr}') { continue }
        Log ('Entry: {0}  =>  {1}' -f $id, $desc)
        if ($id -eq '{bootmgr}' -or $desc -match 'Windows Boot Manager|Windows-Start-Manager') { $bootmgrId = $id; continue }
        if ($desc -match $netPattern) { $net.Add([pscustomobject]@{ id = $id; desc = $desc }) }
    }
    if ($net.Count -eq 0) { Log 'WARNING: no network/PXE entry detected -> order NOT changed (check the entries above).'; return }

    $firstId = ([regex]::Match($fwEnum, '(?im)^\s*displayorder\s+(\{[^}]+\})')).Groups[1].Value
    if ($net.id -contains $firstId) { Log ('Network already first ({0}) -> ok, no change.' -f $firstId); return }

    if ($bootmgrId) { & $bcd /set "{fwbootmgr}" displayorder $bootmgrId /addlast | Out-Null; Log ('Windows Boot Manager to the end: {0}' -f $bootmgrId) }
    for ($i = $net.Count - 1; $i -ge 0; $i--) {
        & $bcd /set "{fwbootmgr}" displayorder $net[$i].id /addfirst | Out-Null
        Log ('Network to the front: {0}  ({1})' -f $net[$i].id, $net[$i].desc)
    }
    Log ('New order: ' + ((& $bcd /enum "{fwbootmgr}" 2>$null) -join ' | '))
}

# --------------------------------------------------------------------------- #
if ($Worker) {
    Log '--- Worker (scheduled task, full privileges) ---'
    Invoke-Reorder
    Log '--- Worker end ---'
    return
}

# --------------------------------------------------------------------------- #
# INSTALLER (GPO startup/shutdown script, restricted token): register + start the task.
# --------------------------------------------------------------------------- #
Log '--- Installer (GPO script) ---'
$taskName = 'LMGPO-BootOrderPXE'
$localDir = Join-Path $env:ProgramData 'lmgpo'
$localScript = Join-Path $localDir 'bootorder-pxe-first.ps1'   # deliberately WITHOUT spaces in the path
try {
    New-Item -ItemType Directory -Force -Path $localDir | Out-Null
    if ($PSCommandPath -and (Test-Path -LiteralPath $PSCommandPath)) {
        Copy-Item -LiteralPath $PSCommandPath -Destination $localScript -Force
        Log ('script copied locally -> ' + $localScript)
    } else { Log 'WARN: $PSCommandPath empty — worker script cannot be placed locally.' }
} catch { Log ('copy error: ' + $_.Exception.Message) }

try {
    # Task as SYSTEM/HIGHEST privileges, trigger at system start. Path without spaces -> no inner quotes needed.
    $tr = "powershell.exe -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File $localScript -Worker"
    (& schtasks.exe /Create /TN $taskName /TR $tr /SC ONSTART /RU 'SYSTEM' /RL HIGHEST /F 2>&1) | ForEach-Object { Log ('schtasks /Create: ' + $_) }
    (& schtasks.exe /Run /TN $taskName 2>&1) | ForEach-Object { Log ('schtasks /Run: ' + $_) }
    Log 'task registered + started immediately (the task does the actual reorder).'
} catch { Log ('task registration failed: ' + $_.Exception.Message) }
Log '--- Installer end ---'

# bootorder-pxe-first.ps1 — UEFI-Bootreihenfolge: Netzwerk/PXE zuerst (-> LINBO), Windows
# Boot Manager zuletzt. Windows draengt seinen Boot Manager sonst nach jedem Start wieder vor.
#
# WARUM ZWEISTUFIG (Scheduled Task):
# Das GPO-Start-/Shutdown-Skript laeuft zwar als SYSTEM, aber mit einem ABGESPECKTEN Token
# ohne SeSystemEnvironmentPrivilege (Client-Log: "Dem Client fehlt ein erforderliches Recht.",
# auch fuer {bootmgr}). Damit ist KEIN bcdedit-Zugriff auf die UEFI-NVRAM moeglich. Loesung:
#  - INSTALLER-Modus (Default, vom GPO aufgerufen): kopiert dieses Skript lokal und registriert
#    einen Scheduled Task, der es als SYSTEM mit HOECHSTEN Rechten (volles Token, inkl.
#    SeSystemEnvironmentPrivilege) beim Systemstart ausfuehrt — und startet ihn sofort einmal.
#  - WORKER-Modus (-Worker, vom Task aufgerufen): macht die eigentliche bcdedit-Umsortierung.
# Alles wird nach %SystemRoot%\Temp\lmgpo-bootorder.log geloggt.
param([switch]$Worker)
$ErrorActionPreference = 'SilentlyContinue'
$log = Join-Path $env:SystemRoot 'Temp\lmgpo-bootorder.log'
function Log($m) { try { ('{0}  {1}' -f (Get-Date -Format 's'), $m) | Out-File -LiteralPath $log -Append -Encoding utf8 } catch {} }

# --------------------------------------------------------------------------- #
# WORKER: eigentliche Umsortierung (laeuft mit vollen Rechten via Scheduled Task)
# --------------------------------------------------------------------------- #
function Invoke-Reorder {
    Log ('whoami /priv (SeSystemEnvironment): ' + ((& whoami /priv 2>&1 | Select-String 'SeSystemEnvironment') -join ' | '))

    # SeSystemEnvironmentPrivilege aktivieren (im vollen Token vorhanden, aber ggf. disabled).
    $csharp = @'
[DllImport("advapi32.dll", SetLastError=true)] static extern bool OpenProcessToken(IntPtr h, uint a, out IntPtr t);
[DllImport("advapi32.dll", SetLastError=true)] static extern bool LookupPrivilegeValue(string s, string n, out long l);
[DllImport("advapi32.dll", SetLastError=true)] static extern bool AdjustTokenPrivileges(IntPtr t, bool d, ref TP p, uint bl, IntPtr ps, IntPtr rl);
[DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
[StructLayout(LayoutKind.Sequential)] public struct TP { public uint Count; public long Luid; public uint Attr; }
public static string Enable(string priv) {
    IntPtr t;
    if (!OpenProcessToken(GetCurrentProcess(), 0x0028, out t)) return "OpenProcessToken-Fehler " + Marshal.GetLastWin32Error();
    long luid;
    if (!LookupPrivilegeValue(null, priv, out luid)) return "LookupPrivilegeValue-Fehler " + Marshal.GetLastWin32Error();
    TP tp = new TP(); tp.Count = 1; tp.Luid = luid; tp.Attr = 0x00000002;
    bool r = AdjustTokenPrivileges(t, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
    int err = Marshal.GetLastWin32Error();
    if (!r) return "AdjustTokenPrivileges-Fehler " + err;
    if (err == 1300) return "NICHT im Token (ERROR_NOT_ALL_ASSIGNED)";
    return "aktiviert";
}
'@
    try { Add-Type -Namespace LMGPO -Name Tok -MemberDefinition $csharp -ErrorAction Stop; Log ('SeSystemEnvironmentPrivilege: ' + [LMGPO.Tok]::Enable('SeSystemEnvironmentPrivilege')) } catch { Log ('Privileg-Enable Ausnahme: ' + $_.Exception.Message) }

    $bcd = Join-Path $env:SystemRoot 'System32\bcdedit.exe'
    if (-not [Environment]::Is64BitProcess -and [Environment]::Is64BitOperatingSystem) {
        $sn = Join-Path $env:SystemRoot 'Sysnative\bcdedit.exe'; if (Test-Path -LiteralPath $sn) { $bcd = $sn }
    }
    $fwEnum = (& $bcd /enum "{fwbootmgr}" 2>&1 | Out-String)
    Log ("bcdedit /enum {fwbootmgr} (roh):`n" + $fwEnum.Trim())
    if ($fwEnum -notmatch 'fwbootmgr') {
        if ($fwEnum -match 'erforderliches Recht|required privilege|privilege is not held') { Log 'ABBRUCH: immer noch Rechte-Fehler — auch der Task-Kontext hat das Privileg nicht (sehr ungewoehnlich).' }
        else { Log 'ABBRUCH: {fwbootmgr} nicht lesbar (evtl. Legacy/BIOS) — Rohausgabe oben pruefen.' }
        return
    }

    $netPattern = '(?i)\bIPV?4\b|\bIPV?6\b|\bIP4\b|\bIP6\b|PXE|Network|Netzwerk|\bLAN\b|Ethernet'
    $curId = $null; $net = New-Object System.Collections.Generic.List[object]; $bootmgrId = $null
    foreach ($line in (& $bcd /enum firmware 2>$null)) {
        $mi = [regex]::Match($line, '^\s*(?:identifier|Bezeichner)\s+(\{[^}]+\}|\S+)')
        if ($mi.Success) { $curId = $mi.Groups[1].Value; continue }
        $md = [regex]::Match($line, '^\s*(?:description|Beschreibung)\s+(.+?)\s*$')
        if (-not ($md.Success -and $curId)) { continue }
        $id = $curId; $desc = $md.Groups[1].Value; $curId = $null
        if ($id -eq '{fwbootmgr}') { continue }
        Log ('Eintrag: {0}  =>  {1}' -f $id, $desc)
        if ($id -eq '{bootmgr}' -or $desc -match 'Windows Boot Manager|Windows-Start-Manager') { $bootmgrId = $id; continue }
        if ($desc -match $netPattern) { $net.Add([pscustomobject]@{ id = $id; desc = $desc }) }
    }
    if ($net.Count -eq 0) { Log 'WARNUNG: kein Netzwerk/PXE-Eintrag erkannt -> Reihenfolge NICHT geaendert (Eintraege oben pruefen).'; return }

    $firstId = ([regex]::Match($fwEnum, '(?im)^\s*displayorder\s+(\{[^}]+\})')).Groups[1].Value
    if ($net.id -contains $firstId) { Log ('Netzwerk steht bereits vorn ({0}) -> ok, keine Aenderung.' -f $firstId); return }

    if ($bootmgrId) { & $bcd /set "{fwbootmgr}" displayorder $bootmgrId /addlast | Out-Null; Log ('Windows Boot Manager ans Ende: {0}' -f $bootmgrId) }
    for ($i = $net.Count - 1; $i -ge 0; $i--) {
        & $bcd /set "{fwbootmgr}" displayorder $net[$i].id /addfirst | Out-Null
        Log ('Netzwerk nach vorne: {0}  ({1})' -f $net[$i].id, $net[$i].desc)
    }
    Log ('Neue Reihenfolge: ' + ((& $bcd /enum "{fwbootmgr}" 2>$null) -join ' | '))
}

# --------------------------------------------------------------------------- #
if ($Worker) {
    Log '--- Worker (Scheduled Task, volle Rechte) ---'
    Invoke-Reorder
    Log '--- Worker Ende ---'
    return
}

# --------------------------------------------------------------------------- #
# INSTALLER (GPO-Start-/Shutdown-Skript, eingeschraenkter Token): Task anlegen + starten.
# --------------------------------------------------------------------------- #
Log '--- Installer (GPO-Skript) ---'
$taskName = 'LMGPO-BootOrderPXE'
$localDir = Join-Path $env:ProgramData 'lmgpo'
$localScript = Join-Path $localDir 'bootorder-pxe-first.ps1'   # bewusst OHNE Leerzeichen im Pfad
try {
    New-Item -ItemType Directory -Force -Path $localDir | Out-Null
    if ($PSCommandPath -and (Test-Path -LiteralPath $PSCommandPath)) {
        Copy-Item -LiteralPath $PSCommandPath -Destination $localScript -Force
        Log ('Skript lokal kopiert -> ' + $localScript)
    } else { Log 'WARN: $PSCommandPath leer — Worker-Skript nicht lokal ablegbar.' }
} catch { Log ('Kopier-Fehler: ' + $_.Exception.Message) }

try {
    # Task als SYSTEM/HOECHSTE Rechte, Trigger beim Systemstart. Pfad ohne Leerzeichen -> keine inneren Quotes noetig.
    $tr = "powershell.exe -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File $localScript -Worker"
    (& schtasks.exe /Create /TN $taskName /TR $tr /SC ONSTART /RU 'SYSTEM' /RL HIGHEST /F 2>&1) | ForEach-Object { Log ('schtasks /Create: ' + $_) }
    (& schtasks.exe /Run /TN $taskName 2>&1) | ForEach-Object { Log ('schtasks /Run: ' + $_) }
    Log 'Task registriert + sofort gestartet (die eigentliche Umsortierung erledigt der Task).'
} catch { Log ('Task-Registrierung fehlgeschlagen: ' + $_.Exception.Message) }
Log '--- Installer Ende ---'

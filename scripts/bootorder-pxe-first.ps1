# bootorder-pxe-first.ps1 — Computer-Start- UND Shutdown-Skript (linuxmuster-gpo-template),
# laeuft als SYSTEM beim Boot und beim Herunterfahren. Zweck: UEFI-Bootreihenfolge so setzen,
# dass Netzwerk/PXE ZUERST bootet (-> LINBO) und der Windows Boot Manager ZULETZT.
#
# Zugriff auf {fwbootmgr} (UEFI-NVRAM) braucht das Recht SeSystemEnvironmentPrivilege. Im
# GPO-Startskript-SYSTEM-Kontext ist es nicht automatisch aktiv -> bcdedit meldet sonst
# "Dem Client fehlt ein erforderliches Recht.". Dieses Skript aktiviert das Privileg selbst.
# Robust: 64-bit bcdedit (Sysnative), viele Netz-Muster, locale-tolerant (DE/EN), idempotent,
# nicht-destruktiv (/addfirst /addlast), bricht den Boot nie ab, loggt alles nach
# %SystemRoot%\Temp\lmgpo-bootorder.log.
$ErrorActionPreference = 'SilentlyContinue'
$log = Join-Path $env:SystemRoot 'Temp\lmgpo-bootorder.log'
function Log($m) { try { ('{0}  {1}' -f (Get-Date -Format 's'), $m) | Out-File -LiteralPath $log -Append -Encoding utf8 } catch {} }

Log '--- Start bootorder-pxe-first ---'
Log ('Kontext: ' + ((& whoami) 2>&1) + ' | 64bit-Proc=' + [Environment]::Is64BitProcess + ' | 64bit-OS=' + [Environment]::Is64BitOperatingSystem)

# SeSystemEnvironmentPrivilege im eigenen Token aktivieren (fuer Zugriff auf {fwbootmgr}).
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
    if (err == 1300) return "NICHT im Token (ERROR_NOT_ALL_ASSIGNED) -> Scheduled Task noetig";
    return "aktiviert";
}
'@
$privState = '?'
try { Add-Type -Namespace LMGPO -Name Tok -MemberDefinition $csharp -ErrorAction Stop; $privState = [LMGPO.Tok]::Enable('SeSystemEnvironmentPrivilege') } catch { $privState = 'Ausnahme: ' + $_.Exception.Message }
Log ('SeSystemEnvironmentPrivilege: ' + $privState)
Log ('whoami /priv (SeSystemEnvironment): ' + ((& whoami /priv 2>&1 | Select-String 'SeSystemEnvironment') -join ' '))

# bcdedit robust: aus 32-bit ueber Sysnative die echte 64-bit bcdedit nutzen.
$bcd = Join-Path $env:SystemRoot 'System32\bcdedit.exe'
if (-not [Environment]::Is64BitProcess -and [Environment]::Is64BitOperatingSystem) {
    $sn = Join-Path $env:SystemRoot 'Sysnative\bcdedit.exe'
    if (Test-Path -LiteralPath $sn) { $bcd = $sn }
}
$peType = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control' -Name PEFirmwareType -ErrorAction SilentlyContinue).PEFirmwareType
Log ('bcdedit=' + $bcd + ' | PEFirmwareType=' + $peType + ' (1=BIOS/Legacy, 2=UEFI)')

# {fwbootmgr} existiert nur auf UEFI + braucht das Privileg. Rohausgabe inkl. Fehler loggen.
$fwEnum = (& $bcd /enum "{fwbootmgr}" 2>&1 | Out-String)
Log ("bcdedit /enum {fwbootmgr} (roh):`n" + $fwEnum.Trim())
if ($fwEnum -notmatch 'fwbootmgr') {
    # Gegenprobe: on-disk BCD ({bootmgr}) braucht KEIN Firmware-Privileg. Klaert bcdedit vs. Privileg vs. Legacy.
    $bm = (& $bcd /enum "{bootmgr}" 2>&1 | Out-String)
    Log ('Gegenprobe bcdedit /enum {bootmgr}: ' + ($(if ($bm -match 'bootmgr') { 'OK (bcdedit funktioniert -> {fwbootmgr}-Problem ist Privileg/Firmware)' } else { 'auch Fehler: ' + $bm.Trim() })))
    if ($fwEnum -match 'erforderliches Recht|required privilege|privilege is not held') {
        Log 'ABBRUCH: Privileg SeSystemEnvironmentPrivilege konnte nicht genutzt werden. Falls oben "NICHT im Token": Scheduled-Task-Variante noetig.'
    } elseif ($peType -eq 2) {
        Log 'ABBRUCH: PEFirmwareType=UEFI, aber {fwbootmgr} nicht lesbar — Rohausgabe oben pruefen.'
    } else {
        Log 'ABBRUCH: Kein UEFI (Legacy/BIOS) -> Bootreihenfolge liegt nicht in der NVRAM.'
    }
    return
}

# Netzwerk/PXE-Muster (zuverlaessig, case-insensitive; ohne mehrdeutige Herstellernamen).
$netPattern = '(?i)\bIPV?4\b|\bIPV?6\b|\bIP4\b|\bIP6\b|PXE|Network|Netzwerk|\bLAN\b|Ethernet'

# Firmware-Eintraege zeilenweise parsen: identifier steht je Block VOR description.
$curId = $null
$net = New-Object System.Collections.Generic.List[object]
$bootmgrId = $null
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

if ($net.Count -eq 0) {
    Log 'WARNUNG: kein Netzwerk/PXE-Eintrag erkannt -> Bootreihenfolge NICHT geaendert.'
    Log '         (Eintraege oben pruefen; passenden Netz-Eintrag ins $netPattern aufnehmen.)'
    return
}

# Idempotenz: steht bereits ein Netzwerk-Eintrag an erster Stelle? -> nichts schreiben.
$firstId = ([regex]::Match($fwEnum, '(?im)^\s*displayorder\s+(\{[^}]+\})')).Groups[1].Value
if ($net.id -contains $firstId) { Log ('Netzwerk steht bereits vorn ({0}) -> ok, keine NVRAM-Aenderung.' -f $firstId); return }

# Reihenfolge korrigieren: Windows Boot Manager ans Ende, Netzwerk-Eintraege nach vorne.
if ($bootmgrId) { & $bcd /set "{fwbootmgr}" displayorder $bootmgrId /addlast | Out-Null; Log ('Windows Boot Manager ans Ende: {0}' -f $bootmgrId) }
for ($i = $net.Count - 1; $i -ge 0; $i--) {   # rueckwaerts /addfirst -> erster gefundener steht zuerst
    & $bcd /set "{fwbootmgr}" displayorder $net[$i].id /addfirst | Out-Null
    Log ('Netzwerk nach vorne: {0}  ({1})' -f $net[$i].id, $net[$i].desc)
}
Log ('Neue Reihenfolge: ' + ((& $bcd /enum "{fwbootmgr}" 2>$null) -join ' | '))
Log '--- Ende ---'

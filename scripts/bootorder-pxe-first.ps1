# bootorder-pxe-first.ps1 — Computer-Start- UND Shutdown-Skript (linuxmuster-gpo-template),
# laeuft als SYSTEM beim Boot und beim Herunterfahren (letzte Aktion vor dem Ausschalten,
# damit der naechste Boot zuverlaessig PXE nimmt, falls Windows die Reihenfolge waehrend der
# Sitzung umgestellt hat). Zweck: UEFI-Bootreihenfolge so setzen, dass Netzwerk/PXE ZUERST bootet
# (-> LINBO) und der Windows Boot Manager ZULETZT. Windows draengt seinen Boot Manager sonst
# nach jedem Start wieder an die erste Stelle; dieses Skript korrigiert das bei jedem Boot.
#
# "Richtig gemacht":
#  - ruft IMMER die 64-bit bcdedit auf (auch aus 32-bit-PowerShell -> Sysnative statt SysWOW64),
#  - erkennt Netzwerk-Eintraege ueber viele zuverlaessige Muster (IPV4/IPV6/PXE/LAN/...),
#    verdrahtet KEINE GUIDs fest (die sind pro Firmware/Geraet verschieden),
#  - locale-tolerant (DE/EN bcdedit-Ausgabe),
#  - idempotent: schreibt die UEFI-NVRAM nur, wenn nicht ohnehin schon ein Netzwerk-Eintrag
#    vorn steht (schont die begrenzten NVRAM-Schreibzyklen),
#  - nicht-destruktiv: nutzt /addfirst /addlast (loescht keine anderen Eintraege wie USB/HDD),
#  - bricht den Boot NIE ab; alles wird nach %SystemRoot%\Temp\lmgpo-bootorder.log geloggt
#    (inkl. ALLER gefundenen Eintraege + Rohausgaben zur Diagnose).
$ErrorActionPreference = 'SilentlyContinue'
$log = Join-Path $env:SystemRoot 'Temp\lmgpo-bootorder.log'
function Log($m) { try { ('{0}  {1}' -f (Get-Date -Format 's'), $m) | Out-File -LiteralPath $log -Append -Encoding utf8 } catch {} }

Log '--- Start bootorder-pxe-first ---'

# bcdedit robust: aus einem 32-bit-Prozess wird System32\bcdedit.exe nach SysWOW64 umgeleitet
# (dort gibt es KEIN bcdedit) -> leere Ausgabe. Ueber Sysnative die echte 64-bit bcdedit nutzen.
$bcd = Join-Path $env:SystemRoot 'System32\bcdedit.exe'
if (-not [Environment]::Is64BitProcess -and [Environment]::Is64BitOperatingSystem) {
    $sn = Join-Path $env:SystemRoot 'Sysnative\bcdedit.exe'
    if (Test-Path -LiteralPath $sn) { $bcd = $sn }
}
Log ('bcdedit={0} | 64bit-Prozess={1} | 64bit-OS={2}' -f $bcd, [Environment]::Is64BitProcess, [Environment]::Is64BitOperatingSystem)

# UEFI vs. BIOS zuverlaessig ueber die Registry (PEFirmwareType: 1=BIOS/Legacy, 2=UEFI).
$peType = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control' -Name PEFirmwareType -ErrorAction SilentlyContinue).PEFirmwareType
Log ('PEFirmwareType={0} (1=BIOS/Legacy, 2=UEFI)' -f $peType)

# {fwbootmgr} existiert nur auf UEFI. Rohausgabe (inkl. Fehler via 2>&1) fuer die Diagnose loggen.
$fwEnum = (& $bcd /enum "{fwbootmgr}" 2>&1 | Out-String)
Log ("bcdedit /enum {fwbootmgr} (roh):`n" + $fwEnum.Trim())
if ($fwEnum -notmatch 'fwbootmgr') {
    if ($peType -eq 2) { Log 'ABBRUCH: PEFirmwareType=UEFI, aber {fwbootmgr} nicht lesbar — bcdedit-Rohausgabe oben pruefen.' }
    else { Log 'ABBRUCH: Kein UEFI (PEFirmwareType != 2) -> hier ist nichts zu setzen (Legacy/BIOS-Bootreihenfolge liegt nicht in der NVRAM).' }
    return
}

# Netzwerk/PXE-Muster: zuverlaessige, eindeutige Netzwerk-Indikatoren (case-insensitive).
# Bewusst OHNE mehrdeutige Hersteller-Namen (Intel-SSD, Broadcom-HBA waeren Fehltreffer) —
# stattdessen wird jeder Eintrag geloggt; fehlt ein Netz-Eintrag im Match, hier ergaenzen.
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

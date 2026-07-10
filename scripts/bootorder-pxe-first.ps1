# bootorder-pxe-first.ps1 — Computer-Startskript (linuxmuster-gpo-template), laeuft als
# SYSTEM beim Boot. Zweck: UEFI-Bootreihenfolge so setzen, dass Netzwerk/PXE ZUERST bootet
# (-> LINBO) und der Windows Boot Manager ZULETZT. Windows draengt seinen Boot Manager sonst
# nach jedem Start wieder an die erste Stelle; dieses Skript korrigiert das bei jedem Boot.
#
# "Richtig gemacht":
#  - erkennt Netzwerk-Eintraege ueber viele zuverlaessige Muster (IPV4/IPV6/PXE/LAN/...),
#    verdrahtet KEINE GUIDs fest (die sind pro Firmware/Geraet verschieden),
#  - locale-tolerant (DE/EN bcdedit-Ausgabe),
#  - idempotent: schreibt die UEFI-NVRAM nur, wenn nicht ohnehin schon ein Netzwerk-Eintrag
#    vorn steht (schont die begrenzten NVRAM-Schreibzyklen),
#  - nicht-destruktiv: nutzt /addfirst /addlast (loescht keine anderen Eintraege wie USB/HDD),
#  - bricht den Boot NIE ab; alles wird nach %SystemRoot%\Temp\lmgpo-bootorder.log geloggt
#    (inkl. ALLER gefundenen Eintraege — so ist eine Fehlerkennung sichtbar und ein Muster
#    laesst sich gezielt ergaenzen).
$ErrorActionPreference = 'SilentlyContinue'
$log = Join-Path $env:SystemRoot 'Temp\lmgpo-bootorder.log'
function Log($m) { try { ('{0}  {1}' -f (Get-Date -Format 's'), $m) | Out-File -LiteralPath $log -Append -Encoding utf8 } catch {} }

Log '--- Start bootorder-pxe-first ---'

# Nur UEFI: {fwbootmgr} existiert nur auf UEFI-Systemen (bei BIOS/Legacy nichts tun).
$fwEnum = (& bcdedit /enum "{fwbootmgr}" 2>$null) -join "`n"
if ($fwEnum -notmatch 'fwbootmgr') { Log 'Kein UEFI/{fwbootmgr} -> nichts zu tun (BIOS/Legacy?).'; return }

# Netzwerk/PXE-Muster: zuverlaessige, eindeutige Netzwerk-Indikatoren (case-insensitive).
# Bewusst OHNE mehrdeutige Hersteller-Namen (Intel-SSD, Broadcom-HBA waeren Fehltreffer) —
# stattdessen wird jeder Eintrag geloggt; fehlt ein Netz-Eintrag im Match, hier ergaenzen.
$netPattern = '(?i)\bIPV?4\b|\bIPV?6\b|\bIP4\b|\bIP6\b|PXE|Network|Netzwerk|\bLAN\b|Ethernet'

# Firmware-Eintraege zeilenweise parsen: identifier steht je Block VOR description.
$curId = $null
$net = New-Object System.Collections.Generic.List[object]
$bootmgrId = $null
foreach ($line in (& bcdedit /enum firmware 2>$null)) {
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
    Log '         (Log oben pruefen; passenden Netz-Eintrag ins $netPattern aufnehmen.)'
    return
}

# Idempotenz: steht bereits ein Netzwerk-Eintrag an erster Stelle? -> nichts schreiben.
$firstId = ([regex]::Match($fwEnum, '(?im)^\s*displayorder\s+(\{[^}]+\})')).Groups[1].Value
if ($net.id -contains $firstId) { Log ('Netzwerk steht bereits vorn ({0}) -> ok, keine NVRAM-Aenderung.' -f $firstId); return }

# Reihenfolge korrigieren: Windows Boot Manager ans Ende, Netzwerk-Eintraege nach vorne.
if ($bootmgrId) { & bcdedit /set "{fwbootmgr}" displayorder $bootmgrId /addlast | Out-Null; Log ('Windows Boot Manager ans Ende: {0}' -f $bootmgrId) }
for ($i = $net.Count - 1; $i -ge 0; $i--) {   # rueckwaerts /addfirst -> erster gefundener steht zuerst
    & bcdedit /set "{fwbootmgr}" displayorder $net[$i].id /addfirst | Out-Null
    Log ('Netzwerk nach vorne: {0}  ({1})' -f $net[$i].id, $net[$i].desc)
}
Log ('Neue Reihenfolge: ' + ((& bcdedit /enum "{fwbootmgr}" 2>$null) -join ' | '))
Log '--- Ende ---'

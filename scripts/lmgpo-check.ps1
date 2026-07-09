<#
.SYNOPSIS
    Prüft auf einem domänenverbundenen Windows-11-Client, welche LMN-*-GPOs
    angekommen sind und ob die Einstellungen tatsächlich wirken.

.DESCRIPTION
    REIN LESEND. Es wird nichts verändert. Nur mit dem Schalter -Refresh wird
    vorab ein 'gpupdate /force' ausgeführt (Standard-Windows-Refresh, harmlos).

    Als Administrator ausführen (für 'gpresult /scope computer' + Firewall/Gruppen).

.PARAMETER Refresh
    Führt vor der Prüfung 'gpupdate /force' aus (empfohlen für einen frischen Stand).

.PARAMETER ReportPath
    Pfad für den vollständigen HTML-GPO-Bericht (Default: .\lmgpo-gpresult.html).

.PARAMETER WlanCaSubject
    Optional: Subject (bzw. Teil davon) des RADIUS-CA-Zertifikats, das für das
    Lehrer-Enterprise-WLAN im Trusted-Root-Store des Rechners liegen soll. Prüft dessen Vorhandensein.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File lmgpo-check.ps1 -Refresh -WlanCaSubject "RADIUS CA"
#>
[CmdletBinding()]
param(
    [switch]$Refresh,
    [switch]$NoReport,
    [string]$ReportPath = ".\lmgpo-gpresult.html",
    [string]$WlanCaSubject = ""
)

$ErrorActionPreference = 'Continue'
$ok = 0; $fail = 0; $skip = 0

function Write-Head($t) { Write-Host "`n=== $t ===" -ForegroundColor Cyan }
function Mark($cond) { if ($cond) { "[OK] " } else { "[!!] " } }

# --- Adminrechte? -----------------------------------------------------------
$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "WARNUNG: nicht als Administrator gestartet — Computer-GPOs, Firewall" -ForegroundColor Yellow
    Write-Host "         und Gruppen-Prüfungen sind evtl. unvollständig.`n" -ForegroundColor Yellow
}

# --- optionaler Refresh (einzige nicht-lesende Aktion, nur mit -Refresh) -----
if ($Refresh) {
    Write-Head "gpupdate /force (nur wegen -Refresh)"
    gpupdate /force | Out-Host
}

# --- 1) Angewandte LMN-GPOs (gpresult) --------------------------------------
Write-Head "Angewandte LMN-*-GPOs (gpresult)"
$gp = & gpresult /r /scope computer 2>$null
$applied = @(); $denied = @()
$section = ""
foreach ($line in $gp) {
    if ($line -match "Applied Group Policy Objects|Angewendete Gruppenrichtlinienobjekte") { $section = "applied"; continue }
    if ($line -match "were filtered out|herausgefiltert")                                  { $section = "denied";  continue }
    if ($line -match "The (computer|following)|Die folgenden")                             { $section = "" }
    $t = $line.Trim()
    if ($t -like "LMN-*") { if ($section -eq "applied") { $applied += $t } elseif ($section -eq "denied") { $denied += $t } }
}
if ($applied) { $applied | Sort-Object -Unique | ForEach-Object { Write-Host "  [OK] angewandt:  $_" -ForegroundColor Green } }
else { Write-Host "  [!!] Keine LMN-GPO als 'angewandt' gefunden (Computerscope)." -ForegroundColor Red }
if ($denied) { $denied | Sort-Object -Unique | ForEach-Object { Write-Host "  [--] gefiltert:  $_ (z.B. per Deny-Apply, das kann korrekt sein)" -ForegroundColor DarkGray } }

# --- 2) Ist-Werte vs. Soll-Werte (Registry) ---------------------------------
Write-Head "Registry-Ist-Werte vs. Soll"
$checks = @(
    @{ N="Telemetrie aus";           P="HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"; K="AllowTelemetry"; E=0 }
    @{ N="Auto-Update aus (LINBO)";  P="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"; K="NoAutoUpdate"; E=1 }
    @{ N="RDP aktiviert";            P="HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"; K="fDenyTSConnections"; E=0 }
    @{ N="Sperre nach 30 Min";       P="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; K="InactivityTimeoutSecs"; E=1800 }
    @{ N="Sperrbildschirm weg";      P="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization"; K="NoLockScreen"; E=1 }
    @{ N="Standby=Nie (AC)";         P="HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\29f6c1db-86da-48c5-9fdb-f2b67b1f44da"; K="ACSettingIndex"; E=0 }
    @{ N="Display aus 1800s (AC)";   P="HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e"; K="ACSettingIndex"; E=1800 }
    @{ N="Fast Startup aus";         P="HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power"; K="HiberbootEnabled"; E=0 }
    @{ N="MS-Konten blockiert";      P="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; K="NoConnectedUser"; E=3 }
    @{ N="Wallpaper gesetzt (User)"; P="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; K="Wallpaper"; E=$null }
)
foreach ($c in $checks) {
    $v = (Get-ItemProperty -Path $c.P -Name $c.K -ErrorAction SilentlyContinue).($c.K)
    if ($null -eq $v) { Write-Host ("  [--] {0,-26} nicht gesetzt (GPO evtl. nicht auf dieses Gerät gefiltert)" -f $c.N) -ForegroundColor DarkGray; $skip++; continue }
    $good = ($null -eq $c.E) -or ("$v" -eq "$($c.E)")
    if ($good) { Write-Host ("  {0}{1,-26} = {2}" -f (Mark $true), $c.N, $v) -ForegroundColor Green; $ok++ }
    else       { Write-Host ("  {0}{1,-26} = {2}  (erwartet {3})" -f (Mark $false), $c.N, $v, $c.E) -ForegroundColor Red; $fail++ }
}

# --- 3) Firewall-Regeln (LMN-*) ---------------------------------------------
Write-Head "Windows-Firewall: LMN-Regeln"
$fw = Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like "LMN *" -or $_.Name -like "LMN-*" }
if ($fw) { $fw | ForEach-Object { Write-Host ("  {0}{1}  ({2}, {3})" -f (Mark ($_.Enabled -eq 'True')), $_.DisplayName, $_.Direction, $_.Action) -ForegroundColor Green } }
else { Write-Host "  [--] keine LMN-Firewallregeln gefunden (Paket 06 evtl. nicht angewandt)" -ForegroundColor DarkGray }

# --- 4) Lokale Gruppen: Admins + RDP-Users ----------------------------------
Write-Head "Lokale Gruppen (Domänen-Admins/RDP)"
foreach ($grp in @("Administratoren","Administrators","Remotedesktopbenutzer","Remote Desktop Users")) {
    $m = net localgroup "$grp" 2>$null
    if ($LASTEXITCODE -eq 0) {
        $names = $m | Where-Object { $_ -and $_ -notmatch "Alias|Kommentar|Comment|Mitglied|Members|---|erfolgreich|command completed" }
        Write-Host ("  {0}:" -f $grp) -ForegroundColor Cyan
        $names | ForEach-Object { if ($_.Trim()) { Write-Host "     $_" } }
    }
}

# --- 5) Windows-Aktivierung (KMS) -------------------------------------------
Write-Head "Windows-Aktivierung"
(cscript //nologo "$env:windir\System32\slmgr.vbs" /dli 2>$null | Select-String -Pattern "Lizenz|License|aktivier|activat") | ForEach-Object { Write-Host "  $_" }

# --- 6) WLAN (Profile / aktuelle Verbindung / RADIUS-CA) --------------------
Write-Head "WLAN-Profile"
$rawProfiles = netsh wlan show profiles 2>$null
if ($LASTEXITCODE -ne 0 -or -not $rawProfiles) {
    Write-Host "  [--] Kein WLAN-Dienst/Adapter (z.B. Desktop/VM) — WLAN-Prüfung übersprungen." -ForegroundColor DarkGray
} else {
    $wlanProfiles = @()
    foreach ($line in $rawProfiles) { if ($line -match 'Profil.*:\s*(.+?)\s*$') { $wlanProfiles += $matches[1].Trim() } }
    $wlanProfiles = @($wlanProfiles | Sort-Object -Unique)
    if (-not $wlanProfiles) { Write-Host "  [--] Keine WLAN-Profile hinterlegt (13-wlan-* evtl. nicht angewandt)." -ForegroundColor DarkGray }
    foreach ($p in $wlanProfiles) {
        $d = netsh wlan show profile name="$p" 2>$null
        $authM = ($d | Select-String -Pattern 'WPA3-Enterprise|WPA2-Enterprise|WPA3-Personal|WPA2-Personal|WPA-Personal|Open' | Select-Object -First 1)
        $eapM  = ($d | Select-String -Pattern 'PEAP|EAP-TLS|EAP-TTLS' | Select-Object -First 1)
        $auth  = if ($authM) { $authM.Matches[0].Value } else { "?" }
        $eap   = if ($eapM)  { " EAP=" + $eapM.Matches[0].Value } else { "" }
        $isEnt = $auth -match 'Enterprise'
        Write-Host ("  Profil: {0,-22} [{1}]{2}" -f $p, $auth, $eap) -ForegroundColor $(if ($isEnt) { "Cyan" } else { "Green" })
    }
    Write-Head "WLAN-Verbindung (aktuell)"
    $iface = netsh wlan show interfaces 2>$null
    $shown = ($iface | Select-String -Pattern 'SSID|State|Status|Authentifiz|Authentication|Signal')
    if ($shown) { $shown | ForEach-Object { Write-Host "     $($_.Line.Trim())" } }
    else { Write-Host "     (nicht verbunden)" -ForegroundColor DarkGray }
}
if ($WlanCaSubject) {
    Write-Head "RADIUS-CA-Zertifikat (Trusted Root, für Lehrer-Enterprise-WLAN)"
    $ca = Get-ChildItem Cert:\LocalMachine\Root -ErrorAction SilentlyContinue | Where-Object { $_.Subject -match [regex]::Escape($WlanCaSubject) }
    if ($ca) { Write-Host ("  {0}RADIUS-CA vorhanden: {1}  (Thumbprint {2})" -f (Mark $true), $ca[0].Subject, $ca[0].Thumbprint) -ForegroundColor Green; $ok++ }
    else     { Write-Host ("  {0}RADIUS-CA '{1}' NICHT im Trusted-Root-Store" -f (Mark $false), $WlanCaSubject) -ForegroundColor Red; $fail++ }
}

# --- 7) Voller HTML-Bericht (Ausgabedatei; mit -NoReport überspringbar) ------
if (-not $NoReport) {
    Write-Head "Vollständiger GPO-Bericht"
    try { gpresult /h $ReportPath /f | Out-Null; Write-Host "  geschrieben: $ReportPath" -ForegroundColor Green } catch { Write-Host "  HTML-Bericht fehlgeschlagen: $_" -ForegroundColor Yellow }
}

Write-Host "`n===================================================" -ForegroundColor Cyan
Write-Host ("Ergebnis: {0} OK, {1} FEHLER, {2} nicht gesetzt/übersprungen" -f $ok, $fail, $skip) -ForegroundColor $(if ($fail) { "Red" } else { "Green" })
$changed = @()
if (-not $NoReport) { $changed += "HTML-Bericht $ReportPath geschrieben" }
if ($Refresh)       { $changed += "gpupdate /force ausgeführt (angefordert)" }
if ($changed) { Write-Host ("Keine System-/GPO-Einstellungen verändert. Ausgabe: " + ($changed -join "; ") + ".") -ForegroundColor DarkGray }
else          { Write-Host "Rein lesend — nichts verändert, keine Datei geschrieben." -ForegroundColor DarkGray }
exit $(if ($fail) { 1 } else { 0 })

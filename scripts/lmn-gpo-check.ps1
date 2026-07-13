<#
.SYNOPSIS
    Checks on a domain-joined Windows 11 client which LMN-* GPOs have arrived and
    whether the settings actually take effect.

.DESCRIPTION
    READ-ONLY. Nothing is changed. Only with the -Refresh switch is a 'gpupdate /force'
    run first (standard Windows refresh, harmless).

    Covers computer AND user policies: privacy, update split, power/lock, RDP/firewall/
    groups, KMS, hotspot block, OneDrive, hibernation, loopback, Firefox, role proxy,
    student lockdown (HKCU), Veyon, Wi-Fi, time sync (W32Time) and the boot-order
    startup-script log.

    Run twice: (1) as ADMINISTRATOR for computer GPOs/firewall/groups,
    (2) as the logged-in STUDENT (not elevated) for the user restrictions (lockdown/proxy).

.PARAMETER Refresh
    Runs 'gpupdate /force' before checking (recommended for a fresh state).

.PARAMETER ReportPath
    Path for the full HTML GPO report (default: .\lmn-gpo-gpresult.html).

.PARAMETER WlanCaSubject
    Optional: subject (or part of it) of the RADIUS CA certificate that should be in the
    machine's Trusted Root store for the teacher enterprise Wi-Fi. Checks its presence.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File lmn-gpo-check.ps1 -Refresh -WlanCaSubject "RADIUS CA"
#>
[CmdletBinding()]
param(
    [switch]$Refresh,
    [switch]$NoReport,
    [string]$ReportPath = ".\lmn-gpo-gpresult.html",
    [string]$WlanCaSubject = ""
)

$ErrorActionPreference = 'Continue'
$ok = 0; $fail = 0; $skip = 0

function Write-Head($t) { Write-Host "`n=== $t ===" -ForegroundColor Cyan }
function Mark($cond) { if ($cond) { "[OK] " } else { "[!!] " } }
function Test-Reg($c) {
    # $c = @{ N=name; P=regPath; K=valueName; E=expected (or $null = only 'is set') }
    $v = (Get-ItemProperty -Path $c.P -Name $c.K -ErrorAction SilentlyContinue).($c.K)
    if ($null -eq $v) {
        Write-Host ("  [--] {0,-30} not set (GPO may not be filtered to this device/user)" -f $c.N) -ForegroundColor DarkGray
        $script:skip++; return
    }
    if (($null -eq $c.E) -or ("$v" -eq "$($c.E)")) {
        Write-Host ("  {0}{1,-30} = {2}" -f (Mark $true), $c.N, $v) -ForegroundColor Green; $script:ok++
    } else {
        Write-Host ("  {0}{1,-30} = {2}  (expected {3})" -f (Mark $false), $c.N, $v, $c.E) -ForegroundColor Red; $script:fail++
    }
}

# --- Admin rights? ----------------------------------------------------------
$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "WARNING: not started as Administrator — computer GPOs, firewall" -ForegroundColor Yellow
    Write-Host "         and group checks may be incomplete.`n" -ForegroundColor Yellow
}

# --- optional refresh (the only non-read-only action, only with -Refresh) -----
if ($Refresh) {
    Write-Head "gpupdate /force (because of -Refresh)"
    gpupdate /force | Out-Host
}

# --- 1) Applied LMN GPOs (gpresult) -----------------------------------------
Write-Head "Applied LMN-* GPOs (gpresult)"
$gp = & gpresult /r /scope computer 2>$null
$applied = @(); $denied = @()
$section = ""
foreach ($line in $gp) {
    # NOTE: the German alternatives match localized gpresult output and MUST stay.
    if ($line -match "Applied Group Policy Objects|Angewendete Gruppenrichtlinienobjekte") { $section = "applied"; continue }
    if ($line -match "were filtered out|herausgefiltert")                                  { $section = "denied";  continue }
    if ($line -match "The (computer|following)|Die folgenden")                             { $section = "" }
    $t = $line.Trim()
    if ($t -like "LMN-*") { if ($section -eq "applied") { $applied += $t } elseif ($section -eq "denied") { $denied += $t } }
}
if ($applied) { $applied | Sort-Object -Unique | ForEach-Object { Write-Host "  [OK] applied:   $_" -ForegroundColor Green } }
else { Write-Host "  [!!] No LMN GPO found as 'applied' (computer scope)." -ForegroundColor Red }
if ($denied) { $denied | Sort-Object -Unique | ForEach-Object { Write-Host "  [--] filtered:  $_ (e.g. via deny-apply, which can be correct)" -ForegroundColor DarkGray } }

# --- 1b) Applied LMN GPOs (user scope) --------------------------------------
Write-Head "Applied LMN-* GPOs (user scope)"
Write-Host "  Note: running as the logged-in STUDENT/teacher shows THEIR user GPOs (lockdown/proxy/Firefox)." -ForegroundColor DarkGray
$gpu = & gpresult /r /scope user 2>$null
$uapplied = @(); $usec = ""
foreach ($line in $gpu) {
    if ($line -match "Applied Group Policy Objects|Angewendete Gruppenrichtlinienobjekte") { $usec = "applied"; continue }
    if ($line -match "were filtered out|herausgefiltert")                                  { $usec = "denied";  continue }
    if ($line -match "The (user|following)|Die folgenden")                                 { $usec = "" }
    $t = $line.Trim()
    if ($t -like "LMN-*" -and $usec -eq "applied") { $uapplied += $t }
}
if ($uapplied) { $uapplied | Sort-Object -Unique | ForEach-Object { Write-Host "  [OK] applied:   $_" -ForegroundColor Green } }
else { Write-Host "  [--] No LMN user GPO applied (run as student/teacher; otherwise no user packs active)." -ForegroundColor DarkGray }

# --- 2) Actual vs. expected values (registry) -------------------------------
Write-Head "Registry actual vs. expected"
$checks = @(
    @{ N="Telemetry off";            P="HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"; K="AllowTelemetry"; E=0 }
    @{ N="Auto-update off (LINBO)";  P="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"; K="NoAutoUpdate"; E=1 }
    @{ N="RDP enabled";              P="HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"; K="fDenyTSConnections"; E=0 }
    @{ N="Lock after 30 min";        P="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; K="InactivityTimeoutSecs"; E=1800 }
    @{ N="Lock screen removed";      P="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization"; K="NoLockScreen"; E=1 }
    @{ N="Standby=Never (AC)";       P="HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\29f6c1db-86da-48c5-9fdb-f2b67b1f44da"; K="ACSettingIndex"; E=0 }
    @{ N="Display off 1800s (AC)";   P="HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e"; K="ACSettingIndex"; E=1800 }
    @{ N="Fast Startup off";         P="HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power"; K="HiberbootEnabled"; E=0 }
    @{ N="MS accounts blocked";      P="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; K="NoConnectedUser"; E=3 }
    @{ N="Wallpaper set (user)";     P="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; K="Wallpaper"; E=$null }
    @{ N="Mobile hotspot prohibited"; P="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections"; K="NC_ShowSharedAccessUI"; E=0 }
    @{ N="OneDrive sync off";        P="HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive"; K="DisableFileSyncNGSC"; E=1 }
    @{ N="Hibernation off (hib.)";   P="HKLM:\SYSTEM\CurrentControlSet\Control\Power"; K="HibernateEnabled"; E=0 }
    @{ N="Loopback merge active";    P="HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"; K="UserPolicyMode"; E=2 }
    @{ N="Proxy per-user enforced";  P="HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings"; K="ProxySettingsPerUser"; E=1 }
    @{ N="Firefox first-run off";    P="HKLM:\SOFTWARE\Policies\Mozilla\Firefox"; K="DontCheckDefaultBrowser"; E=1 }
    @{ N="KMS host set";             P="HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform"; K="KeyManagementServiceName"; E=$null }
)
Write-Host "  (Note: some apply filtered — e.g. hibernation NOT on noPXE, loopback/hotspot per pack.)" -ForegroundColor DarkGray
foreach ($c in $checks) { Test-Reg $c }

# --- 3) Firewall rules (LMN-*) ----------------------------------------------
Write-Head "Windows firewall: LMN rules"
$fw = Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like "LMN *" -or $_.Name -like "LMN-*" }
if ($fw) { $fw | ForEach-Object { Write-Host ("  {0}{1}  ({2}, {3})" -f (Mark ($_.Enabled -eq 'True')), $_.DisplayName, $_.Direction, $_.Action) -ForegroundColor Green } }
else { Write-Host "  [--] no LMN firewall rules found (package 06 may not be applied)" -ForegroundColor DarkGray }

# --- 4) Local groups: admins + RDP users ------------------------------------
Write-Head "Local groups (domain admins / RDP)"
# The group names below are the localized Windows group names — keep both DE and EN.
foreach ($grp in @("Administratoren","Administrators","Remotedesktopbenutzer","Remote Desktop Users")) {
    $m = net localgroup "$grp" 2>$null
    if ($LASTEXITCODE -eq 0) {
        # -notmatch filters localized 'net localgroup' header/footer lines (DE + EN) — keep as is.
        $names = $m | Where-Object { $_ -and $_ -notmatch "Alias|Kommentar|Comment|Mitglied|Members|---|erfolgreich|command completed" }
        Write-Host ("  {0}:" -f $grp) -ForegroundColor Cyan
        $names | ForEach-Object { if ($_.Trim()) { Write-Host "     $_" } }
    }
}

# --- 5) Windows activation (KMS) --------------------------------------------
Write-Head "Windows activation"
# 'Lizenz|aktivier' match localized slmgr output — keep.
(cscript //nologo "$env:windir\System32\slmgr.vbs" /dli 2>$null | Select-String -Pattern "Lizenz|License|aktivier|activat") | ForEach-Object { Write-Host "  $_" }

# --- 6) Wi-Fi (profiles / current connection / RADIUS CA) -------------------
Write-Head "Wi-Fi profiles"
$rawProfiles = netsh wlan show profiles 2>$null
if ($LASTEXITCODE -ne 0 -or -not $rawProfiles) {
    Write-Host "  [--] No Wi-Fi service/adapter (e.g. desktop/VM) — Wi-Fi check skipped." -ForegroundColor DarkGray
} else {
    $wlanProfiles = @()
    # 'Profil.*:' matches localized netsh output (DE 'Profil', EN 'Profile') — keep.
    foreach ($line in $rawProfiles) { if ($line -match 'Profil.*:\s*(.+?)\s*$') { $wlanProfiles += $matches[1].Trim() } }
    $wlanProfiles = @($wlanProfiles | Sort-Object -Unique)
    if (-not $wlanProfiles) { Write-Host "  [--] No Wi-Fi profiles present (13-wlan-* may not be applied)." -ForegroundColor DarkGray }
    foreach ($p in $wlanProfiles) {
        $d = netsh wlan show profile name="$p" 2>$null
        $authM = ($d | Select-String -Pattern 'WPA3-Enterprise|WPA2-Enterprise|WPA3-Personal|WPA2-Personal|WPA-Personal|Open' | Select-Object -First 1)
        $eapM  = ($d | Select-String -Pattern 'PEAP|EAP-TLS|EAP-TTLS' | Select-Object -First 1)
        $auth  = if ($authM) { $authM.Matches[0].Value } else { "?" }
        $eap   = if ($eapM)  { " EAP=" + $eapM.Matches[0].Value } else { "" }
        $isEnt = $auth -match 'Enterprise'
        Write-Host ("  Profile: {0,-22} [{1}]{2}" -f $p, $auth, $eap) -ForegroundColor $(if ($isEnt) { "Cyan" } else { "Green" })
    }
    Write-Head "Wi-Fi connection (current)"
    $iface = netsh wlan show interfaces 2>$null
    # 'Authentifiz' matches localized netsh output — keep.
    $shown = ($iface | Select-String -Pattern 'SSID|State|Status|Authentifiz|Authentication|Signal')
    if ($shown) { $shown | ForEach-Object { Write-Host "     $($_.Line.Trim())" } }
    else { Write-Host "     (not connected)" -ForegroundColor DarkGray }
}
if ($WlanCaSubject) {
    Write-Head "RADIUS CA certificate (Trusted Root, for teacher enterprise Wi-Fi)"
    $ca = Get-ChildItem Cert:\LocalMachine\Root -ErrorAction SilentlyContinue | Where-Object { $_.Subject -match [regex]::Escape($WlanCaSubject) }
    if ($ca) { Write-Host ("  {0}RADIUS CA present: {1}  (thumbprint {2})" -f (Mark $true), $ca[0].Subject, $ca[0].Thumbprint) -ForegroundColor Green; $ok++ }
    else     { Write-Host ("  {0}RADIUS CA '{1}' NOT in the Trusted Root store" -f (Mark $false), $WlanCaSubject) -ForegroundColor Red; $fail++ }
}

# --- 6b) User policies (HKCU): student lockdown & role proxy ----------------
Write-Head "User policies (HKCU) — apply to students only (role-student)"
Write-Host "  Run as the logged-in STUDENT (not elevated), otherwise you see your own view." -ForegroundColor DarkGray
$uchecks = @(
    @{ N="Proxy not changeable";      P="HKCU:\SOFTWARE\Policies\Microsoft\Internet Explorer\Control Panel"; K="Proxy"; E=1 }
    @{ N="Connections tab locked";    P="HKCU:\SOFTWARE\Policies\Microsoft\Internet Explorer\Control Panel"; K="ConnectionsTab"; E=1 }
    @{ N="Registry Editor locked";    P="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; K="DisableRegistryTools"; E=2 }
    @{ N="WinINET proxy active";      P="HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"; K="ProxyEnable"; E=1 }
    @{ N="Proxy server (role)";       P="HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"; K="ProxyServer"; E=$null }
)
foreach ($c in $uchecks) { Test-Reg $c }

# --- 6c) Veyon (classroom management) ---------------------------------------
Write-Head "Veyon (LDAP directory, teachers only)"
if (Test-Path "HKLM:\SOFTWARE\Veyon Solutions\Veyon\LDAP") {
    Test-Reg @{ N="Veyon LDAP ServerHost";     P="HKLM:\SOFTWARE\Veyon Solutions\Veyon\LDAP"; K="ServerHost"; E=$null }
    Test-Reg @{ N="Veyon LDAPS (Security=2)";  P="HKLM:\SOFTWARE\Veyon Solutions\Veyon\LDAP"; K="ConnectionSecurity"; E=2 }
    Test-Reg @{ N="Authorized groups only";    P="HKLM:\SOFTWARE\Veyon Solutions\Veyon\AccessControl"; K="AccessRestrictedToUserGroups"; E="true" }
    $ag = (Get-ItemProperty "HKLM:\SOFTWARE\Veyon Solutions\Veyon\AccessControl" -Name AuthorizedUserGroups -ErrorAction SilentlyContinue).AuthorizedUserGroups
    if ($ag) { Write-Host ("  [OK] Authorized teacher groups: {0}" -f ($ag -join ', ')) -ForegroundColor Green }
} else { Write-Host "  [--] No Veyon configuration (package 10 not applied)." -ForegroundColor DarkGray }

# --- 6d) Boot order (startup-script log, package 16) ------------------------
Write-Head "Boot order (log of the PXE-first startup script)"
$blog = Join-Path $env:SystemRoot 'Temp\lmn-gpo-bootorder.log'
if (Test-Path $blog) {
    Write-Host "  Last lines from $blog :" -ForegroundColor Cyan
    Get-Content $blog -Tail 12 -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "     $_" }
} else { Write-Host "  [--] No boot-order log (package 16 inactive / script not run yet)." -ForegroundColor DarkGray }

# --- 6e) Time synchronisation (W32Time, package 17) -------------------------
Write-Head "Time synchronisation (W32Time)"
if (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpClient") {
    Test-Reg @{ N="W32Time NTP client active"; P="HKLM:\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpClient"; K="Enabled"; E=1 }
    Test-Reg @{ N="Time mode (Type)";          P="HKLM:\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpClient"; K="Type"; E=$null }
    Test-Reg @{ N="NtpServer (if Type=NTP)";   P="HKLM:\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpClient"; K="NtpServer"; E=$null }
    Test-Reg @{ N="MaxPhaseCorrection (always)"; P="HKLM:\SOFTWARE\Policies\Microsoft\W32Time\Config"; K="MaxPosPhaseCorrection"; E=$null }
} else { Write-Host "  [--] No W32Time policy (package 17 not applied)." -ForegroundColor DarkGray }
# Runtime status (read-only): does the machine actually sync from the server?
$src = ((& w32tm /query /source 2>&1) -join ' ').Trim()
if (-not $src) { Write-Host "  [--] W32Time service not responding." -ForegroundColor DarkGray }
# 'Freilaufend|Lokale CMOS' match localized w32tm output — keep.
elseif ($src -match 'Free-running|Freilaufend|Local CMOS|Lokale CMOS') {
    Write-Host ("  {0}Time source: {1}  (NOT synchronised with the server!)" -f (Mark $false), $src) -ForegroundColor Red; $fail++
} else { Write-Host ("  {0}Time source: {1}" -f (Mark $true), $src) -ForegroundColor Green; $ok++ }
$st = & w32tm /query /status 2>&1
# 'Quelle|Abweichung|Letzte erfolgreiche' match localized w32tm output — keep.
($st | Select-String -Pattern 'Stratum|Source|Quelle|Offset|Abweichung|Last Successful|Letzte erfolgreiche|Poll') | ForEach-Object { Write-Host "     $($_.Line.Trim())" }

# --- 7) Full HTML report (output file; skippable with -NoReport) ------------
if (-not $NoReport) {
    Write-Head "Full GPO report"
    try { gpresult /h $ReportPath /f | Out-Null; Write-Host "  written: $ReportPath" -ForegroundColor Green } catch { Write-Host "  HTML report failed: $_" -ForegroundColor Yellow }
}

Write-Host "`n===================================================" -ForegroundColor Cyan
Write-Host ("Result: {0} OK, {1} FAIL, {2} not set/skipped" -f $ok, $fail, $skip) -ForegroundColor $(if ($fail) { "Red" } else { "Green" })
$changed = @()
if (-not $NoReport) { $changed += "HTML report $ReportPath written" }
if ($Refresh)       { $changed += "gpupdate /force run (requested)" }
if ($changed) { Write-Host ("No system/GPO settings changed. Output: " + ($changed -join "; ") + ".") -ForegroundColor DarkGray }
else          { Write-Host "Read-only — nothing changed, no file written." -ForegroundColor DarkGray }
exit $(if ($fail) { 1 } else { 0 })

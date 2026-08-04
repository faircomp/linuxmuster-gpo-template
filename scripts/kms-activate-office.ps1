# kms-activate-office.ps1 — Activate volume-licensed Microsoft Office against the KMS host
# set via GPO (pack 09b-kms-office). Computer startup script (lmn-gpo).
#
# WHY CIM AND NOT ospp.vbs: ospp.vbs exits 0 on every path (each exit is a bare
# WScript.Quit), so failures are indistinguishable from success; on error paths it can raise
# a MODAL message box, which in session 0 nobody can dismiss; it refuses to run unless
# started by cscript; and it lives in a different folder for MSI vs Click-to-Run and for
# 32- vs 64-bit Office. The CIM call below is exactly what its /act does internally.
#
# Idempotent, language-neutral and throttled: an activated machine exits after one filtered
# CIM query without touching the network; an unactivated one nudges at most every
# $MinRetryHours (the Software Protection service retries every 2 h by itself anyway).
# Log: %SystemRoot%\Temp\lmn-gpo-office-activation.log
$ErrorActionPreference = 'SilentlyContinue'

# Office application ID in SoftwareLicensingProduct — covers Office 2013 through LTSC 2024,
# including volume-licensed Project and Visio. (Windows is 55c92734-…, a separate product.)
$OfficeAppId   = '0ff1ce15-a989-479d-af46-f275c6370663'
$MinRetryHours = 4
$OsppKey       = 'HKLM:\SOFTWARE\Microsoft\OfficeSoftwareProtectionPlatform'
$StateKey      = 'HKLM:\SOFTWARE\lmn-gpo\OfficeActivation'
$log           = Join-Path $env:SystemRoot 'Temp\lmn-gpo-office-activation.log'
function Log($m) { try { ('{0}  {1}' -f (Get-Date -Format 's'), $m) | Out-File -LiteralPath $log -Append -Encoding utf8 } catch {} }

# Language-neutral selection: the application ID is a GUID, PartialProductKey proves a key is
# installed, and VOLUME_KMSCLIENT is a non-localized channel token. The channel filter also
# excludes MAK, retail and Microsoft 365 Apps, so this script can never trigger an online
# activation against Microsoft's servers.
$products = @(Get-CimInstance -ClassName SoftwareLicensingProduct -OperationTimeoutSec 120 `
    -Filter "ApplicationId='$OfficeAppId' AND PartialProductKey IS NOT NULL" |
    Where-Object { $_.Description -like '*VOLUME_KMSCLIENT*' })
if ($products.Count -eq 0) { return }   # no volume-licensed Office on this machine

# LicenseStatus 1 = Licensed. A freshly installed GVLK Office sits at 2 (OOBGrace), NOT 0 —
# so the gate must be "-ne 1"; testing for 0 would make this script a permanent no-op.
$pending = @($products | Where-Object { $_.LicenseStatus -ne 1 })
if ($pending.Count -eq 0) { return }    # already activated -> real no-op, no network access

# Throttle across reboots so a lab still below the KMS count threshold does not hammer the host.
$last = (Get-ItemProperty -LiteralPath $StateKey -Name LastAttemptUtc -ErrorAction SilentlyContinue).LastAttemptUtc
if ($last) {
    $lastDt = [datetime]::MinValue
    if ([datetime]::TryParse($last, [ref]$lastDt) -and
        ((Get-Date).ToUniversalTime() - $lastDt.ToUniversalTime()).TotalHours -lt $MinRetryHours) { return }
}

# KMS host/port as configured by the GPO; fall back to whatever the client discovered via DNS.
$kmsHost = (Get-ItemProperty -LiteralPath $OsppKey -Name KeyManagementServiceName -ErrorAction SilentlyContinue).KeyManagementServiceName
$kmsPort = (Get-ItemProperty -LiteralPath $OsppKey -Name KeyManagementServicePort -ErrorAction SilentlyContinue).KeyManagementServicePort
if (-not $kmsHost) { $kmsHost = $pending[0].DiscoveredKeyManagementServiceMachineName }
if (-not $kmsPort) { $kmsPort = 1688 }

# At boot the network is frequently not up yet — that is the usual cause of 0xC004F074
# ("no KMS could be contacted"). Probe first and leave quietly instead of logging a scary
# failure; the client retries on its own every two hours.
if ($kmsHost) {
    $reachable = $false
    $tcp = New-Object System.Net.Sockets.TcpClient
    try { $reachable = $tcp.ConnectAsync($kmsHost, [int]$kmsPort).Wait(3000) -and $tcp.Connected }
    catch { $reachable = $false }
    finally { $tcp.Dispose() }
    if (-not $reachable) { Log ("KMS host {0}:{1} not reachable yet — skipped." -f $kmsHost, $kmsPort); return }
}

try { if (-not (Test-Path -LiteralPath $StateKey)) { New-Item -Path $StateKey -Force | Out-Null } } catch {}
Set-ItemProperty -LiteralPath $StateKey -Name LastAttemptUtc `
    -Value ((Get-Date).ToUniversalTime().ToString('o')) -Force

foreach ($p in $pending) {
    $r = $p | Invoke-CimMethod -MethodName Activate
    Log ("Activate '{0}' (was LicenseStatus {1}) -> returnValue {2}" -f $p.Name, $p.LicenseStatus, $r.ReturnValue)
}

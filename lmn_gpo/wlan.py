"""WLAN profile generation for GPO deployment via computer startup scripts.

We deploy WLAN via `netsh wlan add profile ... user=all` (machine/all-user profiles
connect BEFORE login) rather than the native "Wireless Network Policies" (which is an
AD object that can't be authored from a Samba DC without Windows GPMC).

Two modes:
- PSK (WPA2-Personal): student notebooks. Multiple SSIDs (all sites), auto-connect.
- Enterprise (WPA2/802.1X, PEAP-MSCHAPv2, USER auth + SSO preLogon): teacher notebooks.
  RADIUS enforces "only teachers"; the client just presents the logged-in user's creds.
  Needs ONLY the RADIUS CA cert (no client certs). Windows 11 requires the CA thumbprint
  inside the profile XML (store presence alone no longer suffices).
"""
from __future__ import annotations

import base64
import hashlib
import re
from xml.sax.saxutils import escape


def read_cert_der(path: str) -> bytes:
    """Load a cert file (PEM or DER) and return the raw DER bytes of the FIRST cert.

    A PEM file may hold a chain (root + intermediate); only the first certificate
    block is decoded - concatenating all base64 blocks would yield invalid DER and a
    wrong SHA-1 thumbprint (or a padding error). For PEAP TrustedRootCA exactly one
    CA cert is meant.
    """
    with open(path, "rb") as fh:
        data = fh.read()
    if b"BEGIN CERTIFICATE" in data:
        text = data.decode("ascii", "ignore")
        m = re.search(r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----",
                      text, re.DOTALL)
        block = m.group(1) if m else text
        b64 = "".join(line.strip() for line in block.splitlines() if line.strip())
        return base64.b64decode(b64)
    return data


def thumbprint(der: bytes) -> str:
    """SHA-1 thumbprint as 40 uppercase hex chars (no spaces)."""
    return hashlib.sha1(der).hexdigest().upper()


def _spaced(tp: str) -> str:
    return " ".join(tp[i:i + 2] for i in range(0, len(tp), 2)).lower()


# --------------------------------------------------------------------------- #
# Profile XML
# --------------------------------------------------------------------------- #
def psk_profile_xml(ssid: str, psk: str) -> str:
    s = escape(ssid)
    return (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">\n'
        f'  <name>{s}</name>\n'
        f'  <SSIDConfig><SSID><name>{s}</name></SSID></SSIDConfig>\n'
        '  <connectionType>ESS</connectionType>\n'
        '  <connectionMode>auto</connectionMode>\n'
        '  <MSM><security>\n'
        '    <authEncryption>\n'
        '      <authentication>WPA2PSK</authentication>\n'
        '      <encryption>AES</encryption>\n'
        '      <useOneX>false</useOneX>\n'
        '    </authEncryption>\n'
        '    <sharedKey>\n'
        '      <keyType>passPhrase</keyType>\n'
        '      <protected>false</protected>\n'
        f'      <keyMaterial>{escape(psk)}</keyMaterial>\n'
        '    </sharedKey>\n'
        '  </security></MSM>\n'
        '</WLANProfile>\n'
    )


def enterprise_profile_xml(ssid: str, servernames: str, tp: str) -> str:
    """WPA2-Enterprise PEAP-MSCHAPv2, USER auth + SSO preLogon (connects at login with
    the logged-in user's domain credentials; RADIUS restricts to the teacher group)."""
    s = escape(ssid)
    server_el = (f'              <msPeap:ServerNames>{escape(servernames)}</msPeap:ServerNames>\n'
                 if servernames else "")
    return (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">\n'
        f'  <name>{s}</name>\n'
        f'  <SSIDConfig><SSID><name>{s}</name></SSID></SSIDConfig>\n'
        '  <connectionType>ESS</connectionType>\n'
        '  <connectionMode>auto</connectionMode>\n'
        '  <MSM><security>\n'
        '    <authEncryption>\n'
        '      <authentication>WPA2</authentication>\n'
        '      <encryption>AES</encryption>\n'
        '      <useOneX>true</useOneX>\n'
        '    </authEncryption>\n'
        '    <OneX xmlns="http://www.microsoft.com/networking/OneX/v1">\n'
        '      <authMode>user</authMode>\n'
        '      <singleSignOn>\n'
        '        <type>preLogon</type>\n'
        '        <maxDelay>10</maxDelay>\n'
        '        <userBasedVirtualLan>false</userBasedVirtualLan>\n'
        '      </singleSignOn>\n'
        '      <EAPConfig>\n'
        '        <EapHostConfig xmlns="http://www.microsoft.com/provisioning/EapHostConfig"'
        ' xmlns:eapCommon="http://www.microsoft.com/provisioning/EapCommon"'
        ' xmlns:baseEap="http://www.microsoft.com/provisioning/BaseEapMethodConfig">\n'
        '          <EapMethod>\n'
        '            <eapCommon:Type>25</eapCommon:Type>\n'
        '            <eapCommon:VendorId>0</eapCommon:VendorId>\n'
        '            <eapCommon:VendorType>0</eapCommon:VendorType>\n'
        '            <eapCommon:AuthorId>0</eapCommon:AuthorId>\n'
        '          </EapMethod>\n'
        '          <Config xmlns:baseEap="http://www.microsoft.com/provisioning/BaseEapConnectionPropertiesV1"'
        ' xmlns:msPeap="http://www.microsoft.com/provisioning/MsPeapConnectionPropertiesV1"'
        ' xmlns:msChapV2="http://www.microsoft.com/provisioning/MsChapV2ConnectionPropertiesV1">\n'
        '            <baseEap:Eap>\n'
        '              <baseEap:Type>25</baseEap:Type>\n'
        '              <msPeap:EapType>\n'
        '                <msPeap:ServerValidation>\n'
        '                  <msPeap:DisableUserPromptForServerValidation>true</msPeap:DisableUserPromptForServerValidation>\n'
        + ("                " + server_el if server_el else "") +
        f'                  <msPeap:TrustedRootCA>{_spaced(tp)}</msPeap:TrustedRootCA>\n'
        '                </msPeap:ServerValidation>\n'
        '                <msPeap:FastReconnect>true</msPeap:FastReconnect>\n'
        '                <msPeap:InnerEapOptional>false</msPeap:InnerEapOptional>\n'
        '                <baseEap:Eap>\n'
        '                  <baseEap:Type>26</baseEap:Type>\n'
        '                  <msChapV2:EapType>\n'
        '                    <msChapV2:UseWinLogonCredentials>true</msChapV2:UseWinLogonCredentials>\n'
        '                  </msChapV2:EapType>\n'
        '                </baseEap:Eap>\n'
        '                <msPeap:EnableQuarantineChecks>false</msPeap:EnableQuarantineChecks>\n'
        '                <msPeap:RequireCryptoBinding>false</msPeap:RequireCryptoBinding>\n'
        '                <msPeap:PeapExtensions />\n'
        '              </msPeap:EapType>\n'
        '            </baseEap:Eap>\n'
        '          </Config>\n'
        '        </EapHostConfig>\n'
        '      </EAPConfig>\n'
        '    </OneX>\n'
        '  </security></MSM>\n'
        '</WLANProfile>\n'
    )


# --------------------------------------------------------------------------- #
# Startup-script generation: installer + self-healing worker
# --------------------------------------------------------------------------- #
# A plain boot-time import cannot work reliably. 'netsh wlan add profile' wraps
# WlanSetProfile, which needs a wireless INTERFACE GUID; the profile store lives per
# interface inside WlanSvc, and WlanEnumInterfaces only sees interfaces that are present
# AND enabled. WlanSvc itself is trigger-started, so a GPO startup script routinely runs
# before the wireless NIC has arrived. netsh without interface= then adds the profile to
# "all wireless interfaces" -- which is the empty set -- and reports nothing useful.
#
# So the startup script no longer does the work: it installs a worker plus a scheduled task
# that reconciles desired-vs-actual at boot, every 15 minutes and at every logon. Same
# two-stage pattern as scripts/bootorder-pxe-first.ps1, which already works on these clients.


def _ps_single_quote(s: str) -> str:
    """Quote a value for a PowerShell single-quoted string (doubling embedded quotes)."""
    return "'" + str(s).replace("'", "''") + "'"


def _profiles_array(entries: list) -> str:
    """PowerShell array of ordered [name, base64-xml] pairs. An array (not a hashtable)
    because the connection preference follows the configured order."""
    rows = ",\n".join(
        "    @(%s, '%s')" % (_ps_single_quote(name),
                             base64.b64encode(xml.encode("utf-8")).decode("ascii"))
        for name, xml in entries)
    return "$PROFILES = @(\n" + rows + "\n)\n" if rows else "$PROFILES = @()\n"


_WORKER = r'''
$ErrorActionPreference = 'SilentlyContinue'
$log      = Join-Path $env:SystemRoot 'Temp\lmn-gpo-wlan.log'
$dir      = Join-Path $env:ProgramData 'lmn-gpo\wlan'
$taskName = 'LMN-GPO-WlanProfiles'
$stateKey = 'HKLM:\SOFTWARE\lmn-gpo\wlan'
function Log($m) { try { ('{0}  {1}' -f (Get-Date -Format 's'), $m) | Out-File -LiteralPath $log -Append -Encoding utf8 } catch {} }

function Invoke-Reconcile {
    if (-not $PROFILES.Count) { return }

    # 1. WlanSvc must run - every netsh wlan call is a silent no-op while it is stopped.
    $svc = Get-Service -Name WlanSvc -ErrorAction SilentlyContinue
    if (-not $svc) { Log 'WlanSvc not installed (machine has no WLAN feature) -> nothing to do.'; return }
    if ($svc.StartType -ne 'Automatic') { Set-Service -Name WlanSvc -StartupType Automatic; Log 'WlanSvc StartType -> Automatic' }
    if ($svc.Status -ne 'Running') { Start-Service -Name WlanSvc; Log ('WlanSvc was ' + $svc.Status + ', start requested') }
    for ($i = 0; $i -lt 30 -and (Get-Service WlanSvc).Status -ne 'Running'; $i++) { Start-Sleep -Seconds 2 }
    if ((Get-Service WlanSvc).Status -ne 'Running') { Log 'ABORT: WlanSvc did not reach Running.'; return }

    # 2. Re-enable a wireless adapter that was administratively disabled - a disabled
    #    adapter is not enumerable, and then there is nowhere to store a profile.
    foreach ($a in (Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object {
                    $_.PhysicalMediaType -eq 'Native 802.11' -or $_.InterfaceDescription -match 'Wi-?Fi|Wireless|802\.11' })) {
        if ($a.Status -eq 'Disabled') { Enable-NetAdapter -Name $a.Name -Confirm:$false; Log ('adapter enabled: ' + $a.Name) }
    }

    # 3. Wait for at least one wireless interface. 'Name' is the label in both EN and DE.
    $ifaces = @()
    for ($i = 0; $i -lt 30; $i++) {
        $ifaces = @(netsh wlan show interfaces 2>$null |
                    Select-String -Pattern '^\s*Name\s*:\s*(.+?)\s*$' |
                    ForEach-Object { $_.Matches[0].Groups[1].Value })
        if ($ifaces.Count) { break }
        Start-Sleep -Seconds 2
    }
    if (-not $ifaces.Count) { Log 'no wireless interface yet -> will retry at the next repetition.'; return }

    foreach ($iface in $ifaces) {
        # 4. Import every profile on every interface. netsh OVERWRITES, so this is both
        #    idempotent and how a changed passphrase reaches an already-provisioned client
        #    -- never skip an existing profile, or a PSK rotation would never arrive.
        $added = 0; $failed = 0
        for ($p = 0; $p -lt $PROFILES.Count; $p++) {
            $name = $PROFILES[$p][0]
            $f = Join-Path $dir ('.stage-' + [Guid]::NewGuid().ToString('N') + '.xml')
            try {
                [IO.File]::WriteAllBytes($f, [Convert]::FromBase64String($PROFILES[$p][1]))
                $out = (& netsh.exe wlan add profile filename="$f" interface="$iface" user=all 2>&1 | Out-String).Trim()
                if ($LASTEXITCODE -ne 0) {
                    # WlanSetProfile fails with ERROR_ALREADY_EXISTS when a PER-USER profile
                    # of the same name exists - even with overwrite. Drop it and retry once.
                    & netsh.exe wlan delete profile name="$name" interface="$iface" 2>&1 | Out-Null
                    $out = (& netsh.exe wlan add profile filename="$f" interface="$iface" user=all 2>&1 | Out-String).Trim()
                }
                if ($LASTEXITCODE -eq 0) { $added++ } else { $failed++; Log ("FAILED '{0}' on '{1}' (exit {2}): {3}" -f $name, $iface, $LASTEXITCODE, $out) }
            } finally { Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue }
        }
        # 5. netsh inserts each new profile at the TOP, so import order comes out reversed.
        #    Set the preference explicitly: first configured network = priority 1.
        for ($p = 0; $p -lt $PROFILES.Count; $p++) {
            & netsh.exe wlan set profileorder name="$($PROFILES[$p][0])" interface="$iface" priority=$($p + 1) 2>&1 | Out-Null
        }
        # A present profile still never associates while auto-config is off.
        & netsh.exe wlan set autoconfig enabled=yes interface="$iface" 2>&1 | Out-Null
        if ($failed -or $added -ne $PROFILES.Count) { Log ("interface '{0}': {1} ok, {2} failed" -f $iface, $added, $failed) }
    }

    # 6. Record the outcome so the check script can see when this last succeeded.
    try {
        if (-not (Test-Path -LiteralPath $stateKey)) { New-Item -Path $stateKey -Force | Out-Null }
        Set-ItemProperty -LiteralPath $stateKey -Name LastRunUtc -Value ((Get-Date).ToUniversalTime().ToString('o')) -Force
        Set-ItemProperty -LiteralPath $stateKey -Name Managed -Value ([string[]]($PROFILES | ForEach-Object { $_[0] })) -Type MultiString -Force
    } catch {}
}

if ($Worker) { Invoke-Reconcile; return }

# --------------------------------------------------------------------------- #
# INSTALLER (the GPO startup script). Keep it quick - it runs inside the GPO
# script budget; the scheduled task does the waiting.
# --------------------------------------------------------------------------- #
Log '--- installer ---'
New-Item -ItemType Directory -Force -Path $dir | Out-Null
# The passphrase is inside this script, so keep the local copy readable by SYSTEM and
# Administrators only. SIDs, not names - 'Administrators' is localized (DE: Administratoren).
& icacls.exe $dir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' 2>&1 | Out-Null

$localScript = Join-Path $dir 'wlan-profiles.ps1'
if ($PSCommandPath -and (Test-Path -LiteralPath $PSCommandPath)) {
    Copy-Item -LiteralPath $PSCommandPath -Destination $localScript -Force
} else { Log 'WARN: $PSCommandPath empty - worker cannot be placed locally.' }

$ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$taskXml = Join-Path $dir 'wlan-task.xml'
$xml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Author>lmn-gpo</Author></RegistrationInfo>
  <Triggers>
    <BootTrigger>
      <Enabled>true</Enabled><Delay>PT30S</Delay>
      <Repetition><Interval>PT15M</Interval><StopAtDurationEnd>false</StopAtDurationEnd></Repetition>
    </BootTrigger>
    <LogonTrigger><Enabled>true</Enabled></LogonTrigger>
  </Triggers>
  <Principals><Principal id="Author"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <ExecutionTimeLimit>PT10M</ExecutionTimeLimit>
    <Hidden>true</Hidden><Enabled>true</Enabled>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>$ps</Command>
      <Arguments>-NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "$localScript" -Worker</Arguments>
    </Exec>
  </Actions>
</Task>
"@
[IO.File]::WriteAllText($taskXml, $xml, [Text.Encoding]::Unicode)
(& schtasks.exe /Create /TN $taskName /XML "$taskXml" /F 2>&1) | ForEach-Object { Log ('schtasks /Create: ' + $_) }

# Fast path: try once inline as well, so a normal boot with a working adapter is done now.
Invoke-Reconcile
Log '--- installer end ---'
'''


def _build_script(entries: list, prologue: str = "") -> str:
    head = ("# Auto-generated by lmn-gpo. Computer startup script (SYSTEM, before login).\n"
            "# Installs a self-healing scheduled task that keeps the WLAN profiles present.\n"
            "# Log: %SystemRoot%\\Temp\\lmn-gpo-wlan.log\n"
            "param([switch]$Worker)\n")
    # Profile XMLs travel base64-encoded so the .ps1 stays pure ASCII (Windows PowerShell
    # reads a BOM-less .ps1 in the system codepage) while non-ASCII SSIDs survive intact.
    return head + _profiles_array(entries) + prologue + _WORKER


def build_psk_script(networks: list) -> str:
    """networks: [{'ssid': ..., 'psk': ...}] - order defines the connection preference."""
    entries = [(n["ssid"], psk_profile_xml(n["ssid"], n["psk"]))
               for n in networks if n.get("ssid") and n.get("psk")]
    return _build_script(entries)


def build_enterprise_script(ssid: str, servernames: str, ca_der: bytes) -> str:
    """Enterprise: install the RADIUS CA cert (Trusted Root) + import the PEAP profile."""
    tp = thumbprint(ca_der)
    b64 = base64.b64encode(ca_der).decode("ascii")
    # The CA must be trusted before the profile is used, and re-adding is harmless.
    prologue = (
        "function Install-RadiusCa {\n"
        f"    $certb64 = '{b64}'\n"
        "    $cf = Join-Path $env:TEMP ('lmn-gpo-radius-ca-' + [Guid]::NewGuid().ToString('N') + '.cer')\n"
        "    try {\n"
        "        [IO.File]::WriteAllBytes($cf, [Convert]::FromBase64String($certb64))\n"
        "        & certutil.exe -addstore -f Root \"$cf\" 2>&1 | Out-Null\n"
        "    } finally { Remove-Item -LiteralPath $cf -Force -ErrorAction SilentlyContinue }\n"
        "}\n"
        "Install-RadiusCa\n")
    return _build_script([(ssid, enterprise_profile_xml(ssid, servernames, tp))], prologue)

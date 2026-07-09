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
from xml.sax.saxutils import escape


def read_cert_der(path: str) -> bytes:
    """Load a cert file (PEM or DER) and return the raw DER bytes."""
    with open(path, "rb") as fh:
        data = fh.read()
    if b"BEGIN CERTIFICATE" in data:
        text = data.decode("ascii", "ignore")
        b64 = "".join(line.strip() for line in text.splitlines()
                      if line.strip() and "CERTIFICATE" not in line)
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
        '<?xml version="1.0"?>\n'
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
        '<?xml version="1.0"?>\n'
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
# Startup-script generation (self-contained: writes XML/cert to temp, imports, cleans up)
# --------------------------------------------------------------------------- #
_HEADER = ("# Auto-generiert vom linuxmuster-gpo-template. Computer-Startskript (SYSTEM,\n"
           "# vor dem Login). Idempotent: netsh/certutil ueberschreiben vorhandene Profile.\n"
           "$ErrorActionPreference = 'SilentlyContinue'\n"
           "$tmp = Join-Path $env:TEMP 'lmgpo-wlan'\n"
           "New-Item -ItemType Directory -Force -Path $tmp | Out-Null\n")


def _add_profile_block(name: str, xml: str) -> str:
    return (f"$xml = @'\n{xml}'@\n"
            f"$f = Join-Path $tmp '{name}.xml'\n"
            "Set-Content -LiteralPath $f -Value $xml -Encoding ASCII\n"
            'netsh wlan add profile filename="$f" user=all | Out-Null\n'
            "Remove-Item -LiteralPath $f -Force\n")


def build_psk_script(networks: list) -> str:
    """networks: [{'ssid': ..., 'psk': ...}]."""
    out = [_HEADER]
    for i, n in enumerate(networks):
        if not n.get("ssid") or not n.get("psk"):
            continue
        out.append(_add_profile_block(f"psk{i}", psk_profile_xml(n["ssid"], n["psk"])))
    return "".join(out)


def build_enterprise_script(ssid: str, servernames: str, ca_der: bytes) -> str:
    """Enterprise: install the RADIUS CA cert (Trusted Root) + import the PEAP profile."""
    tp = thumbprint(ca_der)
    b64 = base64.b64encode(ca_der).decode("ascii")
    out = [_HEADER]
    out.append(
        f"$certb64 = '{b64}'\n"
        "$cf = Join-Path $tmp 'radius-ca.cer'\n"
        "[IO.File]::WriteAllBytes($cf, [Convert]::FromBase64String($certb64))\n"
        'certutil -addstore -f Root "$cf" | Out-Null\n'
        "Remove-Item -LiteralPath $cf -Force\n")
    out.append(_add_profile_block("enterprise", enterprise_profile_xml(ssid, servernames, tp)))
    return "".join(out)

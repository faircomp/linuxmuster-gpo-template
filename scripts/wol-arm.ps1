# wol-arm.ps1 — Wake-on-LAN scharf schalten (Schul-Fleet).
# Computer-Startskript (linuxmuster-gpo-template). Idempotent & robust: Fehler
# einzelner Adapter/Cmdlets werden ignoriert.
#
# Hinweis: Fast Startup wird per Registry-Policy (HiberbootEnabled=0, Paket
# 05-wol) für ALLE Geräte ausgeschaltet — das reicht für ein echtes S5 und damit
# für WoL. Der Ruhezustand (Hibernate) wird bewusst NICHT hier, sondern separat
# im Paket 05b-ruhezustand-aus deaktiviert (das noPXE-Geräte/Notebooks per
# Deny-Filter ausnimmt, damit sie ihren Ruhezustand behalten).
$ErrorActionPreference = 'SilentlyContinue'

Get-NetAdapter -Physical | Where-Object { $_.Status -ne 'Disabled' } | ForEach-Object {
    $name = $_.Name
    $desc = $_.InterfaceDescription
    # Magic-Packet-Wake aktivieren (nur auf Adaptern, die es unterstützen).
    try { Set-NetAdapterPowerManagement -Name $name -WakeOnMagicPacket Enabled -ErrorAction Stop } catch {}
    # Gerät darf den Rechner aufwecken.
    try { powercfg -deviceenablewake "$desc" | Out-Null } catch {}
}

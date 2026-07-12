# wol-arm.ps1 — Arm Wake-on-LAN (school fleet).
# Computer startup script (linuxmuster-gpo-template). Idempotent & robust: errors
# from individual adapters/cmdlets are ignored.
#
# Note: Fast Startup is disabled via registry policy (HiberbootEnabled=0, package
# 05-wol) for ALL devices — that is enough for a real S5 and therefore for WoL.
# Hibernate is deliberately NOT disabled here, but separately in package
# 05b-ruhezustand-aus (which excludes noPXE devices/notebooks via a deny filter,
# so they keep their hibernate state).
$ErrorActionPreference = 'SilentlyContinue'

Get-NetAdapter -Physical | Where-Object { $_.Status -ne 'Disabled' } | ForEach-Object {
    $name = $_.Name
    $desc = $_.InterfaceDescription
    # Enable magic-packet wake (only on adapters that support it).
    try { Set-NetAdapterPowerManagement -Name $name -WakeOnMagicPacket Enabled -ErrorAction Stop } catch {}
    # Allow the device to wake the machine.
    try { powercfg -deviceenablewake "$desc" | Out-Null } catch {}
}

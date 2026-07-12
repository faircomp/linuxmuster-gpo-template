# hibernate-off.ps1 — Disable hibernate completely.
# Computer startup script (linuxmuster-gpo-template). Via a GPO deny filter it does
# NOT apply to noPXE devices (e.g. teacher notebooks), so they keep their hibernate.
# Idempotent: no-op if hibernate is already off.
$ErrorActionPreference = 'SilentlyContinue'
powercfg /hibernate off | Out-Null

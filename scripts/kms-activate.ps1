# kms-activate.ps1 — Activate Windows against the KMS host set via GPO.
# Computer startup script (linuxmuster-gpo-template). Idempotent & quiet: only
# activates when no valid Windows license is active yet. The check is
# CIM-based (language-neutral), NOT via the display text of slmgr /dli.
$ErrorActionPreference = 'SilentlyContinue'

# ApplicationId 55c92734-... = Windows operating-system licenses; LicenseStatus 1 = Licensed.
$activated = Get-CimInstance -ClassName SoftwareLicensingProduct `
    -Filter "ApplicationId='55c92734-d682-4d71-983e-d6ec3f16059f' AND PartialProductKey IS NOT NULL" |
    Where-Object { $_.LicenseStatus -eq 1 }

if (-not $activated) {
    cscript //nologo "$env:windir\System32\slmgr.vbs" /ato | Out-Null
}

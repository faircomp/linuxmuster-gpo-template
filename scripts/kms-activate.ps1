# kms-activate.ps1 — Windows gegen den per GPO gesetzten KMS-Host aktivieren.
# Computer-Startskript (linuxmuster-gpo-template). Idempotent & ruhig: aktiviert
# nur, wenn noch keine gültige Windows-Lizenz aktiv ist. Die Prüfung ist
# CIM-basiert (sprachneutral), NICHT über den Anzeigetext von slmgr /dli.
$ErrorActionPreference = 'SilentlyContinue'

# ApplicationId 55c92734-... = Windows-Betriebssystem-Lizenzen; LicenseStatus 1 = Licensed.
$activated = Get-CimInstance -ClassName SoftwareLicensingProduct `
    -Filter "ApplicationId='55c92734-d682-4d71-983e-d6ec3f16059f' AND PartialProductKey IS NOT NULL" |
    Where-Object { $_.LicenseStatus -eq 1 }

if (-not $activated) {
    cscript //nologo "$env:windir\System32\slmgr.vbs" /ato | Out-Null
}

# hibernate-off.ps1 — Ruhezustand (Hibernate) komplett deaktivieren.
# Computer-Startskript (linuxmuster-gpo-template). Gilt per GPO-Deny-Filter NICHT
# für noPXE-Geräte (z.B. Lehrer-Notebooks), damit diese ihren Ruhezustand behalten.
# Idempotent: no-op, wenn Hibernate bereits aus ist.
$ErrorActionPreference = 'SilentlyContinue'
powercfg /hibernate off | Out-Null

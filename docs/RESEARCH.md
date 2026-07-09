# Recherche & Begründung

Konsolidierte, quellenbelegte Grundlage für das Toolkit. Alle Mechanismus- und
Struktur-Aussagen sind gegen den sophomorix4-Quellcode **und** eine echte
linuxmuster.net-7.3-Instanz (Samba 4.19.5) verifiziert.

## 1. Der Kernmechanismus (Windows-GPO vom Samba-DC aus)

Ein Windows-Client wendet eine GPO nur an, wenn **drei** Dinge konsistent sind:
`Registry.pol` (PReg-Format) · Version identisch in `GPT.INI` **und** AD-Attribut
`versionNumber` · passende **Client-Side-Extension-GUID** in
`gPCMachineExtensionNames`/`gPCUserExtensionNames`. Fehlt die CSE-GUID, ignoriert der
Client die Datei (häufigste Fehlerquelle).

- **Registry/Admin-Templates + Firewall** → `samba-tool gpo load --content=json` erledigt
  alle drei Schritte atomar (verifiziert Samba 4.19). CSE `{35378EAC-683F-11D2-A89A-00C04FBBCFA2}`.
- **GptTmpl.inf** (Benutzerrechte, Restricted Groups) → Datei selbst schreiben, CSE
  `{827D319E-6EAC-11D2-A4EA-00C04F79F83A}`, Version bumpen.
- **Groups.xml** (GPP lokale Admins, additiv) → CSE `{17D89FEC-5C44-4972-B12D-241CAEF74509}`.
- **Startskripte** (WoL) → `Machine/Scripts/psscripts.ini`, CSE `{42B5FAAE-6536-11D2-AE5A-0000F87571E3}`.
- **Security-Filtering**: `samba-tool dsacl set` (Recht „Apply Group Policy"
  `edacfd8f-ffb3-11d1-b41d-00a0c968f939`). Nach DACL-Änderungen `samba-tool ntacl sysvolreset`
  (gefahrlos, solange `Domain Admins` keine `gidNumber` hat) → `gpo aclcheck` bleibt grün.

Quellen: [MS-GPREG](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpreg/5c092c22-bf6b-4e7f-b180-b20743d368f5) ·
[Samba policies.py](https://raw.githubusercontent.com/samba-team/samba/master/python/samba/policies.py) ·
[SambaWiki Group Policy](https://wiki.samba.org/index.php/Group_Policy) ·
[MS-GPFAS (Firewall-Regel-Grammatik)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpfas/2efe0b76-7b4a-41ff-9050-1023f8196d16) ·
[CSE-GUID-Liste](https://www.infrastructureheroes.org/microsoft-infrastructure/microsoft-windows/guid-list-of-group-policy-client-extensions/)

## 2. linuxmuster.net 7.x Struktur (verifiziert)

- Base-DN aus RootDSE (`DC=…`); OUs `OU=SCHOOLS` und `OU=GLOBAL` direkt darunter.
- Schule: `OU=<schule>,OU=SCHOOLS` (Default `default-school`, leeres Präfix; sonst `<schule>-`).
- Geräte: `CN=<host>,OU=<raum>,OU=Devices,OU=<schule>,OU=SCHOOLS` — **Pro-Raum-OUs existieren**
  (per GPO-Link targetbar). Zusätzlich ist jeder Raum eine Sicherheitsgruppe (`sophomorixType=room`).
- **PXE/LINBO-Status steht nicht im AD.** Nicht-LINBO-Geräte landen in der Gerätegruppe
  **`d_nopxe`** (`sophomorixType=devicegroup`, Spalte `dgr` der devices.csv) → per Security-Filtering targetbar.
- Admin-Gruppen: `global-admins` (Mitglied von `Domain Admins` und jeder `<schule>-admins`),
  `all-admins`, `role-globaladministrator` (unter `OU=GLOBAL`); pro Schule `<präfix>admins`.
- linuxmusters eigene `sophomorix:school:<schule>` (an der Schul-OU) **nie anfassen** — wird bei
  Updates überschrieben. Eigene GPOs mit Präfix `LMN-`.

Quellen: [sophomorix4](https://github.com/linuxmuster/sophomorix4) (`SophomorixSambaAD.pm`, `sophomorix.ini`) ·
[docs.linuxmuster.net GPO](https://docs.linuxmuster.net/de/latest/systemadministration/gpo/gpo.html) ·
[paedML „GPO für Fortgeschrittene"](https://wiki.linuxmuster.net/community/_media/anwenderwiki:windowsclient_lmn7:gpo_fortgeschrittene.pdf)

## 3. Targeting-Modell

- **Global** (alle Schulen): Link an `OU=SCHOOLS` (vererbt auf alle Geräte-OUs; Nicht-Windows-Server
  ignorieren GPOs ohnehin).
- **Pro Schule**: Link an `OU=Devices,OU=<schule>` (Multischule: Loop über alle Schulen).
- **Update-Split & Lehrer-Notebooks**: **Deny-Apply** auf die Gruppe (`d_nopxe` bzw. Lehrer-Gruppe) →
  diese Geräte fallen auf den Windows-Standard zurück. (Kein Exklusiv-Filter nötig, aclcheck-sauber.)
- **Loopback = Merge** (`UserPolicyMode=2`) für User-Einstellungen, die dem Rechner folgen sollen.

## 4. Einstellungen & Begründung (Kurz)

| Pack | Warum / Quelle |
|---|---|
| Updates | LINBO-Rechner werden per Image gepflegt → `NoAutoUpdate=1`; noPXE via Deny → Windows-Default. [waas-wu-settings](https://learn.microsoft.com/en-us/windows/deployment/update/waas-wu-settings) |
| Energie | Netzwerkerreichbarkeit: Standby=Nie, Display 1800 s, Hybrid-Standby aus. Power-Setting-GUIDs. [admx.help Power](https://admx.help/) |
| Sperren | `InactivityTimeoutSecs=1800` (computer-weit, manipulationssicher) statt Screensaver. |
| WoL | Fast Startup aus (`HiberbootEnabled=0`) für echtes S5 + Startskript arm't NICs. |
| Remote-Mgmt | RDP+NLA, Firewall (RDP/SMB/RPC/ICMP) nur von Server-IP; `net rpc … shutdown` (so macht es auch die linuxmuster-WebUI). |
| Admins | `global-admins` (via Domain Admins ohnehin) explizit + `<schule>-admins` je Schule → lokale Admins + RDP-Users. |

## 5. Datenschutz / DSGVO (Nachweis)

DSK-Beschluss zu Windows: **Enterprise/Education + `AllowTelemetry=0` (Security) +
Restricted-Traffic-Baseline** → im Labortest kein Telemetrie-Abfluss. Auf **Pro** wird `0` als `1`
behandelt → dort HKCU-Fallbacks. Zusätzlich blockiert: MS-Konten, OneDrive (optional), Werbe-ID,
Aktivitätsverlauf, Standort, Copilot/Recall, Cloud-Sync.

Quellen: [DSK-Beschluss Windows 10 (PDF)](https://www.datenschutzkonferenz-online.de/media/dskb/TOP_30_Beschluss_Windows_10_mit_Anlagen.pdf) ·
[DSK Anlage 1 – technische Aspekte](https://www.datenschutzkonferenz-online.de/media/ah/20191106_win10_pruefschema_hinweise_dsk.pdf) ·
[LfD Niedersachsen](https://www.lfd.niedersachsen.de/) ·
[MS – manage-connections](https://learn.microsoft.com/en-us/windows/privacy/manage-connections-from-windows-operating-system-components-to-microsoft-services)

> Hinweis: Jede Einstellung ist im Katalog (`catalog/*.yaml`) mit Klartext-Namen dokumentiert und
> vor dem Ausrollen mit `lmgpo apply --dry-run` einsehbar.

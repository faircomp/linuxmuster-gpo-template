# Veyon-GPO-Paket — Design A (UMGESETZT als `catalog/10-veyon-schule.yaml`)

Stand: **umgesetzt + serverseitig auf der crabbox verifiziert** (apply/idempotent/remove, MULTI_SZ,
Firewall-Standortsperre, Bind-PW-Hex). Offen bleibt nur der echte Windows-Client-Test (`gpupdate`/
`gpresult`) — wie bei allen Paketen. Umsetzung über unsere Registry-Engine (`samba-tool gpo load`).

Nutzung: `veyon_binddn` + `veyon_bindpw_hex` in die `site.yaml` (Assistent fragt danach; Hex via
`lmgpo-cli veyon-encrypt-password` oder aus einem Configurator-Export). Dann greift Paket `10-veyon-schule`
pro Schule. Bind-Passwort ist reversibel (§5) → `global-veyon` eng berechtigt halten + Passwort rotieren.

## 0. config.json vs. reine Registry — Entscheidung

**Reine Registry** (nicht `veyon-cli config import`). Begründung: die reale Config nutzt
`AccessControlRulesProcessingEnabled=false` → keine `@JsonValue`-Regel-Arrays, also entfällt der
einzige echte Nachteil des Registry-Wegs. Registry passt in unsere idempotente Engine, braucht kein
`veyon-cli`/Startskript am Client und wird pro Schule aus dem AD generiert. (config.json nur nötig bei
komplexen Regelsätzen/Golden-Config — hier nicht der Fall. Sicherheit identisch, da Bind-PW so oder so
in world-lesbarem sysvol bzw. NETLOGON läge.)

Config liegt unter `HKLM\SOFTWARE\Veyon Solutions\Veyon\<Sektion>` (64-Bit-View, tattooing). Wirkt nach Reboot.

## 1. Grundsatz

- Auth = **Logon-Authentifizierung + LDAP-Directory** (dateilos, kein Key-File-Problem).
- Ein GPO **pro Schule** (`scope: school`, an `OU=Devices,OU=<schule>`).
- Directory = nur **Schüler-Computer** der Schule (`ComputersFilter=(sophomorixRole=classroom-studentcomputer)`).
- Raum-Mapping über das **`sophomorixComputerRoom`-Attribut** des Computerobjekts
  (`ComputerLocationsByAttribute=true`, `LocationNameAttribute=sophomorixComputerRoom`) — sauberer als by-container.
- LDAP-Directory-Plugin-UUID (bestätigt): **`6f0a491e-c1c6-4338-8244-f823b0bf8670`** (für `NetworkObjectDirectory\Plugin` und `UserGroups\Backend`).
- **Lehrer-Notebook-Master: zurückgestellt.**

## 2. Design A — Roaming (GEWÄHLT)

Veyon hat **keine standortbasierte** Zugriffskontrolle, nur identitätsbasiert (ist-Lehrer). „Nur an der
Schule, wo ich bin" erzwingt daher die **Netzwerkebene** — hier die **OPNsense** (§3).

- Auth global: jeder Lehrer darf grundsätzlich Master.
- `BaseDN = DC=…` (Wurzel), `UserTree = OU=SCHOOLS`, `GroupTree = OU=Groups,OU=GLOBAL`.
- `AccessControl\AuthorizedUserGroups = ["CN=role-teacher,OU=Groups,OU=GLOBAL,DC=…"]`.
  (**`role-teacher`** = Lehrer sind DIREKTE Mitglieder → kein `QueryNestedUserGroups` nötig.)
- `ComputerTree` pro Schule → Raumliste schulscharf.
- **Standort-Sperre = OPNsense** (§3): Windows-Firewall bleibt für Veyon offen; die Trennung zwischen
  Schul-Subnetzen/VLANs macht die OPNsense.

> Verworfene Alternative (Design B, strikt per Schule): `UserTree`/`GroupTree = OU=<schule>`,
> `AuthorizedUserGroups` = Schul-Lehrergruppe → kein Roaming. Nicht gewählt.

**Schüler-Roaming (unkritisch, keine Anpassung nötig):** „Login nur für Lehrer" betrifft den Veyon-*Master*,
nicht die Windows-Anmeldung — Schüler melden sich normal an und werden überwacht. Veyons AccessControl prüft
den *verbindenden* Nutzer (Lehrer) gegen `role-teacher` (`AccessControlProvider::processAuthorizedGroups`:
Schnittmenge der Gruppen des zugreifenden Nutzers), **nicht** den lokal angemeldeten Schüler. Ein Schüler ist
nie in `role-teacher` → kann nie steuern, egal aus welcher Schule. Die Rechnerliste hängt am Computer-Objekt
(`classroom-studentcomputer` + `sophomorixComputerRoom`), nicht am Schüler; Config ist rein HKLM. Einzige
externe Voraussetzung: linuxmuster/AD muss die schulübergreifende Windows-Anmeldung erlauben.

## 3. Standort-Sperre = OPNsense (nicht Windows-Firewall)

Die Windows-Firewall bleibt für Veyon **komplett offen**: Veyon öffnet Port 11100 selbst
(`Network\FirewallExceptionEnabled=1`), das Paket setzt **keine** eigene Windows-Firewallregel.
Die Trennung zwischen Schulen (kein Fernsteuern einer anderen Schule) macht die **OPNsense** zwischen
den Schul-Subnetzen/VLANs. → Kein `subnets.csv`/Netzmasken-Handling im Toolkit nötig.

## 4. Master — aktueller Raum als Default, andere wählbar

- `Master\AutoSelectCurrentLocation = true` (weiche Vorauswahl des eigenen Standorts).
- `Master\ShowCurrentLocationOnly = false` (NICHT setzen — wäre harte Sperre).
- aus der Real-Config zusätzlich sinnvoll: `Master\HideLocalComputer=true`, `Master\HideEmptyLocations=true`,
  `Master\AccessControlForMasterEnabled=true`.
- Voraussetzung: Master-PC steht als Computerobjekt mit korrektem `sophomorixComputerRoom`; DNS vor-/rückwärts sauber.

## 5. SICHERHEIT — Bind-Passwort (Kernbefund)

Veyon-`BindPassword` ist **NICHT gehasht** — RSA mit einem **statischen, öffentlich im Veyon-Repo
liegenden Schlüssel** (`default-pkey.pem`, in jeder Installation identisch) → **trivial umkehrbar**
(mit `openssl` bewiesen). Lesbar in **(1) sysvol-`Registry.pol`** (Authenticated Users/Schüler) und
**(2) Client-Registry** (`HKLM\SOFTWARE\Veyon Solutions`, `BUILTIN\Users`-Read, da Veyon keine restriktive
Registry-DACL setzt).

Maßnahmen (Grundproblem bleibt, nur Schadensbegrenzung):
- **Dedizierter Read-only-Bind-User `global-veyon`** (NICHT `global-binduser`), Leserechte möglichst eng
  (Computerobjekte + `sophomorixComputerRoom`/MAC/`dNSHostName` + `role-teacher`) → bei Kompromittierung
  kein Schüler-PII, nur Rechnernamen/Räume + Lehrerliste.
- GPO auf **`Domain Computers` security-filtern** (Schüler raus → schließt sysvol-Weg; MS16-072 beachten).
- **Client-Registry-DACL härten** (Users-Read auf `HKLM\SOFTWARE\Veyon Solutions` entziehen; SYSTEM behält).
- **LDAPS erzwingen** (`ConnectionSecurity=2`, Port 636, CA `/etc/linuxmuster/ssl/cacert.pem`, `TLSVerifyMode=1`).
- Anonymer Bind (linuxmuster verbietet ihn) / Kerberos-Bind (Veyon kann kein SASL) → keine Optionen.

## 6. Config-Inventar (aus realer Export-Config, Schule „msg" als Muster)

```
[Authentication] Method = 0                       (Logon)   ; DWORD
[NetworkObjectDirectory] Plugin = 6f0a491e-c1c6-4338-8244-f823b0bf8670
[UserGroups] Backend = 6f0a491e-...   UseDomainUserGroups = false
[LDAP]
  BaseDN                    = DC=<schule>,DC=<...>          ; Wurzel
  ServerHost                = server.<realm>                ; FQDN
  ServerPort                = 636      ConnectionSecurity = 2   TLSVerifyMode = 1
  BindDN                    = CN=global-veyon,OU=Management,OU=GLOBAL,DC=...
  BindPassword              = <RSA-Hex>                     ; UNSICHER (siehe §5)
  UseBindCredentials        = true     RecursiveSearchOperations = true
  ComputerTree              = OU=Devices,OU=<schule>,OU=SCHOOLS
  ComputersFilter           = (sophomorixRole=classroom-studentcomputer)
  ComputerHostNameAttribute = dNSHostName    ComputerHostNameAsFQDN = true
  ComputerMacAddressAttribute = sophomorixComputerMAC
  ComputerLocationsByAttribute = true   ComputerLocationsByContainer = false
  ComputerLocationAttribute = sophomorixComputerRoom
  LocationNameAttribute     = sophomorixComputerRoom
  UserLoginNameAttribute    = sAMAccountName               ; (Real-Config: 'sAMAccountname' — prüfen)
  GroupMemberAttribute      = member
  UserTree                  = OU=SCHOOLS                   ; Design A (Roaming)
  GroupTree                 = OU=Groups,OU=GLOBAL          ; Design A (Roaming)
[AccessControl]
  AccessRestrictedToUserGroups        = true
  AccessControlRulesProcessingEnabled = false
  AuthorizedUserGroups                = [ CN=role-teacher,OU=Groups,OU=GLOBAL,DC=... ]   (Design A)
[Master]
  AutoSelectCurrentLocation = true   ShowCurrentLocationOnly = false
  HideLocalComputer = true   HideEmptyLocations = true   AccessControlForMasterEnabled = true
[Network] VeyonServerPort = 11100   FirewallExceptionEnabled = 1
[Service] RemoteConnectionNotifications = true
[Windows] SoftwareSASEnabled = 1
```
Typen: Strings=SZ, Ports/Enums=DWORD, bool="true"/"false"(SZ), Gruppenliste=MULTI_SZ.
`Core\*` (InstallationID, PluginVersions) NICHT ausrollen (Veyon-intern/pro Maschine).

## 7. Was das Toolkit liefert vs. neue Setup-Fragen

Auto: realm/BaseDN/Schulen/`OU=Devices`/serverip/`server.<realm>`/cacert-Pfad/`role-teacher`-DN/Subnetze.
Neu zu klären: `global-veyon` (anlegen lassen? Rechte-Scope?), Design A vs. B, LDAPS-CA-Datei-Verteilung
(GPP-Files/Share), Security-Filter+Registry-DACL-Härtung ein/aus, TLSCACertificateFile-Pfad am Client.

## 8. Caveats / Grenzen

- **WLAN-Geräte** (Rolle `wlan`) sind keine Computerobjekte → nicht im Directory.
- `dNSHostName` case-sensitiv (Real-Config zeigt `sAMAccountname` klein — gegen echten Export prüfen).
- Veyon liest Config beim Dienststart → Reboot nötig.
- Exakte Location-/UUID-Werte final gegen einen `veyon-cli config export` eines per GUI konfigurierten Masters abgleichen.
- Verifikation nur mit echtem Windows-Client (`lmgpo-check.ps1` erweitern).

## 9. Zurückgestellt

Veyon-Master auf Lehrer-Notebooks (nicht alle noPXE-Geräte) — inkl. gesonderter Behandlung des Bind-PW-Risikos.

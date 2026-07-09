# linuxmuster-gpo-template

Ein wiederverwendbares **Group-Policy-Template-Toolkit** für **linuxmuster.net 7.x**
(Ubuntu 24.04 + Samba 4.19 Active-Directory-DC). Es erstellt, verlinkt und berechtigt
Windows-11-Gruppenrichtlinien **direkt vom Linux-Server aus** – ohne Windows-GPMC –
und ist **Multischule-fähig** (mehrere Schulen pro Server sowie identisches Ausrollen
über viele Kunden-Server hinweg).

> Status: **in Aufbau.** Fundament (Umgebungserkennung, `doctor`/`env`/`list`) steht und ist
> gegen eine echte linuxmuster-7.3-Instanz verifiziert. GPO-Engine, Policy-Katalog und
> Setup-Assistent folgen.

## Warum das funktioniert

Damit ein Windows-Client eine vom Samba-DC gesetzte GPO anwendet, müssen drei Dinge
konsistent sein: die `Registry.pol` (PReg-Format), die Version in `GPT.INI` **und** im
AD-Attribut `versionNumber`, sowie die passende **Client-Side-Extension-GUID** in
`gPCMachineExtensionNames`. `samba-tool gpo load` erledigt genau das atomar für
Registry-basierte Policies; für Sicherheitseinstellungen (Benutzerrechte, Restricted
Groups), lokale Admins (GPP) und Startskripte schreibt das Toolkit die Dateien selbst und
registriert die jeweilige CSE-GUID. Details: [`docs/`](docs/).

## Konzept

- **Deklarativer YAML-Katalog** (`catalog/`): ein Paket pro Anliegen (Datenschutz, Updates,
  Energie, Sperren, WoL, Remote-Management, lokale Admins …), mit Scope (global / pro Schule
  / noPXE / Raum / Lehrer-Notebook) und Ziel (Computer/User).
- **`lmgpo`-CLI** mit interaktivem **Setup-Assistenten**, idempotent, überall `--dry-run`.
- **Dynamische Erkennung**: Realm, Base-DN, Server-IP/Subnetz, Schulen, deren Präfixe,
  Admin-Gruppen, die `d_nopxe`-Gerätegruppe und Räume werden live aus dem AD gelesen –
  nichts ist auf `default-school` hartkodiert.
- **Schonend**: rührt `sophomorix:*`- und Default-GPOs nie an, sichert bestehende GPOs vor
  Änderungen, prüft ACLs (`aclcheck`/`sysvolcheck`).

## Nutzung (Stand jetzt)

Auf dem Schulserver als **root** ausführen:

```bash
./lmgpo-cli doctor          # Umgebungs-Selbstcheck
./lmgpo-cli env --json      # erkannte Umgebung als JSON
./lmgpo-cli list            # vorhandene GPOs + Verlinkungen
```

## Was das Toolkit setzen wird (aus den Anforderungen)

- Datenschutz/DSGVO: Telemetrie, Werbe-ID, Aktivitätsverlauf, Standort, Consumer-/Spotlight-Features aus
- Windows-Update: **aus für LINBO-Rechner**, **an für Nicht-LINBO-Geräte** (`d_nopxe`)
- First-Run/OOBE: „Fertig einrichten“, Spotlight, Cortana, OneDrive-/Edge-Erstlauf aus
- Energie: **kein Standby**, Display aus nach 30 Min, Sperre nach 30 Min (`InactivityTimeoutSecs`)
- **Fast Startup aus** (`HiberbootEnabled=0`) + **Wake-on-LAN** arm (Startskript)
- Remote-Management: RDP aktiv, Firewall-Regeln (RDP/SMB/RPC/ICMP, auf Server-IP begrenzbar),
  Remote-Shutdown-Recht
- Lokale Admins/RDP: `global-admins` überall, `<schule>-admins` pro Schule
- Lehrer-Notebooks: lockerere Energie-/Sperr-Regeln

## Anforderungen

linuxmuster.net 7.x Samba-AD-DC, Python ≥ 3.10, `python3-yaml`, `samba` Python-Bindings,
`samba-tool` (Samba ≥ 4.16 für `gpo load`). Läuft als root auf dem DC.

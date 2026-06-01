# ROADMAP - Traffic_HUB

Projekt-Roadmap für das plattformübergreifende Netzwerkverkehr-Überwachungstool.

## Phasen & Meilensteine

### [x] Phase 1: Projekt-Kickoff & Struktur (Meilenstein 1)
- [x] Projektverzeichnis anlegen
- [x] Git-Repository initialisieren und `.gitignore` einrichten
- [x] Dependencies in `requirements.txt` festlegen
- [x] HEIMDALL-konforme `core/config.py` und Logging aufsetzen

### [x] Phase 2: Schnittstellen & Durchsatz (Meilenstein 2)
- [x] Implementierung der Netzwerkadapter-Erkennung via `psutil`
- [x] Berechnung des aktuellen Durchsatzes (Upload & Download in Bytes/s)
- [x] Integration in das strukturierte Logging (`structlog`)

### [x] Phase 3: Paket-Sniffing & Analyse (Meilenstein 3)
- [x] Implementierung des Paket-Sniffers mit `scapy`
- [x] Filterung nach IP-Paketen (TCP, UDP, ICMP)
- [x] Identifizierung von Quell- und Ziel-IPs sowie Ports

### [x] Phase 4: Live-Dashboard & Qualitätssicherung (Meilenstein 4)
- [x] CLI Live-Dashboard mit `rich` (Live-Aktualisierung der Tabellen)
- [x] Ausführliches Testing auf verschiedenen Betriebssystemen (Windows, macOS, Linux)
- [x] Beheben von Performance-Flaschenhälsen bei hohem Traffic-Aufkommen

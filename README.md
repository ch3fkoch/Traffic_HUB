# Traffic_HUB

Plattformübergreifendes Netzwerk-Traffic-Überwachungs- und Analyse-Tool für Windows, macOS und Linux. 
Traffic_HUB analysiert aktive Netzwerkadapter, misst den Durchsatz (Upload/Download in Echtzeit) und loggt Paketziele (IP/Port), um Transparenz über den Datenverkehr der Endgeräte zu schaffen.

## Features
- **Adapter-Erkennung:** Listet alle aktiven und inaktiven Netzwerk-Schnittstellen auf.
- **Traffic-Messung:** Zeigt gesendete und empfangene Bytes sowie die aktuelle Übertragungsrate pro Sekunde.
- **Paket-Sniffing:** Analysiert ausgehende und eingehende IP-Pakete (Quell- und Ziel-IPs, Ports, Protokolle wie TCP/UDP/ICMP).
- **Dashboard:** Schöne Echtzeit-Terminal-Oberfläche (CLI) zur Live-Analyse.

## Installation

1. **Repository klonen**
2. **Virtual Environment erstellen und aktivieren:**
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # Unter Windows: .venv\Scripts\activate
   ```
3. **Abhängigkeiten installieren:**
   ```bash
   pip install -r requirements.txt
   ```

## Ausführung & Berechtigungen

Da die Paketüberwachung auf Betriebssystemebene ansetzt, werden erhöhte Rechte benötigt:
- **macOS / Linux:**
  ```bash
  sudo .venv/bin/python app.py
  ```
- **Windows:**
  Starten Sie die PowerShell oder Eingabeaufforderung als Administrator und führen Sie aus:
  ```powershell
  .venv\Scripts\python.exe app.py
  ```
  *(Hinweis für Windows: Ggf. muss [Npcap](https://npcap.com/) installiert sein, damit Scapy Pakete aufzeichnen kann).*

## Lizenz

Dieses Projekt ist unter der MIT-Lizenz lizenziert – siehe die [LICENSE](LICENSE)-Datei für Details.

# Benutzerhandbuch & Testanleitung: Traffic_HUB

Dieses Handbuch beschreibt die Einrichtung, das Testen und die Funktionsweise von **Traffic_HUB** auf den verschiedenen Betriebssystemen (Windows, macOS und Linux).

---

## 1. Voraussetzungen & Installation

Traffic_HUB nutzt Python und benötigt zusätzliche Berechtigungen für das Auslesen von Netzwerkpaketen.

### Virtual Environment (venv) vorbereiten
Öffnen Sie Ihr Terminal im Verzeichnis `/Users/stephan/developer/Traffic_HUB` und führen Sie folgende Befehle aus:

1. **Virtual Environment erstellen:**
   ```bash
   python3 -m venv .venv
   ```
2. **Virtual Environment aktivieren:**
   - **macOS / Linux:**
     ```bash
     source .venv/bin/activate
     ```
   - **Windows (PowerShell):**
     ```powershell
     .venv\Scripts\Activate.ps1
     ```
3. **Abhängigkeiten installieren:**
   ```bash
   pip install -r requirements.txt
   ```

---

## 2. Platformspezifische Besonderheiten (Wichtig!)

### macOS und Linux
Auf unixoiden Systemen greift Scapy auf `/dev/bpf*` (Berkeley Packet Filter) zu. Dies erfordert **Root-Rechte**. 
* **Ausführung:** Starten Sie die Skripte immer mit vorangestelltem `sudo`.
* **Beispiel:** `sudo .venv/bin/python app.py`

### Windows
Unter Windows wird das Paket-Sniffing über den Npcap-Treiber abgewickelt.
1. **Npcap installieren:** Laden Sie [Npcap](https://npcap.com/) herunter und installieren Sie es (wählen Sie bei der Installation "Install Npcap in WinPcap API-compatible Mode").
2. **Admin-Rechte:** Starten Sie Ihre PowerShell oder Eingabeaufforderung als **Administrator** und aktivieren Sie dort das Virtual Environment, um die Skripte auszuführen.

---

## 3. Testverfahren: Schritt-für-Schritt

Wir haben drei Test- und Ausführungsebenen implementiert. So verifizieren Sie die Funktionalität:

### Test 1: Adapter-Erkennung & Durchsatz (Keine Admin-Rechte nötig)
Dieses Skript listet alle Adapter und deren aktuellen Byte-Durchsatz (in KB/s) auf.
* **Befehl:**
  ```bash
  python test_monitor.py
  ```
* **Was wird geprüft?**
  - Erkennt das Skript alle Adapter (z. B. WLAN `en0`, Localhost `lo0`)?
  - Werden die IP-Adressen und MAC-Adressen richtig zugeordnet?
  - Reagiert die Durchsatzmessung, wenn Sie eine Website aufrufen?

### Test 2: Paket-Sniffing (Admin-/Root-Rechte erforderlich)
Dieses Skript horcht für 10 Sekunden auf der primären Netzwerkschnittstelle und listet die Top 15 Verbindungen (IPs/Ports/Protokolle) sortiert nach Datenvolumen auf.
* **Befehl:**
  ```bash
  sudo .venv/bin/python test_sniff.py
  ```
* **Was wird geprüft?**
  - Werden Pakete aufgezeichnet (Zähler im Terminal steigt)?
  - Werden Quell- und Ziel-IPs inklusive der Ports (z. B. HTTPS `:443`, DNS `:53`) richtig aufgeschlüsselt?
  - Werden die Protokolle (TCP, UDP, ICMP) korrekt erkannt?

### Test 3: Das Live-Dashboard (Vollständige App)
Das Echtzeit-Dashboard im Terminal kombiniert Adapter-Durchsatz und Verbindungsanalyse.
* **Befehl:**
  ```bash
  sudo .venv/bin/python app.py
  ```
* **Bedienung:**
  - Das Dashboard aktualisiert sich sekündlich automatisch.
  - Das aktuell gesniffte Interface wird mit einem Zeiger (`👉`) markiert.
  - **Beenden:** Drücken Sie **STRG+C** (KeyboardInterrupt). Das Dashboard schließt sich sauber und stellt die normale Terminalansicht wieder her.

---

## 4. Erklärung der Messwerte

* **Speed (Mbps):** Die maximale theoretische Verbindungsgeschwindigkeit des Adapters (z. B. 1000 Mbps für Gigabit-Ethernet).
* **Upload-/Download-Rate:** Die aktuell übertragenen Bytes pro Sekunde (live berechnet als Differenz zwischen zwei Zeitpunkten).
* **Proto:** Das Transportprotokoll des IP-Pakets:
  - `TCP`: Webverkehr (HTTP/HTTPS), SSH, FTP, etc.
  - `UDP`: DNS-Abfragen, Video-Streaming, Gaming.
  - `ICMP`: Ping-Befehle und Netzwerkdiagnose.
* **Quelle / Ziel (IP:Port):** Der Weg des Datenpakets. Lokale IPs beginnen meist mit `192.168.*`, `10.*` oder `172.*`. Ports deuten auf den Dienst hin (z. B. `443` für verschlüsselten Web-Traffic).

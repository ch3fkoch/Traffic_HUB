# ==============================================================================
# DATEI: test_sniff.py
# ZIEL: Testen der Paket-Sniffing-Funktionalität und Verbindungserkennung (Meilenstein 3)
# Rocky Linux kompatibel – HEIMDALL Standard
# ==============================================================================

import time
from core.config import cfg
from core.monitor import NetworkMonitor, SCAPY_AVAILABLE

def main():
    # HEIMDALL Programmstart-Vorschriften
    cfg.ensure_dirs()
    validation_warnings = cfg.validate()
    for warning in validation_warnings:
        cfg.logger.warning(warning)

    if not SCAPY_AVAILABLE:
        cfg.logger.error("Scapy ist nicht verfügbar. Test wird abgebrochen.")
        return

    cfg.logger.info("Starte Paket-Sniffing Test (benötigt Root/Admin-Rechte)...")

    monitor = NetworkMonitor()

    # Aktive Schnittstelle mit IP finden
    interfaces = monitor.get_interfaces()
    target_interface = None
    for iface in interfaces:
        if iface["is_up"] and iface["ips"] and iface["name"] != "lo0":
            target_interface = iface["name"]
            break

    if not target_interface:
        # Fallback auf Loopback
        target_interface = "lo0"

    cfg.logger.info(f"Ausgewähltes Interface für Sniffing: {target_interface}")

    # Sniffing starten
    monitor.start_sniffing(target_interface)

    print(f"\nSniffe auf {target_interface} für 10 Sekunden...")
    for i in range(10):
        time.sleep(1.0)
        connections = monitor.get_connections()
        print(f"Sekunde {i+1}/10 - Erfasste Verbindungen: {len(connections)}", end="\r")

    # Sniffing stoppen
    print("\nStoppe Sniffer...")
    monitor.stop_sniffing()

    # Ergebnisse auswerten
    connections = monitor.get_connections()
    print("\n--- Top 15 erkannte Netzwerkverbindungen ---")
    if not connections:
        print("Keine Verbindungen erfasst. Haben Sie das Skript mit sudo/Admin-Rechten gestartet?")
    else:
        # Nach Bytes sortieren
        sorted_connections = sorted(connections, key=lambda x: x["bytes"], reverse=True)
        print(f"{'PROTO':<6} | {'QUELLE (IP:PORT)':<30} | {'ZIEL (IP:PORT)':<30} | {'PAKETE':<8} | {'BYTES':<10}")
        print("-" * 92)
        for conn in sorted_connections[:15]:
            sport_str = f":{conn['sport']}" if conn['sport'] else ""
            dport_str = f":{conn['dport']}" if conn['dport'] else ""
            
            src = f"{conn['src_ip']}{sport_str}"
            dst = f"{conn['dst_ip']}{dport_str}"
            
            print(f"{conn['proto']:<6} | {src:<30} | {dst:<30} | {conn['packets']:<8} | {conn['bytes']:<10}")
    print("--------------------------------------------\n")

if __name__ == "__main__":
    main()

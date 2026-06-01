# ==============================================================================
# DATEI: test_monitor.py
# ZIEL: Testen der Schnittstellen-Erkennung und Durchsatzmessung
# Rocky Linux kompatibel – HEIMDALL Standard
# ==============================================================================

import time
from core.config import cfg
from core.monitor import NetworkMonitor

def main():
    # HEIMDALL Programmstart-Vorschriften
    cfg.ensure_dirs()
    validation_warnings = cfg.validate()
    for warning in validation_warnings:
        cfg.logger.warning(warning)

    cfg.logger.info("Starte manuellen Test für Netzwerküberwachung...")

    monitor = NetworkMonitor()

    # 1. Schnittstellen auflisten
    interfaces = monitor.get_interfaces()
    print("\n--- Gefundene Netzwerkadapter ---")
    for iface in interfaces:
        status = "AKTIV" if iface["is_up"] else "INAKTIV"
        ips_str = ", ".join(iface["ips"]) if iface["ips"] else "keine IP"
        print(f"Name: {iface['name']:<15} | Status: {status:<8} | IP(s): {ips_str:<25} | MAC: {iface['mac']}")
    print("---------------------------------\n")

    # 2. Durchsatz für 5 Sekunden messen
    print("Messe Durchsatz für 5 Sekunden (Intervall: 1s)...")
    
    # Erste Messung initialisiert den Monitor
    monitor.measure_throughput()
    
    for i in range(5):
        time.sleep(cfg.monitoring.interval_seconds)
        throughput = monitor.measure_throughput()
        
        print(f"\nMessung {i+1}/5:")
        has_traffic = False
        for name, stats in throughput.items():
            sent = stats["bytes_sent_per_sec"]
            recv = stats["bytes_recv_per_sec"]
            # Nur Schnittstellen mit Verkehr oder aktive Schnittstellen ausgeben, um die Konsole sauber zu halten
            if sent > 0 or recv > 0:
                has_traffic = True
                # Formatierung in KB/s
                sent_kb = sent / 1024.0
                recv_kb = recv / 1024.0
                print(f"  {name:<15} -> Send: {sent_kb:8.2f} KB/s | Recv: {recv_kb:8.2f} KB/s")
        
        if not has_traffic:
            print("  (Kein nennenswerter Netzwerkverkehr auf den Schnittstellen festgestellt)")

if __name__ == "__main__":
    main()

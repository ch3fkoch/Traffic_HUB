# ==============================================================================
# DATEI: app.py
# ZIEL: Live-Dashboard-Anwendung für Netzwerkverkehr-Überwachung (Meilenstein 4)
# Rocky Linux kompatibel – HEIMDALL Standard
# ==============================================================================

import time
import sys
from typing import Optional
from datetime import datetime
from rich.console import Console, Group
from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from rich.align import Align
from rich import box

from core.config import cfg
from core.monitor import NetworkMonitor, SCAPY_AVAILABLE

console = Console()

def format_size(bytes_value: float, per_second: bool = False) -> str:
    """Formatiert Byte-Werte in eine lesbare Einheit (B, KB, MB, GB)."""
    suffix = "/s" if per_second else ""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_value < 1024.0:
            return f"{bytes_value:.2f} {unit}{suffix}"
        bytes_value /= 1024.0
    return f"{bytes_value:.2f} PB{suffix}"

def generate_dashboard(monitor: NetworkMonitor, selected_iface: Optional[str], sniff_error_occurred: bool) -> Group:
    """Erstellt das Live-Dashboard-Layout als Gruppe von Rich-Elementen."""
    # 1. Header & System-Informationen
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    system_info = f"Plattform: {sys.platform.upper()} | Zeit: {current_time}"
    
    if sniff_error_occurred:
        sniff_status = "[bold red]DEAKTIVIERT (Fehlende Root-Rechte / sudo)[/bold red]"
    elif not SCAPY_AVAILABLE:
        sniff_status = "[bold yellow]DEAKTIVIERT (Scapy nicht installiert)[/bold yellow]"
    else:
        sniff_status = f"[bold green]AKTIV auf {selected_iface}[/bold green]"

    header_text = (
        f"[bold cyan]TRAFFIC_HUB[/bold cyan] - Netzwerk-Live-Monitor\n"
        f"[dim]{system_info}[/dim] | Sniffer: {sniff_status}"
    )
    header_panel = Panel(Align.center(header_text), box=box.ROUNDED, style="cyan")

    # 2. Tabelle der Netzwerkadapter (psutil)
    interfaces = monitor.get_interfaces()
    throughput = monitor.measure_throughput()
    
    adapter_table = Table(title="Netzwerkschnittstellen", box=box.MINIMAL_DOUBLE_HEAD, expand=True)
    adapter_table.add_column("Adapter", style="bold magenta", width=12)
    adapter_table.add_column("Status", width=10)
    adapter_table.add_column("IP-Adressen", style="green", width=32)
    adapter_table.add_column("Speed (Mbps)", justify="right", width=12)
    adapter_table.add_column("Upload-Rate", justify="right", style="cyan", width=15)
    adapter_table.add_column("Download-Rate", justify="right", style="cyan", width=15)

    for iface in interfaces:
        name = iface["name"]
        status = "[green]AKTIV[/green]" if iface["is_up"] else "[red]INAKTIV[/red]"
        ips = ", ".join(iface["ips"]) if iface["ips"] else "[dim]keine IP[/dim]"
        speed = str(iface["speed_mbps"]) if iface["speed_mbps"] > 0 else "[dim]N/A[/dim]"
        
        rates = throughput.get(name, {"bytes_sent_per_sec": 0.0, "bytes_recv_per_sec": 0.0})
        up_rate = format_size(rates["bytes_sent_per_sec"], per_second=True)
        down_rate = format_size(rates["bytes_recv_per_sec"], per_second=True)
        
        # Markiere das aktuell gesniffte Interface
        name_display = f"👉 {name}" if name == selected_iface else f"  {name}"
        
        adapter_table.add_row(name_display, status, ips, speed, up_rate, down_rate)

    # 3. Tabelle der Top-Verbindungen (scapy)
    connections = monitor.get_connections()
    
    conn_table = Table(title="Top 10 Verbindungen (nach Datenvolumen)", box=box.MINIMAL_DOUBLE_HEAD, expand=True)
    conn_table.add_column("Proto", style="bold yellow", width=8)
    conn_table.add_column("Quelle (IP:Port)", width=35)
    conn_table.add_column("Ziel (IP:Port)", width=35)
    conn_table.add_column("Pakete", justify="right", width=10)
    conn_table.add_column("Datenvolumen", justify="right", style="green", width=15)

    if not SCAPY_AVAILABLE or sniff_error_occurred:
        conn_table.add_row(
            "[dim]N/A[/dim]", 
            "[dim]Paket-Sniffing deaktiviert.[/dim]", 
            "[dim]Bitte mit sudo / Administrator-Rechten starten.[/dim]", 
            "[dim]-[/dim]", 
            "[dim]-[/dim]"
        )
    elif not connections:
        conn_table.add_row(
            "-", 
            "[dim]Warte auf Pakete...[/dim]", 
            "-", 
            "-", 
            "-"
        )
    else:
        # Sortieren nach Bytes absteigend und die Top 10 nehmen
        sorted_conns = sorted(connections, key=lambda x: x["bytes"], reverse=True)[:10]
        for conn in sorted_conns:
            sport = f":{conn['sport']}" if conn['sport'] else ""
            dport = f":{conn['dport']}" if conn['dport'] else ""
            src = f"{conn['src_ip']}{sport}"
            dst = f"{conn['dst_ip']}{dport}"
            
            conn_table.add_row(
                conn["proto"],
                src,
                dst,
                f"{conn['packets']:,}",
                format_size(conn["bytes"])
            )

    return Group(header_panel, adapter_table, Panel(conn_table, box=box.ROUNDED))

def main():
    # HEIMDALL Programmstart-Vorschriften
    cfg.ensure_dirs()
    validation_warnings = cfg.validate()
    for warning in validation_warnings:
        cfg.logger.warning(warning)

    monitor = NetworkMonitor()
    
    # 1. Aktiven Adapter mit IP ermitteln für das Sniffing
    interfaces = monitor.get_interfaces()
    selected_iface = None
    for iface in interfaces:
        # Wir bevorzugen echte Schnittstellen wie en0, eth0, wlan0 etc., die UP sind und eine IP haben
        if iface["is_up"] and iface["ips"] and iface["name"] != "lo0":
            selected_iface = iface["name"]
            break
            
    if not selected_iface:
        selected_iface = "lo0" # Fallback auf Loopback

    # 2. Sniffer starten
    sniff_error_occurred = False
    if SCAPY_AVAILABLE:
        try:
            monitor.start_sniffing(selected_iface)
            # Kurz warten und prüfen, ob der Thread direkt aufgrund von PermissionError abgebrochen ist
            time.sleep(0.2)
            if monitor._sniff_thread and not monitor._sniff_thread.is_alive() and not monitor._stop_sniff:
                sniff_error_occurred = True
        except Exception as e:
            cfg.logger.error("Konnte Sniffing nicht initialisieren", error=str(e))
            sniff_error_occurred = True
    else:
        sniff_error_occurred = True

    cfg.logger.info("Starte Live-Dashboard. Beenden mit STRG+C.")

    # 3. Live-Aktualisierungsschleife
    try:
        # Erste Messung zur Initialisierung des Durchsatzzählers
        monitor.measure_throughput()
        time.sleep(0.5)

        with Live(generate_dashboard(monitor, selected_iface, sniff_error_occurred), screen=True, auto_refresh=False) as live:
            while True:
                time.sleep(cfg.monitoring.interval_seconds)
                # Dashboard neu rendern und anzeigen
                live.update(generate_dashboard(monitor, selected_iface, sniff_error_occurred), refresh=True)
    except KeyboardInterrupt:
        cfg.logger.info("Beenden durch Benutzer (STRG+C)...")
    finally:
        # 4. Clean Termination
        monitor.stop_sniffing()
        console.print("\n[bold green]Traffic_HUB wurde sauber beendet.[/bold green]\n")

if __name__ == "__main__":
    main()

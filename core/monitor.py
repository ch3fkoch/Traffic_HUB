# ==============================================================================
# DATEI: core/monitor.py
# ZIEL: Netzwerkadapter-Erkennung, Durchsatzmessung und Paket-Sniffing (Meilenstein 3)
# Rocky Linux kompatibel – HEIMDALL Standard
# ==============================================================================

import time
import socket
import threading
from typing import Dict, Any, List, Optional
import psutil

# Optionaler Import von scapy zur Ermöglichung von Graceful Degradation
SCAPY_AVAILABLE = False
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP
    SCAPY_AVAILABLE = True
except Exception:
    pass

from core.config import cfg

class NetworkMonitor:
    """
    Stellt Methoden zur Erkennung von Netzwerkadaptern,
    zur Messung des Datendurchsatzes sowie zum Paket-Sniffing bereit.
    """

    def __init__(self):
        self.logger = cfg.logger
        self.prev_io: Dict[str, Any] = {}
        self.prev_time: float = 0.0
        
        # Sniffing-spezifische Attribute
        self.connections: Dict[tuple, Dict[str, Any]] = {}
        self.lock = threading.Lock()
        self._sniff_thread: Optional[threading.Thread] = None
        self._stop_sniff = False
        self.current_interface: Optional[str] = None

    def get_interfaces(self) -> List[Dict[str, Any]]:
        """Listet alle Netzwerkadapter mit ihren Attributen auf."""
        self.logger.info("Starte Schnittstellen-Erkennung...")
        interfaces = []
        
        try:
            addrs = psutil.net_if_addrs()
            stats = psutil.net_if_stats()
        except Exception as e:
            self.logger.error("Fehler beim Abrufen der Schnittstellen-Informationen", error=str(e))
            return []

        for name, addr_list in addrs.items():
            if_stats = stats.get(name)
            is_up = if_stats.isup if if_stats else False
            speed = if_stats.speed if if_stats else 0
            mtu = if_stats.mtu if if_stats else 0
            
            ips = []
            mac = None
            
            for conn in addr_list:
                if conn.family == socket.AF_INET:
                    ips.append(conn.address)
                elif conn.family == getattr(socket, "AF_INET6", -1):
                    ips.append(conn.address.split('%')[0])
                elif conn.family == getattr(psutil, "AF_LINK", -1):
                    mac = conn.address

            interfaces.append({
                "name": name,
                "is_up": is_up,
                "speed_mbps": speed,
                "mtu": mtu,
                "ips": ips,
                "mac": mac
            })
            
            self.logger.debug("Schnittstelle erkannt", name=name, is_up=is_up, ips=ips, mac=mac)
            
        return interfaces

    def measure_throughput(self) -> Dict[str, Dict[str, float]]:
        """Misst den aktuellen Durchsatz (Bytes/Sekunde Up und Down) für alle Schnittstellen."""
        current_time = time.time()
        
        try:
            current_io = psutil.net_io_counters(pernic=True)
        except Exception as e:
            self.logger.error("Fehler beim Abrufen der I/O-Zähler", error=str(e))
            return {}

        throughput: Dict[str, Dict[str, float]] = {}

        if not self.prev_io or self.prev_time == 0.0:
            self.prev_io = current_io
            self.prev_time = current_time
            for name in current_io.keys():
                throughput[name] = {
                    "bytes_sent_per_sec": 0.0,
                    "bytes_recv_per_sec": 0.0
                }
            return throughput

        time_delta = current_time - self.prev_time
        if time_delta <= 0:
            time_delta = 0.001

        for name, io in current_io.items():
            if name in self.prev_io:
                prev = self.prev_io[name]
                bytes_sent = max(0.0, float(io.bytes_sent - prev.bytes_sent))
                bytes_recv = max(0.0, float(io.bytes_recv - prev.bytes_recv))
                
                throughput[name] = {
                    "bytes_sent_per_sec": bytes_sent / time_delta,
                    "bytes_recv_per_sec": bytes_recv / time_delta
                }
            else:
                throughput[name] = {
                    "bytes_sent_per_sec": 0.0,
                    "bytes_recv_per_sec": 0.0
                }

        self.prev_io = current_io
        self.prev_time = current_time

        return throughput

    # --- Meilenstein 3: Sniffing-Logik ---

    def start_sniffing(self, interface: str):
        """Startet das Paket-Sniffing im Hintergrund-Thread."""
        if not SCAPY_AVAILABLE:
            self.logger.error("Scapy ist nicht verfügbar. Sniffing kann nicht gestartet werden.")
            return

        with self.lock:
            if self._sniff_thread and self._sniff_thread.is_alive():
                self.logger.warning("Sniffer läuft bereits.", interface=self.current_interface)
                return
            
            self._stop_sniff = False
            self.current_interface = interface
            # Verbindungsliste zurücksetzen
            self.connections.clear()

        self._sniff_thread = threading.Thread(
            target=self._sniff_loop, 
            args=(interface,), 
            daemon=True
        )
        self._sniff_thread.start()
        self.logger.info("Sniffing-Hintergrundthread gestartet", interface=interface)

    def stop_sniffing(self):
        """Beendet den Sniffing-Hintergrundthread."""
        with self.lock:
            self._stop_sniff = True
            
        if self._sniff_thread:
            self._sniff_thread.join(timeout=2.0)
            self.logger.info("Sniffing-Hintergrundthread beendet")

    def _sniff_loop(self, interface: str):
        """Der eigentliche Sniffing-Loop (läuft im Hintergrundthread)."""
        try:
            # Scapy sniff blockiert. Wir nutzen stop_filter zur Beendigung.
            sniff(
                iface=interface,
                prn=self._packet_callback,
                stop_filter=self._stop_filter,
                store=False
            )
        except Exception as e:
            self.logger.error("Kritischer Fehler im Sniffing-Loop", error=str(e))

    def _stop_filter(self, packet) -> bool:
        """Prüft, ob der Loop gestoppt werden soll."""
        return self._stop_sniff

    def _packet_callback(self, packet):
        """Wird für jedes aufgezeichnete Paket aufgerufen."""
        if not SCAPY_AVAILABLE:
            return

        try:
            if IP in packet:
                ip_layer = packet[IP]
                src_ip = ip_layer.src
                dst_ip = ip_layer.dst
                proto = "OTHER"
                sport = 0
                dport = 0
                packet_size = len(packet)

                # Detailliertere Protokoll-Analysen
                if TCP in packet:
                    proto = "TCP"
                    sport = packet[TCP].sport
                    dport = packet[TCP].dport
                elif UDP in packet:
                    proto = "UDP"
                    sport = packet[UDP].sport
                    dport = packet[UDP].dport
                elif ICMP in packet:
                    proto = "ICMP"

                key = (src_ip, sport, dst_ip, dport, proto)

                with self.lock:
                    # Schutz vor Speicherüberlauf (Buffer-Pruning)
                    if len(self.connections) >= cfg.monitoring.packet_buffer_size:
                        # Älteste Verbindungen löschen
                        sorted_conns = sorted(
                            self.connections.items(), 
                            key=lambda x: x[1]["last_seen"]
                        )
                        # Entferne die ältesten 10%
                        num_to_remove = max(1, int(cfg.monitoring.packet_buffer_size * 0.1))
                        for k, _ in sorted_conns[:num_to_remove]:
                            self.connections.pop(k, None)

                    if key not in self.connections:
                        self.connections[key] = {
                            "packets": 0,
                            "bytes": 0,
                            "first_seen": time.time(),
                            "last_seen": 0.0
                        }
                    
                    self.connections[key]["packets"] += 1
                    self.connections[key]["bytes"] += packet_size
                    self.connections[key]["last_seen"] = time.time()
        except Exception as e:
            # Fehler im Paket-Callback abfangen, um Thread nicht zu töten
            pass

    def get_connections(self) -> List[Dict[str, Any]]:
        """Gibt die Liste aller erkannten Verbindungen zurück."""
        with self.lock:
            result = []
            for (src_ip, sport, dst_ip, dport, proto), stats in self.connections.items():
                result.append({
                    "src_ip": src_ip,
                    "sport": sport,
                    "dst_ip": dst_ip,
                    "dport": dport,
                    "proto": proto,
                    "packets": stats["packets"],
                    "bytes": stats["bytes"],
                    "first_seen": stats["first_seen"],
                    "last_seen": stats["last_seen"]
                })
            return result

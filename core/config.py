# ==============================================================================
# DATEI: core/config.py
# ZIEL: Zentrale Konfigurationsverwaltung und Logging-Initialisierung für Traffic_HUB
# Rocky Linux kompatibel – HEIMDALL Standard
# ==============================================================================

import os
import sys
import logging
from pathlib import Path
from typing import Any
from dotenv import load_dotenv

# Base Directory Resolution
_BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(dotenv_path=_BASE_DIR / ".env")

PROJECT_NAME = os.getenv("PROJECT_NAME", "TRAFFIC_HUB")

class _Paths:
    """Namespace für Pfade im Projekt."""
    def __init__(self, base_dir: Path):
        self.base_dir = base_dir
        self.core_dir = base_dir / "core"
        self.log_dir = base_dir / "logs"
        self.data_dir = base_dir / "data"

class _LoggingConfig:
    """Namespace für Logging-Einstellungen."""
    def __init__(self):
        self.level = os.getenv("LOG_LEVEL", "INFO").upper()

class _MonitoringConfig:
    """Namespace für Traffic-Monitoring-Einstellungen."""
    def __init__(self):
        self.interval_seconds = float(os.getenv("MONITOR_INTERVAL_S", "1.0"))
        self.packet_buffer_size = int(os.getenv("PACKET_BUFFER_SIZE", "1000"))

class _Config:
    """
    Singleton-ähnliche Konfigurationsklasse.
    Wird einmal instanziiert und dann als `cfg` importiert.
    """
    PROJECT_NAME: str = PROJECT_NAME
    logger: Any = None

    def __init__(self):
        self.paths = _Paths(_BASE_DIR)
        self.logging = _LoggingConfig()
        self.monitoring = _MonitoringConfig()
        
        # Kompatibilitäts-Aliase (direkter Zugriff)
        self.BASE_DIR = self.paths.base_dir
        self.LOG_DIR = self.paths.log_dir
        self.DATA_DIR = self.paths.data_dir

    def ensure_dirs(self):
        """Legt alle benötigten Verzeichnisse an, falls sie nicht existieren."""
        for directory in [self.paths.log_dir, self.paths.data_dir]:
            directory.mkdir(parents=True, exist_ok=True)

    def validate(self) -> list[str]:
        """Prüft alle Pflichtfelder beim Start."""
        errors = []
        # Da wir lokal auf Netzwerkschnittstellen lauschen, prüfen wir, ob wir Root/Admin-Rechte haben,
        # falls scapy benutzt werden soll.
        if sys.platform != "win32" and os.geteuid() != 0:
            errors.append("[CONFIG-WARNUNG] Das Programm läuft nicht als Root (sudo). Paket-Sniffing schlägt ggf. fehl.")
        return errors

    def __repr__(self) -> str:
        return f"<{PROJECT_NAME}_Config BASE={self.paths.base_dir} LEVEL={self.logging.level}>"

# Instanziierung des Singletons
cfg = _Config()
cfg.ensure_dirs()

# --- Logging-Initialisierung mit structlog und Standard-Rotation ---
import structlog
from logging.handlers import TimedRotatingFileHandler

def create_rotating_handler(filename, backup_count=3):
    handler = TimedRotatingFileHandler(
        cfg.paths.log_dir / filename,
        when="midnight",
        interval=1,
        backupCount=backup_count,
        encoding='utf-8'
    )
    handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S'))
    return handler

# Standard Python Logging Setup
root_logger = logging.getLogger()
log_level = getattr(logging, cfg.logging.level, logging.INFO)
root_logger.setLevel(log_level)

# Handler hinzufügen
root_logger.addHandler(create_rotating_handler("traffic_hub_system.log"))

# Structlog Konfiguration
structlog.configure(
    processors=[
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="%Y-%m-%d %H:%M:%S"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.dev.ConsoleRenderer() if log_level == logging.DEBUG else structlog.processors.JSONRenderer(),
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)

cfg.logger = structlog.get_logger("TrafficHubCore")

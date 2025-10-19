from pathlib import Path

# Base directory 
BASE_DIR = Path(__file__).parent.parent

# Directories
SCAN_DIR = BASE_DIR / "data" / "pcaps"
DB_PATH = BASE_DIR / "data" / "index.db"

# Protocols to detect - focus on SIGTRAN first (Mike's suggestion)
PROTOCOLS = [
    # SIGTRAN family (priority)
    "m3ua",     # SIGTRAN
    "m2ua",     # SIGTRAN
    "sua",      # SIGTRAN
    "sctp",     # SIGTRAN transport
    "sccp",     # Related to SIGTRAN
    
    # Other protocols (can add later)
    "sip",      # VoIP
    "isup",     # SS7
    "gre",      # Tunneling
]

# tshark timeout - 90 seconds for large files (>1GB)
TSHARK_TIMEOUT = 90

# Ensure directories exist
SCAN_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

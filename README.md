# PCAP Catalog CLI

A command-line tool to **catalog and search PCAP files** by protocol.
This project indexes `.pcap` and `.pcapng` files into a local SQLite database, 
detects network protocols (SIGTRAN, SIP, Diameter, GTP, etc.), and lets you 
search or show details quickly via CLI.

---

## Features

- Scan PCAP or PCAPNG files and store protocol info in SQLite  
- Search by protocol (e.g., `sip`, `gtp`, `sccp`)  
- List recently indexed files  
- Show full details for one file  
- Uses `tshark` for fast protocol hierarchy detection  
- Built in pure Python, no server required  

---

## Project Structure

```
pcapcat/
├── app/
│   ├── cli.py              # Command-line interface
│   ├── scanner.py          # PCAP scanning & protocol detection
│   ├── db.py               # SQLite database wrapper
│   ├── config.py           # Global settings
│   ├── __init__.py
│   └── tests/              # Optional test scripts
│
├── data/
│   ├── pcaps/              # Place your .pcap / .pcapng files here
│   └── index.db            # SQLite database (auto-created)
│
├── .gitignore
├── README.md
└── requirements.txt
```

---

## Installation (Linux)

### 1. Install dependencies

```bash
sudo apt update
sudo apt install -y python3 python3-pip tshark sqlite3
```

### 2. Clone or copy the project

```bash
git clone https://github.com/<your-repo>/pcapcat.git
cd pcapcat
```

### 3. Install Python packages

```bash
pip install -r requirements.txt
```

(requirements.txt should contain: pyshark, tabulate, etc. if you use them.)

---

## Configuration

Default paths are defined in `app/config.py`:

```python
SCAN_DIR = BASE_DIR / "data" / "pcaps"
DB_PATH = BASE_DIR / "data" / "index.db"
```

- PCAPs to be scanned should be placed under `data/pcaps/`
- The database `index.db` will be auto-created if missing.

---

## Usage

### 1. Scan PCAP files

Scan all files under the default folder:

```bash
python -m app.cli scan
```

Scan a specific file:

```bash
python -m app.cli scan camel.pcap
```

Scan a different directory:

```bash
python -m app.cli scan /path/to/folder
```

### 2. List indexed files

```bash
python -m app.cli list
```

### 3. Show one file's details

```bash
python -m app.cli view 1
```

Output example:
```
ID:            1
Filename:      camel.pcap
Path:          data/pcaps/camel.pcap
Packets:       13450
Protocols:     sip, udp, ip
Scanned at:    2025-10-19 09:30:21
```

### 4. Search by protocol

```bash
# Find all files that contain ETH traffic
python -m app.cli search -p eth

# Find files that contain SIP or SCCP
python -m app.cli search -p sip -p sccp
```

---

## Example Workflow

```bash
# 1. Drop PCAP files into data/pcaps/
# 2. Scan them and insert into database
python -m app.cli scan

# 3. Search by protocol
python -m app.cli search -p sccp -p sip

# 4. Inspect one file with ID no 2 
python -m app.cli view 2
```

---

## Database Schema

```sql
CREATE TABLE pcap_files (
    id INTEGER PRIMARY KEY,
    filename TEXT,
    filepath TEXT,
    file_hash TEXT,
    total_packets INTEGER,
    protocols TEXT,
    scanned_at TEXT 
);
```

`protocols` stores a JSON object:
e.g., `{"sip": 200, "udp": 210, "ip": 210}`

---

## Development Notes

- Runs entirely offline on Linux
- Designed as a POC (Proof of Concept) 
- Extendable to web UI or REST API easily (FastAPI/Flask)
- You can Dockerize it later for deployment


---

## Author

Ngoc Khong

Contact: khongthibichngoc@gmail.com
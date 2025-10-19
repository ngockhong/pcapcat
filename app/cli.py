import argparse
from app.config import SCAN_DIR
from app.db import Database
from app.scanner import PCAPScanner
from pathlib import Path


def cmd_list(args):
    db = Database()
    rows = db.list_pcaps(limit=args.limit)
    for row in rows:
        print(f"{row[0]:>3}  {row[1]:<25}  {row['6']}")   
            #tuple, not dict so must use index 0,1.. [0]: id , [1]: filename, [6]: scanned_at
    db.close()

def cmd_search(args):
    db = Database()
    protos = [p.lower() for p in args.protocol]
    sql = " OR ".join(["protocols LIKE ?"] * len(protos))
    params = [f'%"{p}"%' for p in protos]
    query = f"SELECT id, filename, protocols FROM pcap_files WHERE {sql}"
    db.cursor.execute(query, params)
    for row in db.cursor.fetchall():
        print(f"[{row[0]}] {row[1]}  ->  {row[2]}")
    db.close()

def cmd_viewDetail(args):
    db = Database()
    db.cursor.execute("SELECT * FROM pcap_files WHERE id=?", (args.id,))
    row = db.cursor.fetchone()
    if not row:
        print("Not found")
    else:
        print("\n=== PCAP DETAILS ===")
        print(f"ID: {row[0]}")
        print(f"Filename: {row[1]}")
        print(f"Path: {row[2]}")
        print(f"Total packets: {row[4]}")
        print(f"Protocols: {row[5]}")
    db.close()

def cmd_scan(args):
    """scan all pcap/pcapng files under SCAN_DIR or a provided path and insert results into db """

    path = Path(args.path) if args.path else SCAN_DIR
    print(path)

    if not path.exists():
        alt_path = SCAN_DIR / path.name
        #print(alt_path)
        if alt_path.exists():
            path = alt_path
        else:
            print("Path not found:", path)
            return
    

    db = Database()
    try:
        if path.is_file():
            pcap_files = [path]
        else:
            pcap_files = [p for p in path.rglob("*") if p.suffix.lower() in [".pcap", ".pcapng"]]

        if not pcap_files:
            print(f"No PCAP files found under {path}")
            return

        print(f"🔍 Found {len(pcap_files)} PCAP file(s) in {path}\n")

        for i, file in enumerate(pcap_files, start=1):
            print(f"[{i}/{len(pcap_files)}] Scanning {file.name}")
            try:
                scanner = PCAPScanner(
                    pcap_path=file,
                    db=db,
                    verbose=getattr(args, "verbose", False)
                )
                scanner.scan()
            except Exception as e:
                print(f"Error scanning {file.name}: {e}")
        print("\n Scan complete.")

    finally:
        db.close()


def main():
    parser = argparse.ArgumentParser(description="PCAP Catalog CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    # subcommand list
    list_parser = sub.add_parser("list", help="List recently scanned pcaps")
    list_parser.add_argument("--limit", type=int, default=20, help="Limit number of rows")
    list_parser.set_defaults(func=cmd_list)

    # sub command search
    search_parser = sub.add_parser("search", help="Search pcaps by protocol")
    search_parser.add_argument("-p", "--protocol", action="append", required=True, help="Protocol name")
    search_parser.set_defaults(func=cmd_search)

    #sub command view detail
    viewDetail_parser = sub.add_parser("view", help="View details of one pcap")
    viewDetail_parser.add_argument("id", type=int)
    viewDetail_parser.set_defaults(func=cmd_viewDetail)

    #sub command scan
    scan_parser = sub.add_parser("scan", help="Scan file or directory for new pcaps")
    scan_parser.add_argument("path", nargs="?", help=f"Path to file or directory (default: {SCAN_DIR})")
    scan_parser.set_defaults(func=cmd_scan)

    args = parser.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()
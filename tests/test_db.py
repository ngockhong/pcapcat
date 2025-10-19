import argparse
from app.db import Database
from app.config import SCAN_DIR
import os
import hashlib
import datetime

def md5sum(file_path):
    """calc md5 hash"""
    with open(file_path, "rb") as f:
        data = f.read()
    return hashlib.md5(data).hexdigest()

def scan_and_insert_dummy(db):
    print(f"Scan folder: {SCAN_DIR}")

    for file in SCAN_DIR.glob("*.pcap*"):       #Read pcap and pcapng
        file_hash = md5sum(file)
        #file_size = os.path.getsize(file)
        total_packets = 0  # (dummy)
        protocols = "{}"   # (dummy)
        scanned_at = datetime.datetime.now().isoformat(timespec="seconds") # dummy

        # check for duplicate
        dup = db.check_duplicate(file_hash)
        if dup:
            print(f"Duplicate found: {dup[1]} (ID={dup[0]}) - skip {file.name}")
            continue

        pcap_id = db.insert_pcap(
            filename=file.name,
            filepath=str(file),
            file_hash=file_hash,
            total_packets=total_packets,
            protocols=protocols,
            scanned_at=scanned_at,
        )

        if pcap_id:
            print(f"Added {file.name} (id={pcap_id})")
        else:
            print(f"Failed to insert {file.name}")

    db.close()
    print("\n Complete inserting.")

def print_db(db):
    print("\n Current database entries:")
    for row in db.get_all_pcaps():
        print(row)
    db.close()
    print("\n End of DB.")

def main():
    db = Database()
    parser = argparse.ArgumentParser(description="Test database insert for PCAP catalog")
    parser.add_argument("--reset", action="store_true", help="Delete old DB before scanning")
    parser.add_argument("--scandummy", action="store_true", help="Scan and insert into DB using dummy metadata")
    parser.add_argument("--printall", action="store_true", help="Print all entries in DB")
    args = parser.parse_args()

    if args.reset:
        db.reset_database()
    elif args.scandummy:
        scan_and_insert_dummy(db)
    elif args.printall:
        print_db(db)


if __name__ == "__main__":
    main()
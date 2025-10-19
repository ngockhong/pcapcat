import argparse
from pathlib import Path
from app.config import SCAN_DIR
from app.db import Database
from app.scanner import PCAPScanner

def resolve_pcap_path(file_arg):
    """
    Resolve PCAP file path:
    - If full path exists, use it
    - If just filename, look in SCAN_DIR
    - Return Path object or None if not found
    """
    # Try as-is first (full path or relative path)
    path = Path(file_arg)
    if path.exists():
        return path
    
    # Try in SCAN_DIR
    scan_path = SCAN_DIR / file_arg
    if scan_path.exists():
        return scan_path
    
    # Not found anywhere
    return None


def test_extract_fast(pcap_file, max_packets=None):
    """Test tshark fast extraction"""

    print(f"\n{'='*70}")
    print(f"TEST: Extract metadata (tshark fast mode)")
    print(f"File: {pcap_file}")
    if max_packets:
        print(f"Max packets: {max_packets}")
    print(f"{'='*70}")
    
    scanner = PCAPScanner(
        pcap_path=pcap_file,
        db=None,  # No DB needed for extract test
        max_packets=max_packets,
        verbose=True,
        fast=True
    )
    
    meta = scanner.extract_metadata()
    
    print(f"\n Results:")
    print(f"  Total packets: {meta['total_packets']:,}")
    print(f"  Unique protocols: {len(meta['protocols'])}")
    print(f"\n  Protocol breakdown:")
    
    # Sort by count
    sorted_protos = sorted(meta['protocols'].items(), key=lambda x: x[1], reverse=True)
    for proto, count in sorted_protos:
        pct = (count / meta['total_packets'] * 100) if meta['total_packets'] > 0 else 0
        print(f"    {proto:20} {count:7,} ({pct:5.1f}%)")
    
    print(f"\n Scanning by tshark completed")


def test_extract_pyshark(pcap_file, max_packets=None):
    """Test pyshark extraction"""

    print(f"\n{'='*70}")
    print(f"TEST: Extract metadata (Pyshark mode)")
    print(f"File: {pcap_file}")
    if max_packets:
        print(f"Max packets: {max_packets}")
    print(f"{'='*70}")
    
    scanner = PCAPScanner(
        pcap_path=pcap_file,
        db=None,
        max_packets=max_packets,
        verbose=True,
        fast=False
    )
    
    meta = scanner.extract_metadata()
    
    print(f"\n Results:")
    print(f"  Total packets: {meta['total_packets']:,}")
    print(f"  Unique protocols: {len(meta['protocols'])}")
    print(f"\n  Protocol breakdown:")
    
    sorted_protos = sorted(meta['protocols'].items(), key=lambda x: x[1], reverse=True)
    for proto, count in sorted_protos:
        pct = (count / meta['total_packets'] * 100) if meta['total_packets'] > 0 else 0
        print(f"    {proto:20} {count:7,} ({pct:5.1f}%)")
    
    print(f"\n Scanning by Pyshark completed")

def test_full_scan(pcap_file, fast=True, max_packets=None):
    """Test full scan with database insert"""

    print(f"\n{'='*70}")
    print(f"TEST: Full scan with DB insert")
    print(f"File: {pcap_file}")
    print(f"Method: {'tshark' if fast else 'pyshark'}")
    if max_packets:
        print(f"Max packets: {max_packets}")
    print(f"{'='*70}")
    
    db = Database()
    
    scanner = PCAPScanner(
        pcap_path=pcap_file,
        db=db,
        max_packets=max_packets,
        verbose=True,
        fast=fast
    )
    
    pcap_id = scanner.scan()
    
    if pcap_id:
        print(f"\n Successfully scanned PCAP ID: {pcap_id}")
        print(f"\n Database entry:")
        saved = db.get_pcap(pcap_id)
        if saved:
            print(f"  ID: {saved[0]}")
            print(f"  Filename: {saved[1]}")
            print(f"  Hash: {saved[3]}")
            print(f"  Total packets: {saved[4]:,}")
            print(f"  Scanned at: {saved[6]}")
    else:
        print(f"\n Scan failed or duplicate found")
    
    db.close()


def main():
    parser = argparse.ArgumentParser(
        description="Test PCAPScanner functionality",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
            Examples:
            python test_scanner.py --file samples/test.pcap --fast
            python test_scanner.py --file samples/test.pcap --pyshark
            python test_scanner.py --file samples/test.pcap --pyshark --max 100
            python test_scanner.py --file samples/test.pcap --scan
            python test_scanner.py --file samples/test.pcap --scan --fast
            python test_scanner.py --file samples/test.pcap --scan --fast --max 100
        """
    )
    
    parser.add_argument(
        "--file", 
        type=str, 
        required=True,
        help="Path to PCAP file to test"
    )
    
    parser.add_argument(
        "--fast", 
        action="store_true",
        help="Use tshark fast mode"
    )
    
    parser.add_argument(
        "--pyshark",
        action="store_true", 
        help="Use pyshark mode"
    )
    
    parser.add_argument(
        "--max",
        type=int,
        metavar="N",
        help="Limit to N packets (works with --fast, --pyshark, or --scan)"
    )
    
    parser.add_argument(
        "--scan",
        action="store_true",
        help="Test full scan with database insert"
    )
    
    args = parser.parse_args()
    
    # Resolve file path then validate file exists
    pcap_file = resolve_pcap_path(args.file)

    if not pcap_file:
        print(f"File not found: {pcap_file}")
        return
    
    file_size_mb = pcap_file.stat().st_size / (1024 * 1024)
    if file_size_mb > 500 and args.pyshark and not args.max:
        print(f"\n WARNING: Large file ({file_size_mb:.1f} MB) + PyShark = VERY SLOW!")
        print(f"\n Recommendations:")
        print(f"   1. Use --fast instead (10-20x faster)")
        print(f"   2. Or add --max 10000 to sample first 10k packets")
        print(f"\n Suggested commands:")
        print(f"   python -m app.test_scanner --file \"{pcap_file.name}\" --fast")
        print(f"   python -m app.test_scanner --file \"{pcap_file.name}\" --pyshark --max 10000")
        
        response = input("\n Continue anyway? (y/N): ")
        if response.lower() != 'y':
            print("\n Cancelled. Please run another command")
            return
        
    # Check for conflicting flags
    if args.fast and args.pyshark and not args.scan:
        print(f"Cannot use --fast and --pyshark together (choose 1)")
        print(f"Use --scan --fast or --scan (default pyshark) for full scan")
        return
    
    # Run requested tests
    if args.fast:
        test_extract_fast(pcap_file, max_packets=args.max)
    
    elif args.pyshark:
        test_extract_pyshark(pcap_file, max_packets=args.max)
    
    elif args.scan:
        # Use fast mode if --fast also specified otherwise use pyshark
        use_fast = args.fast
        test_full_scan(pcap_file, fast=use_fast, max_packets=args.max)
    
    else:
        # No specific test - show usage
        parser.print_help()


if __name__ == "__main__":
    main()
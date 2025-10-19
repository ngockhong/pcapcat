import datetime
import hashlib
import json
from pathlib import Path
import subprocess
import pyshark
from app.db import Database

class PCAPScanner:

    # Protocols that trigger deep scan mode
    DEEP_SCAN_TRIGGERS = {
        # SS7/SIGTRAN (2G/3G signaling)
        'sccp', 'tcap', 'map', 'camel', 'isup', 'inap', 'm3ua', 'sctp', 'sua',
        
        # Diameter (4G/5G AAA)
        'diameter',
        
        # GTP (needs tunnel inspection)
        'gtp', 'gtpv2', 'gtp-u', 'gtp-c',
        
        # SIP/IMS/VoLTE
        'sip', 'megaco', 'h248',
        
        # 5G Core
        'ngap', 'pfcp', 'http2',
        
        # Tunneled/encrypted (need deep inspection)
        'ipsec', 'gre', 'l2tp',
        
        # LTE/5G RAN
        's1ap', 'x2ap', 'f1ap', 'e1ap'
    }

    # Adaptive sampling thresholds
    SMALL_FILE_THRESHOLD = 500 * 1024 * 1024   # 500MB
    MEDIUM_FILE_THRESHOLD = 2 * 1024 * 1024 * 1024  # 2GB
    
    DEEP_SCAN_SAMPLE_SMALL = None  # Full scan for small files
    DEEP_SCAN_SAMPLE_MEDIUM = 50000  # 50k packets for medium files
    DEEP_SCAN_SAMPLE_LARGE = 20000   # 20k packets for large files

    def __init__(
                self, 
                pcap_path, 
                db,
                max_packets= None,
                verbose= False,
                fast = True,
                ):
        
        """
        pcap_path: pcap file path
        db: Db instance
        max_packets: int or None. If int, stop after that many packets
        verbose: bool. If True print extra logs of ongoing progress
        fast: bool. If True use tshark subprocess to execute faster on large files. 
        
        Auto adaptive deep scan if signaling protocol detected
        """

        self.pcap_path = Path(pcap_path)
        self.db = db
        self.max_packets = None if max_packets is None else int(max_packets)
        self.verbose = verbose
        self.fast = fast

        # Get file size for adaptive strategy
        self.file_size = self.pcap_path.stat().st_size

    def _log(self, *args, **kwargs):
        if self.verbose:
            print(*args, **kwargs)

    def _format_size(self, size_bytes):
        """Format file size in human-readable format"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.1f}{unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.1f}TB"

    def _file_hash(self):
        """calc md5 for duplicate, read in chunk for large file """
        h = hashlib.md5()
        with open(self.pcap_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()

    def _get_deep_scan_limit(self):
        """
        Determine how many packets to deep scan based on file size.
        
        Returns:
            int or None: Packet limit for deep scan, None for full scan
        """
        if self.file_size < self.SMALL_FILE_THRESHOLD:
            return self.DEEP_SCAN_SAMPLE_SMALL  # None = full scan
        elif self.file_size < self.MEDIUM_FILE_THRESHOLD:
            return self.DEEP_SCAN_SAMPLE_MEDIUM  # 50k packets
        else:
            return self.DEEP_SCAN_SAMPLE_LARGE   # 20k packets

    def _needs_deep_scan(self, protocols_dict):
        """
        Check if any protocol in the quick scan requires deep inspection.
        
        Args:
            protocols_dict: dict from io,phs output
            
        Returns:
            bool: True if deep scan needed
        """
        detected = set(protocols_dict.keys())
        triggers = detected & self.DEEP_SCAN_TRIGGERS
        
        if triggers:
            deep_limit = self._get_deep_scan_limit()
            sample_info = f"sampling {deep_limit:,} packets" if deep_limit else "full scan"
            self._log(f"\n  Deep scan triggered by: {', '.join(sorted(triggers))}")
            self._log(f"    Strategy: {sample_info} (file size: {self._format_size(self.file_size)})")
            return True
        return False
    
    def extract_metadata(self):
        """
        Extract metadata using either pyshark wrapper or tshark CLI (fast).
        Returns dict: {"total_packets": int, "protocols": {proto: count, ...}}
        """
        if self.fast:
            return self._extract_metadata_fast()
        else:
            return self._extract_metadata_pyshark()
        
    
    def _extract_metadata_pyshark(self):
        protocols = {}
        total_packets = 0

        try:
            cap = pyshark.FileCapture(
                str(self.pcap_path),
                only_summaries=False,   #full decode toread packet.layers
                keep_packets=False,  # don't retain packets in memory
            )

            for pkt in cap:
                total_packets += 1
                
                for layer in pkt.layers:
                    lname = layer.layer_name.lower().strip()
                    if lname:
                        protocols[lname] = protocols.get(lname, 0) + 1

                # stop early if limit reached
                if self.max_packets and total_packets >= self.max_packets:
                    self._log(f"[pyshark] reached max_packets={self.max_packets}")
                    break

            cap.close()

        except Exception as e:
            print(f"[!] PyShark error parsing {self.pcap_path.name}: {e}")

        return {
            "total_packets": total_packets,
            "protocols": protocols,
            "is_sampled": False
        }

    def _extract_metadata_fast(self):
        """
        tshark mode with adaptive sampling, 2 steps:
        1. built-in protocol hierarchy stats of tshark
        2. “deep scan mode” -T fields -e frame.protocols if signaling protocols detected 
        (with sampling for large files)
                <500MB - full
                <2GB   - 50k packets
                >=2GB  - 20k packets + extrapolation
        """

        self._log("\n 1. Quick scan with tshark -z io,phs...")
        
        # Stage 1: Quick protocol hierarchy statistics
        protocols = {}
        total_packets = 0
        
        try:
            cmd = [
                'tshark',
                '-r', str(self.pcap_path),
                '-q',  # quiet mode
                '-z', 'io,phs'  # protocol hierarchy statistics
            ]
            
            if self.max_packets:
                cmd.extend(['-c', str(self.max_packets)])
            
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=120,
                check=True
            )
            
            # Parse io,phs output
            in_hierarchy = False
            for line in result.stdout.split('\n'):
                line = line.strip()
                
                if 'Protocol Hierarchy Statistics' in line:
                    in_hierarchy = True
                    continue
                
                if not in_hierarchy or not line:
                    continue
                
                # Parse lines like: "  tcp   frames:700 bytes:350000"
                if 'frames:' in line:
                    parts = line.split()
                    proto = parts[0].lower().strip()
                    
                    # Extract frame count
                    for part in parts:
                        if part.startswith('frames:'):
                            count = int(part.split(':')[1])
                            protocols[proto] = count
                            total_packets = max(total_packets, count)
                            break
            
            # If io,phs didn't work or returned nothing, fallback to frame count
            if total_packets == 0:
                self._log("   io,phs returned no data, getting packet count...")
                count_result = subprocess.run(
                    ['tshark', '-r', str(self.pcap_path), '-T', 'fields', '-e', 'frame.number'] +
                    (['-c', str(self.max_packets)] if self.max_packets else []),
                    capture_output=True,
                    text=True,
                    timeout=60
                )
                total_packets = len([l for l in count_result.stdout.split('\n') if l.strip()])
            
            self._log(f"   Found {total_packets:,} packets, {len(protocols)} protocol types")
            
        except subprocess.TimeoutExpired:
            print(f"[!] tshark io,phs timeout for {self.pcap_path.name}")
            return {"total_packets": 0, "protocols": {}, "is_sampled": False}
        except Exception as e:
            print(f"[!] tshark io,phs error parsing {self.pcap_path.name}: {e}")
            return {"total_packets": 0, "protocols": {}, "is_sampled": False}
        
        # Check if deep scan needed
        is_sampled = False
        if self._needs_deep_scan(protocols):
            self._log("\n[Stage 2] Deep scan mode activated...")
            deep_protocols, is_sampled = self._deep_scan_protocols(total_packets)
            
            # Merge deep scan results (deep scan is more accurate for protocol diversity)
            if deep_protocols:
                protocols = deep_protocols
        else:
            self._log("\n Quick scan sufficient (no signaling protocols detected)")
        
        return {
            "total_packets": total_packets,
            "protocols": protocols,
            "is_sampled": is_sampled
        }
    
    def _deep_scan_protocols(self, total_packets):
        """
        Deep protocol scan using -T fields -e frame.protocols with adaptive sampling.
        
        Args:
            total_packets: Total packet count from quick scan
            
        Returns:
            tuple: (protocols_dict, is_sampled)
        """

        protocols = {}
        deep_limit = self._get_deep_scan_limit()
        is_sampled = deep_limit is not None
        
        # Apply user's max_packets limit if stricter
        if self.max_packets:
            if deep_limit is None:
                deep_limit = self.max_packets
            else:
                deep_limit = min(deep_limit, self.max_packets)
        
        try:
            cmd = [
                'tshark',
                '-r', str(self.pcap_path),
                '-T', 'fields',
                '-e', 'frame.protocols',  # Full protocol chain
            ]
            
            if deep_limit:
                cmd.extend(['-c', str(deep_limit)])
            
            self._log(f"   Deep scanning {deep_limit:,} packets..." if deep_limit else "   Deep scanning all packets...")
            
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=300,  # Longer timeout for deep scan
                check=True
            )
            
            # Parse frame.protocols output
            packet_count = 0
            for line in result.stdout.strip().split('\n'):
                if line:
                    packet_count += 1
                    for lname in line.split(':'):
                        lname = lname.lower().strip()
                        if lname:
                            protocols[lname] = protocols.get(lname, 0) + 1
            
            self._log(f"   Deep scan found {len(protocols)} protocol types from {packet_count:,} packets")
            
            # If sampled, add metadata to indicate this
            if is_sampled and packet_count < total_packets:
                sample_rate = (packet_count / total_packets) * 100
                self._log(f"   Sampled {sample_rate:.1f}% of total packets")
            
        except subprocess.TimeoutExpired:
            print(f"Deep scan timeout for {self.pcap_path.name} - using quick scan results")
            return {}, False
        except Exception as e:
            print(f"Deep scan error: {e} - using quick scan results")
            return {}, False
        
        return protocols, is_sampled

    
    def scan(self):


        self._log(f"\n{'='*70}")
        self._log(f"Scanning: {self.pcap_path.name}")
        self._log(f"Method: {'tshark CLI' if self.fast else 'pyshark'}")
        self._log(f"{'='*70}")

        # Step 1: Calculate hash
        self._log("\n[1/3] Calculating file hash...")
        file_hash = self._file_hash()
        self._log(f"      Hash: {file_hash}")

        #check duplicate
        dup = self.db.check_duplicate(file_hash)
        if dup:
            print(f"Duplicate found: {dup[1]} (ID={dup[0]}) - skip {self.pcap_path.name}")
            return None
        
        # Step 2: Extract metadata
        self._log("\n [2/3] Extracting metadata...")
        meta = self.extract_metadata()

        total_packets = meta["total_packets"]
        protocols = meta['protocols']
        is_sampled = meta.get('is_sampled', False)

        # Show top protocols in verbose mode
        if self.verbose and protocols:
            self._log(f"\n Top 15 Protocols{' (from sample)' if is_sampled else ''}:")
            sorted_protos = sorted(protocols.items(), key=lambda x: x[1], reverse=True)
            for proto, count in sorted_protos[:15]:
                pct = (count / sum(protocols.values()) * 100) if protocols else 0
                
                # Highlight signaling protocols
                marker = "X" if proto in self.DEEP_SCAN_TRIGGERS else "  "
                self._log(f"  {marker} {proto:15} {count:7,} ({pct:5.1f}%)")
        
        
        # Step 3: Save to database
        self._log("\n[3/3] Saving to database...")
        
        # Convert protocols dict to JSON
        protocols_json = json.dumps(protocols)
        
        pcap_id = self.db.insert_pcap(
            filename=self.pcap_path.name,
            filepath=str(self.pcap_path.absolute()),
            file_hash=file_hash,
            total_packets=total_packets,
            protocols=protocols_json,
            scanned_at=datetime.datetime.now().isoformat()
        )
        
        if pcap_id:
            self._log(f"Successfully scanned PCAP ID: {pcap_id}")
            
            # Non-verbose summary
            if not self.verbose:
                #print(f"{self.pcap_path.name} - {total_packets:,} packets (ID: {pcap_id})")
                if any(p in self.DEEP_SCAN_TRIGGERS for p in protocols):
                    scan_indicator = "[DEEP-SAMPLED]" if is_sampled else "[DEEP]"
                else:
                    scan_indicator = "[QUICK]"

                size_str = self._format_size(self.file_size)
                print(f"{scan_indicator} {self.pcap_path.name} - {total_packets:,} packets, {size_str} (ID: {pcap_id})")

        else:
            print(f"Failed to save {self.pcap_path.name} to database")
        
        return pcap_id
import sqlite3
from app.config import DB_PATH
import os


class Database:
    def __init__(self):
        self.conn = sqlite3.connect(str(DB_PATH))
        self.cursor = self.conn.cursor()
        self._create_tables()

    def _create_tables(self):
        """Create pcap_files table"""

        # Table pcap_files
        self.cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS pcap_files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                filepath TEXT NOT NULL,
                file_hash TEXT UNIQUE NOT NULL, --MD5 hash (detect duplicates)
                total_packets INTEGER,
                protocols TEXT, -- JSON: {"TCP": 3000, "UDP": 1500}
                scanned_at TEXT -- timestamp '2025-10-18T14:30:00'
            )
        """
        )

        """
        #packets
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS packets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pcap_file_id INTEGER NOT NULL,
                packet_number INTEGER,
                timestamp TEXT,
                length INTEGER,
                protocol TEXT,
                src_ip TEXT,
                dst_ip TEXT,
                src_port INTEGER,
                dst_port INTEGER,
                FOREIGN KEY (pcap_file_id) REFERENCES pcap_files(id) ON DELETE CASCADE
            )
        ''')
        """

    def check_duplicate(self, file_hash):
        """
        Check hash for duplicate

        Returns:
        - pcap_id if existed
        - None if not yet
        """
        self.cursor.execute(
            "SELECT id, filename FROM pcap_files WHERE file_hash = ?", (file_hash,)
        )
        result = self.cursor.fetchone()
        return result

    def insert_pcap(
        self, filename, filepath, file_hash, total_packets, protocols, scanned_at
    ):
        """
        Insert PCAP metadata

        Returns:
        - pcap_id if success
        - None if duplicate
        """
        try:
            self.cursor.execute(
                """
                INSERT INTO pcap_files 
                (filename, filepath, file_hash, total_packets, protocols, scanned_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """,
                (filename, filepath, file_hash, total_packets, protocols, scanned_at),
            )

            self.conn.commit()
            return self.cursor.lastrowid

        except sqlite3.IntegrityError:  # duplicate hash
            return None

    def get_all_pcaps(self):
        """Query all pcap files"""
        self.cursor.execute(
            "SELECT * FROM pcap_files " \
            "ORDER BY id ASC"
            )
        return self.cursor.fetchall()
    
    def list_pcaps(self, limit=50):
        """Return latest indexed pcaps."""
        self.cursor.execute("""
            SELECT id, filename, filepath, total_packets, protocols, scanned_at
            FROM pcap_files
            ORDER BY id ASC
            LIMIT ?
        """, (limit,))
        return self.cursor.fetchall()
    

    def get_pcap_by_id(self, pcap_id):
        """Query pcap by id"""
        self.cursor.execute("SELECT * FROM pcap_files WHERE id = ?", (pcap_id,))
        return self.cursor.fetchone()

    def close(self):
        """Close connection"""
        self.conn.close()

    
    
    def reset_database(self):
        """Delete the SQLite file"""
        self.close()
        if os.path.exists(str(DB_PATH)):
            os.remove(str(DB_PATH))
            print(f"Deleted database file: {DB_PATH}")
        else:
            print("No database file found.")
    

    def clear_tables(self):
        #Delete all records from table
        self.cursor.execute("DELETE FROM pcap_files")
        self.conn.commit()
        print("Cleared all records in database.")
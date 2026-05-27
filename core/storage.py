import sqlite3
import json
import time
import logging
from typing import List, Optional, Dict, Any

logger = logging.getLogger(__name__)

class CVEStorage:
    """
    SQLite-based storage for CVE data to provide high-performance caching and 
    persistent intelligence data for the SBOM Manager.
    """
    def __init__(self, db_path: str = "data/intelligence_cache.db", ttl_days: int = 7):
        self.db_path = db_path
        self.ttl_seconds = ttl_days * 24 * 60 * 60
        self._init_db()

    def _init_db(self):
        """Initialize the SQLite database with required tables."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                # Table for CPE -> Vulnerabilities (NVD Cache)
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS cpe_cache (
                        cpe TEXT PRIMARY KEY,
                        vulnerabilities TEXT,
                        timestamp INTEGER,
                        hits INTEGER DEFAULT 0
                    )
                """)
                # Table for Name@Version -> CPE (CPE Resolver Cache)
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS cpe_mapping (
                        key TEXT PRIMARY KEY,
                        cpe TEXT,
                        timestamp INTEGER
                    )
                """)
                conn.commit()
        except sqlite3.Error as e:
            logger.error(f"Database initialization failed: {e}")
            raise

    def get_cpe(self, name: str, version: str) -> Optional[str]:
        """Retrieve a cached CPE for a given name and version."""
        key = f"{name}@{version}"
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT cpe, timestamp FROM cpe_mapping WHERE key = ?", (key,))
                row = cursor.fetchone()
                if row:
                    cpe, timestamp = row
                    if (time.time() - timestamp) < self.ttl_seconds:
                        return cpe
        except sqlite3.Error:
            pass
        return None

    def set_cpe(self, name: str, version: str, cpe: str):
        """Cache a CPE resolution for a name and version."""
        key = f"{name}@{version}"
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT OR REPLACE INTO cpe_mapping (key, cpe, timestamp) VALUES (?, ?, ?)",
                    (key, cpe, int(time.time()))
                )
                conn.commit()
        except sqlite3.Error as e:
            logger.error(f"Error writing to CPE mapping: {e}")

    def get(self, cpe: str) -> Optional[List[Dict[str, Any]]]:
        """Retrieve vulnerabilities for a given CPE if the cache is not expired."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT vulnerabilities, timestamp FROM cpe_cache WHERE cpe = ?", 
                    (cpe,)
                )
                row = cursor.fetchone()
                
                if row:
                    vulns_json, timestamp = row
                    if (time.time() - timestamp) < self.ttl_seconds:
                        # Increment hit count for future analysis
                        cursor.execute(
                            "UPDATE cpe_cache SET hits = hits + 1 WHERE cpe = ?", 
                            (cpe,)
                        )
                        conn.commit()
                        return json.loads(vulns_json)
                    
                    # Cache expired
                    logger.debug(f"Cache expired for CPE: {cpe}")
        except (sqlite3.Error, json.JSONDecodeError) as e:
            logger.error(f"Error reading from CVE storage: {e}")
            
        return None

    def set(self, cpe: str, vulnerabilities: List[Dict[str, Any]]):
        """Store vulnerability data for a given CPE."""
        try:
            vulns_json = json.dumps(vulnerabilities)
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT INTO cpe_cache (cpe, vulnerabilities, timestamp, hits) 
                    VALUES (?, ?, ?, 0) 
                    ON CONFLICT(cpe) DO UPDATE SET 
                        vulnerabilities = excluded.vulnerabilities, 
                        timestamp = excluded.timestamp,
                        hits = hits + 1
                    """, 
                    (cpe, vulns_json, int(time.time()))
                )
                conn.commit()
        except sqlite3.Error as e:
            logger.error(f"Error writing to CVE storage: {e}")

    def cleanup_expired(self):
        """Remove expired entries from the cache."""
        try:
            expiry_limit = int(time.time()) - self.ttl_seconds
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM cpe_cache WHERE timestamp < ?", (expiry_limit,))
                conn.commit()
                logger.info(f"Cleaned up {cursor.rowcount} expired cache entries.")
        except sqlite3.Error as e:
            logger.error(f"Error during cache cleanup: {e}")

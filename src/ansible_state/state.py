"""SQLite observation registry; no destructive operations."""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path


class Registry:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.path)
        self.db.execute("""
            CREATE TABLE IF NOT EXISTS observations (
                host TEXT NOT NULL,
                resource_type TEXT NOT NULL,
                resource_path TEXT NOT NULL,
                checksum TEXT,
                attributes TEXT NOT NULL,
                last_run TEXT NOT NULL,
                PRIMARY KEY (host, resource_type, resource_path)
            )
        """)
        self.db.commit()

    def record(self, host: str, resource_type: str, resource_path: str,
               checksum: str | None, attributes: dict, run_id: str) -> None:
        self.db.execute("""
            INSERT INTO observations VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(host, resource_type, resource_path) DO UPDATE SET
                checksum=excluded.checksum,
                attributes=excluded.attributes,
                last_run=excluded.last_run
        """, (host, resource_type, resource_path, checksum,
              json.dumps(attributes, sort_keys=True), run_id))
        self.db.commit()

    def list_resources(self) -> list[dict]:
        rows = self.db.execute("""
            SELECT host, resource_type, resource_path, checksum, attributes, last_run
            FROM observations ORDER BY host, resource_type, resource_path
        """).fetchall()
        return [
            dict(host=r[0], resource_type=r[1], resource_path=r[2],
                 checksum=r[3], attributes=json.loads(r[4]), last_run=r[5])
            for r in rows
        ]

    def close(self) -> None:
        self.db.close()

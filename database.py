from __future__ import annotations

import asyncio
import os
import time
from pathlib import Path
from typing import Any, Sequence

import turso_serverless


SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    user_id INTEGER PRIMARY KEY,
    username TEXT,
    first_name TEXT,
    last_name TEXT,
    language_code TEXT,
    phone TEXT,
    country_code TEXT,
    points INTEGER NOT NULL DEFAULT 0,
    banned INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    last_active INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS points_ledger (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    delta INTEGER NOT NULL,
    reason TEXT NOT NULL,
    related_user_id INTEGER,
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS referrals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    referrer_id INTEGER NOT NULL,
    referred_id INTEGER UNIQUE NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at INTEGER NOT NULL,
    rewarded_at INTEGER
);
CREATE TABLE IF NOT EXISTS scans (
    scan_id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    raw_url TEXT NOT NULL,
    extension_name TEXT,
    version TEXT,
    canonical_url TEXT,
    final_url TEXT,
    archive_sha256 TEXT,
    source_path TEXT,
    report_path TEXT,
    ioc_path TEXT,
    secrets_path TEXT,
    status TEXT NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS admin_audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    admin_id INTEGER NOT NULL,
    action TEXT NOT NULL,
    target_id INTEGER,
    reason TEXT,
    created_at INTEGER NOT NULL
);
"""


class StatsDB:
    """Turso-backed persistence layer using the official Python serverless driver."""

    def __init__(self, connection: Any | None = None) -> None:
        if connection is not None:
            self.conn = connection
        else:
            self.url = os.getenv("TURSO_DATABASE_URL", "").strip()
            self.auth_token = os.getenv("TURSO_AUTH_TOKEN", "").strip()
            if not self.url:
                raise RuntimeError("TURSO_DATABASE_URL is required")
            if not self.auth_token:
                raise RuntimeError("TURSO_AUTH_TOKEN is required")
            try:
                self.conn = turso_serverless.connect(self.url, auth_token=self.auth_token)
            except Exception as exc:
                raise RuntimeError(f"Could not connect to Turso: {exc}") from exc
        try:
            self._initialize_schema()
        except Exception as exc:
            raise RuntimeError(f"Could not initialize Turso schema: {exc}") from exc
        self.lock = asyncio.Lock()

    def _initialize_schema(self) -> None:
        for statement in SCHEMA.split(";"):
            statement = statement.strip()
            if statement:
                self.conn.execute(statement)
        self.conn.commit()

    @staticmethod
    def _row_to_dict(cursor: Any, row: Any) -> dict[str, Any] | None:
        if row is None:
            return None
        columns = [column[0] for column in (cursor.description or [])]
        return {column: row[index] for index, column in enumerate(columns)}

    def _one(self, sql: str, params: Sequence[Any] = ()) -> dict[str, Any] | None:
        cursor = self.conn.execute(sql, params)
        return self._row_to_dict(cursor, cursor.fetchone())

    def _many(self, sql: str, params: Sequence[Any] = ()) -> list[dict[str, Any]]:
        cursor = self.conn.execute(sql, params)
        return [self._row_to_dict(cursor, row) for row in cursor.fetchall() if row is not None]

    async def upsert_user(self, tg_user: Any, referral_id: int | None = None) -> tuple[bool, bool]:
        now = int(time.time())
        async with self.lock:
            exists = self._one("SELECT user_id FROM users WHERE user_id=?", (tg_user.id,)) is not None
            self.conn.execute(
                "INSERT INTO users(user_id,username,first_name,last_name,language_code,created_at,last_active) VALUES(?,?,?,?,?,?,?) "
                "ON CONFLICT(user_id) DO UPDATE SET username=excluded.username,first_name=excluded.first_name,last_name=excluded.last_name,language_code=excluded.language_code,last_active=excluded.last_active",
                (tg_user.id, tg_user.username, tg_user.first_name or "", tg_user.last_name or "", tg_user.language_code, now, now),
            )
            referral_created = False
            if not exists and referral_id and referral_id != tg_user.id and self._one("SELECT user_id FROM users WHERE user_id=?", (referral_id,)):
                self.conn.execute("INSERT OR IGNORE INTO referrals(referrer_id,referred_id,status,created_at) VALUES(?,?,?,?)", (referral_id, tg_user.id, "pending", now))
                referral_created = True
            self.conn.commit()
            return exists, referral_created

    async def set_contact(self, user_id: int, phone: str) -> None:
        country = "".join(character for character in phone if character.isdigit())[:3] or None
        async with self.lock:
            self.conn.execute("UPDATE users SET phone=?,country_code=?,last_active=? WHERE user_id=?", (phone, country, int(time.time()), user_id))
            self.conn.commit()

    async def delete_contact(self, user_id: int) -> None:
        async with self.lock:
            self.conn.execute("UPDATE users SET phone=NULL,country_code=NULL,last_active=? WHERE user_id=?", (int(time.time()), user_id))
            self.conn.commit()

    async def get_user(self, user_id: int) -> dict[str, Any] | None:
        async with self.lock:
            return self._one("SELECT * FROM users WHERE user_id=?", (user_id,))

    async def get_points(self, user_id: int) -> int:
        user = await self.get_user(user_id)
        return int(user["points"]) if user else 0

    async def add_points(self, user_id: int, delta: int, reason: str, related_user_id: int | None = None) -> int:
        async with self.lock:
            row = self._one("SELECT points FROM users WHERE user_id=?", (user_id,))
            if not row:
                raise ValueError("User is not registered.")
            old_points = int(row["points"])
            new_points = max(0, old_points + delta)
            actual_delta = new_points - old_points
            self.conn.execute("UPDATE users SET points=?,last_active=? WHERE user_id=?", (new_points, int(time.time()), user_id))
            if actual_delta:
                self.conn.execute("INSERT INTO points_ledger(user_id,delta,reason,related_user_id,created_at) VALUES(?,?,?,?,?)", (user_id, actual_delta, reason, related_user_id, int(time.time())))
            self.conn.commit()
            return new_points

    async def spend_point(self, user_id: int, reason: str) -> int:
        async with self.lock:
            row = self._one("SELECT points FROM users WHERE user_id=? AND banned=0", (user_id,))
            if not row or int(row["points"]) < 1:
                raise ValueError("You need at least 1 point to run this scan.")
            new_points = int(row["points"]) - 1
            self.conn.execute("UPDATE users SET points=?,last_active=? WHERE user_id=?", (new_points, int(time.time()), user_id))
            self.conn.execute("INSERT INTO points_ledger(user_id,delta,reason,created_at) VALUES(?,?,?,?)", (user_id, -1, reason, int(time.time())))
            self.conn.commit()
            return new_points

    async def complete_referral(self, referred_id: int) -> tuple[int, bool]:
        async with self.lock:
            row = self._one("SELECT referrer_id FROM referrals WHERE referred_id=? AND status='pending'", (referred_id,))
            if not row:
                return 0, False
            referrer_id = int(row["referrer_id"])
            now = int(time.time())
            self.conn.execute("UPDATE referrals SET status='rewarded',rewarded_at=? WHERE referred_id=?", (now, referred_id))
            for user_id, related in ((referred_id, referrer_id), (referrer_id, referred_id)):
                self.conn.execute("UPDATE users SET points=points+1,last_active=? WHERE user_id=?", (now, user_id))
                self.conn.execute("INSERT INTO points_ledger(user_id,delta,reason,related_user_id,created_at) VALUES(?,?,?,?,?)", (user_id, 1, "verified referral reward", related, now))
            self.conn.commit()
            return referrer_id, True

    async def record_scan(self, scan_id: str, user_id: int, raw_url: str, report: dict[str, Any], result: Any, status: str = "ok") -> None:
        manifest = report.get("manifest") or {}
        async with self.lock:
            self.conn.execute(
                "INSERT OR REPLACE INTO scans(scan_id,user_id,raw_url,extension_name,version,canonical_url,final_url,archive_sha256,source_path,report_path,ioc_path,secrets_path,status,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (scan_id, user_id, raw_url[:2000], str(report.get("extension_name", report.get("suggested_name", "unknown"))), str(manifest.get("version", "unknown")), report.get("canonical_url"), report.get("final_url"), report.get("archive", {}).get("sha256"), str(result.source_zip), str(result.report_path), str(result.ioc_path), str(result.secrets_path), status, int(time.time())),
            )
            self.conn.commit()

    async def list_scans(self, user_id: int, limit: int = 10) -> list[dict[str, Any]]:
        async with self.lock:
            return self._many("SELECT * FROM scans WHERE user_id=? ORDER BY created_at DESC LIMIT ?", (user_id, limit))

    async def get_scan(self, scan_id: str) -> dict[str, Any] | None:
        async with self.lock:
            return self._one("SELECT * FROM scans WHERE scan_id=?", (scan_id,))

    async def list_users(self, offset: int = 0, limit: int = 8) -> list[dict[str, Any]]:
        async with self.lock:
            return self._many("SELECT * FROM users ORDER BY created_at DESC LIMIT ? OFFSET ?", (limit, offset))

    async def referral_rows(self, user_id: int) -> list[dict[str, Any]]:
        async with self.lock:
            return self._many("SELECT r.*,u.username,u.first_name,u.last_name FROM referrals r LEFT JOIN users u ON u.user_id=r.referred_id WHERE r.referrer_id=? ORDER BY r.created_at DESC", (user_id,))

    async def stats(self) -> dict[str, int]:
        async with self.lock:
            row = self._one("SELECT (SELECT COUNT(*) FROM users) AS users,(SELECT COALESCE(SUM(points),0) FROM users) AS points,(SELECT COUNT(*) FROM scans) AS scans,(SELECT COUNT(*) FROM scans WHERE status='ok') AS successful,(SELECT COUNT(*) FROM referrals WHERE status='rewarded') AS referrals")
            return {key: int(row[key]) for key in ("users", "points", "scans", "successful", "referrals")} if row else {"users": 0, "points": 0, "scans": 0, "successful": 0, "referrals": 0}

    async def audit(self, admin_id: int, action: str, target_id: int | None = None, reason: str = "") -> None:
        async with self.lock:
            self.conn.execute("INSERT INTO admin_audit(admin_id,action,target_id,reason,created_at) VALUES(?,?,?,?,?)", (admin_id, action, target_id, reason[:1000], int(time.time())))
            self.conn.commit()

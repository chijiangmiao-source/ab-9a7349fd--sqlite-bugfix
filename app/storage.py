"""SQLite 持久化层。

授权族、刷新凭证哈希与轮换记录全部落盘到 SQLite 文件（挂载卷），
因此服务进程/容器重启后，已提交的轮换结果仍可凭原标识恢复。

安全要求：持久化内容中不得出现「可直接作为 Bearer 刷新凭证提交」的明文。
轮换记录只保存后继凭证的哈希（用于凭证匹配）与受保护密文（见 crypto_box，
用服务主密钥封装），密文在重放时可解密还原，但拿到数据库文件而没有主密钥
的人无法直接使用它。主密钥来自环境变量 CREDENTIAL_MASTER_KEY，或数据目录中
0600 权限的密钥文件。
"""
import os
import sqlite3
import threading
from contextlib import contextmanager

from crypto_box import InvalidToken, CryptoBox, load_master_key

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
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    family_id             TEXT NOT NULL REFERENCES families(family_id),
    terminal_id           TEXT NOT NULL,
    rotation_id           TEXT NOT NULL,              -- 客户端提供的稳定轮换标识（幂等键）
    old_credential_hash   TEXT NOT NULL,
    new_credential_enc    TEXT NOT NULL,              -- 后继凭证的受保护密文（非可提交凭证）
    new_credential_hash   TEXT NOT NULL,              -- 仅存哈希：新凭证的匹配键
    new_generation        INTEGER NOT NULL,
    created_at            TEXT NOT NULL,
    UNIQUE (family_id, old_credential_hash, rotation_id)  -- 幂等约束
);
"""

# 迁移用：与正式 SCHEMA 中定义一致的安全轮换表（受保护密文列）。
_SECURE_TABLE = """
CREATE TABLE rotations_secure (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    family_id             TEXT NOT NULL REFERENCES families(family_id),
    terminal_id           TEXT NOT NULL,
    rotation_id           TEXT NOT NULL,
    old_credential_hash   TEXT NOT NULL,
    new_credential_enc    TEXT NOT NULL,
    new_credential_hash   TEXT NOT NULL,
    new_generation        INTEGER NOT NULL,
    created_at            TEXT NOT NULL,
    UNIQUE (family_id, old_credential_hash, rotation_id)
)
"""


class Storage:
    """单连接 + 进程级锁；所有写操作在 BEGIN IMMEDIATE 事务中完成。"""

    def __init__(self, path, key_file=None):
        self._path = path
        # 默认把密钥文件放在数据库旁边（生产环境即 /data 卷内，0600 权限）；
        # 配置 CREDENTIAL_MASTER_KEY 后优先使用环境注入的密钥，密钥不落卷。
        if key_file is None:
            key_file = os.path.join(
                os.path.dirname(os.path.abspath(path)),
                "." + os.path.basename(path) + ".credential.key",
            )
        master_key, key_source = load_master_key(key_file)
        self._box = CryptoBox(master_key)
        self._key_source = key_source

        self._conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=FULL")
            self._conn.execute("PRAGMA busy_timeout=5000")
            self._conn.execute("PRAGMA foreign_keys=ON")
            if self._has_legacy_plaintext_column():
                self._migrate_legacy_rotation_credentials()
            self._conn.executescript(SCHEMA)

    @property
    def key_source(self):
        return self._key_source

    def close(self):
        with self._lock:
            self._conn.close()

    # ---- 后继凭证的受保护封装（重放时可恢复，不存明文） ----

    def protect_secret(self, plaintext):
        """明文凭证 -> 受保护密文（持久化用，无法直接作为 Bearer 提交）。"""
        return self._box.seal(plaintext)

    def reveal_secret(self, protected):
        """受保护密文 -> 明文凭证（幂等重放时精确恢复首次签发值）。"""
        return self._box.open(protected)

    # ---- 旧库迁移 ----

    def _columns(self, table):
        return {
            row["name"]
            for row in self._conn.execute(f"PRAGMA table_info({table})").fetchall()
        }

    def _has_legacy_plaintext_column(self):
        cols = self._columns("rotations")
        return bool(cols) and "new_credential" in cols

    def _migrate_legacy_rotation_credentials(self):
        """把旧表中的后继凭证明文改为受保护密文，并擦除文件中的明文残留。"""
        with self._lock:
            # 先把历史 WAL 并入主库，确保扫描/重写覆盖全部旧页面。
            self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            legacy_rows = self._conn.execute("SELECT * FROM rotations").fetchall()
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                self._conn.execute("DROP TABLE rotations")
                # 单条 execute：executescript 会隐式提交，破坏显式事务。
                self._conn.execute(_SECURE_TABLE)
                for row in legacy_rows:
                    self._conn.execute(
                        "INSERT INTO rotations_secure (id, family_id, terminal_id,"
                        " rotation_id, old_credential_hash, new_credential_enc,"
                        " new_credential_hash, new_generation, created_at)"
                        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (row["id"], row["family_id"], row["terminal_id"],
                         row["rotation_id"], row["old_credential_hash"],
                         self._box.seal(row["new_credential"]),
                         row["new_credential_hash"], row["new_generation"],
                         row["created_at"]),
                    )
                self._conn.execute("ALTER TABLE rotations_secure RENAME TO rotations")
                self._conn.execute("COMMIT")
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise
            # 合并 WAL 并重写整个数据库文件，丢弃仍残留明文的旧页面/空闲页。
            self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            self._conn.execute("VACUUM")
            self._conn.execute("PRAGMA journal_mode=WAL")

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

    def insert_rotation(self, family_id, terminal_id, rotation_id,
                        old_credential_hash, new_credential_enc, new_credential_hash,
                        new_generation, created_at):
        self._conn.execute(
            "INSERT INTO rotations (family_id, terminal_id, rotation_id,"
            " old_credential_hash, new_credential_enc, new_credential_hash,"
            " new_generation, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (family_id, terminal_id, rotation_id, old_credential_hash,
             new_credential_enc, new_credential_hash, new_generation, created_at),
        )

    def find_rotation_by_old_hash(self, family_id, old_credential_hash):
        row = self._conn.execute(
            "SELECT * FROM rotations WHERE family_id = ? AND old_credential_hash = ?",
            (family_id, old_credential_hash),
        ).fetchone()
        return dict(row) if row else None

    def count_rotations(self, family_id):
        row = self._conn.execute(
            "SELECT COUNT(*) AS n FROM rotations WHERE family_id = ?", (family_id,)
        ).fetchone()
        return row["n"]

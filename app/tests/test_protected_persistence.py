"""后继凭证持久化安全测试。

覆盖：
- 轮换后 SQLite 中不存在可直接作为 Bearer 提交的后继凭证明文；
- 持久化的受保护密文无法直接通过鉴权，且原始数据库文件字节中无明文；
- 服务重启（重新打开同一数据库）后相同请求精确重放同一后继；
- 旧版明文列数据库可自动迁移为密文并擦除文件中的明文残留；
- CryptoBox 的可恢复性、随机 nonce、篡改/错误密钥检测。
"""
import glob
import os
import sqlite3
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import service  # noqa: E402
from crypto_box import CryptoBox, InvalidToken  # noqa: E402
from storage import Storage  # noqa: E402


class ProtectedPersistenceTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tmp.name, "test.db")
        self.storage = Storage(self.db_path)
        self.terminal = "term-secure-1"
        self.fam = service.create_family(self.storage, self.terminal)
        self.first = service.rotate(
            self.storage, self.terminal, self.fam["credential"], "rot-1")
        self.successor = self.first["credential"]

    def tearDown(self):
        self.storage.close()
        self.tmp.cleanup()

    def _rotation_rows(self):
        conn = sqlite3.connect(self.db_path)
        try:
            conn.row_factory = sqlite3.Row
            return [dict(r) for r in conn.execute("SELECT * FROM rotations")]
        finally:
            conn.close()

    def test_successor_credential_is_not_stored_in_plaintext(self):
        rows = self._rotation_rows()
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertNotIn("new_credential", row)  # 明文列已不存在
        for value in row.values():
            self.assertNotEqual(value, self.successor)
            self.assertFalse(
                isinstance(value, str) and value.startswith("rft_"),
                f"持久化值看起来是可直接呈现的凭证: {value!r}",
            )
        # 哈希与密文元数据仍在（匹配键 + 可恢复值）。
        self.assertTrue(self.successor.startswith("rft_"))
        self.assertEqual(row["new_credential_hash"], service._hash(self.successor))
        self.assertTrue(row["new_credential_enc"])

    def test_protected_value_cannot_be_used_directly_as_bearer(self):
        enc = self._rotation_rows()[0]["new_credential_enc"]
        # 直接把持久化记录里的字符串当 Bearer 刷新凭证提交必须被拒。
        with self.assertRaises(service.InvalidCredentialError):
            service.rotate(self.storage, self.terminal, enc, "rot-attack")

    def test_plaintext_absent_from_sqlite_file_bytes(self):
        self.storage.close()
        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        conn.close()
        for path in glob.glob(self.db_path + "*"):
            with open(path, "rb") as fh:
                self.assertNotIn(self.successor.encode("utf-8"), fh.read(),
                                 f"{os.path.basename(path)} 中出现后继凭证明文")
        self.storage = Storage(self.db_path)  # 重新打开供 tearDown 关闭

    def test_replay_after_restart_recovers_exact_successor(self):
        self.storage.close()
        reopened = Storage(self.db_path)
        try:
            again = service.rotate(
                reopened, self.terminal, self.fam["credential"], "rot-1")
            self.assertEqual(again["outcome"], "replayed")
            self.assertEqual(again["credential"], self.successor)
            self.assertEqual(again["generation"], self.first["generation"])
            # 恢复出来的后继仍可继续轮换。
            nxt = service.rotate(
                reopened, self.terminal, self.successor, "rot-2")
            self.assertEqual(nxt["outcome"], "accepted")
            self.assertEqual(nxt["generation"], 3)
        finally:
            reopened.close()

    def test_same_successor_sealed_with_distinct_nonces(self):
        a = self.storage.protect_secret(self.successor)
        b = self.storage.protect_secret(self.successor)
        self.assertNotEqual(a, b)  # 随机 nonce：相同明文密文不同
        self.assertEqual(self.storage.reveal_secret(a), self.successor)
        self.assertEqual(self.storage.reveal_secret(b), self.successor)


class LegacyMigrationTestCase(unittest.TestCase):
    """旧版数据库把后继凭证明文存在 rotations.new_credential，需自动迁移。"""

    LEGACY_SCHEMA = """
    CREATE TABLE families (
        family_id TEXT PRIMARY KEY, terminal_id TEXT NOT NULL UNIQUE,
        status TEXT NOT NULL DEFAULT 'active', revocation_reason TEXT,
        generation INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL);
    CREATE TABLE credentials (
        id INTEGER PRIMARY KEY AUTOINCREMENT, family_id TEXT NOT NULL,
        credential_hash TEXT NOT NULL UNIQUE, generation INTEGER NOT NULL,
        status TEXT NOT NULL, created_at TEXT NOT NULL);
    CREATE TABLE rotations (
        id INTEGER PRIMARY KEY AUTOINCREMENT, family_id TEXT NOT NULL,
        terminal_id TEXT NOT NULL, rotation_id TEXT NOT NULL,
        old_credential_hash TEXT NOT NULL, new_credential TEXT NOT NULL,
        new_credential_hash TEXT NOT NULL, new_generation INTEGER NOT NULL,
        created_at TEXT NOT NULL,
        UNIQUE (family_id, old_credential_hash, rotation_id));
    """

    def _build_legacy_db(self, path):
        terminal = "term-legacy"
        old = "rft_" + "a" * 48
        successor = "rft_" + "b" * 48
        conn = sqlite3.connect(path)
        try:
            conn.executescript(self.LEGACY_SCHEMA)
            conn.execute(
                "INSERT INTO families (family_id, terminal_id, status, generation,"
                " created_at) VALUES ('fam_leg', ?, 'active', 2, '2026-01-01T00:00:00+00:00')",
                (terminal,))
            conn.execute(
                "INSERT INTO credentials (family_id, credential_hash, generation, status,"
                " created_at) VALUES ('fam_leg', ?, 1, 'rotated', '2026-01-01T00:00:00+00:00')",
                (service._hash(old),))
            conn.execute(
                "INSERT INTO credentials (family_id, credential_hash, generation, status,"
                " created_at) VALUES ('fam_leg', ?, 2, 'current', '2026-01-01T00:00:00+00:00')",
                (service._hash(successor),))
            conn.execute(
                "INSERT INTO rotations (family_id, terminal_id, rotation_id,"
                " old_credential_hash, new_credential, new_credential_hash,"
                " new_generation, created_at) VALUES ('fam_leg', ?, 'rot-leg', ?, ?, ?, 2,"
                " '2026-01-01T00:00:00+00:00')",
                (terminal, service._hash(old), successor, service._hash(successor)))
            conn.commit()
        finally:
            conn.close()
        return terminal, old, successor

    def test_legacy_plaintext_db_migrates_and_replays_exact_successor(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = os.path.join(tmp.name, "legacy.db")
        terminal, old, successor = self._build_legacy_db(path)

        storage = Storage(path)
        try:
            cols = {r[1] for r in sqlite3.connect(path).execute(
                "PRAGMA table_info(rotations)")}
            self.assertNotIn("new_credential", cols)
            self.assertIn("new_credential_enc", cols)

            replay = service.rotate(storage, terminal, old, "rot-leg")
            self.assertEqual(replay["outcome"], "replayed")
            self.assertEqual(replay["credential"], successor)
            self.assertEqual(replay["generation"], 2)

            # 迁移后数据库文件字节中不再残留明文。
            storage.close()
            conn = sqlite3.connect(path)
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            conn.close()
            for db_file in glob.glob(path + "*"):
                with open(db_file, "rb") as fh:
                    self.assertNotIn(successor.encode(), fh.read())
        finally:
            try:
                storage.close()
            except Exception:
                pass


class CryptoBoxTestCase(unittest.TestCase):
    def test_roundtrip(self):
        box = CryptoBox(b"k" * 32)
        token = box.seal("rft_" + "c" * 48)
        self.assertEqual(box.open(token), "rft_" + "c" * 48)
        self.assertNotIn("rft_", token)

    def test_tampered_token_rejected(self):
        box = CryptoBox(b"k" * 32)
        token = box.seal("rft_secret")
        import base64
        raw = bytearray(base64.urlsafe_b64decode(token + "=" * (-len(token) % 4)))
        raw[-1] ^= 0x01  # 翻转密文最后一位
        tampered = base64.urlsafe_b64encode(bytes(raw)).decode().rstrip("=")
        with self.assertRaises(InvalidToken):
            box.open(tampered)

    def test_wrong_key_rejected(self):
        token = CryptoBox(b"a" * 32).seal("rft_secret")
        with self.assertRaises(InvalidToken):
            CryptoBox(b"b" * 32).open(token)

    def test_rejects_bad_key_length(self):
        with self.assertRaises(ValueError):
            CryptoBox(b"short")


if __name__ == "__main__":
    unittest.main()

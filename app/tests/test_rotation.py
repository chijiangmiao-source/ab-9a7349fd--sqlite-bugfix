"""授权族轮换核心逻辑的单元测试（标准库 unittest，无第三方依赖）。"""
import os
import shutil
import sqlite3
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import service  # noqa: E402
from storage import Storage  # noqa: E402


class RotationTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tmp.name, "test.db")
        self.storage = Storage(self.db_path)

    def tearDown(self):
        self.storage.close()
        self.tmp.cleanup()

    def _family(self, terminal="term-1"):
        return service.create_family(self.storage, terminal)

    # ---- 创建 ----

    def test_create_family_issues_generation_one_credential(self):
        fam = self._family()
        self.assertEqual(fam["generation"], 1)
        self.assertTrue(fam["credential"].startswith("rft_"))
        self.assertEqual(fam["family_status"], "active")

    def test_terminal_can_bind_only_one_family(self):
        self._family("term-dup")
        with self.assertRaises(service.TerminalAlreadyBoundError):
            self._family("term-dup")

    def test_create_family_requires_terminal_id(self):
        with self.assertRaises(ValueError):
            self._family("  ")

    # ---- 首次轮换 ----

    def test_first_rotation_accepted_and_generation_increments(self):
        fam = self._family()
        res = service.rotate(self.storage, "term-1", fam["credential"], "rot-1")
        self.assertEqual(res["outcome"], "accepted")
        self.assertEqual(res["generation"], 2)
        self.assertTrue(res["credential"].startswith("rft_"))
        self.assertNotEqual(res["credential"], fam["credential"])
        self.assertEqual(res["family_status"], "active")

    # ---- 幂等重放 ----

    def test_replay_returns_identical_successor_without_advancing(self):
        fam = self._family()
        first = service.rotate(self.storage, "term-1", fam["credential"], "rot-1")
        for _ in range(3):
            again = service.rotate(self.storage, "term-1", fam["credential"], "rot-1")
            self.assertEqual(again["outcome"], "replayed")
            self.assertEqual(again["credential"], first["credential"])
            self.assertEqual(again["generation"], first["generation"])
        view = service.get_family_by_terminal(self.storage, "term-1")
        self.assertEqual(view["generation"], 2)
        self.assertEqual(self.storage.count_rotations(fam["family_id"]), 1)

    def test_replay_survives_service_restart(self):
        fam = self._family()
        first = service.rotate(self.storage, "term-1", fam["credential"], "rot-1")
        # 模拟服务重启：关闭并重新打开同一数据库文件。
        self.storage.close()
        self.storage = Storage(self.db_path)
        again = service.rotate(self.storage, "term-1", fam["credential"], "rot-1")
        self.assertEqual(again["outcome"], "replayed")
        self.assertEqual(again["credential"], first["credential"])
        self.assertEqual(again["generation"], first["generation"])

    def test_replay_returns_historical_successor_after_later_rotations(self):
        fam = self._family()
        first = service.rotate(self.storage, "term-1", fam["credential"], "rot-1")
        second = service.rotate(self.storage, "term-1", first["credential"], "rot-2")
        self.assertEqual(second["generation"], 3)
        again = service.rotate(self.storage, "term-1", fam["credential"], "rot-1")
        self.assertEqual(again["outcome"], "replayed")
        self.assertEqual(again["credential"], first["credential"])
        self.assertEqual(again["generation"], 2)

    # ---- 并发同标识 ----

    def test_concurrent_identical_requests_observe_same_result(self):
        fam = self._family()
        barrier = threading.Barrier(2)

        def call():
            barrier.wait()
            return service.rotate(self.storage, "term-1", fam["credential"], "rot-1")

        results = []
        threads = [threading.Thread(target=lambda: results.append(call())) for _ in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(results), 2)
        self.assertEqual(sorted(r["outcome"] for r in results), ["accepted", "replayed"])
        self.assertEqual(results[0]["credential"], results[1]["credential"])
        self.assertEqual(results[0]["generation"], results[1]["generation"])
        self.assertEqual(results[0]["generation"], 2)
        view = service.get_family_by_terminal(self.storage, "term-1")
        self.assertEqual(view["generation"], 2)

    # ---- 异标识重放 => 撤销 ----

    def test_reuse_with_different_rotation_id_revokes_family(self):
        fam = self._family()
        first = service.rotate(self.storage, "term-1", fam["credential"], "rot-1")
        res = service.rotate(self.storage, "term-1", fam["credential"], "rot-OTHER")
        self.assertEqual(res["outcome"], "revoked")
        self.assertEqual(res["family_status"], "revoked")
        self.assertIn("reuse", res["revocation_reason"])

        # 此前签发的后继凭证随后同样被拒绝。
        successor = service.rotate(self.storage, "term-1", first["credential"], "rot-2")
        self.assertEqual(successor["outcome"], "revoked")
        self.assertIn("reuse", successor["revocation_reason"])

        # 原（旧凭证, 原轮换标识）重放也被拒绝。
        replay = service.rotate(self.storage, "term-1", fam["credential"], "rot-1")
        self.assertEqual(replay["outcome"], "revoked")

        # 状态查询可见撤销原因。
        view = service.get_family_by_terminal(self.storage, "term-1")
        self.assertEqual(view["family_status"], "revoked")
        self.assertIn("reuse", view["revocation_reason"])

    # ---- 落盘安全：后继凭证不得以可直投明文保存 ----

    def _all_text_values_in_db(self):
        raw = sqlite3.connect(self.db_path)
        values = []
        tables = [r[0] for r in raw.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")]
        for table in tables:
            cols = [r[1] for r in raw.execute(f"PRAGMA table_info({table})")]
            text_cols = [c for c in cols]
            if not text_cols:
                continue
            for row in raw.execute(f"SELECT * FROM {table}"):
                for value in row:
                    if isinstance(value, str):
                        values.append(value)
        raw.close()
        return values

    def _db_file_bytes(self):
        blob = b""
        for suffix in ("", "-wal", "-shm"):
            part = self.db_path + suffix
            if os.path.exists(part):
                with open(part, "rb") as fh:
                    blob += fh.read()
        return blob

    def test_persisted_record_contains_no_directly_usable_successor(self):
        fam = self._family()
        first = service.rotate(self.storage, "term-1", fam["credential"], "rot-1")
        successor = first["credential"]

        # 数据库任何文本列中都不存在与后继凭证逐字节相同的值。
        for value in self._all_text_values_in_db():
            self.assertNotEqual(value, successor)
            self.assertNotIn(successor, value)

        # 后继的原始 hex 也不得出现在数据库文件（含 WAL）字节中。
        self.assertNotIn(successor.encode("utf-8"), self._db_file_bytes())

        # 但受保护的可恢复信封与哈希仍在，支持断回应后精确重放。
        raw = sqlite3.connect(self.db_path)
        row = raw.execute(
            "SELECT new_credential_envelope, new_credential_hash FROM rotations"
        ).fetchone()
        raw.close()
        envelope, new_hash = row
        self.assertTrue(envelope.startswith("pae1."))
        self.assertEqual(new_hash, service._hash(successor))
        self.assertNotIn(successor, envelope)

        # 重放结果与首次完全一致。
        again = service.rotate(self.storage, "term-1", fam["credential"], "rot-1")
        self.assertEqual(again["outcome"], "replayed")
        self.assertEqual(again["credential"], successor)

    def test_database_copy_without_key_cannot_replay_successor(self):
        from protection import CredentialProtector
        fam = self._family()
        first = service.rotate(self.storage, "term-1", fam["credential"], "rot-1")
        successor = first["credential"]
        self.storage.close()

        # 模拟数据卷泄露：只拿到 SQLite 文件（密钥文件不随数据卷拷贝），
        # 任何没有正确密钥的一方都无法恢复可直投的后继凭证。
        leaked_dir = tempfile.TemporaryDirectory()
        leaked_db = os.path.join(leaked_dir.name, "leaked.db")
        shutil.copyfile(self.db_path, leaked_db)
        wrong_key_storage = Storage(leaked_db, protector=CredentialProtector(b"x" * 32))
        with self.assertRaises(RuntimeError):
            service.rotate(wrong_key_storage, "term-1", fam["credential"], "rot-1")
        wrong_key_storage.close()
        leaked_dir.cleanup()

        # 合法服务端重启后（密钥文件仍在）重放精确一致。
        self.storage = Storage(self.db_path)
        again = service.rotate(self.storage, "term-1", fam["credential"], "rot-1")
        self.assertEqual(again["outcome"], "replayed")
        self.assertEqual(again["credential"], successor)

    def test_tampered_envelope_is_not_replayed(self):
        fam = self._family()
        first = service.rotate(self.storage, "term-1", fam["credential"], "rot-1")
        raw = sqlite3.connect(self.db_path)
        envelope = raw.execute(
            "SELECT new_credential_envelope FROM rotations").fetchone()[0]
        # 篡改信封中段（nonce/tag 区域），保持版本前缀仍为 pae1.。
        pos = len(envelope) // 2
        replacement = "A" if envelope[pos] != "A" else "B"
        tampered = envelope[:pos] + replacement + envelope[pos + 1:]
        raw.execute("UPDATE rotations SET new_credential_envelope = ?", (tampered,))
        raw.commit()
        raw.close()
        with self.assertRaises(RuntimeError):
            service.rotate(self.storage, "term-1", fam["credential"], "rot-1")
        # 首次返回的凭证本身未被污染（保存在进程外时仍然有效）。
        self.assertTrue(first["credential"].startswith("rft_"))

    def test_envelope_cannot_be_moved_between_rotation_records(self):
        fam = self._family()
        r1 = service.rotate(self.storage, "term-1", fam["credential"], "rot-1")
        r2 = service.rotate(self.storage, "term-1", r1["credential"], "rot-2")
        # 把代次 2 的信封复制到代次 3 的记录（AAD 不匹配，搬运无效）。
        raw = sqlite3.connect(self.db_path)
        env1 = raw.execute(
            "SELECT new_credential_envelope FROM rotations WHERE new_generation = 2"
        ).fetchone()[0]
        raw.execute(
            "UPDATE rotations SET new_credential_envelope = ?"
            " WHERE new_generation = 3", (env1,))
        raw.commit()
        raw.close()
        # 代次 2 的正常重放仍精确；被植入异记录信封的代次 3 记录拒绝重放。
        again1 = service.rotate(self.storage, "term-1", fam["credential"], "rot-1")
        self.assertEqual(again1["credential"], r1["credential"])
        with self.assertRaises(RuntimeError):
            service.rotate(self.storage, "term-1", r1["credential"], "rot-2")
        self.assertTrue(r2["credential"].startswith("rft_"))

    # ---- 旧版明文落盘数据的迁移 ----

    def test_legacy_plaintext_database_is_migrated_and_purged(self):
        self.storage.close()
        # 使用全新数据库文件，手工构造修复前的旧表（后继凭证明文落盘）。
        legacy_path = os.path.join(self.tmp.name, "legacy.db")
        legacy = sqlite3.connect(legacy_path)
        legacy.executescript("""
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
        """)
        old_cred = "rft_" + "0" * 48
        successor = "rft_" + "1" * 48
        import hashlib
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).isoformat(timespec="milliseconds")
        legacy.execute(
            "INSERT INTO families VALUES ('fam_legacy','term-legacy','active',NULL,2,?)",
            (now,))
        legacy.execute(
            "INSERT INTO credentials (family_id, credential_hash, generation, status, created_at)"
            " VALUES ('fam_legacy', ?, 1, 'rotated', ?)",
            (hashlib.sha256(old_cred.encode()).hexdigest(), now))
        legacy.execute(
            "INSERT INTO credentials (family_id, credential_hash, generation, status, created_at)"
            " VALUES ('fam_legacy', ?, 2, 'current', ?)",
            (hashlib.sha256(successor.encode()).hexdigest(), now))
        legacy.execute(
            "INSERT INTO rotations (family_id, terminal_id, rotation_id,"
            " old_credential_hash, new_credential, new_credential_hash,"
            " new_generation, created_at) VALUES ('fam_legacy','term-legacy',"
            " 'rot-legacy', ?, ?, ?, 2, ?)",
            (hashlib.sha256(old_cred.encode()).hexdigest(), successor,
             hashlib.sha256(successor.encode()).hexdigest(), now))
        legacy.commit()
        legacy.close()
        self.db_path = legacy_path
        self.assertIn(successor.encode(), self._db_file_bytes())

        # 打开即迁移：明文列消失、文件字节中不再残留后继明文。
        self.storage = Storage(self.db_path)
        raw = sqlite3.connect(self.db_path)
        columns = [r[1] for r in raw.execute("PRAGMA table_info(rotations)")]
        raw.close()
        self.assertNotIn("new_credential", columns)
        self.assertIn("new_credential_envelope", columns)
        self.assertNotIn(successor.encode(), self._db_file_bytes())

        # 迁移后断回应重放仍能取回与首次完全一致的后继。
        replayed = service.rotate(
            self.storage, "term-legacy", old_cred, "rot-legacy")
        self.assertEqual(replayed["outcome"], "replayed")
        self.assertEqual(replayed["credential"], successor)
        self.assertEqual(replayed["generation"], 2)

    # ---- 错误路径 ----

    def test_unknown_terminal_rejected(self):
        with self.assertRaises(service.UnknownTerminalError):
            service.rotate(self.storage, "no-such-terminal", "rft_x", "rot-1")

    def test_unknown_credential_rejected(self):
        self._family()
        with self.assertRaises(service.InvalidCredentialError):
            service.rotate(self.storage, "term-1", "rft_not_issued", "rot-1")

    def test_rotate_requires_all_fields(self):
        fam = self._family()
        with self.assertRaises(ValueError):
            service.rotate(self.storage, "term-1", fam["credential"], "")
        with self.assertRaises(ValueError):
            service.rotate(self.storage, "term-1", "", "rot-1")


if __name__ == "__main__":
    unittest.main()

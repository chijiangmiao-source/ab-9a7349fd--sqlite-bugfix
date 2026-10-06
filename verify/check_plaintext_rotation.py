#!/usr/bin/env python3
"""轮换落盘明文探针（无需启动 HTTP 服务）。

在临时容器文件系统上的 SQLite 数据库中：
  1. 创建一个绑定终端标识的授权族；
  2. 用该族当前凭证执行一次真实轮换；
  3. 直接读取本次轮换的持久化记录与数据库文件字节，
     检查其中是否保存了与服务返回值完全一致、可直接作为 Bearer 刷新凭证提交的后继明文。

发现明文时输出 BUG_PLAINTEXT_ROTATION_CREDENTIAL=True 并以退出码 1 结束；
修复后应输出 ...=False 并以退出码 0 结束。

环境变量：
  APP_DIR  应用源码目录（默认 ../app）
"""
import os
import sqlite3
import sys
import tempfile

APP_DIR = os.environ.get(
    "APP_DIR",
    os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "app")),
)
sys.path.insert(0, APP_DIR)

import service  # noqa: E402
from storage import Storage  # noqa: E402


def main():
    tmp = tempfile.TemporaryDirectory()
    db_path = os.path.join(tmp.name, "probe.db")
    # 固定探针进程的主密钥文件位置（修复后的代码会读取；基线代码忽略该变量）。
    os.environ.setdefault("CREDENTIAL_KEY_FILE",
                          os.path.join(tmp.name, "keys", "credential-protection.key"))

    storage = Storage(db_path)
    terminal = "term-probe"
    family = service.create_family(storage, terminal)
    result = service.rotate(storage, terminal, family["credential"], "rot-probe-1")
    successor = result["credential"]

    raw = sqlite3.connect(db_path)
    raw.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    columns = [r[1] for r in raw.execute("PRAGMA table_info(rotations)")]
    row = raw.execute(
        "SELECT * FROM rotations WHERE family_id = ?", (family["family_id"],)
    ).fetchone()
    raw.close()

    value_by_column = dict(zip(columns, row)) if row else {}

    # 1) 结构化记录中不得存在与返回值逐字节相同的可直投凭证（无论列名）。
    plaintext_column = next(
        (name for name, value in value_by_column.items()
         if isinstance(value, str) and value == successor),
        None,
    )

    # 2) 数据库文件字节中同样不得出现后继凭证明文（含 WAL 残留）。
    blob_parts = []
    for suffix in ("", "-wal", "-shm"):
        part = db_path + suffix
        if os.path.exists(part):
            with open(part, "rb") as fh:
                blob_parts.append(fh.read())
    on_disk_bytes = b"".join(blob_parts)
    plaintext_on_disk = successor.encode("utf-8") in on_disk_bytes

    storage.close()
    tmp.cleanup()

    bug = bool(plaintext_column or plaintext_on_disk)
    print(f"BUG_PLAINTEXT_ROTATION_CREDENTIAL={'True' if bug else 'False'}")
    if plaintext_column:
        print(f"  persisted column '{plaintext_column}' equals the returned successor"
              f" (length {len(successor)})")
    if plaintext_on_disk:
        print("  successor plaintext found in SQLite file bytes (including WAL)")
    if not bug:
        print("  rotation record keeps only a protected recoverable envelope and hashes")
    return 1 if bug else 0


if __name__ == "__main__":
    sys.exit(main())

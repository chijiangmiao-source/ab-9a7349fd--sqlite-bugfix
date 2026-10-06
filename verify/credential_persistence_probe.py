#!/usr/bin/env python3
"""后继刷新凭证落盘审计（compose verify 的一部分，亦可独立运行）。

在临时容器文件系统的 SQLite 数据库上：
  1. 创建一个绑定终端标识的授权族，并用其当前凭证执行一次真实轮换；
  2. 直接读取这次轮换的持久化记录，检查其中是否保存了与服务返回值
     完全一致、可直接作为 Bearer 刷新凭证提交的后继凭证；
  3. 把记录中的每个持久化字符串值当作 Bearer 凭证直接提交，
     任何一次被接受/重放都说明该值“可直接使用”；
  4. 检查点落盘后扫描全部 SQLite 文件（db / -wal / -shm）原始字节；
  5. 模拟服务重启（关闭后以同一数据库文件重新打开），用相同请求重试，
     仍须返回与首次完全一致的后继凭证（受保护值必须可恢复）。

发现明文可直接使用的后继凭证时输出：
    BUG_PLAINTEXT_ROTATION_CREDENTIAL=True
并以退出码 1 结束；安全且重放正常时输出 ...=False 并以 0 结束。

环境变量：
  APP_DIR  应用源码目录（默认 ../app）
"""
import glob
import os
import sqlite3
import sys
import tempfile
import uuid

APP_DIR = os.environ.get(
    "APP_DIR",
    os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "app")),
)
sys.path.insert(0, APP_DIR)

import service  # noqa: E402
from storage import Storage  # noqa: E402

SIGNAL = "BUG_PLAINTEXT_ROTATION_CREDENTIAL"


def main():
    findings = []
    tmp = tempfile.TemporaryDirectory()
    db_path = os.path.join(tmp.name, "audit.db")
    terminal = "term-audit-" + uuid.uuid4().hex[:8]
    rotation_id = "rot-audit-1"

    storage = Storage(db_path)
    fam = service.create_family(storage, terminal)
    first = service.rotate(storage, terminal, fam["credential"], rotation_id)
    successor = first["credential"]
    assert first["outcome"] == "accepted" and successor.startswith("rft_"), first

    # ---- (1) 直接读取持久化的轮换记录 ----
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    rows = [dict(r) for r in conn.execute("SELECT * FROM rotations").fetchall()]
    assert len(rows) == 1, f"期望恰好一条轮换记录，实际 {len(rows)}"
    record = rows[0]
    print("持久化轮换记录列：" + ", ".join(record.keys()))

    exact_matches = [k for k, v in record.items()
                     if isinstance(v, str) and v == successor]
    rft_cells = [k for k, v in record.items()
                 if isinstance(v, str) and v.startswith("rft_")]
    if exact_matches:
        findings.append(
            "轮换记录列 %s 保存了与服务返回值完全一致的后继凭证明文"
            % ", ".join(exact_matches))
    if rft_cells:
        findings.append(
            "轮换记录列 %s 保存了 rft_ 前缀的可直接呈现凭证值" % ", ".join(rft_cells))

    # ---- (2) 持久化值能否直接作为 Bearer 刷新凭证提交 ----
    directly_usable = []
    for key, value in record.items():
        if not isinstance(value, str) or not value:
            continue
        try:
            probe = service.rotate(
                storage, terminal, value, f"rot-direct-use-{key}")
        except service.InvalidCredentialError:
            continue  # 未知凭证：该持久化值无法直接使用，符合预期
        except Exception:
            continue  # 其它拒绝（如撤销）同样不可用
        if probe.get("outcome") in ("accepted", "replayed") and probe.get("credential"):
            directly_usable.append(key)
    if directly_usable:
        findings.append(
            "轮换记录列 %s 中的持久化值可直接作为 Bearer 刷新凭证提交并被接受"
            % ", ".join(directly_usable))

    # ---- (3) 模拟服务重启后以相同请求重试：必须精确恢复同一后继 ----
    storage.close()
    storage = Storage(db_path)
    replay = service.rotate(storage, terminal, fam["credential"], rotation_id)
    replay_ok = (
        replay.get("outcome") == "replayed"
        and replay.get("credential") == successor
        and replay.get("generation") == first["generation"]
    )
    print("重启后同请求重放结果：outcome=%s generation=%s 凭证一致=%s"
          % (replay.get("outcome"), replay.get("generation"),
             replay.get("credential") == successor))

    # ---- (4) 检查点截断 WAL 后扫描所有 SQLite 文件原始字节 ----
    probe_conn = sqlite3.connect(db_path)
    try:
        probe_conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    finally:
        probe_conn.close()
    storage.close()

    raw_hits = []
    for db_file in glob.glob(db_path + "*"):
        with open(db_file, "rb") as fh:
            if successor.encode("utf-8") in fh.read():
                raw_hits.append(os.path.basename(db_file))
    if raw_hits:
        findings.append(
            "SQLite 文件原始字节中出现后继凭证明文：%s" % ", ".join(raw_hits))

    print("-" * 60)
    if findings:
        for item in findings:
            print(" [LEAK] " + item)
        print(f"{SIGNAL}=True")
        return 1
    if not replay_ok:
        print(" [FAIL] 受保护后继凭证无法在重启后精确重放（可恢复性被破坏）")
        print(f"{SIGNAL}=False")
        return 1
    print(" [OK] 持久化记录不含可直接作为 Bearer 提交的后继凭证")
    print(" [OK] 重启后相同请求返回与首次完全一致的后继凭证")
    print(f"{SIGNAL}=False")
    return 0


if __name__ == "__main__":
    sys.exit(main())

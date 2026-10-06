# 深空地面站 · 授权族轮换服务

操作员在页面创建**绑定终端标识的授权族**，凭「当前刷新凭证 + 稳定轮换标识」发起轮换。
系统保证：

- **首次轮换**：签发唯一后继凭证，代次递增，状态可用；
- **幂等重放**：相同（旧凭证, 轮换标识）重传 —— 包括**服务重启后**的重试 —— 取回与首次**完全一致**的后继凭证与代次，代次不再推进，页面明确呈现「已接受 / 重放」；
- **断回应故障演练**：启用「提交后断连」故障后，首次请求已提交但响应未送达；重启后凭原标识恢复已持久化的后继；
- **并发同标识**：两个并发相同请求只观察到同一结果（恰一次接受、一次重放）；
- **异标识重放（重用检测）**：已轮换旧凭证搭配不同轮换标识再次出现 → 整个授权族撤销并记录原因，**此前签发的后继凭证随后同样被拒绝**；
- **健康检查**：`GET /health`，宿主机端口可通过 `APP_HOST_PORT` 配置。

## 后继凭证落盘保护

轮换记录必须支持断回应后的精确重放（后继凭证需要可恢复），但**绝不保存
可直接作为 Bearer 刷新凭证提交的明文**，否则能读取 SQLite 文件的数据卷、
备份或运行环境即可拿走仍可继续轮换的凭证（仅存哈希不能满足可恢复要求）。

因此落盘的后继凭证是一个**认证加密信封**（`pae1.…`，HMAC 计数模式流密码 +
encrypt-then-MAC，HKDF-SHA256 派生独立加密/认证子密钥），并绑定本条轮换
记录的上下文（family / rotation_id / 代次 / 凭证哈希）作为 AAD：信封无法
在记录间搬运或被篡改，仅服务在合法重放路径上解出原样后继。

数据密钥存放在 SQLite 文件**之外**，两种注入方式：

| 方式 | 说明 |
| --- | --- |
| `CREDENTIAL_KEY_FILE`（compose 默认） | 密钥文件（0600，首启自动生成），compose 中位于与 `app-data` 分离的独立卷 `app-keys`（`/secrets`）；备份/拷贝数据卷不带走密钥 |
| `CREDENTIAL_PROTECTION_KEY` | 64 位十六进制（32 字节），适合由外部密钥管理系统直接注入，优先级最高 |

未配置时本地开发默认在数据库目录旁生成 `.credential-protection.key`。
使用修复前版本产生的旧库（明文列 `new_credential`）在首次打开时自动迁移：
明文改写为信封、校验哈希、重建数据库文件（VACUUM + WAL truncate）清除残留。

## 快速开始（Docker Compose）

```bash
# 构建应用并运行验收：verify 跑完单元测试 + 落盘探针 + 冒烟 + 三大场景 + 页面校验后退出
docker compose up --build --exit-code-from verify
echo "验收退出码: $?"     # 0 = 全部通过，非 0 = 存在失败项
docker compose down
```

也可以分步执行（效果等价）：

```bash
docker compose build
docker compose up -d app
docker compose run --rm verify; echo "exit=$?"
docker compose down
```

## 手动体验操作员页面

```bash
cp .env.example .env        # 可选：修改 APP_HOST_PORT（默认 8080）
docker compose up -d --build app
```

- 页面：<http://localhost:8080/>（创建授权族 / 发起轮换 / 状态查询 / 故障注入演练）
- 健康检查：<http://localhost:8080/health>（端口由 `APP_HOST_PORT` 决定）

数据持久化在命名卷 `app-data`（SQLite，WAL 模式），保护密钥在独立卷
`app-keys`（`/secrets`）；`docker compose restart app` 或容器重建后，
已提交的轮换记录仍可凭原标识重放恢复。

## API 一览

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/health` | 健康响应 `{"status":"ok"}` |
| POST | `/api/families` | 创建授权族 `{terminal_id}` → 201 `{credential, generation:1, family_status:"active"}` |
| POST | `/api/rotate` | 轮换 `{terminal_id, credential, rotation_id}` → 200 `accepted/replayed`；409 `revoked`（含 `revocation_reason`）；401 无效凭证；404 未知终端 |
| GET | `/api/terminals/<tid>/family` | 授权族状态（代次、状态、撤销原因） |
| GET/POST | `/api/admin/faults` | 查看/设置故障注入 `{"drop_after_commit": bool}`（内存态，重启自动清除） |
| POST | `/api/admin/shutdown` | 退出服务进程（守护循环自动拉起，用于重启演练） |

### 轮换语义

```
旧凭证状态      轮换标识          结果
current        任意              accepted：签发唯一后继，代次+1
rotated        与首次相同         replayed：返回首次提交的后继与代次，不推进
rotated        与首次不同         revoked：授权族撤销，记录重用原因，后继凭证一并失效
```

幂等键为 `(family_id, old_credential_hash, rotation_id)` 的唯一约束；
写路径经进程级锁 + `BEGIN IMMEDIATE` 事务串行化，并发相同请求只会落一条轮换记录。

## verify 验收内容（退出码即结果）

1. **代码测试**：`app/tests/` 下 25 项单元测试 —— 创建/首轮换/重放/重启恢复/并发/撤销/错误路径，以及信封加解密、AAD 绑定、篡改拒绝、数据卷无密钥不可恢复、旧明文库迁移；
2. **落盘明文探针** `verify/check_plaintext_rotation.py`：临时 SQLite 建族并完成一次真实轮换，直接读取持久化记录与文件字节；存在与服务返回值逐字节相同的可直投后继时输出 `BUG_PLAINTEXT_ROTATION_CREDENTIAL=True`、退出码 1；
3. **API/HTTP 冒烟**：健康端点、建族、首轮换，并**直接检查数据卷（含 WAL）字节**确认后继明文未落盘、仅存 `pae1.` 信封；
4. **场景 A 断回应恢复**：启用故障 → 首次请求连接中断 → 进程重启 → 原标识重传取回同一后继（`replayed`，代次 2 不再推进）→ 重放后再次检查数据卷仍无明文 → 后继凭证仍可继续轮换；
5. **场景 B 并发同标识**：两线程同时发起相同请求 → 同一凭证同一世代，恰一次 `accepted` 一次 `replayed`；
6. **场景 C 异标识重放**：撤销 + 原因可见 + 后继凭证被拒 + 原重放亦被拒；
7. **页面可观察结果**：页面包含「已接受/重放/已撤销/撤销原因/断回应」等呈现元素，且轮换响应字段与页面渲染一一对应。

## 本地开发（无 Docker）

```bash
cd app && python3 -m unittest discover -s tests -v     # 单元测试
cd app && PORT=18080 DB_PATH=/tmp/dsg/app.db \
  CREDENTIAL_KEY_FILE=/tmp/dsg/keys/credential.key sh ./run.sh &   # 守护方式启动（支持重启演练）
python3 verify/check_plaintext_rotation.py             # 落盘明文探针（期望 ...=False，退出码 0）
APP_BASE_URL=http://127.0.0.1:18080 APP_DIR=$PWD/app \
  APP_DATA_PATH=/tmp/dsg/app.db python3 verify/verify.py
```

## 目录结构

```
app/
  server.py            HTTP 服务（标准库 http.server）
  service.py           轮换核心逻辑（幂等/重用检测/撤销）
  storage.py           SQLite 持久化（WAL，唯一约束兜底；后继凭证仅存认证加密信封）
  protection.py        后继凭证认证加密信封（HKDF + HMAC 计数模式 + EtM，标准库）
  static/index.html    操作员页面
  run.sh               进程守护循环（退出即重启）
  tests/test_rotation.py
  tests/test_protection.py
verify/
  verify.py                       验收器（compose 的 verify 服务）
  check_plaintext_rotation.py     落盘明文探针（BUG_PLAINTEXT_ROTATION_CREDENTIAL 信号）
  Dockerfile
compose.yaml           app + verify + 独立密钥卷 app-keys，APP_HOST_PORT 可配置宿主机端口
```

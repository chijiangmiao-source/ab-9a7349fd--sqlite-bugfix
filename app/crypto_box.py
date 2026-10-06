"""后继刷新凭证的信封加密（仅依赖 Python 标准库）。

威胁模型
--------
攻击者能够取得 SQLite 数据库文件本身（持久化卷快照、仅针对数据库的
备份、拖库或运行环境文件读取），但无法读取服务的主密钥。主密钥优先通过
环境变量 CREDENTIAL_MASTER_KEY 注入（由编排系统管理，不落在数据卷上）；
未配置时由服务在数据目录维护一个 0600 权限的密钥文件。

持久化的轮换记录只保存「受保护值」（随机 nonce + 密文 + 认证标签）：
它不是 rft_ 刷新凭证，sha256 后也匹配不到任何已签发凭证，无法直接作为
Bearer 刷新凭证提交；但服务在幂等重放（含服务重启后的重试）时可用主密钥
解开，精确恢复首次签发的后继凭证。只保存哈希无法满足「断回应后精确重放」
这一可恢复性要求，哈希仍另行保留用于凭证匹配。

加密构造（Encrypt-then-MAC，原语均为标准库 HMAC-SHA256 PRF）
-----------------------------------------------------------
nonce       16 字节随机（128 位，同一主密钥下碰撞概率可忽略）
enc_key     = HMAC(K, "enc" || nonce)
mac_key     = HMAC(K, "mac" || nonce)
keystream_i = HMAC(enc_key, nonce || be32(i))            # PRF-CTR 密钥流
ciphertext  = plaintext XOR keystream
tag         = HMAC(mac_key, VERSION || nonce || ciphertext)
token       = base64url(VERSION || nonce || tag || ciphertext)
密钥按 nonce 分离派生，无需维护计数器状态；认证失败（篡改/错误密钥）时
open() 抛出 InvalidToken，服务按无效凭证处理。
"""
import base64
import binascii
import hashlib
import hmac
import os
import secrets

VERSION = b"\x01"
NONCE_LEN = 16
TAG_LEN = 32
BLOCK_LEN = 32

ENV_MASTER_KEY = "CREDENTIAL_MASTER_KEY"
ENV_KEY_FILE = "CREDENTIAL_KEY_FILE"
DEFAULT_KEY_FILE = "/data/.credential.key"
KEY_LEN = 32


class InvalidToken(Exception):
    """受保护值无法认证/解密（篡改、截断或主密钥不匹配）。"""


def _xor_keystream(data, enc_key, nonce):
    """PRF-CTR：HMAC(enc_key, nonce || be32(counter)) 生成密钥流。"""
    out = bytearray(len(data))
    counter = 0
    for offset in range(0, len(data), BLOCK_LEN):
        block = hmac.new(
            enc_key,
            nonce + counter.to_bytes(4, "big"),
            hashlib.sha256,
        ).digest()
        chunk = data[offset:offset + BLOCK_LEN]
        out[offset:offset + len(chunk)] = bytes(a ^ b for a, b in zip(chunk, block))
        counter += 1
    return bytes(out)


class CryptoBox:
    """以 32 字节主密钥封装/打开受保护凭证值。"""

    def __init__(self, master_key):
        if not isinstance(master_key, (bytes, bytearray)) or len(master_key) != KEY_LEN:
            raise ValueError("master_key 必须是 %d 字节" % KEY_LEN)
        self._key = bytes(master_key)

    def _derive(self, nonce):
        enc_key = hmac.new(self._key, b"enc" + nonce, hashlib.sha256).digest()
        mac_key = hmac.new(self._key, b"mac" + nonce, hashlib.sha256).digest()
        return enc_key, mac_key

    def seal(self, plaintext):
        """明文凭证 -> 自包含受保护 token（base64url 字符串，不含明文）。"""
        if not isinstance(plaintext, str):
            raise TypeError("plaintext 必须是 str")
        data = plaintext.encode("utf-8")
        nonce = secrets.token_bytes(NONCE_LEN)
        enc_key, mac_key = self._derive(nonce)
        ciphertext = _xor_keystream(data, enc_key, nonce)
        tag = hmac.new(
            mac_key, VERSION + nonce + ciphertext, hashlib.sha256
        ).digest()
        token = VERSION + nonce + tag + ciphertext
        return base64.urlsafe_b64encode(token).decode("ascii").rstrip("=")

    def open(self, token):
        """受保护 token -> 明文凭证；任何损坏/不匹配均抛 InvalidToken。"""
        if not isinstance(token, str):
            raise InvalidToken("token 必须是 str")
        try:
            raw = base64.urlsafe_b64decode(token + "=" * (-len(token) % 4))
        except (binascii.Error, ValueError) as exc:
            raise InvalidToken("base64 解码失败") from exc
        if len(raw) < 1 + NONCE_LEN + TAG_LEN or raw[:1] != VERSION:
            raise InvalidToken("token 头部或长度不合法")
        nonce = raw[1:1 + NONCE_LEN]
        tag = raw[1 + NONCE_LEN:1 + NONCE_LEN + TAG_LEN]
        ciphertext = raw[1 + NONCE_LEN + TAG_LEN:]
        enc_key, mac_key = self._derive(nonce)
        expected = hmac.new(
            mac_key, VERSION + nonce + ciphertext, hashlib.sha256
        ).digest()
        if not hmac.compare_digest(tag, expected):
            raise InvalidToken("认证标签不匹配（数据被篡改或主密钥不正确）")
        data = _xor_keystream(ciphertext, enc_key, nonce)
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise InvalidToken("解密结果不是合法 UTF-8") from exc


def _decode_env_key(raw):
    """支持 base64/base64url/hex 编码的 32 字节主密钥。"""
    candidates = []
    padded = raw + "=" * (-len(raw) % 4)
    for decoder in (base64.urlsafe_b64decode, base64.b64decode):
        try:
            candidates.append(decoder(padded.encode("ascii")))
        except (binascii.Error, ValueError):
            pass
    try:
        candidates.append(binascii.unhexlify(raw.strip()))
    except (binascii.Error, ValueError):
        pass
    for value in candidates:
        if len(value) == KEY_LEN:
            return value
    raise ValueError(
        "%s 必须解码为 %d 字节随机密钥（建议：openssl rand -base64 32 "
        "或 openssl rand -hex 32）" % (ENV_MASTER_KEY, KEY_LEN)
    )


def load_master_key(key_file=None):
    """加载 32 字节主密钥，返回 (key, source)，source ∈ {"env","file"}。

    1) 环境变量 CREDENTIAL_MASTER_KEY（base64/base64url/hex，32 字节）优先，
       密钥不落数据卷；
    2) 否则使用 CREDENTIAL_KEY_FILE（默认 /data/.credential.key）：存在则
       读取，不存在则以 0600 权限新建随机密钥。
    """
    raw = os.environ.get(ENV_MASTER_KEY, "").strip()
    if raw:
        return _decode_env_key(raw), "env"

    path = key_file or os.environ.get(ENV_KEY_FILE, "").strip() or DEFAULT_KEY_FILE
    if os.path.exists(path):
        with open(path, "rb") as fh:
            key = fh.read()
        if len(key) != KEY_LEN:
            raise ValueError(
                "密钥文件 %s 内容必须是 %d 字节原始随机密钥" % (path, KEY_LEN)
            )
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        return key, "file"

    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, exist_ok=True)
    key = secrets.token_bytes(KEY_LEN)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:  # 并发启动时另一进程已创建
        with open(path, "rb") as fh:
            return fh.read(), "file"
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(key)
            fh.flush()
            os.fsync(fh.fileno())
    except BaseException:
        # 写入失败时不要留下半截密钥文件
        try:
            os.unlink(path)
        except OSError:
            pass
        raise
    os.chmod(path, 0o600)
    return key, "file"

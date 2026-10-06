"""后继刷新凭证的落盘保护。

威胁模型：SQLite 数据卷 / 备份 / 可读取数据库文件的运行环境，不得因此获得
「可直接作为 Bearer 刷新凭证提交」的后继凭证；但断回应后的精确重放又要求
后继凭证可以被**可逆恢复**（仅存哈希不够）。

因此后继凭证不以明文落库，而是封装为不透明的认证加密信封：

  pae1.<key-id>.<nonce>.<tag>.<ciphertext>     （各段为 urlsafe-base64）

- 数据密钥为 256 bit，存放在数据库文件之外（独立密钥卷或外部注入），
  拷贝 SQLite 文件不会带走密钥；
- 每条消息使用 256 bit 随机 nonce，密钥由 HKDF-SHA256 派生为独立的
  加密 / 认证子密钥；
- 加密为 HMAC-SHA256 计数模式流密码（PRF 反演密钥流），
  认证为 encrypt-then-MAC 的 HMAC-SHA256，并将轮换记录上下文
  （family_id / rotation_id / 代次 / 凭证哈希）作为 AAD 绑定，
  信封无法在记录间搬运或篡改；
- 标记比较使用恒定时间比较；解密失败统一抛出 InvalidToken。

标准库没有 AES，这里不引入第三方依赖（Compose 构建无网络也可工作）；
HMAC-SHA256 作为 PRF 构造计数器模式流密码 + 独立 MAC 密钥的
encrypt-then-MAC，在 256 位随机 nonce 下提供等价的认证加密安全性。

密钥来源（按优先级）：
  1. 环境变量 CREDENTIAL_PROTECTION_KEY：64 位十六进制（32 字节），
     适合交由外部密钥管理系统注入；
  2. 环境变量 CREDENTIAL_KEY_FILE 指定的密钥文件（0600，不存在则创建）；
  3. 默认密钥文件 <数据库目录>/.credential-protection.key —— 仅用于本地
     开发；Compose 产物把它显式指向独立密钥卷 /secrets，与 SQLite 所在的
     /data 数据卷分离，数据卷备份不包含密钥。
"""
import base64
import hashlib
import hmac
import os
import secrets
from pathlib import Path

ENVELOPE_VERSION = "pae1"
_KEY_LEN = 32
_NONCE_LEN = 32  # 256 位随机 nonce：同密钥下碰撞概率可忽略
_TAG_LEN = 32

# HKDF 域分隔：即便同一主密钥被别处复用，也派生出彼此独立的子密钥。
_HKDF_SALT = b"deep-space-ground-station/pae1/v1"
_INFO_ENC = b"pae1/encryption-key"
_INFO_MAC = b"pae1/authentication-key"
_STREAM_LABEL = b"pae1/keystream"
_AUTH_LABEL = b"pae1/auth"


class InvalidToken(Exception):
    """信封无法通过认证或格式非法（密钥错误、内容被篡改或上下文不匹配）。"""


def hkdf_sha256(salt, ikm, info, length):
    """RFC 5869 HKDF-SHA256（extract-and-expand）。"""
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm = b""
    block = b""
    i = 1
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes([i]), hashlib.sha256).digest()
        okm += block
        i += 1
    return okm[:length]


def _b64e(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64d(text):
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


def _xor(data, keystream):
    return bytes(a ^ b for a, b in zip(data, keystream))


def _keystream(enc_key, nonce, length):
    out = b""
    counter = 0
    while len(out) < length:
        block_index = counter.to_bytes(8, byteorder="big")
        out += hmac.new(enc_key, _STREAM_LABEL + nonce + block_index,
                        hashlib.sha256).digest()
        counter += 1
    return out[:length]


def _auth_input(aad, nonce, ciphertext):
    # 显式长度前缀，杜绝字段拼接歧义。
    return (
        _AUTH_LABEL
        + len(aad).to_bytes(8, "big") + aad
        + len(nonce).to_bytes(8, "big") + nonce
        + len(ciphertext).to_bytes(8, "big") + ciphertext
    )


def rotation_associated_data(family_id, rotation_id, new_generation,
                             new_credential_hash):
    """信封绑定的轮换记录上下文（AAD）：信封不得离开其所属记录仍有效。"""
    family_id = family_id.encode("utf-8")
    rotation_id = rotation_id.encode("utf-8")
    new_credential_hash = new_credential_hash.encode("utf-8")
    generation = int(new_generation).to_bytes(8, "big")
    return (
        b"rotation-successor"
        + len(family_id).to_bytes(4, "big") + family_id
        + len(rotation_id).to_bytes(4, "big") + rotation_id
        + generation
        + len(new_credential_hash).to_bytes(4, "big") + new_credential_hash
    )


class CredentialProtector:
    """后继凭证的认证加密封装 / 恢复。"""

    def __init__(self, main_key):
        if not isinstance(main_key, (bytes, bytearray)) or len(main_key) != _KEY_LEN:
            raise ValueError("protection key must be exactly 32 bytes")
        self._key = bytes(main_key)
        self._enc_key = hkdf_sha256(_HKDF_SALT, self._key, _INFO_ENC, 32)
        self._mac_key = hkdf_sha256(_HKDF_SALT, self._key, _INFO_MAC, 32)
        digest = hashlib.sha256(self._key).digest()[:8]
        self.key_id = _b64e(digest)

    def protect(self, secret, associated_data):
        """加密并认证 secret，返回纯文本的不透明信封字符串。"""
        nonce = secrets.token_bytes(_NONCE_LEN)
        data = secret.encode("utf-8")
        ciphertext = _xor(data, _keystream(self._enc_key, nonce, len(data)))
        tag = hmac.new(self._mac_key,
                       _auth_input(associated_data, nonce, ciphertext),
                       hashlib.sha256).digest()
        return ".".join((
            ENVELOPE_VERSION, self.key_id,
            _b64e(nonce), _b64e(tag), _b64e(ciphertext),
        ))

    def reveal(self, envelope, associated_data):
        """校验并解密信封；任何不一致都抛出 InvalidToken（不返回部分结果）。"""
        try:
            if not isinstance(envelope, str):
                raise InvalidToken("envelope must be text")
            parts = envelope.split(".")
            if len(parts) != 5 or parts[0] != ENVELOPE_VERSION:
                raise InvalidToken("malformed envelope")
            version, key_id, nonce_b64, tag_b64, ct_b64 = parts
            nonce = _b64d(nonce_b64)
            tag = _b64d(tag_b64)
            ciphertext = _b64d(ct_b64)
        except (ValueError, TypeError) as exc:
            raise InvalidToken("malformed envelope") from exc

        if version != ENVELOPE_VERSION or len(nonce) != _NONCE_LEN \
                or len(tag) != _TAG_LEN or key_id != self.key_id:
            raise InvalidToken("envelope header mismatch")

        expected = hmac.new(self._mac_key,
                            _auth_input(associated_data, nonce, ciphertext),
                            hashlib.sha256).digest()
        if not hmac.compare_digest(tag, expected):
            raise InvalidToken("authentication tag mismatch")

        plaintext = _xor(ciphertext, _keystream(self._enc_key, nonce, len(ciphertext)))
        try:
            return plaintext.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise InvalidToken("plaintext is not valid utf-8") from exc


def _load_or_create_key_file(path):
    path = Path(path)
    if path.exists():
        key = path.read_bytes()
        if len(key) != _KEY_LEN:
            raise ValueError(
                f"credential protection key file {path} must contain exactly"
                f" {_KEY_LEN} raw bytes, got {len(key)}"
            )
        return key

    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):  # Linux：拒绝符号链接替换
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)  # 仅属主可读写
    try:
        key = secrets.token_bytes(_KEY_LEN)
        os.write(fd, key)
        os.fsync(fd)
    finally:
        os.close(fd)
    try:
        dir_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    except (OSError, PermissionError):
        pass
    return key


def build_default_protector(db_path):
    """按环境变量解析数据密钥，构造 CredentialProtector。

    显式注入的环境密钥优先；否则使用密钥文件（Compose 指向独立密钥卷，
    无配置的本地开发默认放在数据库旁，仅为开发便利）。
    """
    env_key = os.environ.get("CREDENTIAL_PROTECTION_KEY")
    if env_key:
        try:
            key = bytes.fromhex(env_key.strip())
        except ValueError as exc:
            raise ValueError(
                "CREDENTIAL_PROTECTION_KEY must be 64 hex characters (32 bytes)"
            ) from exc
        if len(key) != _KEY_LEN:
            raise ValueError(
                "CREDENTIAL_PROTECTION_KEY must be 64 hex characters (32 bytes)"
            )
        return CredentialProtector(key)

    key_file = os.environ.get("CREDENTIAL_KEY_FILE")
    if not key_file:
        key_file = str(Path(db_path).resolve().parent / ".credential-protection.key")
    return CredentialProtector(_load_or_create_key_file(key_file))

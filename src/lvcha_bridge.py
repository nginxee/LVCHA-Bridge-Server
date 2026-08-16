#!/usr/bin/env python3
"""LVCHA VPN 桥接: SOCKS5 入站 -> LVCHA 隧道 -> 节点服务器
用法:
  python lvcha_bridge.py [--port 10808] [--host 127.0.0.1]
  (首次运行 autoRegister 自动注册; 已有凭证走 refreshToken)
依赖: pip install pycryptodome
"""
import base64
import json
import os
import random
import select
import socket
import struct
import sys
import threading
import time
import urllib.request
import urllib.parse
import uuid
from pathlib import Path

from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5

# ============ 常量 (逆向验证) ============
FALLBACK_KEY = bytes.fromhex("7c54c25398aa16afd495622f310ce692471751061292ed9aa4f1ac160cc19fe5")
APK_SIZE = 5807186
SO_PARAM = "p15=lvchanative.so;&"
FIRST_DATA_MAX = 16 * 1024  # l61 首段数据上限: 超出即建隧道, 剩余数据走 k61 流式
RECV_BUF = 256 * 1024  # 256K 接收缓冲区, 提升大文件/流媒体吞吐

API_HOSTS = [
    "bd72149f094e78c2811f735db18a68a6-2069558124.ap-southeast-1.elb.amazonaws.com",
    "a384693bb964ed5c1eccbe39ee1000bc-1759550417.ap-southeast-1.elb.amazonaws.com",
    "147bcf1410cd7a6a7878b93e13ac4f4a-414842270.ap-southeast-1.elb.amazonaws.com",
]

STATE_FILE = Path(__file__).resolve().parent.parent / "data" / "credentials" / "bridge_state.json"
LOGF = Path(__file__).resolve().parent.parent / "captures" / "logs" / "bridge.log"

# ============ 日志: 级别 DEBUG/INFO/WARNING/ERROR + 颜色 (控制台彩色, 落盘纯文本) ============
_LEVELS = {"DEBUG": 10, "INFO": 20, "WARNING": 30, "ERROR": 40}
_LEVEL_COLORS = {10: "\033[90m", 30: "\033[33m", 40: "\033[91m"}
_RESET = "\033[0m"
if sys.platform == "win32":
    os.system("")  # 启用 Windows 终端 ANSI VT 转义 (Win10+ conhost / Windows Terminal)
COLOR_TTY = bool(getattr(sys.stdout, "isatty", lambda: False)())  # 重定向/后台运行时不带颜色
LOG_MIN_LEVEL = _LEVELS.get(os.environ.get("LVCHA_LOG_LEVEL", "INFO").upper(), 20)  # 默认 INFO, 设 DEBUG 看全量

_LOGF_DIR_OK = False  # 目录已确认存在, 跳过后续 mkdir (每条日志省一次 stat)

def _log(level: str, fmt, *a):
    lv = _LEVELS.get(level, 20)
    if lv < LOG_MIN_LEVEL:
        return                                     # 低于阈值直接丢弃 (默认 INFO 时隐藏 DEBUG 细节)
    msg = fmt % a if a else fmt                    # 支持 printf 风格: info("x=%d", x)
    line = time.strftime("[%H:%M:%S] ") + f"[{level:^7s}] " + msg
    try:
        if COLOR_TTY:
            print(_LEVEL_COLORS.get(lv, "") + line + _RESET, flush=True)
        else:
            print(line, flush=True)
    except Exception:
        pass  # pythonw 无 stdout (后台运行), 仅落盘
    try:
        global _LOGF_DIR_OK
        if not _LOGF_DIR_OK:
            LOGF.parent.mkdir(parents=True, exist_ok=True)
            _LOGF_DIR_OK = True
        if LOGF.exists() and LOGF.stat().st_size > 5 * 1024 * 1024:
            LOGF.replace(LOGF.with_name("bridge.log.1"))  # 5MB 轮转, 防磁盘写满
        with open(LOGF, "a", encoding="utf-8") as f:
            f.write(line + "\n")  # 文件落纯文本, 不带 ANSI 颜色
    except Exception:
        pass  # 日志写入失败不阻塞主流程

def debug(*a):     _log("DEBUG", *a)
def info(*a):      _log("INFO", *a)
def warning(*a):   _log("WARNING", *a)
def error(*a):     _log("ERROR", *a)

# ============ 签名 / API (lvcha_protocol 已验证) ============
def sign(params: dict, uid: str) -> str:
    items = [f"{k}={v}&" for k, v in params.items() if v not in (None, "")]
    items += [f"p14={APK_SIZE}&", SO_PARAM]
    items.sort(key=lambda s: s.lower())
    concat = "".join(items).encode("utf-8")
    key = uid.encode() if uid else FALLBACK_KEY
    iv = os.urandom(12)
    c = AES.new(key, AES.MODE_GCM, nonce=iv, mac_len=16)
    blob = b"\x02" + iv + c.encrypt(concat) + c.digest()  # 必须显式附加 16B tag!
    return base64.b64encode(blob).decode()

def decrypt_resp(body: bytes, uid: str) -> dict:
    """响应: base64( [12B IV][密文+16B tag] ), 无 flag。uid 空用 fallback。"""
    b = base64.b64decode(body)
    key = uid.encode() if uid else FALLBACK_KEY
    c = AES.new(key, AES.MODE_GCM, nonce=b[:12], mac_len=16)
    pt = c.decrypt(b[12:-16])
    c.verify(b[-16:])
    return json.loads(pt)

def full_params(token: str = "", uid: str = "") -> dict:
    p = {
        "platform": "1", "device": "1bbd6d4813ba766e", "promotion": "501281083",
        "p1": "108100", "p2": "6", "p3": "1", "p4": "22101316C", "p5": "3", "p6": "31",
        "p7": "com.abjlvcha.main", "p8": "22", "p9": str(uuid.uuid4()),
        "p10": "47", "p11": "zh", "p12": "e8704e350d52e68456aeb63f85b17fa6",
        "p13": str(APK_SIZE),
    }
    if token:
        p["token"] = token
    if uid:
        p["uid"] = uid  # vs1.V() 注入 uid 参与签名 (实测明文确认)
    return p

def api_post(path: str, params: dict, uid: str, token: str = "", timeout=12):
    body_map = {"v": "22", "content": sign(params, uid)}
    if token:
        body_map["token"] = token  # vq1.a(): body = {v, content, token} (实测确认)
    body = urllib.parse.urlencode(body_map).encode()
    last_err = None
    for host in API_HOSTS:
        try:
            req = urllib.request.Request(f"http://{host}{path}", data=body, headers={
                "Content-Type": "application/x-www-form-urlencoded", "User-Agent": "okhttp/4.12.0"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                raw = r.read()
            return decrypt_resp(raw, uid)
        except Exception as e:
            last_err = e
            error(f"API {path} {host} 失败: {type(e).__name__} {str(e)[:80]}")
            time.sleep(random.uniform(0.3, 1.5))   # 随机退避, 模拟真实客户端行为间隔
    raise RuntimeError(f"API 全部失败: {last_err}")

# ============ 凭证管理 ============
def load_state():
    if STATE_FILE.exists():
        return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    return {}

def save_state(st):
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)  # 同类根因: 目录不存在时自动创建
    STATE_FILE.write_text(json.dumps(st, ensure_ascii=False), encoding="utf-8")

def fresh_device_params():
    """生成全新的设备特征参数 (device/p10/p12 每次运行随机, 规避设备指纹追踪)"""
    p = full_params()
    p["device"] = os.urandom(8).hex()
    p["p10"] = uuid.uuid4().hex[:16]
    p["p12"] = uuid.uuid4().hex[:16]
    return p

def try_refresh_existing_credentials():
    """尝试复用已有凭证: refreshToken 续期, 避免频繁 autoRegister 触发限流。
    返回 (uid, token_blob, rsa_pub_der) 或 None (凭证无效/不存在)"""
    st = load_state()
    uid = st.get("uid", "")
    token_b64 = st.get("token", "")
    secret = st.get("secret", "")
    if not uid or not token_b64:
        return None
    # 尝试 refreshToken 续期
    info("尝试复用已有凭证 refreshToken ...")
    try:
        resp = api_post("/v3/refreshToken",
                        full_params(token=token_b64, uid=uid), uid, token=token_b64)
        if resp.get("code") == 1:
            body = resp["body"]
            uid = body.get("uid", uid)
            token_b64 = body.get("token", token_b64)
            secret = body.get("secret", secret)
            if secret:
                st.update({"uid": uid, "token": token_b64, "secret": secret})
                save_state(st)
                info(f"refreshToken 成功 uid={uid[:16]}..., 凭证已续期")
                return uid, token_b64, secret
            else:
                warning("refreshToken 未返回 secret, 尝试用旧 secret")
        else:
            warning(f"refreshToken 失败: code={resp.get('code')} {resp.get('msg','')}")
    except Exception as e:
        warning(f"refreshToken 异常: {type(e).__name__} {str(e)[:80]}")
    return None


def ensure_credentials():
    """凭证获取: 优先复用已有 token (refreshToken), 失败才 autoRegister 换新身份。
    返回 (uid, token_blob, rsa_pub_der)"""
    # 第一优先: 复用已有凭证
    result = try_refresh_existing_credentials()
    if result:
        return result
    # 第二优先: 全新设备特征 autoRegister
    info("使用全新设备特征 autoRegister ...")
    params = fresh_device_params()
    resp = api_post("/v3/autoRegister", params, "")
    if resp.get("code") != 1:
        raise RuntimeError(f"autoRegister 失败: {resp}")
    body = resp["body"]
    uid, token_b64 = body["uid"], body["token"]
    secret = body.get("secret", "")

    if not secret:
        info("autoRegister 未返回 secret, refreshToken 获取 ...")
        try:
            resp2 = api_post("/v3/refreshToken", full_params(token=token_b64, uid=uid), uid, token=token_b64)
            if resp2.get("code") == 1:
                b2 = resp2["body"]
                uid = b2.get("uid", uid)
                token_b64 = b2.get("token", token_b64)
                secret = b2.get("secret", "")
        except Exception as e:
            warning("refreshToken 失败: %s", e)

    if not secret:
        raise RuntimeError("未能获取 RSA 公钥 (secret), 无法建立隧道")

    st = {"uid": uid, "token": token_b64, "secret": secret}
    save_state(st)
    info(f"autoRegister 成功 uid={uid[:16]}...")
    return uid, token_b64, secret

# ============ 节点获取 ============
def get_nodes(uid, token_b64):
    resp = api_post("/v3/getNodeList", full_params(token=token_b64, uid=uid), uid, token=token_b64)
    if resp.get("code") != 1:
        raise RuntimeError(f"getNodeList 失败: {resp}")
    nodes = []
    for region in resp["body"]["node_list"]:
        for nd in region.get("type_list", []):
            addr = nd["address"].lstrip("/")
            if addr.startswith("["):
                continue  # IPv6 跳过
            host, port = addr.rsplit(":", 1)
            nodes.append((region["name"], host, int(port)))
    return nodes

# ============ 连接限速 (防机器人特征) ============
_tunnel_rate_lock = threading.Lock()
_tunnel_last_ts = 0.0
_tunnel_rate_min = 0.03  # 最小隧道间隔 30ms (私有部署, 正常浏览不会触发限流)
_tunnel_rate_max = 0.08  # 随机抖动上界: 实际间隔 [30ms, 80ms]

def _rate_limit_tunnel():
    """全局隧道限速: 新建隧道前调用, 确保间隔 ≥ _tunnel_rate_min + 随机抖动。
    防止短时间内大量 TCP+RSA 握手被服务器识别为机器人行为。"""
    global _tunnel_last_ts
    with _tunnel_rate_lock:
        now = time.time()
        wait = _tunnel_last_ts + _tunnel_rate_min + random.uniform(0, _tunnel_rate_max - _tunnel_rate_min) - now
        if wait > 0:
            time.sleep(wait)
        _tunnel_last_ts = time.time()

# ============ 隧道 ============
class Tunnel:
    """单条 LVCHA 隧道连接, 流 ID 固定 1。"""
    def __init__(self, host, port, token_b64, rsa_pub_pem, timeout=5, target=None, tport=None, first_data=b"", proto=1, rate_limit=True):
        if rate_limit:
            _rate_limit_tunnel()  # 拟人化: 新建隧道前加随机延迟
        self.sock = socket.create_connection((host, port), timeout=timeout)
        try:
            self.sock.settimeout(60)
            self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)  # 禁 Nagle: 小包立即发, 省 ~40ms
            self.token = base64.b64decode(token_b64)          # sessionId blob
            self.key = os.urandom(32)                          # 每会话随机隧道密钥
            self.enc_key = rsa_pub_pem                         # base64 DER (PKCS#8) 公钥
            self.target = target
            self.tport = tport
            self.proto = proto                                 # 1=TCP, 2=UDP
            self._handshake(first_data)
        except Exception:
            self.sock.close()                                  # 握手失败不留 fd 泄漏
            raise

    def _handshake(self, first_data: bytes):
        if not self.target:
            raise ValueError("需要 target")
        pem = "-----BEGIN PUBLIC KEY-----\n" + self.enc_key + "\n-----END PUBLIC KEY-----\n"
        rsa = RSA.import_key(pem)                          # base64 DER -> PEM 包装
        cipher = PKCS1_v1_5.new(rsa)
        rsa_blob = cipher.encrypt(self.key)               # RSA-512 PKCS1 -> 64B
        inner = (b"\x01"                                   # version
                 + struct.pack(">H", len(self.token)) + self.token
                 + b"\x02"                                 # cipher = AES-GCM
                 + struct.pack(">H", len(rsa_blob)) + rsa_blob)
        # 会话包内嵌加密的 l61 目标头 + 首段数据 (j61.e.c(z=false): [12B IV][ct+tag] 无长度)
        l61 = self._target_header(1, self.target, self.tport, self.proto) + first_data
        extra = self._encrypt_plain(l61)                  # 无长度前缀加密
        self._send_raw(struct.pack(">I", len(inner) + len(extra)) + inner + extra)

    def _target_header(self, stream_id, ip, port, proto=1):
        try:
            addr = socket.inet_aton(ip)
            family = 1
        except OSError:
            addr = socket.inet_pton(socket.AF_INET6, ip)
            family = 2
        return (struct.pack(">H", stream_id) + b"\x01"
                + bytes([proto, family]) + addr
                + struct.pack(">H", port))  # 无尾部字节, 之后直接接首段数据

    def _encrypt_plain(self, data: bytes) -> bytes:
        """无长度前缀加密: [12B IV][密文+16B tag]"""
        iv = os.urandom(12)
        c = AES.new(self.key, AES.MODE_GCM, nonce=iv, mac_len=16)
        return iv + c.encrypt(data) + c.digest()

    def _send_raw(self, data):
        self.sock.sendall(data)

    def _encrypt(self, data: bytes) -> bytes:
        iv = os.urandom(12)
        c = AES.new(self.key, AES.MODE_GCM, nonce=iv, mac_len=16)
        return struct.pack(">I", 12 + len(data) + 16) + iv + c.encrypt(data) + c.digest()

    def send_data(self, data: bytes, stream_id: int = 1):
        """数据帧 (k61): 明文 = [2B 流ID][1B 类型=2][数据], 加密后 [4B len][12B IV][密文+16B tag]"""
        inner = struct.pack(">H", stream_id) + b"\x02" + data
        self._send_raw(self._encrypt(inner))

    def recv_frame(self) -> bytes:
        """返回解密后的帧内容"""
        hdr = self._recv_exact(4)
        flen = struct.unpack(">I", hdr)[0]
        if flen <= 0 or flen > 1 << 23:  # 8MB 硬上限 (放宽: 服务器可能下发大帧)
            raise ConnectionError(f"非法帧长 {flen}")
        frame = self._recv_exact(flen)
        iv, ct = frame[:12], frame[12:]
        c = AES.new(self.key, AES.MODE_GCM, nonce=iv, mac_len=16)
        pt = c.decrypt(ct[:-16])
        c.verify(ct[-16:])
        return pt

    def _recv_exact(self, n):
        buf = bytearray()
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("连接关闭")
            buf.extend(chunk)
        return bytes(buf)

    def close(self):
        try:
            self.sock.close()
        except Exception:
            pass

# ============ 隧道 DNS (本地 DNS 被污染, 走隧道向 8.8.8.8 解析) ============
_DNS_CACHE = {}          # 正缓存: {host: (expire_time, [ips])}
_DNS_FAIL_CACHE = {}     # 失败负缓存: 自适应 TTL (30s→120s→300s), 避免重复探测已知不可达域名
_DNS_FAIL_COUNT = {}     # 连续失败次数 (自适应负缓存依据)
_DNS_HARD_FAIL = {}      # 双失败硬缓存: 隧道+本地都失败, 5分钟内不重试 (防刷屏)
_DNS_CACHE_LOCK = threading.Lock()
_DNS_SERVERS = ("8.8.8.8", "1.1.1.1")   # 并行查询, 首个成功即返回
_DNS_PENDING = {}        # 防并发: 同一域名同时只走一次隧道 DNS, 其余线程等结果
_DNS_CACHE_MAX = 500     # 缓存上限: 超出时清理过期 + 最老条目, 防内存无限增长

def _dns_cache_cleanup():
    """定期清理过期 DNS 缓存条目, 防内存无限增长。
    超过上限时优先删过期, 再删最早过期条目。"""
    now = time.time()
    with _DNS_CACHE_LOCK:
        # 删过期
        expired = [k for k, v in _DNS_CACHE.items() if v[0] <= now]
        for k in expired:
            _DNS_FAIL_COUNT.pop(k, None)
        for k in expired:
            del _DNS_CACHE[k]
        expired_f = [k for k, v in _DNS_FAIL_CACHE.items() if v <= now]
        for k in expired_f:
            _DNS_FAIL_COUNT.pop(k, None)
            del _DNS_FAIL_CACHE[k]
        expired_h = [k for k, v in _DNS_HARD_FAIL.items() if v <= now]
        for k in expired_h:
            del _DNS_HARD_FAIL[k]
        # 超限: 删最早过期
        while len(_DNS_CACHE) > _DNS_CACHE_MAX:
            oldest = min(_DNS_CACHE, key=lambda k: _DNS_CACHE[k][0])
            del _DNS_CACHE[oldest]
            _DNS_FAIL_COUNT.pop(oldest, None)

def build_dns_query(hostname, qid):
    """构造 DNS A 查询包 (仅头部 + 单问题)"""
    hdr = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    q = b"".join(bytes([len(p)]) + p.encode() for p in hostname.split(".")) + b"\x00"
    return hdr + q + struct.pack(">HH", 1, 1)  # type=A, class=IN

def parse_dns_a(resp, qid):
    """解析 DNS 响应, 返回所有 A 记录 IP 列表 (处理名字压缩)"""
    if len(resp) < 12 or struct.unpack(">H", resp[:2])[0] != qid:
        raise ConnectionError("DNS 响应 qid 不匹配")
    if struct.unpack(">H", resp[2:4])[0] & 0x000F != 0:
        raise ConnectionError("DNS 响应错误码")
    ancount = struct.unpack(">H", resp[6:8])[0]
    pos = 12
    while resp[pos] != 0:            # 跳过问题区
        pos += resp[pos] + 1
    pos += 5
    ips, ttl = [], 300
    for _ in range(ancount):
        if resp[pos] & 0xC0 == 0xC0:  # 名字压缩指针
            pos += 2
        else:
            while resp[pos] != 0:
                pos += resp[pos] + 1
            pos += 1
        typ, _cls, rttl, rdlen = struct.unpack(">HHIH", resp[pos:pos + 10])
        pos += 10
        if typ == 1 and rdlen == 4:
            ips.append(socket.inet_ntoa(resp[pos:pos + 4]))
            ttl = min(ttl, rttl)
        pos += rdlen
    return ips, min(300, max(60, ttl))   # TTL 收敛到 [60, 300] 缓存窗口

def _is_ip(host):
    """IPv4 / IPv6 字面量判断 (SOCKS ATYP=4 的 IPv6 不能当域名去解析)"""
    try:
        socket.inet_pton(socket.AF_INET, host)
        return True
    except OSError:
        try:
            socket.inet_pton(socket.AF_INET6, host)
            return True
        except OSError:
            return False

def _tunnel_dns_query(server, host, dns_server="8.8.8.8"):
    """一次 UDP 隧道 DNS 查询 (经 dns_server:53), 返回 (A 记录列表, ttl)"""
    qid = int.from_bytes(os.urandom(2), "big")
    query = build_dns_query(host, qid)
    node = server.current_node()
    tun = Tunnel(node[1], node[2], server.token_b64, server.rsa_pub,
                 target=dns_server, tport=53, first_data=query, proto=2, rate_limit=False)
    tun.sock.settimeout(2.5)
    try:
        f = tun.recv_frame()
        if len(f) >= 3 and f[2] == 2:
            ips, ttl = parse_dns_a(f[3:], qid)
            if ips:
                return ips, ttl
        raise ConnectionError("无 A 记录")
    finally:
        tun.close()

def _local_resolve(host, timeout=2):
    """带超时的本地 DNS 解析 (socket.gethostbyname 无超时, 在线程中限时执行)"""
    res = {}
    def _do():
        try:
            res["ip"] = socket.gethostbyname(host)
        except Exception as e:
            res["err"] = e
    t = threading.Thread(target=_do, daemon=True)
    t.start()
    t.join(timeout)
    if t.is_alive():
        raise ConnectionError(f"本地DNS解析 {host} 超时 ({timeout}s)")
    if "ip" in res:
        return res["ip"]
    raise ConnectionError(f"本地DNS也无法解析 {host}: {res.get('err', '未知错误')}")

def _dns_fail_ttl(host):
    """自适应负缓存 TTL: 连续失败越多, 缓存越久, 减少对不可达域名的重复探测。
    60s → 120s → 240s → 300s (上限)"""
    count = _DNS_FAIL_COUNT.get(host, 0)
    return min(300, 60 * (2 ** min(count, 2)))  # 60,120,240,300

def tunnel_resolve(server, host):
    """通过 UDP 隧道向 8.8.8.8/1.1.1.1:53 解析域名 (规避本地 DNS 污染)。
    并行查询两个 DNS 服务器, 首个成功即返回 (总超时 3s, 非 6s)。
    防并发: 同一域名只走一次隧道 DNS, 其余线程等结果。
    自适应负缓存: 重复失败的域名缓存更久 (30→300s), 减少无意义重试。
    缓存 TTL 感知 [60, 300s], 多 A 记录随机轮换 (避免单 IP 过载/失效)。
    LRU 淘汰: 缓存超 500 条时清理过期 + 最老条目, 防内存无限增长。"""
    if not host:
        raise ConnectionError("空主机名")
    if _is_ip(host):
        return host                    # 已是 IP (含 IPv6 字面量)
    # 双失败硬缓存: 隧道+本地都失败的域名, 5分钟内直接快速失败 (防同一域名刷屏百条ERROR)
    hard_fail = _DNS_HARD_FAIL.get(host, 0)
    if hard_fail > time.time():
        raise ConnectionError("DNS %s 不可解析 (隧道+本地均失败, 剩余%ds)" % (host, int(hard_fail - time.time())))
    # 仅缓存超限时清理 (每查询都清理在 500 条时锁内遍历耗时显著)
    if len(_DNS_CACHE) > _DNS_CACHE_MAX:
        _dns_cache_cleanup()
    now = time.time()
    with _DNS_CACHE_LOCK:
        hit = _DNS_CACHE.get(host)
        if hit and hit[0] > now:
            return random.choice(hit[1])
        fail_ttl = _dns_fail_ttl(host)
        if _DNS_FAIL_CACHE.get(host, 0) > now:
            debug("隧道DNS %s 负缓存生效 (剩余%ds), 直接回退本地解析", host, int(_DNS_FAIL_CACHE[host]-now))
            try:
                return _local_resolve(host)
            except ConnectionError:
                with _DNS_CACHE_LOCK:
                    _DNS_HARD_FAIL[host] = time.time() + 300
                raise
        # 防并发: 如果同域名正在查询, 等待其结果 (最多 10s)
        pending = _DNS_PENDING.get(host)
        if pending is not None:
            debug("隧道DNS %s 已有查询进行中, 等待结果 ...", host)
            _DNS_CACHE_LOCK.release()
            try:
                pending.wait(timeout=10)
            finally:
                _DNS_CACHE_LOCK.acquire()
            hit = _DNS_CACHE.get(host)
            if hit and hit[0] > time.time():
                return random.choice(hit[1])
            if _DNS_FAIL_CACHE.get(host, 0) > time.time():
                try:
                    return _local_resolve(host)
                except ConnectionError:
                    with _DNS_CACHE_LOCK:
                        _DNS_HARD_FAIL[host] = time.time() + 300
                    raise
            raise ConnectionError(f"隧道DNS {host} 查询超时 (等待10s无结果)")
        pending_event = threading.Event()
        _DNS_PENDING[host] = pending_event
    # 在锁外执行耗时查询: 并行发两个 DNS 服务器, 首个成功即返回
    result = None
    try:
        results = [None]  # [0] = (ips, ttl, srv) 或 Exception (首个成功优先)
        def _query(srv):
            try:
                r = _tunnel_dns_query(server, host, srv)
                with _DNS_CACHE_LOCK:
                    if results[0] is None or isinstance(results[0], Exception):
                        results[0] = (*r, srv)  # 成功覆盖失败
            except Exception as e:
                with _DNS_CACHE_LOCK:
                    if results[0] is None:
                        results[0] = e  # 仅在无结果时记录失败
        threads = [threading.Thread(target=_query, args=(srv,), daemon=True) for srv in _DNS_SERVERS]
        for t in threads:
            t.start()
        # 等待首个成功 (逐个检查, 而非 join 全部)
        deadline = now + 2.5
        for t in threads:
            remaining = deadline - time.time()
            if remaining > 0:
                t.join(remaining)
            else:
                break
        with _DNS_CACHE_LOCK:
            first = results[0]
        if first is not None and not isinstance(first, Exception):
            ips, ttl, srv = first
            with _DNS_CACHE_LOCK:
                _DNS_CACHE[host] = (now + ttl, ips)
                _DNS_FAIL_CACHE.pop(host, None)
                _DNS_FAIL_COUNT.pop(host, None)
                _DNS_HARD_FAIL.pop(host, None)
            result = random.choice(ips)
            debug("隧道DNS %s -> %s (共%d个, TTL %ds, via %s)", host, result, len(ips), ttl, srv)
        else:
            # 收集失败原因用于日志
            errs = []
            for t in threads:
                t.join(0.1)
            with _DNS_CACHE_LOCK:
                if isinstance(first, Exception):
                    errs.append(str(first)[:50])
            # 设自适应负缓存
            with _DNS_CACHE_LOCK:
                _DNS_FAIL_COUNT[host] = _DNS_FAIL_COUNT.get(host, 0) + 1
                _DNS_FAIL_CACHE[host] = now + _dns_fail_ttl(host)
            err_info = " + ".join(errs) if errs else "超时"
            debug("隧道DNS失败 %s: %s (负缓存%ds)", host, err_info, _dns_fail_ttl(host))
            try:
                result = _local_resolve(host)
            except ConnectionError:
                with _DNS_CACHE_LOCK:
                    _DNS_HARD_FAIL[host] = time.time() + 300  # 隧道+本地都失败, 硬缓存5分钟
                raise
    finally:
        with _DNS_CACHE_LOCK:
            _DNS_PENDING.pop(host, None)
        pending_event.set()
    return result

# ============ SOCKS5 服务器 ============
class SocksHandler(threading.Thread):
    def __init__(self, conn, server):
        super().__init__(daemon=True)
        self.conn = conn
        self.server = server
        self.timeout = 30

    def run(self):
        try:
            self._socks_loop()
        except Exception as e:
            # WinError 10053/10054: 浏览器主动关闭连接 (DNS 耗时过长等), 属正常行为
            # 客户端未发送数据: 连接后无动作, 属正常行为 (探活、取消连接等)
            # 故障退避中快速失败: 节点切换期间正常拒绝, 非错误
            # timed out: 节点故障期间连接超时, 属正常行为
            _err_str = str(e)
            if "10053" in _err_str or "10054" in _err_str or "未发送数据" in _err_str or "退避中" in _err_str or "timed out" in _err_str or "DNS" in _err_str:
                debug("会话结束 [%s]: %s", self.conn.getpeername()[0], e)
            else:
                error("会话结束 [%s]: %s", self.conn.getpeername()[0], e)
        finally:
            try:
                self.conn.close()
            except Exception:
                pass

    def _recv_exact(self, n):
        buf = bytearray()
        while len(buf) < n:
            chunk = self.conn.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("SOCKS 客户端断开")
            buf.extend(chunk)
        return bytes(buf)

    def _udp_associate(self, atyp):
        """SOCKS5 UDP ASSOCIATE: 每 UDP 数据报 -> 独立 LVCHA 隧道 (proto=2), 响应封装回客户端"""
        # 读取请求剩余部分 (BND.ADDR/BND.PORT, 忽略)
        if atyp == 1:
            self._recv_exact(6)
        elif atyp == 3:
            ln = self._recv_exact(1)[0]
            self._recv_exact(ln + 2)
        elif atyp == 4:
            self._recv_exact(18)
        else:
            raise ConnectionError(f"ATYP {atyp}")

        udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_sock.bind(("127.0.0.1", 0))
        udp_port = udp_sock.getsockname()[1]
        self.conn.sendall(b"\x05\x00\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack(">H", udp_port))
        debug("UDP ASSOCIATE: 127.0.0.1:%d", udp_port)

        try:
            while True:
                # 检测 SOCKS 控制连接是否关闭 (客户端断开则退出 UDP 循环)
                try:
                    r, _, _ = select.select([self.conn], [], [], 0)
                    if r and self.conn.recv(1) == b"":
                        debug("UDP ASSOCIATE 控制连接已关闭")
                        break
                except Exception:
                    break
                udp_sock.settimeout(0.5)
                try:
                    data, client_addr = udp_sock.recvfrom(65535)
                except socket.timeout:
                    continue
                if len(data) < 4:
                    continue
                rsv, frag, uatyp = data[0], data[1], data[2]
                if rsv != 0 or frag != 0:
                    continue
                try:
                    if uatyp == 1:
                        dst_ip = socket.inet_ntoa(data[4:8])
                        dst_port = struct.unpack(">H", data[8:10])[0]
                        payload = data[10:]
                    elif uatyp == 3:
                        ln = data[4]
                        dst_ip = data[5:5 + ln].decode()
                        dst_port = struct.unpack(">H", data[5 + ln:7 + ln])[0]
                        payload = data[7 + ln:]
                    else:
                        continue
                    if not payload:
                        continue
                    threading.Thread(target=self._udp_send,
                                     args=(udp_sock, uatyp, dst_ip, dst_port, payload, client_addr),
                                     daemon=True).start()
                except Exception as e:
                    warning("UDP 数据报处理失败: %s: %s", type(e).__name__, str(e)[:60])
        finally:
            try:
                udp_sock.close()   # 控制连接关闭后回收 UDP socket, 不留 fd
            except Exception:
                pass

    _udp_throttle = {}  # { (dst_ip, dst_port): last_send_ts } 同目标节流, 防每包一隧道

    def _udp_send(self, udp_sock, uatyp, dst_ip, dst_port, payload, client_addr):
        """单个 UDP 数据报: 新隧道 (proto=2) 发送, 响应按请求 ATYP 形式封装回客户端"""
        # ── 节流: 同目标 300ms 内不重复建隧道 (DNS 查询密集场景防限流) ──
        throttle_key = (dst_ip, dst_port)
        now = time.time()
        last = self._udp_throttle.get(throttle_key, 0)
        if now - last < 0.3:
            return  # 300ms 内已发过, 丢弃重复包
        self._udp_throttle[throttle_key] = now
        # 定期清理过期条目 (每 50 条清一次)
        if len(self._udp_throttle) > 50:
            self._udp_throttle = {k: v for k, v in self._udp_throttle.items() if now - v < 5}
        node = self.server.current_node()
        if self.server.is_node_dead(node):
            return                     # 退避期间丢弃, 不做无谓隧道
        try:
            real_ip = tunnel_resolve(self.server, dst_ip)
        except Exception:
            return
        node = self.server.current_node()
        token_b64, rsa_pub = self.server.token_b64, self.server.rsa_pub
        try:
            debug("UDP 隧道: %s:%d 数据 %dB", real_ip, dst_port, len(payload))
            tun = Tunnel(node[1], node[2], token_b64, rsa_pub,
                         target=real_ip, tport=dst_port, first_data=payload, proto=2)
            tun.sock.settimeout(10)
            f = tun.recv_frame()
            if len(f) >= 3 and f[2] == 2:
                resp = f[3:]
                if resp:
                    # 回包 ATYP 与请求一致 (RFC 1928: 严格客户端按请求地址匹配)
                    if uatyp == 1:
                        pkt = (b"\x00\x00\x00\x01" + socket.inet_aton(real_ip)
                               + struct.pack(">H", dst_port) + resp)
                    else:
                        dom = dst_ip.encode("ascii")
                        pkt = (b"\x00\x00\x00\x03" + bytes([len(dom)]) + dom
                               + struct.pack(">H", dst_port) + resp)
                    udp_sock.sendto(pkt, client_addr)
                    debug("UDP 响应回传: %dB", len(resp))
            tun.close()
        except Exception as e:
            warning("UDP 隧道失败: %s %s", type(e).__name__, str(e)[:60])

    def _socks_loop(self):
        self.conn.settimeout(self.timeout)
        # 握手: [VER=5][NMETHODS][METHODS]
        ver, nm = self._recv_exact(2)
        if ver != 5:
            raise ConnectionError("非 SOCKS5")
        self._recv_exact(nm)
        self.conn.sendall(b"\x05\x00")  # 无认证

        # 请求: [VER][CMD][RSV][ATYP][DST.ADDR][DST.PORT]
        ver, cmd, rsv, atyp = self._recv_exact(4)

        if cmd == 3:  # UDP ASSOCIATE
            self._udp_associate(atyp)
            return
        if cmd != 1:  # 只支持 CONNECT / UDP ASSOCIATE
            self.conn.sendall(b"\x05\x07\x00\x01" + b"\x00" * 6)
            return
        if atyp == 1:
            dst_ip = socket.inet_ntoa(self._recv_exact(4))
        elif atyp == 3:
            ln = self._recv_exact(1)[0]
            dst_ip = self._recv_exact(ln).decode()
        elif atyp == 4:
            dst_ip = socket.inet_ntop(socket.AF_INET6, self._recv_exact(16))
        else:
            raise ConnectionError(f"ATYP {atyp}")
        dst_port = struct.unpack(">H", self._recv_exact(2))[0]

        # 当前节点故障退避中: 快速失败, 不浪费 DNS/首段数据等待 (客户端会重试)
        node = self.server.current_node()
        if self.server.is_node_dead(node):
            raise ConnectionError(f"节点 {node[0]} 故障退避中, 快速失败 (稍后自动恢复)")

        # 解析域名 -> IP: 优先走隧道 DNS (本地 DNS 被污染, google/youtube 会解析到假 IP)
        if _is_ip(dst_ip):                     # ATYP=1/4 已是 IP (含 IPv6 字面量)
            real_ip = dst_ip
        else:
            real_ip = tunnel_resolve(self.server, dst_ip)
        real_port = dst_port
        proto = 1
        debug("解析 %s -> %s:%d", dst_ip, real_ip, real_port)

        node = self.server.current_node()
        token_b64, rsa_pub = self.server.token_b64, self.server.rsa_pub
        if self.server.is_node_dead(node):
            raise ConnectionError(f"节点 {node[0]} 故障退避中, 快速失败")
        debug("SOCKS CONNECT %s:%d via %s:%d (%s)", dst_ip, dst_port, node[1], node[2], node[0])

        # 先发 SOCKS5 成功回复 (客户端收到后才开始发数据)
        self.conn.sendall(b"\x05\x00\x00\x01" + socket.inet_aton("0.0.0.0") + struct.pack(">H", 0))
        # 收集客户端首段数据 (l61 必须内嵌首段数据, 服务器才转发)
        # 数据到达后空闲 20ms 即继续 (不等满窗口), 无数据最长等 5s
        first_data = b""
        idle_limit = time.time() + 5.0
        got_data = False
        # 上限 FIRST_DATA_MAX: 连续上行(上传)超限即建隧道, 剩余经 k61 流式转发;
        # 否则会无限缓冲整个 body 且隧道迟迟不建立 (l61 只需要"有一点"首段数据)
        while time.time() < idle_limit and len(first_data) < FIRST_DATA_MAX:
            self.conn.settimeout(0.02 if got_data else 0.3)
            try:
                chunk = self.conn.recv(RECV_BUF)
                if not chunk:
                    break
                first_data += chunk
                got_data = True
                idle_limit = time.time() + 0.02   # 有数据则再等 20ms 攒剩余
            except socket.timeout:
                if got_data:
                    break   # 数据已收完 (20ms 无新数据)
                # 无数据, 继续等
        self.conn.settimeout(self.timeout)

        debug("first_data %dB", len(first_data))
        if not first_data:
            raise ConnectionError("客户端 5s 内未发送数据 (l61 需要首段数据)")
        try:
            tun = Tunnel(node[1], node[2], token_b64, rsa_pub,
                         target=real_ip, tport=real_port, first_data=first_data)
        except Exception as e:
            self.server.note_failure(node)   # 建隧道失败 -> 故障计数 (加速切换)
            raise
        try:

            # 双向转发: select 0.5s 轮询 stop (超时 continue, 不是退出 — 曾因 try/except 包在
            # while 外导致首个 0.5s 空闲即断连的回归); 慢端有 10~30s 宽限而非 0.5s 秒断
            stop = threading.Event()
            tun.sock.settimeout(10)   # 中继阶段: 帧间隙/发送停滞超时上限

            def to_tunnel():
                try:
                    while not stop.is_set():
                        r, _, _ = select.select([self.conn], [], [], 0.5)
                        if not r:
                            continue                    # 轮询, 不是退出
                        data = self.conn.recv(RECV_BUF)
                        if not data:
                            break
                        tun.send_data(data)   # k61: [2B 流ID][2][数据]
                except Exception as e:
                    _es = str(e)
                    if "10053" in _es or "10054" in _es:
                        debug("to_tunnel 退出: %s: %s", type(e).__name__, _es[:80])
                    else:
                        warning("to_tunnel 退出: %s: %s", type(e).__name__, _es[:80])
                finally:
                    stop.set()

            def from_tunnel():
                try:
                    while not stop.is_set():
                        r, _, _ = select.select([tun.sock], [], [], 0.5)
                        if not r:
                            continue                    # 轮询, 不是退出
                        frame = tun.recv_frame()
                        if len(frame) < 3:
                            continue
                        ftype = frame[2]
                        if ftype == 2:        # 数据帧
                            self.conn.sendall(frame[3:])   # conn 超时 30s, 慢客户端宽限
                        else:
                            debug("下行控制帧 type=%d len=%d: %s", ftype, len(frame), frame[:16].hex())
                except Exception as e:
                    _es = str(e)
                    if "10053" in _es or "10054" in _es:
                        debug("from_tunnel 退出: %s: %s", type(e).__name__, _es[:80])
                    else:
                        warning("from_tunnel 退出: %s: %s", type(e).__name__, _es[:80])
                finally:
                    stop.set()

            t1 = threading.Thread(target=to_tunnel, daemon=True)
            t2 = threading.Thread(target=from_tunnel, daemon=True)
            t1.start(); t2.start()
            t1.join(); t2.join()
        finally:
            tun.close()
            debug("隧道关闭 %s:%d", dst_ip, dst_port)

class SocksServer(threading.Thread):
    def __init__(self, bind_host, bind_port, node, token_b64, rsa_pub, all_nodes=None, on_renew=None):
        super().__init__(daemon=True)
        self.bind = (bind_host, bind_port)
        self.node = node
        self.node_lock = threading.Lock()
        self.token_b64 = token_b64
        self.rsa_pub = rsa_pub
        self.all_nodes = all_nodes or [node]   # 故障切换候选池
        self.fail_count = 0
        self.check_interval = 30               # 健康检查间隔(秒)
        self._reprobing = False                # 防并发重探测
        self._dead_node = None                 # 已确认故障的节点: 退避期间 SOCKS 快速失败
        self._retry_delay = 2.0                # 指数退避起始秒数 (成功切换后复位)
        self._consecutive_fail = 0             # 连续全失败轮数 (仅统计展示; 每次重连已自动换指纹)
        self._renew_cb = on_renew              # autoRegister 换证回调 (规避服务器风控)

    def current_node(self):
        with self.node_lock:
            return self.node

    def set_node(self, node):
        with self.node_lock:
            if node != self.node:
                self.node = node
                self._dead_node = None         # 新节点生效, 解除快速失败
                info("故障切换 -> 新节点: %s %s:%d", node[0], node[1], node[2])

    def is_node_dead(self, node):
        """退避期间当前节点标记不可用: 新连接直接快速失败, 不建必死隧道 (卡 3~10s)"""
        with self.node_lock:
            return node == self._dead_node

    def set_credentials(self, token_b64, rsa_pub, all_nodes):
        """autoRegister 换证后更新凭证与节点池 (服务器风控锁死旧凭证时解封)"""
        with self.node_lock:
            self.token_b64 = token_b64
            self.rsa_pub = rsa_pub
            if all_nodes:
                self.all_nodes = all_nodes
            self.fail_count = 0

    def note_failure(self, node):
        """连接失败 / 健康检查失败共用: 连续 2 次触发重新探测切换 (无需等满检查周期)"""
        cur = self.current_node()
        if node != cur:
            return                    # 旧节点的迟报失败, 已切换
        with self.node_lock:
            self.fail_count += 1
            if self.fail_count < 2:
                debug("节点 %s %s:%d 故障 (%d/2)", node[0], node[1], node[2], self.fail_count)
                return
            self.fail_count = 0
            if self._reprobing:
                return
            self._reprobing = True
        warning("节点 %s %s:%d 连续故障, 重新探测节点 ...", node[0], node[1], node[2])
        threading.Thread(target=self._failover, daemon=True).start()

    _FAILOVER_MAX_RETRIES = 6

    def _failover(self):
        """故障切换策略:
        1) 首轮刷新凭证 (仅一次, 不烧指纹)
        2) 先探同地区 8 个节点; 连续 2 轮失败 → 扩展全地区 12 个节点
        3) 探测间隔递增: 0s → 2s → 5s → 10s → 20s (避免短时间密集连接触发限流)
        4) 最多 _FAILOVER_MAX_RETRIES 轮, 放弃后等健康检查重新触发"""
        try:
            # ── 仅首轮刷新凭证 (避免每轮 autoRegister 烧指纹加剧限流) ──
            if self._renew_cb:
                try:
                    self._renew_cb()
                except Exception as e:
                    warning("指纹刷新失败, 沿用旧特征重试: %s %s", type(e).__name__, str(e)[:80])
            region = self.node[0]
            same_region_failures = 0
            _backoff = [0, 2, 5, 10, 15, 20]  # 轮间退避秒数
            for attempt in range(self._FAILOVER_MAX_RETRIES):
                with self.node_lock:
                    self._dead_node = self.node
                # ── 同地区连续2轮失败 → 扩展全地区 ──
                probe_same = same_region_failures < 2
                if probe_same:
                    pool = [n for n in self.all_nodes if n[0] == region]
                    sample = min(8, len(pool)) if pool else 0
                    label = "同地区"
                else:
                    pool = self.all_nodes
                    sample = min(12, len(pool)) if pool else 0
                    label = "全地区"
                if not pool:
                    warning("无候选节点, 跳过本轮")
                    break
                # ── 探测: 首批有结果即切 (quick) ──
                results = pick_best_node(pool, self.token_b64, self.rsa_pub,
                                         quick=True, sample_size=sample)
                if results:
                    best_lat = results[0][0]
                    if best_lat > 800 or len(results) < max(3, len(pool) // 10):
                        warning("切换质量不佳 (%s %d/%d 可达, 最优 %dms) — 服务器可能仍限流",
                            label, len(results), len(pool), best_lat)
                    with self.node_lock:
                        self._consecutive_fail = 0
                        self._retry_delay = 2.0
                    self.set_node(results[0][1])
                    return
                if probe_same:
                    same_region_failures += 1
                with self.node_lock:
                    self._consecutive_fail += 1
                # ── 退避 (首轮立即重试, 后续递增间隔) ──
                delay = _backoff[min(attempt, len(_backoff) - 1)]
                if attempt < self._FAILOVER_MAX_RETRIES - 1:
                    if delay == 0:
                        warning("无可切换节点 (%s探测失败), 立即重试 ...", label)
                    else:
                        warning("无可切换节点 (%s %d轮失败), %ds后重试",
                            label, same_region_failures if probe_same else attempt + 1, delay)
                        time.sleep(delay)
                else:
                    warning("无可切换节点 (%d轮全失败), 放弃本轮, 等健康检查重新触发",
                        self._FAILOVER_MAX_RETRIES)
        except Exception as e:
            error("故障切换异常: %s %s", type(e).__name__, str(e)[:80])
        finally:
            with self.node_lock:
                self._reprobing = False

    def _health_check(self):
        """后台健康检查 (30s±5s 周期, 随机抖动避免固定模式):
        仅检测节点可达性, 不因延迟触发轮换。连续 2 次不可达才触发故障切换 (同地区)。"""
        while True:
            time.sleep(self.check_interval + random.uniform(-5, 5))
            node = self.current_node()
            lat = verify_node(node, self.token_b64, self.rsa_pub)
            if lat is None:
                self.note_failure(node)
            else:
                with self.node_lock:
                    self.fail_count = 0

    def run(self):
        threading.Thread(target=self._health_check, daemon=True).start()
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(self.bind)
        srv.listen(128)
        info(f"SOCKS5 监听 {self.bind[0]}:{self.bind[1]} (节点 {self.node[0]} {self.node[1]}:{self.node[2]})")
        while True:
            conn, _ = srv.accept()
            SocksHandler(conn, self).start()

# ============ 节点探测 ============
_PROBE_TARGET = {"ip": None, "ts": 0.0}
_PROBE_LOCK = threading.Lock()
_PROBE_FALLBACK_IPS = ["1.1.1.1", "1.0.0.1"]  # Cloudflare 网关 IP, 80 端口有 HTTP 服务 (探测检查 HTTP 关键字可过)

def _probe_target_ip():
    """cp.cloudflare.com 探测目标 IP: 硬编码 fallback → 缓存 10min → 3s 超时线程。
    本地 DNS 被污染时 gethostbyname 返回错误 IP (如 google→Twitter), 用硬编码 IP 兜底。
    服务器按 IP 判定探测目标, 错误 IP = 探测全军覆没。"""
    now = time.time()
    with _PROBE_LOCK:
        if _PROBE_TARGET["ip"] and now - _PROBE_TARGET["ts"] < 600:
            return _PROBE_TARGET["ip"]
    # 优先尝试缓存的 DNS 结果
    res = {}
    def _resolve():
        try:
            res["ip"] = socket.gethostbyname("cp.cloudflare.com")
        except Exception:
            res["ip"] = None
    t = threading.Thread(target=_resolve, daemon=True)
    t.start(); t.join(3)
    ip = res.get("ip")
    if ip and t.is_alive():
        ip = None  # 3s 超时未返回, 不可信
    if ip:
        with _PROBE_LOCK:
            _PROBE_TARGET["ip"], _PROBE_TARGET["ts"] = ip, now
        return ip
    # 本地 DNS 失败/污染 → 用硬编码 Cloudflare IP (1.1.1.1/1.0.0.1 的 non-Anycast 变体)
    fallback = random.choice(_PROBE_FALLBACK_IPS)
    debug("cp.cloudflare.com DNS 解析失败, 使用 fallback IP %s", fallback)
    with _PROBE_LOCK:
        _PROBE_TARGET["ip"], _PROBE_TARGET["ts"] = fallback, now
    return fallback

def probe_node(node, token_b64="", secret="", timeout=4):
    """单节点验证: 建隧道 + cp.cloudflare.com 204 测速请求, 成功返回延迟 ms, 失败返回 None"""
    t0 = time.time()
    s = None
    try:
        s = socket.create_connection((node[1], node[2]), timeout=timeout)
        s.settimeout(timeout)
        key = os.urandom(32)
        token = base64.b64decode(token_b64)
        pem = ("-----BEGIN PUBLIC KEY-----\n" + secret + "\n-----END PUBLIC KEY-----\n")
        rsa_blob = PKCS1_v1_5.new(RSA.import_key(pem)).encrypt(key)
        inner = (b"\x01" + struct.pack(">H", len(token)) + token
                 + b"\x02" + struct.pack(">H", len(rsa_blob)) + rsa_blob)
        tgt = _probe_target_ip()
        if not tgt:
            raise ConnectionError("探测目标解析超时")
        req = b"GET /generate_204 HTTP/1.1\r\nHost: cp.cloudflare.com\r\nConnection: close\r\n\r\n"
        l61 = struct.pack(">H", 1) + b"\x01" + bytes([1, 1]) + socket.inet_aton(tgt) + struct.pack(">H", 80) + req
        iv2 = os.urandom(12)
        c2 = AES.new(key, AES.MODE_GCM, nonce=iv2, mac_len=16)
        l61_enc = iv2 + c2.encrypt(l61) + c2.digest()
        s.sendall(struct.pack(">I", len(inner) + len(l61_enc)) + inner + l61_enc)
        hdr = b""
        while len(hdr) < 4:
            chunk = s.recv(4 - len(hdr))
            if not chunk:
                raise ConnectionError("无响应")
            hdr += chunk
        flen = struct.unpack(">I", hdr)[0]
        body = b""
        while len(body) < flen:
            chunk = s.recv(flen - len(body))
            if not chunk:
                raise ConnectionError("连接关闭")
            body += chunk
        iv3, ct = body[:12], body[12:]
        c3 = AES.new(key, AES.MODE_GCM, nonce=iv3, mac_len=16)
        pt = c3.decrypt(ct[:-16])
        if b"204" in pt[3:40] or b"HTTP" in pt[3:40]:
            return (time.time() - t0) * 1000
        return None
    except Exception:
        return None
    finally:
        if s:
            try:
                s.close()
            except Exception:
                pass

def verify_node(node, token_b64="", secret="", timeout=8):
    """单节点健康检查: 返回延迟 ms (转发正常) 或 None (与探测共用 probe_node)"""
    return probe_node(node, token_b64, secret, timeout)

def pick_best_node(nodes, token_b64="", secret="", timeout=8, same_region=None,
                   quick=False, quiet=False, sample_size=0, fast=False, progress=None):
    """分批并发探测节点:
    - same_region: 同地区节点排最前优先探测, 切换尽量保持原地区
    - quick: 某批一旦有可达结果立即返回 (故障切换秒切, 不再等全批 26s+)
    - quiet: 不打排行日志 (后台例行轮换探测)
    - sample_size: 抽样探测数量 (0=全量, >0=从候选池随机抽样, 降低限流风险)
    - fast: 启动全力模式, 跳过批间延迟, 批大小 40 (首次选节点速度优先)
    只返回可达节点 [(latency_ms, node), ...] 延迟升序 — 未 ping 通的直接剔除不显示。"""
    if same_region:
        same = [n for n in nodes if n[0] == same_region]
        others = [n for n in nodes if n[0] != same_region]
        ordered = same + others
    else:
        ordered = list(nodes)
    # 抽样: 从候选池中随机选取, 同地区节点保证至少被选中
    if sample_size and sample_size < len(ordered):
        sampled = random.sample(ordered, sample_size)
        # 确保同地区节点至少有一个在抽样中
        if same_region:
            has_same = any(n[0] == same_region for n in sampled)
            if not has_same and same:
                # 替换抽样中第一个非同地区节点
                for i, n in enumerate(sampled):
                    if n[0] != same_region:
                        sampled[i] = random.choice(same)
                        break
        ordered = sampled
    results = []
    lock = threading.Lock()
    batch_size = 40 if fast else 20   # fast: 加倍并发, 减少批次数
    done_count = [0]
    total = len(ordered)

    def probe(n):
        lat = probe_node(n, token_b64, secret, timeout)
        if lat is not None:
            with lock:
                results.append((lat, n))
        if progress:
            with lock:
                done_count[0] += 1
            progress(done_count[0], total)

    for i in range(0, len(ordered), batch_size):
        batch = ordered[i:i + batch_size]
        threads = [threading.Thread(target=probe, args=(n,), daemon=True) for n in batch]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        if quick and results:
            _clear_progress()
            break                       # 首批有结果即返回, 切换不等人
        if not fast and i + batch_size < len(ordered):
            time.sleep(random.uniform(0.8, 2.0))   # 随机批间间隔, 降低服务器限流风险

    _clear_progress()
    results.sort()   # 按延迟升序
    # 按地区去重: 每个地区只保留延迟最低的节点 (显示用)
    region_best = {}
    for lat, n in results:
        region = n[0]
        if region not in region_best:
            region_best[region] = (lat, n)
    ranked = sorted(region_best.values(), key=lambda x: x[0])
    if not quiet:
        probed_count = min(sample_size, len(nodes)) if sample_size else len(nodes)
        info("节点延迟排行 (可达 %d/%d, 候选池 %d):", len(results), probed_count, len(nodes))
        for i, (lat, n) in enumerate(ranked):
            info("  #%-3d %-10s %s:%d  %6dms", i+1, n[0], n[1], n[2], lat)
    return ranked

# ============ 主流程 ============
def renew_credentials(server):
    """每次重连/故障切换时调用: 全新设备特征 autoRegister + 刷新节点池。
    服务器按设备指纹/凭证限流节点可达性 (实测旧指纹探测 0/55, 换新指纹后 26/54 恢复),
    每次重连换新身份让节点池恢复全量。失败则抛异常, 由调用方处理。"""
    info("重连: 换新设备指纹 autoRegister ...")
    uid, token_b64, secret = ensure_credentials()
    nodes = get_nodes(uid, token_b64)
    seen, uniq = set(), []
    for n in nodes:
        k = (n[1], n[2])
        if k not in seen:
            seen.add(k)
            uniq.append(n)
    server.set_credentials(token_b64, secret, uniq)
    info(f"指纹刷新成功 uid={uid[:16]}..., 节点 {len(uniq)} 个 (去重后)")

_PROGRESS_W = 0  # 进度条最长行宽, 用于后续清行

def _probe_progress(done, total):
    global _PROGRESS_W
    pct = done * 100 // total if total else 0
    w = 28
    filled = w * done // total if total else 0
    bar = "█" * filled + "░" * (w - filled)
    raw = "  探测节点 [%s] %3d%% (%d/%d)" % (bar, pct, done, total)
    if COLOR_TTY:
        line = "\033[36m" + raw + "\033[0m"
    else:
        line = raw
    _PROGRESS_W = max(_PROGRESS_W, len(raw))
    sys.stdout.write("\r" + line.ljust(_PROGRESS_W + 2))
    sys.stdout.flush()
    if done >= total:
        _clear_progress()

def _clear_progress():
    global _PROGRESS_W
    if _PROGRESS_W:
        sys.stdout.write("\r" + " " * (_PROGRESS_W + 2) + "\r")
        sys.stdout.flush()
        _PROGRESS_W = 0

def main():
    port = 10808
    host = "127.0.0.1"
    args = sys.argv[1:]
    i = 0
    while i < len(args):
        if args[i] == "--port": port = int(args[i+1]); i += 2
        elif args[i] == "--host": host = args[i+1]; i += 2
        else: i += 1

    info("=== LVCHA Bridge ===")
    uid, token_b64, secret = ensure_credentials()
    if not secret:
        raise RuntimeError("未获取到 RSA 公钥 (secret), 无法建立隧道")

    nodes = get_nodes(uid, token_b64)
    # 去重 (同 host:port)
    seen, uniq = set(), []
    for n in nodes:
        k = (n[1], n[2])
        if k not in seen:
            seen.add(k)
            uniq.append(n)
    info(f"节点 {len(uniq)} 个 (去重后)")

    info("正在探测节点延迟...")
    results = pick_best_node(uniq, token_b64, secret, fast=True, progress=_probe_progress)
    if not results:
        raise RuntimeError("无可用节点 (隧道验证全部失败), 请稍后重试")

    # 手动选择节点 (输入编号, 回车默认 #1 最优; pythonw 后台模式无 stdin 自动用最优)
    node = results[0][1]
    try:
        info("请选择节点编号 (回车默认 #1 最优):")
        choice = input("> ").strip()
        if choice.isdigit():
            idx = int(choice)
            if 1 <= idx <= len(results):
                node = results[idx - 1][1]
                info("已选择 #%d: %s %s:%d", idx, node[0], node[1], node[2])
            else:
                warning("编号 %d 无效, 使用 #1 最优节点", idx)
        else:
            info("使用 #1 最优节点")
    except (EOFError, OSError):
        info("(无交互输入, 自动使用 #1 最优节点)")
    latency = next(lat for lat, n in results if n == node)
    info("使用节点: %s %s:%d 延迟 %dms", node[0], node[1], node[2], latency)

    server = SocksServer(host, port, node, token_b64, secret, all_nodes=uniq,
                         on_renew=lambda: renew_credentials(server))
    server.start()
    info(f"桥接运行中: SOCKS5 {host}:{port} (单节点模式)")
    while True:
        time.sleep(3600)

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""诊断: 通过运行中的 bridge (127.0.0.1:10808) 做受控 SOCKS5 测试
对比 TLS 443 / 明文 HTTP 80, 并打印本地 DNS 解析结果 (检查污染)"""
import socket
import ssl
import struct
import sys
import time

PROXY = ("127.0.0.1", 10808)


def socks_connect(dst_host, dst_port, timeout=15):
    s = socket.create_connection(PROXY, timeout=timeout)
    s.settimeout(timeout)
    s.sendall(b"\x05\x01\x00")
    r = s.recv(2)
    if r != b"\x05\x00":
        raise RuntimeError(f"代理握手失败: {r.hex()}")
    host = dst_host.encode()
    s.sendall(b"\x05\x01\x00\x03" + bytes([len(host)]) + host + struct.pack(">H", dst_port))
    r = s.recv(10)
    if r[1] != 0:
        raise RuntimeError(f"SOCKS 连接被拒: rep={r[1]}")
    return s


def test(name, fn):
    t0 = time.time()
    try:
        msg = fn()
        print(f"[OK  ] {name}  {time.time()-t0:.1f}s  {msg}")
        return True
    except Exception as e:
        print(f"[FAIL] {name}  {time.time()-t0:.1f}s  {type(e).__name__}: {e}")
        return False


# 0. 本地 DNS 解析结果 (污染检查)
for host in ("www.google.com", "www.youtube.com", "cp.cloudflare.com", "browser.events.data.msn.cn"):
    try:
        ips = [i[4][0] for i in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)][:3]
        print(f"本地解析 {host} -> {ips}")
    except Exception as e:
        print(f"本地解析 {host} 失败: {e}")
print()

def _http(host, port, path):
    s = socks_connect(host, port)
    s.sendall(f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
    resp = s.recv(512)
    s.close()
    return resp[:60].decode("utf-8", "replace")


def _tls(host, ip=None):
    if ip:
        s = socks_connect_ip(ip, 443)
    else:
        s = socks_connect(host, 443)
    ctx = ssl.create_default_context()
    tls = ctx.wrap_socket(s, server_hostname=host)
    ver = tls.version()
    cert = tls.getpeercert()
    cn = cert.get("subject", ())[0][0][1] if cert else "?"
    tls.close()
    return f"TLS{ver} CN={cn}"


def socks_connect_ip(ip, port, timeout=15):
    """ATYP=1 直连 IP (绕过桥接本地 DNS)"""
    s = socket.create_connection(PROXY, timeout=timeout)
    s.settimeout(timeout)
    s.sendall(b"\x05\x01\x00")
    r = s.recv(2)
    if r != b"\x05\x00":
        raise RuntimeError(f"代理握手失败: {r.hex()}")
    s.sendall(b"\x05\x01\x00\x01" + socket.inet_aton(ip) + struct.pack(">H", port))
    r = s.recv(10)
    if r[1] != 0:
        raise RuntimeError(f"SOCKS 连接被拒: rep={r[1]}")
    return s


def doh_google_ip():
    """多 DoH 源尝试获取 google 真实 IP (本地 UDP 53 被污染)"""
    import urllib.request
    import json
    for url in ("https://1.1.1.1/dns-query?name=www.google.com&type=A",
                "https://dns.alidns.com/resolve?name=www.google.com&type=A",
                "https://doh.pub/dns-query?name=www.google.com&type=A"):
        try:
            req = urllib.request.Request(url, headers={
                "User-Agent": "curl/8.0",
                "Accept": "application/dns-json"})
            with urllib.request.urlopen(req, timeout=8) as r:
                data = json.loads(r.read())
            for ans in data.get("Answer", []):
                if ans.get("type") == 1:
                    return ans["data"]
        except Exception:
            continue
    return "142.250.72.14"  # 已知 google 段, 兜底


real_ip = doh_google_ip()
print(f"DoH 解析 www.google.com -> {real_ip} (对比本地污染: 104.244.42.197)")
print()
test("HTTP  cp.cloudflare.com:80 (204)", lambda: _http("cp.cloudflare.com", 80, "/generate_204"))
test("HTTP  www.google.com:80", lambda: _http("www.google.com", 80, "/"))
test(f"TLS   www.google.com:443 按真实IP {real_ip}", lambda: _tls("www.google.com", real_ip))
test("TLS   www.google.com:443 按域名(桥接本地解析)", lambda: _tls("www.google.com"))
test("TLS   www.youtube.com:443 按域名", lambda: _tls("www.youtube.com"))

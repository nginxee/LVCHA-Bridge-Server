#!/usr/bin/env python3
"""临时测试: 通过 SOCKS5 桥接高速下载, 测速并验证连接稳定性"""
import socket
import struct
import time
import sys

SOCKS_HOST = "127.0.0.1"
SOCKS_PORT = 10808
TEST_URLS = [
    ("speed.cloudflare.com", "/__down?bytes=100000000", 443, "100MB"),
    ("speed.cloudflare.com", "/__down?bytes=10000000", 443, "10MB"),
    ("proof.ovh.net", "/files/100Mb.dat", 80, "100MB"),
]

def socks5_connect(host, port):
    s = socket.create_connection((SOCKS_HOST, SOCKS_PORT), timeout=15)
    s.sendall(b"\x05\x01\x00")
    resp = s.recv(2)
    if resp[1] != 0:
        raise ConnectionError(f"SOCKS5 认证失败: {resp.hex()}")
    dom = host.encode()
    s.sendall(b"\x05\x01\x00\x03" + bytes([len(dom)]) + dom + struct.pack(">H", port))
    resp = s.recv(10)
    if resp[1] != 0:
        raise ConnectionError(f"SOCKS5 CONNECT 失败: code={resp[1]}")
    return s

def http_get(s, path):
    req = f"GET {path} HTTP/1.1\r\nHost: {s.getpeername()[0]}\r\nConnection: close\r\n\r\n"
    s.sendall(req.encode())
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = s.recv(4096)
        if not chunk:
            raise ConnectionError("连接断开")
        buf += chunk
    header, body = buf.split(b"\r\n\r\n", 1)
    status = header.split(b"\r\n")[0].decode()
    if b"200" not in header.split(b"\r\n")[0]:
        raise ConnectionError(f"HTTP {status}")
    return body, s

def speed_test(host, path, port, label):
    print(f"\n{'='*50}")
    print(f"测试: {label} ({host}{path})")
    print(f"{'='*50}")
    try:
        s = socks5_connect(host, port)
        t0 = time.time()
        data, s = http_get(s, path)
        downloaded = len(data)
        # 继续读取剩余数据
        while True:
            try:
                chunk = s.recv(65536)
                if not chunk:
                    break
                data += chunk
                downloaded += len(chunk)
            except socket.timeout:
                break
        elapsed = time.time() - t0
        s.close()
        speed = downloaded / elapsed / 1024 / 1024
        print(f"下载完成: {downloaded/1024/1024:.1f}MB, 耗时 {elapsed:.1f}s, 速度 {speed:.1f} MB/s")
        return speed
    except Exception as e:
        print(f"测试失败: {e}")
        return 0

if __name__ == "__main__":
    print(f"SOCKS5 桥接高速下载测试 ({SOCKS_HOST}:{SOCKS_PORT})")
    print("注意: 首次连接需建立隧道, 速度可能偏低")
    results = []
    for host, path, port, label in TEST_URLS:
        try:
            speed = speed_test(host, path, port, label)
            if speed > 0:
                results.append((label, speed))
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"跳过: {e}")
    if results:
        print(f"\n{'='*50}")
        print("结果汇总:")
        for label, speed in results:
            print(f"  {label}: {speed:.1f} MB/s")
        best = max(results, key=lambda x: x[1])
        print(f"\n最高速度: {best[0]} {best[1]:.1f} MB/s")

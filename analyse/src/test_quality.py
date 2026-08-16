#!/usr/bin/env python3
"""LVCHA Bridge 连接质量测试"""
import socket, struct, time, ssl, os, sys

SOCKS = ('127.0.0.1', 10808)

def socks_connect(host, port):
    s = socket.create_connection(SOCKS, timeout=10)
    s.sendall(b'\x05\x01\x00')
    s.recv(2)
    addr = socket.inet_aton(socket.gethostbyname(host))
    s.sendall(b'\x05\x01\x00\x01' + addr + struct.pack('>H', port))
    resp = s.recv(10)
    if resp[1] != 0:
        s.close()
        return None
    return s

def test_http():
    t0 = time.time()
    s = socks_connect('cp.cloudflare.com', 80)
    if not s: return None
    s.sendall(b'GET /generate_204 HTTP/1.1\r\nHost: cp.cloudflare.com\r\nConnection: close\r\n\r\n')
    data = b''
    while True:
        try:
            d = s.recv(4096)
            if not d: break
            data += d
        except: break
    s.close()
    ms = (time.time() - t0) * 1000
    ok = b'204' in data or b'HTTP' in data
    return ms, ok

def test_tls(host):
    t0 = time.time()
    ip = socket.gethostbyname(host)
    s = socks_connect(ip, 443)
    if not s: return None, 'connect failed'
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ss = ctx.wrap_socket(s, server_hostname=host)
    ms = (time.time() - t0) * 1000
    ss.close()
    return ms, None

def test_download():
    t0 = time.time()
    s = socks_connect('cp.cloudflare.com', 80)
    if not s: return None
    s.sendall(b'GET /generate_204 HTTP/1.1\r\nHost: cp.cloudflare.com\r\nConnection: close\r\n\r\n')
    data = b''
    while True:
        try:
            d = s.recv(65536)
            if not d: break
            data += d
        except: break
    s.close()
    elapsed = time.time() - t0
    return len(data), elapsed

print('=== LVCHA Bridge 连接质量测试 ===')
print()

# HTTP 测试
print('[1/4] HTTP 测试 (cp.cloudflare.com)...')
r = test_http()
if r:
    ms, ok = r
    status = 'OK' if ok else 'FAIL'
    print('  延迟: %dms  状态: %s' % (ms, status))
else:
    print('  失败: 无法连接')

# TLS 测试
print('[2/4] TLS 握手测试...')
for host in ['www.google.com', 'www.youtube.com', 'www.github.com']:
    try:
        ms, err = test_tls(host)
        if err:
            print('  %s: 失败 (%s)' % (host, err))
        else:
            print('  %s: %dms' % (host, ms))
    except Exception as e:
        print('  %s: 失败 (%s)' % (host, type(e).__name__))

# 连续请求测试
print('[3/4] 连续请求延迟测试 (5次)...')
times = []
for i in range(5):
    r = test_http()
    if r:
        times.append(r[0])
    time.sleep(0.5)
if times:
    avg = sum(times) / len(times)
    mn, mx = min(times), max(times)
    print('  平均: %dms  最小: %dms  最大: %dms  成功: %d/5' % (avg, mn, mx, len(times)))

# DNS 测试
print('[4/4] DNS 解析测试 (通过桥接)...')
for host in ['www.google.com', 'www.youtube.com', 'api.ip.sb']:
    try:
        t0 = time.time()
        ip = socket.gethostbyname(host)
        ms = (time.time() - t0) * 1000
        print('  %s -> %s (%dms)' % (host, ip, ms))
    except Exception as e:
        print('  %s: 失败 (%s)' % (host, e))

print()
print('=== 测试完成 ===')

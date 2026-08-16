#!/usr/bin/env python3
"""从 bridge.log 提取 ServerHello 帧并解析 TLS 记录结构"""
import re
import struct

log = open(r"C:\Users\admin.PC-20241201YZZW\Desktop\逆向\绿茶vpn\captures\logs\bridge.log",
           encoding="utf-8", errors="ignore").read()
BS = chr(92) + "x"  # 字面 "\x"

for line in log.splitlines():
    if "下行帧" in line and "2051B" in line:
        m = re.search(r"b'((?:\\x[0-9a-f]{2}|[^'])*)'", line)
        if m:
            s = m.group(1)
            data = bytearray()
            j = 0
            while j < len(s):
                if s[j:j + 2] == BS:
                    data.append(int(s[j + 2:j + 4], 16))
                    j += 4
                else:
                    data.append(ord(s[j]))
                    j += 1
            data = bytes(data)
            print(f"ServerHello 帧数据: {len(data)}B")
            pos = 0
            recs = []
            while pos + 5 <= len(data):
                typ = data[pos]
                ln = struct.unpack(">H", data[pos + 3:pos + 5])[0]
                recs.append((typ, ln, pos))
                pos += 5 + ln
            for typ, ln, p in recs:
                print(f"  记录@{p}: 类型={typ:#x} 长度={ln}")
            cert_idx = data.find(b"\x0b\x00\x00")
            print(f"证书 handshake(0x0b) 位置: {cert_idx if cert_idx >= 0 else '未找到!'}")
            print(f"前 80B: {data[:80].hex()}")
        break

#!/usr/bin/env python3
"""pcap (Ethernet) -> TCP 流重组 -> HTTP 事务提取"""
import struct
import sys
from collections import defaultdict

def parse(path):
    data = open(path, 'rb').read()
    magic = struct.unpack('<I', data[:4])[0]
    le = magic in (0xa1b2c3d4, 0xd4c3b2a1)
    flows = defaultdict(list)  # key=(src,sport,dst,dport) -> [(seq, flags, payload)]
    off = 24
    n = 0
    while off + 16 <= len(data):
        if le:
            ts_sec, ts_usec, cap, orig = struct.unpack('<IIII', data[off:off+16])
        else:
            ts_sec, ts_usec, cap, orig = struct.unpack('>IIII', data[off:off+16])
        pkt = data[off+16:off+16+cap]
        off += 16 + cap
        n += 1
        if len(pkt) < 16:
            continue
        eth_type = struct.unpack('>H', pkt[14:16])[0]
        if eth_type == 0x86DD:  # IPv6
            ip = pkt[16:]
            if len(ip) < 40 or ip[6] != 6:
                continue
            src = ip[8:24].hex(); dst = ip[24:40].hex()
            tcp_off = 16 + 40
        elif eth_type == 0x0800:  # IPv4
            ip = pkt[16:]
            if len(ip) < 20 or ip[9] != 6:
                continue
            ihl = (ip[0] & 0xF) * 4
            src = ip[12:16].hex(); dst = ip[16:20].hex()
            tcp_off = 16 + ihl
        else:
            continue
        tcp = pkt[tcp_off:]
        if len(tcp) < 20:
            continue
        sport, dport = struct.unpack('>HH', tcp[0:4])
        seq = struct.unpack('>I', tcp[4:8])[0]
        flags = tcp[13]
        doff = (tcp[12] >> 4) * 4
        payload = tcp[doff:]
        key = (src, sport, dst, dport)
        flows[key].append((seq, flags, payload))
    return flows, n

def reassemble(flows):
    streams = []
    for key, pkts in flows.items():
        pkts.sort(key=lambda p: p[0])
        # 处理乱序/重传: 按 seq 顺序拼接
        buf = bytearray()
        last_seq = None
        for seq, flags, payload in pkts:
            if not payload:
                continue
            if last_seq is None:
                buf += payload
                last_seq = seq + len(payload)
            else:
                end = seq + len(payload)
                if end <= last_seq:
                    continue  # 重传
                if seq < last_seq:
                    payload = payload[last_seq - seq:]
                buf += payload
                last_seq += len(payload)
        streams.append((key, bytes(buf)))
    return streams

def split_http(data):
    """从字节流中切出 HTTP 请求/响应对"""
    msgs = []
    rest = data
    while rest:
        # 找头部结束
        idx = rest.find(b'\r\n\r\n')
        if idx < 0:
            # 可能是分片尾部
            if rest.strip():
                msgs.append(('PARTIAL', rest))
            break
        head = rest[:idx]
        try:
            head_text = head.decode('utf-8', 'replace')
        except Exception:
            head_text = repr(head)
        lines = head_text.split('\r\n')
        first = lines[0]
        is_req = first.startswith(('GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD '))
        cl = 0
        for ln in lines[1:]:
            if ln.lower().startswith('content-length:'):
                try:
                    cl = int(ln.split(':', 1)[1].strip())
                except ValueError:
                    cl = 0
        body = rest[idx+4:idx+4+cl]
        if len(body) < cl:
            msgs.append(('PARTIAL', head + b'\r\n\r\n' + body))
            break
        msgs.append(('REQ' if is_req else 'RESP', head + b'\r\n\r\n' + body))
        rest = rest[idx+4+cl:]
    return msgs

if __name__ == '__main__':
    flows, n = parse(sys.argv[1] if len(sys.argv) > 1 else 'cap.pcap')
    print(f"包数 {n}, 流数 {len(flows)}")
    for key, data in reassemble(flows):
        src, sport, dst, dport = key
        if not data:
            continue
        print(f"\n===== 流 {src}:{sport} -> {dst}:{dport} ({len(data)}B) =====")
        for kind, msg in split_http(data):
            head_end = msg.find(b'\r\n\r\n')
            head = msg[:head_end][:400].decode('utf-8', 'replace') if head_end > 0 else msg[:200]
            body = msg[head_end+4:] if head_end > 0 else b''
            print(f"--- {kind} ---")
            print(head)
            if body:
                # gzip 尝试解压
                if body[:2] == b'\x1f\x8b':
                    import gzip
                    try:
                        body = gzip.decompress(body)
                    except Exception:
                        pass
                print(f"BODY({len(body)}B): {body[:800].decode('utf-8','replace')}")

#!/usr/bin/env python3
"""分析 LVCHA 抓包: TCP握手/延迟/重传/连接生命周期"""
import struct, sys, os
from collections import defaultdict

def read_pcap(path):
    pkts = []
    with open(path, 'rb') as f:
        hdr = f.read(24)
        if len(hdr) < 24:
            return pkts
        while True:
            phdr = f.read(16)
            if len(phdr) < 16:
                break
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack('<IIII', phdr)
            data = f.read(incl_len)
            if len(data) < incl_len:
                break
            ts = ts_sec + ts_usec / 1e6
            pkts.append((ts, data, orig_len))
    return pkts

def parse_ip(pkt):
    if len(pkt) < 14:
        return None
    eth_type = struct.unpack('>H', pkt[12:14])[0]
    vlan_off = 0
    if eth_type == 0x8100:
        eth_type = struct.unpack('>H', pkt[16:18])[0]
        vlan_off = 4
    if eth_type != 0x0800:
        return None
    ip = pkt[14 + vlan_off:]
    if len(ip) < 20:
        return None
    ihl = (ip[0] & 0x0F) * 4
    proto = ip[9]
    src = '.'.join(str(b) for b in ip[12:16])
    dst = '.'.join(str(b) for b in ip[16:20])
    total_len = struct.unpack('>H', ip[2:4])[0]
    return {'proto': proto, 'src': src, 'dst': dst, 'hdr_len': ihl,
            'total_len': total_len, 'raw': ip}

def parse_tcp(ip_pkt):
    if ip_pkt is None or ip_pkt['proto'] != 6:
        return None
    tcp = ip_pkt['raw'][ip_pkt['hdr_len']:]
    if len(tcp) < 20:
        return None
    src_port, dst_port = struct.unpack('>HH', tcp[0:4])
    seq = struct.unpack('>I', tcp[4:8])[0]
    ack = struct.unpack('>I', tcp[8:12])[0]
    flags = tcp[13]
    win = struct.unpack('>H', tcp[14:16])[0]
    data = tcp[20:]
    return {'src_port': src_port, 'dst_port': dst_port, 'seq': seq, 'ack': ack,
            'flags': flags, 'win': win, 'data': data}

def parse_udp(ip_pkt):
    if ip_pkt is None or ip_pkt['proto'] != 17:
        return None
    udp = ip_pkt['raw'][ip_pkt['hdr_len']:]
    if len(udp) < 8:
        return None
    src_port, dst_port, ulen = struct.unpack('>HHH', udp[0:6])
    return {'src_port': src_port, 'dst_port': dst_port, 'data': udp[8:]}

def flags_str(f):
    names = []
    if f & 0x02: names.append('SYN')
    if f & 0x10: names.append('ACK')
    if f & 0x01: names.append('FIN')
    if f & 0x04: names.append('RST')
    if f & 0x08: names.append('PSH')
    return '|'.join(names) if names else f'0x{f:02x}'

def main():
    path = sys.argv[1] if len(sys.argv) > 1 else r'C:\Users\admin.PC-20241201YZZW\Desktop\myprogram\python\LVCHA_VPN_Bridge\analyse\capture.pcap'
    pkts = read_pcap(path)
    print(f'=== 抓包分析: {os.path.basename(path)} ===')
    print(f'总包数: {len(pkts)}')
    if not pkts:
        return

    t0 = pkts[0][0]
    dur = pkts[-1][0] - t0
    print(f'时长: {dur:.1f}s ({t0:.3f} ~ {pkts[-1][0]:.3f})')
    print()

    # 统计
    proto_count = defaultdict(int)
    ip_set = set()
    streams = defaultdict(list)
    udp_flows = defaultdict(int)
    syn_count = 0
    fin_count = 0
    rst_count = 0
    tcp_data_total = 0
    tcp_pkts_total = 0

    for ts, raw, orig in pkts:
        ip = parse_ip(raw)
        if ip is None:
            proto_count['non-IP'] += 1
            continue
        proto_count[f'proto={ip["proto"]}'] += 1
        ip_set.add(ip['src'])
        ip_set.add(ip['dst'])

        if ip['proto'] == 6:
            tcp = parse_tcp(ip)
            if tcp is None:
                continue
            key = (ip['src'], ip['dst'], tcp['src_port'], tcp['dst_port'])
            streams[key].append((ts, tcp, ip))
            if tcp['flags'] & 0x02 and not (tcp['flags'] & 0x10):
                syn_count += 1
            if tcp['flags'] & 0x01:
                fin_count += 1
            if tcp['flags'] & 0x04:
                rst_count += 1
            if tcp['data']:
                tcp_data_total += len(tcp['data'])
            tcp_pkts_total += 1
        elif ip['proto'] == 17:
            udp = parse_udp(ip)
            if udp:
                key = (ip['src'], ip['dst'], udp['src_port'], udp['dst_port'])
                udp_flows[key] += 1

    print(f'--- 总览 ---')
    print(f'IP 数: {len(ip_set)}  IPs: {", ".join(sorted(ip_set)[:20])}')
    print(f'协议分布: {dict(proto_count)}')
    print(f'TCP SYN={syn_count} FIN={fin_count} RST={rst_count}')
    print(f'TCP 流数: {len(streams)}, 总包: {tcp_pkts_total}, 数据: {tcp_data_total}B')
    print(f'UDP 流数: {len(udp_flows)}')
    print()

    # TCP 流详情 (按起始时间排序)
    print(f'--- TCP 流 (前50条) ---')
    sorted_streams = sorted(streams.items(), key=lambda x: x[1][0][0])
    for i, (key, segs) in enumerate(sorted_streams[:50]):
        src, dst, sport, dport = key
        t_start = segs[0][0] - t0
        t_end = segs[-1][0] - t0
        dur_s = t_end - t_start
        data_b = sum(len(t['data']) for _, t, _ in segs)
        flags_all = set()
        for _, t, _ in segs:
            for c in flags_str(t['flags']).split('|'):
                flags_all.add(c)
        print(f'  [{i+1:3d}] {t_start:7.2f}s ~ {t_end:7.2f}s  {src}:{sport} -> {dst}:{dport}  '
              f'dur={dur_s:.2f}s pkts={len(segs)} data={data_b}B flags={"|".join(sorted(flags_all))}')

    # UDP 流
    if udp_flows:
        print(f'\n--- UDP 流 (前20条) ---')
        for i, (key, count) in enumerate(sorted(udp_flows.items(), key=lambda x: -x[1])[:20]):
            src, dst, sport, dport = key
            print(f'  [{i+1:3d}] {src}:{sport} -> {dst}:{dport}  pkts={count}')

    print(f'\n=== 分析完成 ===')

if __name__ == '__main__':
    main()

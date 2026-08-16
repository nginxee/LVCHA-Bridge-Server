# AGENT.md — LVCHA VPN Bridge 项目指南

本文件供 AI 代理(Claude Code 等)在此项目工作时参考。包含协议关键事实、
已验证结论、代码约定与高频坑,修改代码前必读。

## 项目概述

逆向 `com.abjlvcha.main` "LVCHA VPN" v2.6.7 并实现的 PC 端桥接:
**SOCKS5 入站 → LVCHA 隧道 → 节点服务器**,可接入 Clash Verge。
隧道协议 100% 在 Java 层(DEX),native 库 `liblvchanative.so` 仅做 API 签名,
与隧道无关。

## 目录结构

```
├── AGENT.md              本文件
├── README.md             用户文档
├── REPORT.md             完整逆向报告 (协议规格细节)
├── clash-lvcha.yaml      Clash 配置 (三合一: Windows/Linux/Verge)
├── start_bridge.bat / stop_bridge.bat   Windows 启动/停止脚本 (GBK 编码!)
├── start_bridge.sh / stop_bridge.sh     Linux 启动/停止脚本 (UTF-8)
├── src/
│   ├── lvcha_bridge.py   桥接主程序
│   └── lvcha_protocol.py 签名/API 协议库
├── analyse/              逆向工程工具 (非运行时)
│   ├── capture_proxy.py, decode_strings.py, parse_tls.py
│   ├── pcap_parse.py, probe_api.py, test_download.py, test_socks.py
├── captures/logs/bridge.log   运行日志 (自动生成)
└── data/credentials/bridge_state.json  会话凭证 (uid/token/secret, 自动生成)
```

## 运行方式

```bash
python src/lvcha_bridge.py --port 10808     # 前台 (支持交互式选节点)
start_bridge.bat                             # Windows: 双击启动 (前台终端)
./start_bridge.sh                            # Linux (ARM64/x86_64): 前台运行, 首次自动建 .venv
./stop_bridge.sh                             # Linux: 停止
```

启动流程: 优先复用已有凭证 (refreshToken) → 失败则全新设备特征 autoRegister
→ 节点探测(延迟排行) → 手动/自动选节点 → SOCKS5 监听。

## 协议关键事实 (实测验证)

### 签名 (API 请求)
- `sign = base64( [0x02][12B IV][AES-GCM(key, 排序参数)] )`
- 密钥 = uid 字符串(UTF-8);uid 空 → fallback 硬编码密钥
  `7c54c25398aa16afd495622f310ce692471751061292ed9aa4f1ac160cc19fe5`
- 附加参数: `p14=<APK大小=5807186>&` + `p15=lvchanative.so;&`
- 排序 = 整串 "k=v&" 按 ASCII 不区分大小写
- 请求 body: `v=22&content=<sign>&token=<token>` (token 字段单独传!)
- 响应: `base64( [12B IV][AES-GCM 密文+16B tag] )` — **无 flag 字节**

### 隧道
- 会话包: `[4B 总长][0x01][2B][token blob][0x02 flag][2B][RSA密文(64B)]` + **l61 加密(无长度前缀)**
- token blob = 登录响应 token 字段 base64 解码(980B+,每次 refresh 变长)
- RSA: 512 位,PKCS1 v1.5 加密 32B 随机隧道密钥;公钥 = 登录响应 `secret`(base64 DER,需 PEM 包装)
- l61 目标头: `[2B 流ID][0x01][1B proto(1=TCP/2=UDP)][1B family][IP][2B port][首段数据]`
  - **首段数据必须内嵌在 l61 里**(空数据服务器不转发,会挂死)
- 数据帧(k61): 明文 `[2B 流ID][0x02][数据]` → `[4B len][12B IV][AES-GCM 密文+16B tag]`
- 下行帧: 同格式,类型 2=数据 / 3=控制(忽略)
- **同隧道只支持一个流**: 后续帧(第二个 l61/k61)服务器只回 `[流ID][3][01]` 不转发
- UDP(proto=2): 每数据报一个独立隧道(已验证 DNS 查询响应正常)

### API 服务器
- 端点: `/v3/autoRegister` `/v3/login` `/v3/refreshToken` `/v3/getNodeList` `/v3/check_update`
- 节点 JSON: `{"region","address":"/IP:port","type":4}` 默认端口 45777/39689/32508/26558 等
- 全走 http(明文),不加密传输

## ⚠️ 高频坑 (改代码必看)

1. **GCM tag 必须显式 `c.digest()`** — 曾经漏掉导致帧长错位、TLS 全失败。
   所有加密输出 = `iv + c.encrypt(data) + c.digest()`,帧长 = 12+len+16。
2. **SOCKS5 UDP 封装偏移**: `[0:2 RSV][2 FRAG][3 ATYP][4:8 IP][8:10 PORT][10: DATA]`,
   IP 从 index 4 开始(不是 3)。
3. **服务器限流极敏感**: 高频建隧道/API 请求会触发 IP 级限流
   (API 502 + 隧道无响应,手机 IP 正常)。测试务必低频、间隔数秒。
4. **设备指纹**: 频繁 autoRegister 会被标记;每次运行随机 device/p10/p12。
5. **first_data 收集**: 数据到达后空闲 50ms 即继续(不等固定窗口),上限 16KB
   (`FIRST_DATA_MAX`)——连续上行(上传)超限即建隧道,剩余走 k61 流式,
   避免无限缓冲整个 body;5s 无数据失败关闭。
6. **线程退出**: to_tunnel/from_tunnel 用 select 0.5s 轮询 stop(超时 `continue`
   不是退出——曾因 try/except 包在 while 外导致首个 0.5s 空闲即断连的回归),
   stop 后及时退出;中继阶段 socket 超时 10~30s 作慢端宽限而非秒断。
   UDP 循环用 select 检测控制连接断开。
7. **中文 bat 文件 GBK 编码** — 不要改成 UTF-8(乱码)。
8. **heredoc 陷阱**: 往 Python 源码注入字符串时,`\n`/`\x01` 会被 bash 转义,
   用 chr() 拼接或 Edit 工具,勿用裸 heredoc。
9. `pick_best_node` 多线程**分批并发**探测全部节点(每批 20、批间 1s,规避限流),
   返回可达节点列表 `[(latency_ms, node), ...]` 按延迟升序 — 未 ping 通的剔除不显示。
   超时 8s。探测逻辑统一在 `probe_node`,健康检查(`verify_node`)与之共用。
10. 运行时节点故障: SocksServer 后台健康检查(30s±5s 间隔)+ 建隧道失败即时计数,
     `note_failure` 连续 2 次触发重探测切换(仅同地区候选池,
     `_reprobing` 防并发重探测)。不因延迟触发轮换, 不主动轮换, 仅节点不可达才切换。
     `_failover` 抽样 8 节点(快), 首轮立即重试, 第二轮起指数退避,
     最多 5 轮后放弃, 等健康检查重新触发 — 防止同地区全不可达时无限循环刷屏。
11. **本地 DNS 被污染(实测)**: www.google.com → 104.244.42.197(Twitter)/69.171.235.22(Facebook)/185.45.5.35,
     youtube → 69.171.235.22,连 1.1.1.1/阿里 DoH 都返回假 IP。域名**必须走隧道 DNS**
     (`tunnel_resolve`: UDP 隧道向 8.8.8.8:53 查询,缓存 300s,失败回退本地),不能 getaddrinfo。
     否则 google/youtube 的 ClientHello 被转发到假 IP,假服务器回自己证书 → 浏览器校验失败 1s 断连
     (曾误判为隧道/限流问题,downstream.bin 里真 TLS 握手是百度的,证隧道本身正常)。
12. `_DNS_CACHE` 全局缓存域名解析(TTL 感知,收敛 [60,300]s,多 A 记录随机轮换),
     避免每个连接一次 UDP 隧道;LRU 淘汰上限 500 条,超限时清理过期 + 最老条目;
     隧道 DNS 失败**重试 1 次**才回退本地(本地 DNS 被污染,直接回退会拿到假 IP)。
13. 隧道 DNS 超时 3s, **并行查询** 8.8.8.8 + 1.1.1.1 (首个成功即返回, 总超时 3s 非 6s),
     同域名并发查询去重(`_DNS_PENDING`), 避免多个 SOCKS 线程同时对同一域名建多条 UDP 隧道;
     自适应负缓存: 重复失败域名缓存 30→300s 递增, 减少对不可达域名的重复探测。
14. `socket.gethostbyname()` 通过 `_local_resolve()` 线程封装, 2s 超时保护 (防止 DNS 无响应时无限阻塞)。
15. WinError 10053/10054 (浏览器主动关闭连接) / "退避中" (节点切换期间快速失败) /
    "timed out" (节点故障期间超时) / "未发送数据" (客户端连接后无动作) 均降级为 DEBUG 日志,
    避免大量无意义 ERROR 刷屏。
16. **接收缓冲区**: `RECV_BUF = 256KB`, 提升大文件/流媒体吞吐。
17. **日志懒求值**: debug/warning 用 `%s` 格式, DEBUG 级别关闭时零开销。
18. **select 轮询**: to_tunnel/from_tunnel 0.5s 间隔, 降低延迟敏感场景响应时间。

## 已知限制

- 同隧道单流:每连接一个 Tunnel(新 TCP + RSA 交换),开销大但简单
- UDP:每数据报独立隧道(性能有限,适合 DNS;高频 UDP 会慢;QUIC/HTTP3 无法工作,浏览器回退 TCP)
- DNS:域名走隧道向 8.8.8.8 解析(已修复本地污染问题),重试一次失败才回退本地 getaddrinfo
- IPv6:节点列表跳过;SOCKS ATYP=4 字面量直通,隧道 l61 支持 IPv6 family=2
- 服务器先发言类协议(IMAP/XMPP 等)不受支持:l61 必须内嵌客户端首段数据,客户端不先发言则 5s 后断开

## 开发约定

- 单文件 `src/lvcha_bridge.py`,保持简单直接
- 日志用 `debug/info/warning/error()`(同时 stdout + bridge.log,pythonw 下仅落盘)
- 凭证只存 `data/credentials/bridge_state.json`,不外传
- 修改协议相关代码后,先对照 REPORT.md 的规格再改
- 逆向工具在 `analyse/` 目录,非运行时依赖

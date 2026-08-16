# LVCHA VPN 逆向分析报告

**目标**: `base.apk` — `com.abjlvcha.main` "LVCHA VPN" v2.6.7 (versionCode 47)
**日期**: 2026-08-13
**方法**: apktool 解包 → jadx 反编译(3970 类)→ 逆向 `hl1` 字符串混淆器(1516 条解密)→ 协议层分析

> **2026-08-15 更新 (修复与优化, 桥接实战验证)**:
> 1. **修复连接生命周期回归 (严重)**: to_tunnel/from_tunnel 的 `try/except socket.timeout`
>    曾包在 while 循环外,首个 1s 空闲即线程退出并断连(下载/流媒体/慢响应全挂)。
>    改为 select 1s 轮询 + `continue`,慢端宽限 10~30s。实测下载连接存活 61s 未被切断。
> 2. **修复 first_data 无限缓冲**: 连续上行(上传)会无限滑延 50ms 窗口,整个 body 攒进
>    内存才建隧道。新增 `FIRST_DATA_MAX=16KB` 上限,超限即建隧道,剩余走 k61 流式。
> 3. **DNS 优化**: 缓存 TTL 感知(收敛 [60,300]s)、多 A 记录随机轮换、隧道解析失败
>    重试 1 次才回退本地(本地 DNS 被污染)。
> 4. **IPv6**: SOCKS ATYP=4 字面量直通隧道(l61 family=2),不再被误判为域名。
> 5. **故障切换加速**: 健康检查 120s→30s + 建隧道失败即时计数,连续 2 次触发重探测
>    (`_reprobing` 防并发);实测"故障切换 -> 新节点"链路真实触发。
> 6. **限流缓解**: 节点探测改分批并发(每批 20、批间 1s);API 失败记录 host + 0.3s 退避。
> 7. **其他**: UDP 回包 ATYP 与请求一致(RFC 1928 匹配)、UDP socket 退出即关、
>    下行帧上限 1MB→8MB、握手失败清理 fd、TCP 连接超时 15s→8s、日志 5MB 轮转、
>    listen backlog 32→128。
> 8. **实测 (2026-08-15)**: 63 节点探测 33 可达;HTTP 204/200、TLSv1.3 google/youtube
>    按域名通过;节点故障自动切换真实触发。注: 高强度验证会话(autoRegister + 全量探测
>    + 大下载)触发过服务器限流("隧道无响应"),属既有风险(见 AGENT.md 高频坑 #3)。

> **2026-08-14 更新 (桥接实战验证)**:
> 1. **域名必须走隧道解析**: 本地 DNS 被污染 (google→104.244.42.197/Twitter、youtube→69.171.235.22/Facebook,
>    连 1.1.1.1/阿里 DoH 都返回假 IP)。桥接实现 `tunnel_resolve`: UDP 隧道 (proto=2) 向 8.8.8.8:53 查询,
>    缓存 300s,失败回退本地。已实测 TLSv1.3 完整握手 google/youtube 通过。
> 2. **UDP proto=2 已验证可用**(此前结论"UDP 目标头无响应"有误): 每数据报独立隧道,DNS 查询响应正常。
> 3. **节点探测**: 多线程全并发探测全部节点,只保留 ping 通(隧道建会话 + cp.cloudflare.com 204 验证)的节点。

---

## 1. 总体架构

```
TUN 虚拟网卡 (VpnService, LchaService)
   │  v11: 自研 IP/TCP/UDP 头解析(纯 Java, 无 tun2socks 等开源栈)
   ▼
zm1/xm1: 连接状态机 + 每连接 wm1 会话
   │  j61: 会话首包(身份+密钥交换)
   │  i61: 控制包      l61: 目标地址头
   ▼
q71: 每服务器 SocketChannel 隧道
   │  sd1 加密引擎 (AES-GCM / 自研 ChaCha20)
   ▼
服务器 (host:45777)
```

**关键结论**: 隧道协议 100% 在 Java 层。native 库 `liblvchanative.so` **不参与隧道**,
只做三件事: API 请求签名 (`cs`)、内容加解密 (`gc/d/ga`)、防 Frida/防篡改 (`detectFridaPort`)。

## 2. 隧道协议规格(可直接重实现)

### 2.1 连接
- TCP 直连节点 `address:45777`(默认端口,JSON 里可配)

### 2.2 探测握手(qk0.d — 测速/验证用)
```
客户端 → 7 字节: [00 00 00 03][3 字节随机]
服务器 → 1 字节: 0x0C (12)
服务器 → 12 字节: 挑战响应(缓冲区,用途待确认)
```

### 2.3 会话建立(j61 首包,隧道第一条消息)
```
[4B 总长度]
[byte 1]            版本
[short][sessionId] 登录签发的会话 ID (vs1.U())
[byte 加密类型]     1=ChaCha20 / 2=AES-GCM (B()==1 → 3)
[short][RSA 密文]   RSA/ECB/PKCS1Padding 加密的 32 字节随机隧道密钥
                    公钥来自登录响应 (vs1.O(), X509EncodedKeySpec)
[l61 目标地址头]    后续紧跟首个目标连接
```

**真机抓包验证(2026-08-13, 节点 13.231.165.132:32508 日本)**:
- 实际会话包:`00 00 04 e2 | 01 | 03 d4 | <980B token blob> | 02 | 00 40 | <64B RSA 密文>` ✓ 结构完全吻合
- **sessionId = SharedPreferences `token` 字段的 base64 解码**(980B,已验证逐字节匹配!)
- RSA 密文 **64B = 512 位 RSA**(加密 32B 隧道密钥)
- 上行数据帧(客户端→服务器): `[12B IV][AES-GCM 密文+16B tag]`,**无长度前缀**(sd1.b/c 流式)
- 下行数据帧(服务器→客户端): `[4B 长度][12B IV][密文+tag]`,带长度(sd1.d z=true)

### 2.4 数据帧(sd1 引擎,每连接随机密钥,服务器 RSA 私钥解出)
- **AES-GCM 模式**: `[12B IV][GCM 密文]`(tag 128bit, IV 每帧前置)
- **ChaCha20 模式(自研 ty1)**: `[4B 明文长度][XOR 流]`
  - 32 字节密钥视作 4×8B long,轮转异或;余数逐字节 XOR 密钥字节

### 2.5 目标连接头(l61)
```
[byte 协议] 1=TCP / 2=UDP
[byte 地址族] 1=IPv4 / 2=IPv6
[IP 地址]
[端口]
```

### 2.6 控制包(i61)
```
[short flag][byte 3][byte 数据] → sd1 加密(长度前缀 + 载荷)
flag: 1=SYN 2=PSH 3=RST 等(状态机)
```

### 2.7 认证模型
- 登录 → sessionId + RSA 公钥(RSA 2048, 服务器私钥配对)
- 每次隧道会话独立生成 32B 随机密钥, RSA 加密交给服务器
- **无客户端证书,无 PIN 码**

## 3. 服务器与 API

### 3.1 API 端点(vq1, 全部走 HTTPS)
| 端点 | 用途 |
|---|---|
| `/v3/login` | 登录(账号密码) |
| `/v3/autoRegister` | 自动注册 |
| `/v3/refreshToken` | 刷新 token |
| `/v3/getNodeList` | **节点列表** |
| `/v3/check_update` | 版本检查 |
| `/v3/getOrderId`, `/v3/withdraw`, `/v3/lottery`... | 商业化(充值/提现/抽奖) |

### 3.2 API 服务器(候选列表, 从代码顺序)
1. `a384693bb964ed5c1eccbe39ee1000bc-1759550417.ap-southeast-1.elb.amazonaws.com`
2. `147bcf1410cd7a6a7878b93e13ac4f4a-414842270.ap-southeast-1.elb.amazonaws.com`
3. `131.143.242.140` / `103.255.208.97` / `103.255.208.250` / `103.255.209.5`(IP 直连兜底)
4. `www.lvcha.org`
5. S3 域名兜底: `https://bucket-clxeon.s3.ap-southeast-1.amazonaws.com/v4/domains_264`

### 3.3 请求签名算法(已完全逆向 + **线上验证通过**)
> 结论: **native 层只是"皮"**,签名本体在 Java `u3/Ru3` 类。可 100% 纯 Python 重实现(见 `lvcha_protocol.py`)。

**验证记录(2026-08-13, 真机抓包)**: 解密 App 真实请求 11 个全部成功
- autoRegister(登出态)→ **fallback 密钥** = .so 硬编码 32B
- refreshToken/getNodeList/getHotAPP(登录态)→ **uid 密钥**
- 抓包确认附加项实为: `p14=<APK大小>&` + `p15=lvchanative.so;&`(带 `&`,非完整路径)
- **响应格式**: `base64( [12B IV][AES-GCM 密文+tag] )`,**无 flag 字节**(与请求的 `[0x02][IV][ct]` 不同,解密函数为 sd1.c())
- 真实响应示例: `{"code":1,"body":{"ip":"...","node_list":[{...}]}}`,62 地区 / 96 节点

**签名值** = `Base64( [0x02][12B IV][AES-128/192/256-GCM(key, 明文)])`

**明文构造**:
1. 所有请求参数(跳过 null/空值)拼成 `k=v&` 每项
2. native 追加 2 项到末尾: `p14=<APK大小>&`(p14 = stat 的 st_size,本 APK = 5807186, 抗篡改因子)、`.so 完整路径`(dl_iterate_phdr 获取)
3. **ASCII 不区分大小写排序**(caseInsensitiveCompare = 小写化后 memcmp)
4. 拼接为 UTF-8 字节

**密钥**: `uid` 字符串的 UTF-8 字节(登录响应 `{"uid":...}` 下发,存 SharedPreferences,`vs1.V0(uid)`)。密钥长度必须是 16/24/32 字节(AES-128/192/256),否则 Java 端抛异常返回 null。**uid 为空时回退**到 .so 硬编码 32 字节密钥:
```
7c54c25398aa16afd495622f310ce692471751061292ed9aa4f1ac160cc19fe5
```

**native 层职责全貌**(IDA 反编译确认):
| 函数 | 行为 |
|---|---|
| `cs` | 组装 + 排序 + 拼接 → `Ru3.a()`取密钥 → `Ru3.b(明文,密钥)` AES-GCM 加密 → `Ru3.a(密文)` base64 → 返回 |
| `gc/d/ga` | 同款 Java 静态方法桥(加解密工具),`ga` 返回 .so 自身路径 |
| `JNI_OnLoad` | 校验 APK 签名证书 == 硬编码 X.509(cn=key, 2024-04-19),不符则 `byte_EAD00=0`,全部函数返回 null;同时收集 .so 路径、APK 大小 |
| 反调试 | `detectFridaPort`, anti-Frida(隧道层无关) |

**请求包装**(vq1.a): `{"content": <签名>, "token": <token>, "v": "22"}`;签名参数注入 uid/token/user。

### 3.4 节点 JSON 格式(cy0)
```json
{"region": "香港", "address": "node.hk.example:45777", "model": "?", "type": "?"}
```
默认端口 45777。`type`/`model` 语义未深入(可能与加密模式/计费档位相关)。

## 4. 混淆与保护
- 字符串:`hl1.a(b64, b64)` = base64 解码后 XOR(**已全部解出,1516 条**)
- 类名:R8 全混淆(defpackage.*)
- native:`detectFridaPort`(反 Frida)、签名校验(native 比对自己的签名)
- 无加固壳(未检测到脱壳需求),APK 直接可反编译

## 5. PC 移植方案

> **✅ 已完成: `lvcha_bridge.py` 桥接程序跑通(2026-08-13 实测)**
> - SOCKS5 入站 → LVCHA 隧道 → 节点服务器,Clash Verge 可直接挂
> - 实测: checkip 200(来源=节点IP)、百度 200、Google gstatic 204(翻墙成功)
> - 用法: `python lvcha_bridge.py --port 10808` → Clash 节点 `socks5://127.0.0.1:10808`
> - 关键实现细节(黑盒验证得出):
>   - **l61 目标头必须内嵌首段数据**(否则服务器不转发后续 k61 帧!)
>   - 数据帧(k61)明文 = `[2B 流ID][1B 类型=2][数据]`,加密帧 `[4B 长度][12B IV][密文+tag]`
>   - 类型: 1=l61(目标头) 2=数据 3=控制([流ID][3][1B 状态])
>   - RSA 公钥 = 登录/refreshToken 响应 `secret` 字段(base64 DER, 需 PEM 包装)
>   - 控制帧 `03 01`(流建立)/ `03 02`(数据确认)需忽略
>   - UDP 可用 (每数据报独立隧道, 已验证 DNS 解析; 高频 UDP 性能有限)

### 方案 A: 完整移植(推荐, 2-4 天)
1. **拿会话**: `autoRegister`/`login`(带 `lvcha_protocol.sign` 签名)→ 得 uid/token/RSA 公钥
2. **拿节点**: `/v3/getNodeList`(带签名 + token)
3. **重写隧道**: Python/Go 实现握手 + 帧格式(第 2 节规格已完整)
4. **网络出口**: Windows `wintun` 做 TUN;或先做 SOCKS5 代理版(见 B)

### 方案 B: 代理模式(最省力, 1-2 天)
- 隧道协议天然是"目标地址头 + 流式数据",直接用 HTTP CONNECT/SOCKS5 代理形式转发
- 不搞 TUN,流量手动指到本地代理端口
- **剩余唯一未知**: 签名算法的线上验证(uid 密钥 + p14 是否被服务器校验)+ 隧道首包字节流确认

### 方案 C: 模拟器
- 蓝叠/MuMu 跑原 APK,不移植(有反 Frida/模拟器检测风险)

## 6. 风险提示
- 商业服务条款:重实现客户端、绕过订阅计量可能违约;本报告仅限技术研究
- 服务器位于 AWS 新加坡;跨境网络服务请遵守当地法律
- 后续若需: IDA 分析 `cs()` 签名算法、黑盒抓包验证握手字节、或直接动手写 Go 客户端,均可继续

# LVCHA Bridge Server

基于 python 对 绿茶VPN安卓端 逆向分析制作的 VPN Bridge Server

## 快速开始 (Windows)

```
start_bridge.bat     # 启动
stop_bridge.bat      # Force-stop
```

命令行启动：

```
python src/lvcha_bridge.py --port 10808
```

## 快速开始 (Linux / ARM64)
Tip:若使用Android环境，推荐使用Termux

```
./start_bridge.sh    # 启动
./stop_bridge.sh     # Force-stop
```

以后台daemon启动：

```
nohup ./start_bridge.sh > /dev/null 2>&1 &
```

依赖：`python3` + `python3-venv`（Debian/Ubuntu：`sudo apt install python3 python3-venv`）

## 接入 Clash Verge

1. 先启动桥接（`start_bridge.bat` 或 `./start_bridge.sh`）
2. 打开 Clash Verge → 将 `clash-lvcha.yaml` 拖入到客户端 → 保存
3. 代理页切到 LVCHA 配置，开启系统代理


## 使用说明

**节点选择**：启动时自动探测所有节点延迟，按延迟排序列出可达节点

**日志级别**：INFO，DEBUG启动设置环境变量 `LVCHA_LOG_LEVEL=DEBUG`启动即可

**故障自动切换**：节点挂了会自动切到同地区最快节点

**凭证**：`data/credentials/bridge_state.json`

## 等待完善(Flag)

- QUIC/HTTP3 暂不支持
- 服务器先发言的协议（IMAP/XMPP 等）暂不支持
- 国内部分节点直连可能超时(服务器风控)
- 每条 SOCKS 连接走独立隧道，未做多路复用

## 目录结构

```
├── src/                        核心代码
│   ├── lvcha_bridge.py         桥接主程序
│   └── lvcha_protocol.py       签名协议
├── clash-lvcha.yaml            Clash 配置
├── start_bridge.bat / .sh      启动脚本
├── stop_bridge.bat / .sh       停止脚本
├── analyse/                    逆向工具
├── captures/logs/              运行日志
└── data/credentials/           账号凭证
```

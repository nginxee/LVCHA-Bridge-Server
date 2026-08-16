#!/usr/bin/env python3
"""明文 HTTP 抓包代理: 记录手机 App → LVCHA 服务器的所有请求/响应到 cap_log.txt
用法: python capture_proxy.py [port=8088]  (adb reverse tcp:8088 tcp:8088 后手机代理指 127.0.0.1:8088)"""
import http.server
import socketserver
import sys
import threading
import urllib.request
import time
from pathlib import Path

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8088
LOG = open(Path(__file__).resolve().parent.parent / "captures" / "logs" / "cap_proxy.log",
           "a", encoding="utf-8")   # 项目内路径, 不依赖本机绝对路径

def log(msg):
    line = f"[{time.strftime('%H:%M:%S')}] {msg}"
    print(line, flush=True)
    LOG.write(line + "\n")
    LOG.flush()

class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _handle(self, method):
        body = b""
        if self.headers.get("Content-Length"):
            try:
                body = self.rfile.read(int(self.headers["Content-Length"]))
            except Exception:
                pass
        log(f"--- {method} {self.path}")
        hdrs = {k: v for k, v in self.headers.items()}
        log(f"    headers: {hdrs}")
        if body:
            log(f"    body: {body.decode('utf-8', 'replace')[:4000]}")

        url = self.path if self.path.startswith("http") else f"http://{hdrs.get('Host', '')}{self.path}"
        fwd_headers = {k: v for k, v in hdrs.items()
                       if k.lower() not in ("host", "proxy-connection", "connection", "content-length")}
        try:
            req = urllib.request.Request(url, data=body or None, method=method, headers=fwd_headers)
            with urllib.request.urlopen(req, timeout=20) as r:
                resp = r.read()
                log(f"    RESP {r.status}: {resp.decode('utf-8', 'replace')[:2000]}")
                self.send_response(r.status)
                for k, v in r.getheaders():
                    if k.lower() not in ("transfer-encoding", "connection"):
                        self.send_header(k, v)
                self.send_header("Content-Length", str(len(resp)))
                self.end_headers()
                self.wfile.write(resp)
        except Exception as e:
            log(f"    FWD ERROR: {e}")
            try:
                self.send_response(502)
                self.send_header("Content-Length", "0")
                self.end_headers()
            except Exception:
                pass

    do_GET = lambda self: self._handle("GET")
    do_POST = lambda self: self._handle("POST")
    do_PUT = lambda self: self._handle("PUT")
    do_DELETE = lambda self: self._handle("DELETE")

    def log_message(self, fmt, *args):
        pass  # 静默

if __name__ == "__main__":
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    with socketserver.ThreadingTCPServer(("0.0.0.0", PORT), Handler) as srv:
        print(f"[capture proxy listening on 0.0.0.0:{PORT}]", flush=True)
        srv.serve_forever()

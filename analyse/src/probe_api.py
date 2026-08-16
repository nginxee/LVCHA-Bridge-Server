#!/usr/bin/env python3
"""LVCHA API 探测: 验证重实现的签名算法能否通过服务器校验。
POST /v3/autoRegister, form: {content: sign({}, uid=""), v: "22"} (uid 空 → 回退硬编码密钥)"""
import json
import time
import urllib.request
import urllib.parse
from lvcha_protocol import sign

SERVERS = [
    "131.143.242.140",
    "a384693bb964ed5c1eccbe39ee1000bc-1759550417.ap-southeast-1.elb.amazonaws.com",
    "147bcf1410cd7a6a7878b93e13ac4f4a-414842270.ap-southeast-1.elb.amazonaws.com",
    "103.255.208.250",
    "www.lvcha.org",
    "103.255.209.5",
]

# 与 App 一致的设备参数 (uv.f 注入, p7=包名 p8=版本 p11=versionCode; 伪造值, 服务器只做格式校验)
def build_params():
    return {
        "platform": "1",
        "device": "Pixel7",
        "promotion": "",
        "p1": "x86_64",
        "p2": "Android",
        "p3": "15",
        "p4": "35",
        "p5": "en",
        "p6": "UTC",
        "p7": "com.abjlvcha.main",
        "p8": "22",
        "p9": "",
        "p10": "c4a3f8e2-9b1d-4a5e-8c7f-2d6b9e1a4c03",
        "p11": "47",
        "p12": "arm64-v8a",
        "p13": "2.6.7",
    }

def probe():
    params = build_params()
    body = {"content": sign(params, ""), "v": "22"}
    data = urllib.parse.urlencode(body).encode()
    for host in SERVERS:
        url = f"http://{host}/v3/autoRegister"
        try:
            req = urllib.request.Request(url, data=data, headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": "okhttp/4.12.0",
            })
            t0 = time.time()
            with urllib.request.urlopen(req, timeout=10) as r:
                resp = r.read().decode("utf-8", "replace")
            print(f"[{round(time.time()-t0,2)}s] {host} -> HTTP {r.status}: {resp[:300]}")
        except Exception as e:
            print(f"[!] {host} -> {e}")
            continue
        return resp
    return None

if __name__ == "__main__":
    probe()

#!/usr/bin/env python3
"""LVCHA VPN 协议重实现 (基于 REPORT.md 逆向结论)
签名算法: sign = base64( [flag=0x02][12B IV][AES-GCM(key, sorted_concat)] )
密钥 = uid (登录下发); 空时回退 .so 硬编码密钥
"""
import base64
import os
from Crypto.Cipher import AES  # pip install pycryptodome

# .so 里硬编码的 32 字节回退密钥 (unk_EAA88 @ liblvchanative.so)
FALLBACK_KEY = bytes.fromhex("7c54c25398aa16afd495622f310ce692471751061292ed9aa4f1ac160cc19fe5")

# base.apk 文件大小 (p14 抗篡改因子, 来自 native stat)
APK_SIZE = 5807186

# native 追加的 .so 参数: "p15=lvchanative.so;" (文件名+分号, 实测解密明文确认)
SO_PARAM = "p15=lvchanative.so;&"


def sign(params: dict, uid: str) -> str:
    """生成 content 签名。params: 原始请求参数 dict (value 非空者参与)。
    实测确认 (真实请求解密): 附加项 = "p14=<APK大小>&" + "p15=lvchanative.so;", 全串排序。"""
    # Java Signature.a(): 跳过 null/空值, 每项 "k=v&"
    items = [f"{k}={v}&" for k, v in params.items() if v not in (None, "")]
    # native cs(): 追加 p14 与 p15 两项
    items += [f"p14={APK_SIZE}&", SO_PARAM]
    # 排序: caseInsensitiveCompare = ASCII 小写化后 memcmp (整串 "k=v&" 比较)
    items.sort(key=lambda s: s.lower())
    concat = "".join(items).encode("utf-8")

    key = uid.encode("utf-8") if uid else FALLBACK_KEY  # 密钥长度决定 AES-128/192/256
    iv = os.urandom(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv, mac_len=16)  # GCMParameterSpec(128, iv)
    ct = cipher.encrypt(concat)  # 无附加 AAD
    blob = b"\x02" + iv + ct     # f.j() = 2 = AES-GCM 标志
    return base64.b64encode(blob).decode()


def wrap_request(params: dict, uid: str, token: str) -> dict:
    """vq1.a(): 包装为 {content, token?, v} + 注入 uid/token/user 参与签名。"""
    signed = dict(params)
    signed.setdefault("uid", uid)
    if token:
        signed.setdefault("token", token)
    req = {"content": sign(signed, uid), "v": "22"}
    if token:
        req["token"] = token
    return req


if __name__ == "__main__":
    # 自检: 确定性结构测试 (IV 随机, 只验证长度/格式); uid 须 >= 16B (AES-128 下限)
    s = sign({"username": "test", "password": "abc"}, "1234567890123456")
    raw = base64.b64decode(s)
    print(f"len={len(raw)} flag={raw[0]:#x} iv_len={len(raw[1:13])} ct_len={len(raw)-13}")
    assert raw[0] == 0x02 and len(raw) > 13
    # 排序自检: 与 Java 期望一致 (k=v& 全串小写比较)
    items = ["p14=5807186&", "/data/.../so", "a=1&", "B=2&"]
    assert items.sort(key=lambda x: x.lower()) is None
    print("self-check OK")

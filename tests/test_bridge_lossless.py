"""验证 clash_dict_to_uri 是无损的：能从 URI 还原的字段，必须和原 dict 一致。"""

import pytest
from openray_bridge import clash_dict_to_uri
from openray.domain import parse_uri


# OpenRay 的 xray_uuid() 会把"短自定义 ID"转成 UUIDv5，
# 所以测试用合法 UUID 才能保证 username 原样保留。
VALID_UUID = "11111111-1111-4111-8111-111111111111"


CASES = [
    # ① vless：uuid 必须是合法 UUID
    (
        {"type": "vless", "server": "h.test", "port": 443, "uuid": VALID_UUID,
         "network": "ws", "ws-opts": {"path": "/ws", "headers": {"Host": "h.test"}},
         "tls": True, "servername": "front.test"},
        {"scheme": "vless", "server": "h.test", "port": 443, "username": VALID_UUID,
         "type": "ws", "path": "/ws", "host": "h.test", "security": "tls", "sni": "front.test"},
    ),
    # ② trojan
    (
        {"type": "trojan", "server": "h.test", "port": 443, "password": "pwd",
         "tls": True, "sni": "s.test", "alpn": ["h2", "http/1.1"]},
        {"scheme": "trojan", "server": "h.test", "port": 443, "username": "pwd",
         "security": "tls", "sni": "s.test", "alpn": "h2,http/1.1"},
    ),
    # ③ vmess：uuid 必须是合法 UUID
    (
        {"type": "vmess", "server": "h.test", "port": 443, "uuid": VALID_UUID,
         "alterId": 0, "cipher": "auto", "network": "ws",
         "ws-opts": {"path": "/v"}, "tls": True},
        {"scheme": "vmess", "server": "h.test", "port": 443, "username": VALID_UUID,
         "type": "ws", "path": "/v", "security": "tls"},
    ),
    # ④ ss
    (
        {"type": "ss", "server": "h.test", "port": 443, "cipher": "aes-256-gcm", "password": "pwd"},
        {"scheme": "ss", "server": "h.test", "port": 443, "username": "aes-256-gcm", "password": "pwd"},
    ),
    # ⑤ hysteria2
    (
        {"type": "hysteria2", "server": "h.test", "port": 443, "password": "pwd",
         "sni": "s.test", "obfs": "salamander", "obfs-password": "op"},
        {"scheme": "hysteria2", "server": "h.test", "port": 443, "username": "pwd",
         "sni": "s.test", "obfs": "salamander", "obfs-password": "op"},
    ),
    # ⑥ tuic：uuid 必须是合法 UUID
    (
        {"type": "tuic", "server": "h.test", "port": 443, "uuid": VALID_UUID, "password": "pwd",
         "sni": "s.test", "congestion-controller": "bbr"},
        {"scheme": "tuic", "server": "h.test", "port": 443, "username": VALID_UUID,
         "password": "pwd", "sni": "s.test", "congestion_control": "bbr"},
    ),
    # ⑦ wireguard
    (
        {"type": "wireguard", "server": "h.test", "port": 51820,
         "private-key": "a"*43, "public-key": "b"*43, "ip": "10.0.0.2/32"},
        {"scheme": "wireguard", "server": "h.test", "port": 51820},
    ),
    # ⑧ socks5：OpenRay 的 ALIASES 把 socks5 alias 成 socks
    (
        {"type": "socks5", "server": "h.test", "port": 1080, "username": "u", "password": "p"},
        {"scheme": "socks", "server": "h.test", "port": 1080, "username": "u", "password": "p"},
    ),
]


@pytest.mark.parametrize("clash_dict,expected", CASES)
def test_bridge_lossless(clash_dict, expected):
    uri = clash_dict_to_uri(clash_dict)
    assert uri is not None, f"转换失败: {clash_dict}"
    p = parse_uri(uri)
    assert p.scheme == expected["scheme"]
    assert p.server == expected["server"]
    assert p.port == expected["port"]
    if "username" in expected:
        assert p.username == expected["username"]
    if "password" in expected:
        assert p.password == expected["password"]
    for key in ("type", "path", "host", "security", "sni", "alpn", "obfs", "obfs-password", "congestion_control"):
        if key in expected:
            actual = p.get(key, "")
            assert actual == expected[key], f"{key}: {actual!r} != {expected[key]!r}"

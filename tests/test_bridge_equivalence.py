VALID_UUID = "11111111-1111-4111-8111-111111111111"

BASE_CASES = [
    {"type": "vless", "server": "h", "port": 443, "uuid": VALID_UUID},
    {"type": "trojan", "server": "h", "port": 443, "password": "p", "tls": True},
    {"type": "ss", "server": "h", "port": 443, "cipher": "aes-256-gcm", "password": "p"},
    {"type": "vmess", "server": "h", "port": 443, "uuid": VALID_UUID},
    {"type": "hysteria2", "server": "h", "port": 443, "password": "p"},
    {"type": "tuic", "server": "h", "port": 443, "uuid": VALID_UUID, "password": "p"},
    {"type": "socks5", "server": "h", "port": 1080, "username": "u", "password": "p"},
    {"type": "vless", "server": "h", "port": 443, "uuid": VALID_UUID,
     "tls": True, "servername": "s.test", "network": "ws",
     "ws-opts": {"path": "/ws", "headers": {"Host": "h.test"}}},
    {"type": "vless", "server": "h", "port": 443, "uuid": VALID_UUID,
     "reality-opts": {"public-key": "A"*43, "short-id": "08"}, "servername": "s.test"},
]


def test_extension_changes_identity():
    base = {"type": "vless", "server": "h", "port": 443, "uuid": VALID_UUID}
    ...


def test_extension_isolated():
    base = {"type": "vless", "server": "h", "port": 443, "uuid": VALID_UUID}
    ...

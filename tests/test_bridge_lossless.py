VALID_UUID = "11111111-1111-4111-8111-111111111111"

CASES = [
    # vless
    (
        {"type": "vless", "server": "h.test", "port": 443, "uuid": VALID_UUID,
         "network": "ws", "ws-opts": {"path": "/ws", "headers": {"Host": "h.test"}},
         "tls": True, "servername": "front.test"},
        {"scheme": "vless", "server": "h.test", "port": 443, "username": VALID_UUID,
         "type": "ws", "path": "/ws", "host": "h.test", "security": "tls", "sni": "front.test"},
    ),
    # trojan 不变
    ...
    # vmess
    (
        {"type": "vmess", "server": "h.test", "port": 443, "uuid": VALID_UUID,
         "alterId": 0, "cipher": "auto", "network": "ws",
         "ws-opts": {"path": "/v"}, "tls": True},
        {"scheme": "vmess", "server": "h.test", "port": 443, "username": VALID_UUID,
         "type": "ws", "path": "/v", "security": "tls"},
    ),
    # ss 不变
    # hysteria2 不变
    # tuic
    (
        {"type": "tuic", "server": "h.test", "port": 443, "uuid": VALID_UUID, "password": "pwd",
         "sni": "s.test", "congestion-controller": "bbr"},
        {"scheme": "tuic", "server": "h.test", "port": 443, "username": VALID_UUID,
         "password": "pwd", "sni": "s.test", "congestion_control": "bbr"},
    ),
    # wireguard 不变
    # socks5 - expected scheme 改成 "socks"
    (
        {"type": "socks5", "server": "h.test", "port": 1080, "username": "u", "password": "p"},
        {"scheme": "socks", "server": "h.test", "port": 1080, "username": "u", "password": "p"},
    ),
]

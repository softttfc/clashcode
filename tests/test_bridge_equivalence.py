"""验证 identity_for_clash_proxy == parse_uri(clash_dict_to_uri()).identity（无扩展字段时）。"""

from openray_bridge import (
    MIHOMO_EXTENSIONS, clash_dict_to_uri, identity_for_clash_proxy,
)
from openray.domain import parse_uri


# OpenRay 的 xray_uuid() 会规范化 UUID，测试必须用合法 UUID
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


def test_no_extension_identity_equals_openray():
    for proxy in BASE_CASES:
        assert not any(k in proxy for k in MIHOMO_EXTENSIONS), f"测试用例不应有扩展字段: {proxy}"
        bridge = identity_for_clash_proxy(proxy)
        direct = parse_uri(clash_dict_to_uri(proxy)).identity
        assert bridge == direct, f"identity 不一致: {proxy}\n  bridge={bridge}\n  direct={direct}"


def test_extension_changes_identity():
    base = {"type": "vless", "server": "h", "port": 443, "uuid": VALID_UUID}
    with_ipv4 = dict(base, **{"ip-version": "ipv4"})
    with_ipv6 = dict(base, **{"ip-version": "ipv6"})
    assert identity_for_clash_proxy(with_ipv4) != identity_for_clash_proxy(with_ipv6)
    assert identity_for_clash_proxy(base) != identity_for_clash_proxy(with_ipv4)


def test_extension_isolated():
    """不同扩展字段值产生不同 identity；相同值产生相同 identity。"""
    base = {"type": "vless", "server": "h", "port": 443, "uuid": VALID_UUID}
    a = dict(base, **{"routing-mark": 100})
    b = dict(base, **{"routing-mark": 200})
    a2 = dict(base, **{"routing-mark": 100})
    assert identity_for_clash_proxy(a) != identity_for_clash_proxy(b)
    assert identity_for_clash_proxy(a) == identity_for_clash_proxy(a2)

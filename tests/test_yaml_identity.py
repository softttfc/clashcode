"""对 Clash dict 做差分模糊测试：identity 相同 ⇒ 三客户端渲染相同。"""

import json
import random
from openray_bridge import clash_dict_to_uri, identity_for_clash_proxy
from openray.domain import parse_uri
from openray.render import clash_proxy, singbox_outbound, xray_outbound


RENDERERS = (clash_proxy, singbox_outbound, xray_outbound)


def test_clash_identity_implies_same_render():
    rng = random.Random(20261019)
    groups = {}
    for _ in range(3000):
        proxy = random_clash_proxy(rng)
        h = identity_for_clash_proxy(proxy)
        if h is None:
            continue
        groups.setdefault(h, []).append(proxy)

    merged = [g for g in groups.values() if len(g) > 1]
    assert len(merged) > 50, f"fuzz 没产生足够合并: {len(merged)}"

    failures = []
    for group in merged:
        uris = []
        for proxy in group:
            uri = clash_dict_to_uri(proxy)
            if uri:
                try:
                    uris.append(parse_uri(uri))
                except Exception:
                    pass
        if len(uris) < 2:
            continue
        for renderer in RENDERERS:
            outputs = set()
            for p in uris:
                try:
                    outputs.add(json.dumps(renderer(p), sort_keys=True, ensure_ascii=False))
                except Exception as e:
                    outputs.add(f"ERR: {type(e).__name__}: {e}")
            if len(outputs) != 1:
                failures.append({
                    "renderer": renderer.__name__,
                    "uris": [p.uri for p in uris],
                    "outputs": list(outputs),
                })

    assert not failures, f"identity 相同但渲染不同: {len(failures)} 组\n{json.dumps(failures[0], indent=2, ensure_ascii=False)}"


def random_clash_proxy(rng):
    grid = {
        "type": ["vless", "trojan", "vmess", "ss", "hysteria2", "tuic"],
        "network": [None, "tcp", "raw", "ws", "grpc"],
        "security": [None, "tls", "reality"],
        "sni": [None, "example.com"],
        "fp": [None, "chrome", "firefox"],
        "alpn": [None, "h2"],
        "flow": [None, "xtls-rprx-vision"],
        "reality-opts": [None, {"public-key": "A"*43, "short-id": "08"}],
        "ws-opts": [None, {"path": "/a"}, {"path": "/b", "headers": {"Host": "h.test"}}],
        "grpc-opts": [None, {"grpc-service-name": "svc"}],
        "skip-cert-verify": [None, True],
    }
    proxy = {"type": rng.choice(grid["type"]), "server": "example.com", "port": 443}
    t = proxy["type"]
    if t in ("vless", "vmess"):
        proxy["uuid"] = "11111111-1111-4111-8111-111111111111"
    if t in ("trojan", "ss", "hysteria2"):
        proxy["password"] = "secret"
    if t == "ss":
        proxy["cipher"] = "aes-256-gcm"
    if t == "tuic":
        proxy["uuid"] = "11111111-1111-4111-8111-111111111111"
        proxy["password"] = "secret"
    if t == "vmess":
        proxy["alterId"] = 0
        proxy["cipher"] = "auto"
    for key, values in grid.items():
        if key == "type":
            continue
        v = rng.choices(values, weights=[4] + [1] * (len(values) - 1))[0]
        if v is not None:
            proxy[key] = v
    return proxy

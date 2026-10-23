"""
openray_bridge.py — Clash dict ↔ OpenRay URI/identity 桥接层

设计：
  1. clash_dict_to_uri()：16 协议无损转换
  2. identity_for_clash_proxy()：OpenRay identity + mihomo 扩展哈希
  3. dedup_by_identity()：按 identity 分组 + pick_best
  4. clash_dict_to_proxy()：Clash dict → OpenRay Proxy（供协议检查 / mihomo 验证使用）

九层归一化、语义去重、16 协议解析 —— 全部由 OpenRay domain.py 提供。
本文件只负责"无损映射"和"扩展字段处理"。
"""

from __future__ import annotations

import base64
import hashlib
import json
from collections import OrderedDict
from urllib.parse import quote, urlencode

from openray.domain import ParseError, parse_uri


SCHEME_ALIASES = {
    "hy2": "hysteria2",
    "wg": "wireguard",
    "socks": "socks5",
    "socks5h": "socks5",
}

MIHOMO_EXTENSIONS = (
    "ip-version", "routing-mark", "dialer-proxy", "interface-name",
    "tfo", "mptcp", "smux", "udp-over-tcp", "udp-over-tcp-version",
)


def _b64(s: str) -> str:
    return base64.b64encode(s.encode("utf-8")).decode("utf-8")


def _b64url(s: str) -> str:
    return base64.urlsafe_b64encode(s.encode("utf-8")).decode("utf-8").rstrip("=")


def _q(s) -> str:
    return quote(str(s), safe="")


def _query(params: dict) -> str:
    if not params:
        return ""
    clean = {k: v for k, v in params.items() if v not in (None, "", [], {})}
    if not clean:
        return ""
    return "?" + urlencode(sorted(clean.items()), quote_via=quote)


def _extract_common_query(proxy: dict, ptype: str) -> dict:
    q = {}
    network = str(proxy.get("network", "tcp")).lower()
    if network not in ("", "tcp", "raw"):
        q["type"] = network

    if network == "ws":
        ws = proxy.get("ws-opts") or {}
        if ws.get("path"):
            q["path"] = ws["path"]
        headers = ws.get("headers") or {}
        host = headers.get("Host") or headers.get("host")
        if host:
            q["host"] = host
    elif network == "grpc":
        grpc = proxy.get("grpc-opts") or {}
        if grpc.get("grpc-service-name"):
            q["serviceName"] = grpc["grpc-service-name"]
    elif network == "h2":
        h2 = proxy.get("h2-opts") or {}
        if h2.get("path"):
            q["path"] = h2["path"]
        hosts = h2.get("host")
        if hosts:
            q["host"] = ",".join(hosts) if isinstance(hosts, list) else str(hosts)
    elif network == "http":
        http = proxy.get("http-opts") or {}
        if http.get("path"):
            path = http["path"]
            q["path"] = path[0] if isinstance(path, list) else str(path)
        headers = http.get("headers") or {}
        host = headers.get("Host") or headers.get("host")
        if host:
            q["host"] = host[0] if isinstance(host, list) else str(host)

    is_reality = bool(proxy.get("reality-opts"))
    tls = bool(proxy.get("tls")) or ptype in ("trojan", "hysteria", "hysteria2", "tuic", "juicity", "https")

    if is_reality:
        q["security"] = "reality"
        ro = proxy["reality-opts"]
        if ro.get("public-key"):
            q["pbk"] = ro["public-key"]
        if ro.get("short-id"):
            q["sid"] = str(ro["short-id"])
    elif tls:
        q["security"] = "tls"

    if tls or is_reality:
        sni = proxy.get("servername") or proxy.get("sni")
        if sni:
            q["sni"] = sni
        alpn = proxy.get("alpn")
        if alpn:
            q["alpn"] = ",".join(alpn) if isinstance(alpn, list) else str(alpn)
        fp = proxy.get("client-fingerprint")
        if fp:
            q["fp"] = fp
        if proxy.get("skip-cert-verify"):
            q["allowInsecure"] = "1"

    return q


def _to_vmess(proxy: dict) -> str:
    data = {
        "v": "2", "ps": proxy.get("name", ""),
        "add": proxy.get("server", ""), "port": str(proxy.get("port", 0)),
        "id": proxy.get("uuid", ""), "aid": str(proxy.get("alterId", 0)),
        "scy": proxy.get("cipher", "auto"),
        "net": proxy.get("network", "tcp"), "type": "none",
        "host": "", "path": "",
        "tls": "tls" if proxy.get("tls") else "",
        "sni": proxy.get("servername") or proxy.get("sni", ""),
        "alpn": ",".join(proxy["alpn"]) if isinstance(proxy.get("alpn"), list) else proxy.get("alpn", ""),
        "fp": proxy.get("client-fingerprint", ""),
    }
    network = str(proxy.get("network", "tcp")).lower()
    if network == "ws":
        ws = proxy.get("ws-opts") or {}
        data["path"] = ws.get("path", "/")
        headers = ws.get("headers") or {}
        data["host"] = headers.get("Host") or headers.get("host", "")
    elif network == "h2":
        h2 = proxy.get("h2-opts") or {}
        hosts = h2.get("host", [])
        data["host"] = ",".join(hosts) if isinstance(hosts, list) else str(hosts)
        data["path"] = h2.get("path", "/")
    elif network == "grpc":
        grpc = proxy.get("grpc-opts") or {}
        data["path"] = grpc.get("grpc-service-name", "")
    data = {k: v for k, v in data.items() if v not in ("", None)}
    return "vmess://" + _b64(json.dumps(data, ensure_ascii=False, separators=(",", ":")))


def _to_ss(proxy: dict) -> str | None:
    method = proxy.get("cipher", "")
    password = str(proxy.get("password", ""))
    if not method or not password:
        return None
    userinfo = _b64url(f"{method}:{password}")
    server, port = proxy["server"], int(proxy["port"])
    plugin_str = ""
    if proxy.get("plugin-opts"):
        opts = proxy["plugin-opts"]
        parts = [proxy.get("plugin", "obfs")]
        for k, v in opts.items():
            parts.append(f"{k}={v}" if v is not True else k)
        plugin_str = "?plugin=" + _q(";".join(parts))
    name = _q(proxy.get("name", ""))
    return f"ss://{userinfo}@{server}:{port}{plugin_str}" + (f"#{name}" if name else "")


def _to_ssr(proxy: dict) -> str | None:
    server, port = proxy["server"], int(proxy["port"])
    protocol = proxy.get("protocol", "origin")
    cipher = proxy.get("cipher", "")
    obfs = proxy.get("obfs", "plain")
    password = str(proxy.get("password", ""))
    if not all([cipher, password]):
        return None
    head = f"{server}:{port}:{protocol}:{cipher}:{obfs}:{_b64url(password)}"
    params = []
    if proxy.get("name"):
        params.append("remarks=" + _b64url(proxy["name"]))
    if proxy.get("protocol-param"):
        params.append("protoparam=" + _b64url(str(proxy["protocol-param"])))
    if proxy.get("obfs-param"):
        params.append("obfsparam=" + _b64url(str(proxy["obfs-param"])))
    full = head + ("/?" + "&".join(params) if params else "")
    return "ssr://" + _b64url(full)


def _to_generic(proxy: dict, ptype: str) -> str | None:
    server, port = proxy["server"], int(proxy["port"])

    # ---- userinfo：':' 是 URI 分隔符，必须保持不编码；username / password 各自 _q() ----
    if ptype in ("vless", "tuic", "juicity"):
        uuid_val = str(proxy.get("uuid", ""))
        if ptype in ("tuic", "juicity"):
            pwd = str(proxy.get("password", ""))
            userinfo = (_q(uuid_val) + ":" + _q(pwd)) if pwd else _q(uuid_val)
        else:
            userinfo = _q(uuid_val) if uuid_val else ""
    elif ptype in ("trojan", "hysteria2"):
        userinfo = _q(str(proxy.get("password", "")))
    else:  # hysteria v1：auth 走 query
        userinfo = ""

    if ptype in ("vless", "trojan", "hysteria2", "tuic", "juicity") and not userinfo:
        return None

    q = _extract_common_query(proxy, ptype)
    if ptype == "vless" and proxy.get("flow"):
        q["flow"] = proxy["flow"]
    if ptype == "hysteria":
        if proxy.get("auth-str"):
            q["auth"] = proxy["auth-str"]
        if proxy.get("up"):
            q["upmbps"] = str(proxy["up"])
        if proxy.get("down"):
            q["downmbps"] = str(proxy["down"])
        if proxy.get("protocol"):
            q["protocol"] = str(proxy["protocol"])
    if ptype == "hysteria2":
        if proxy.get("obfs"):
            q["obfs"] = proxy["obfs"]
            if proxy.get("obfs-password"):
                q["obfs-password"] = proxy["obfs-password"]
    if ptype == "tuic":
        if proxy.get("congestion-controller"):
            q["congestion_control"] = proxy["congestion-controller"]
        if proxy.get("udp-relay-mode"):
            q["udp_relay_mode"] = proxy["udp-relay-mode"]
    qs = _query(q)
    name = _q(proxy.get("name", ""))
    uri = f"{ptype}://{userinfo}@{server}:{port}{qs}"
    return uri + (f"#{name}" if name else "")


def _to_legacy(proxy: dict, ptype: str) -> str | None:
    server, port = proxy["server"], int(proxy["port"])
    if ptype == "socks5":
        scheme = "socks5"
    elif ptype == "https" or proxy.get("tls"):
        scheme = "https"
    else:
        scheme = "http"
    user = proxy.get("username", "")
    pwd = proxy.get("password", "")
    auth = ""
    if user:
        auth = _q(user) + (":" + _q(pwd) if pwd else "") + "@"
    name = _q(proxy.get("name", ""))
    uri = f"{scheme}://{auth}{server}:{port}"
    return uri + (f"#{name}" if name else "")


def _to_wireguard(proxy: dict) -> str | None:
    server, port = proxy["server"], int(proxy["port"])
    private = proxy.get("private-key") or proxy.get("privatekey", "")
    public = proxy.get("public-key") or proxy.get("publickey", "")
    if not private or not public:
        return None
    q = {"privatekey": private, "publickey": public}
    for k, uri_k in (
        ("preshared-key", "presharedkey"), ("presharedkey", "presharedkey"),
        ("ip", "address"), ("ipv6", "address"), ("reserved", "reserved"),
        ("mtu", "mtu"), ("workers", "workers"),
    ):
        if proxy.get(k):
            q[uri_k] = str(proxy[k])
    qs = _query(q)
    name = _q(proxy.get("name", ""))
    uri = f"wireguard://{server}:{port}{qs}"
    return uri + (f"#{name}" if name else "")


def clash_dict_to_uri(proxy: dict) -> str | None:
    """Clash proxy dict → URI（无损）。无法转换返回 None。"""
    if not isinstance(proxy, dict):
        return None
    ptype = str(proxy.get("type", "")).lower()
    ptype = SCHEME_ALIASES.get(ptype, ptype)
    if not proxy.get("server") or not proxy.get("port"):
        return None
    try:
        if ptype == "vmess":
            return _to_vmess(proxy)
        if ptype == "ss":
            return _to_ss(proxy)
        if ptype == "ssr":
            return _to_ssr(proxy)
        if ptype in ("vless", "trojan", "hysteria", "hysteria2", "tuic", "juicity"):
            return _to_generic(proxy, ptype)
        if ptype in ("socks5", "http", "https"):
            return _to_legacy(proxy, ptype)
        if ptype == "wireguard":
            return _to_wireguard(proxy)
    except (KeyError, ValueError, TypeError):
        return None
    return None


def identity_for_clash_proxy(proxy: dict) -> str | None:
    """Clash dict → identity（OpenRay identity + mihomo 扩展哈希）。"""
    uri = clash_dict_to_uri(proxy)
    if uri is None:
        return None
    try:
        parsed = parse_uri(uri)
    except (ParseError, UnicodeError):
        return None
    base_identity = parsed.identity
    extensions = {}
    for key in MIHOMO_EXTENSIONS:
        if proxy.get(key) not in (None, "", [], {}):
            extensions[key] = proxy[key]
    if not extensions:
        return base_identity
    ext_json = json.dumps(extensions, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(f"{base_identity}|{ext_json}".encode("utf-8")).hexdigest()


def clash_dict_to_proxy(proxy: dict):
    """Clash dict → OpenRay Proxy（薄封装 clash_dict_to_uri + parse_uri）。

    设计目的：
      - 供 dupconfig.py 的 --protocol-check 与 --verify-nodes 使用。
      - 返回 None 表示"无法转换为 Proxy"（不是协议不兼容），
        调用方应把 None 视为"无法检查"，保留节点 + 警告，而不是剔除。

    依赖：
      - openray.domain.parse_uri（已在文件顶部导入）
      - clash_dict_to_uri（本文件）
    """
    uri = clash_dict_to_uri(proxy)
    if uri is None:
        return None
    try:
        return parse_uri(uri)
    except (ParseError, UnicodeError):
        return None


def dedup_by_identity(proxies: list[dict], keep: str = "first") -> tuple[list[dict], dict]:
    """按 identity 分组 + pick_best。返回 (去重后列表, 统计)。"""
    groups = OrderedDict()
    invalid = 0
    for proxy in proxies:
        if not isinstance(proxy, dict):
            invalid += 1
            continue
        h = identity_for_clash_proxy(proxy)
        if h is None:
            invalid += 1
            continue
        groups.setdefault(h, []).append(proxy)

    def pick(candidates):
        if keep == "best":
            def score(p):
                name = str(p.get("name", ""))
                s = 0
                if any(0x1F1E6 <= ord(c) <= 0x1F1FF for c in name):
                    s += 10
                if 5 <= len(name) <= 30:
                    s += 5
                for w in ("订阅", "加入", "频道", "telegram", "@", "http"):
                    if w in name.lower():
                        s -= 20
                return s
            return max(candidates, key=score)
        return candidates[0]

    deduped = [pick(c) for c in groups.values()]
    stats = {
        "total": len(proxies),
        "unique": len(deduped),
        "duplicates": len(proxies) - len(deduped) - invalid,
        "invalid": invalid,
    }
    return deduped, stats

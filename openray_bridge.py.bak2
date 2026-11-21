"""
openray_bridge.py — Clash dict ↔ OpenRay URI/identity 桥接层

设计：
  1. clash_dict_to_uri()：16 协议无损转换
  2. identity_for_clash_proxy()：OpenRay identity + mihomo 扩展哈希
  3. dedup_by_identity()：按 identity 分组 + pick_best
  4. clash_dict_to_proxy()：Clash dict → OpenRay Proxy（供协议检查 / mihomo 验证使用）

九层归一化、语义去重、16 协议解析 —— 全部由 OpenRay domain.py 提供。
本文件只负责"无损映射"和"扩展字段处理"。

本轮去重缺陷修复（在上一版【本次修改 C1/C2】基础上增量增强，方案编号见下）：
  - B1：默认即 false 的布尔行为字段（tfo/mptcp/udp/udp-over-tcp/xudp 等），
        归一化为 False 时与"根本没写"等价，丢弃不进 identity。
  - C1：值类型书写归一（int/str 表示等价，如 udp-over-tcp-version 2 与 "2"）。
  - A1：canonical 别名折叠（multiplex↔smux、xudp↔packet-encoding），
        别名与规范名同现且值冲突时保守不折叠，避免误合并。
  三者只作用于 identity_for_clash_proxy 的 extensions 构建，对外签名不变。
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

# 原有 9 个 mihomo 扩展字段（保留为向后兼容别名，被 BEHAVIOR_FIELDS 引用）
MIHOMO_EXTENSIONS = (
    "ip-version", "routing-mark", "dialer-proxy", "interface-name",
    "tfo", "mptcp", "smux", "udp-over-tcp", "udp-over-tcp-version",
)

# ============================================================================
# 【本次修改 C1】BEHAVIOR_FIELDS：覆盖所有影响 mihomo 行为的顶层字段
# -----------------------------------------------------------------------------
# 原 MIHOMO_EXTENSIONS 只覆盖 9 个扩展字段，遗漏了以下既不在 URI 编码范围、
# 也不在 MIHOMO_EXTENSIONS 中的行为字段：
#   - udp              : mihomo 是否允许 UDP 转发
#   - packet-encoding  : 数据包编码方式（xudp / packetaddr / none）
#   - xudp             : packet-encoding 的旧字段名（mihomo 兼容旧写法）
#   - multiplex        : 旧的多路复用字段（等价 smux）
# 遗漏导致 P3：「identity 相同但行为不同」的误合并——例如 udp: true 和
# udp: false 的两个节点 identity 相同，但 mihomo 行为完全不同（UDP 转发
# 是否启用）。
#
# 本次将这些字段并入 BEHAVIOR_FIELDS，确保 identity 覆盖所有行为字段。
# MIHOMO_EXTENSIONS 保留为向后兼容别名（不改变其值，避免破坏已有测试）。
# ============================================================================
BEHAVIOR_FIELDS = MIHOMO_EXTENSIONS + (
    "udp",              # mihomo: 是否允许 UDP 转发
    "packet-encoding",  # mihomo: xudp / packetaddr / none
    "xudp",             # 旧字段名，mihomo 兼容（等价 packet-encoding）
    "multiplex",        # 旧字段名，等价 smux
)

# ============================================================================
# 【本次修改 A1】KEY_CANONICAL：把等价字段的"别名键"折叠到唯一规范名
# -----------------------------------------------------------------------------
# 缺陷 A：smux 与 multiplex、packet-encoding 与 xudp 在 mihomo 里是同一旋钮
# 的新旧写法，却被当作两个不同的 key 分别哈希——节点 A 写 xudp:true、节点 B
# 写 packet-encoding:"xudp"（语义完全相同），因键名不同得到不同 identity，
# 形成"同一节点没合并"的假重复。
#
# 折叠规则（单向）：multiplex→smux、xudp→packet-encoding。
# 值联动在 _normalize_extensions 中完成（xudp 布尔 True → packet-encoding
# 字符串 "xudp"；布尔 False 已在 B1 阶段按缺省丢弃）。
#
# 冲突保护：同一节点若同时写了别名与规范名（如既有 multiplex 又有 smux）且
# 归一后取值不同，视为"配置矛盾"，保守**不折叠**（保留原始键名），宁可少合
# 并也不误合并。
# ============================================================================
KEY_CANONICAL = {
    "multiplex": "smux",
    "xudp": "packet-encoding",
}

# ============================================================================
# 【本次修改 C2 + C1】EXT_NORMALIZE：对语义等价的写法做归一化
# -----------------------------------------------------------------------------
# 归一化目的：让「语义相同但写法不同」的扩展字段得到同一 identity，
# 消除 P2 假重复：
#   - ip-version: "4" 与 "ipv4"  → mihomo 语义相同，应得同一 identity
#   - tfo: true 与 "true" 与 1    → mihomo 语义相同，应得同一 identity
#
# 【本次修改 C1】补充"值类型书写归一"，消除 int/str 写法造成的假重复：
#   - udp-over-tcp-version: 2(int) 与 "2"(str) → 同一 identity
#   - routing-mark:        2(int) 与 "2"(str) → 同一 identity
#   只归一**书写形式**（int/str/bool 表示），不猜语义、不做语义合并。
#
# 归一化只处理「值等价」的情况，不处理「值不同」：
#   - ip-version: ipv4 vs ipv6    → 语义不同，仍应得不同 identity（正确）
#
# 【本次修改 B1】布尔字段的归一化器返回 False，代表 mihomo 的默认值，
# 在 _normalize_extensions 中与"没写该字段"等价被丢弃。
# packet-encoding 归一化器对 none/空 返回 None，同样按缺省丢弃。
#
# 未在表中的字段（如 dialer-proxy / interface-name / smux / multiplex）
# 保持原值，因为它们的值语义不具备简单归一化规则（smux/multiplex 是对象）。
# ============================================================================
EXT_NORMALIZE = {
    # mihomo 同时接受 "4"/"ipv4" 与 "6"/"ipv6"（可能为字符串或整数）
    "ip-version":   lambda v: {"4": "ipv4", "6": "ipv6"}.get(str(v).lower(), str(v).lower()),
    # mihomo 布尔字段同时接受 true / "true" / 1 / "1" / yes / on
    "tfo":          lambda v: str(v).lower() in {"1", "true", "yes", "on"},
    "mptcp":        lambda v: str(v).lower() in {"1", "true", "yes", "on"},
    "udp":          lambda v: str(v).lower() in {"1", "true", "yes", "on"},
    "udp-over-tcp": lambda v: str(v).lower() in {"1", "true", "yes", "on"},
    # 【本次修改 A1 配套】xudp 作为布尔写法参与归一，再由 KEY_CANONICAL 折叠
    # 到 packet-encoding（True→"xudp"，False→缺省丢弃）。
    "xudp":         lambda v: str(v).lower() in {"1", "true", "yes", "on"},
    # packet-encoding：xudp / packetaddr 为显式编码，none/空 为缺省（返回 None 丢弃）
    "packet-encoding": lambda v: (
        None if str(v).lower() in ("", "none", "false", "0") else str(v).lower()
    ),
    # 【本次修改 C1】书写形式归一（int/str 等价），不猜语义
    "udp-over-tcp-version": lambda v: str(v),
    "routing-mark":          lambda v: str(v),
}


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


def _normalize_extensions(proxy: dict) -> dict:
    """收集 BEHAVIOR_FIELDS，依次应用 B1（缺省归一）→ C1（书写归一）→ A1（别名折叠）。

    顺序与语义（与第 10 轮方案一一对应）：
      B1：布尔归一化器返回 False 的字段，等同 mihomo 默认值，丢弃（不进键）。
          归一化器返回 None 的（如 packet-encoding: none），同样按缺省丢弃。
      C1：值类型书写归一已在各归一化器内完成（int/str/bool 表示等价）。
      A1：KEY_CANONICAL 把别名键折到规范名；xudp 的布尔值联动为 packet-encoding
          字符串 "xudp"。别名与规范名同现且归一后值冲突 → 保守不折叠（保留原始
          键名），宁可少合并也不误合并。

    返回最终参与 identity 哈希的 extensions 字典。
    """
    ext: dict = {}
    for key in BEHAVIOR_FIELDS:
        v = proxy.get(key)
        if v in (None, "", [], {}):
            continue
        normalizer = EXT_NORMALIZE.get(key)
        nv = normalizer(v) if normalizer else v

        # 【B1】归一化为布尔 False（= mihomo 默认关）或归一化为 None（缺省值）→ 丢弃
        if nv is False or nv is None:
            continue

        # 【A1】别名折叠到规范名；未命中映射的键保持自身
        canonical = KEY_CANONICAL.get(key, key)

        # 【A1 值联动】xudp 是布尔写法，折叠到 packet-encoding 时转成字符串编码名。
        # False 已在 B1 阶段丢弃，走到这里必为 True。
        if key == "xudp":
            nv = "xudp"

        # 【A1 冲突保护】规范名已被另一个键占用且取值不同 → 配置矛盾，
        # 保守不折叠：用原始 key 名落地，使其与"干净的规范名节点"得到不同 identity。
        if canonical in ext and ext[canonical] != nv:
            ext[key] = nv
        else:
            ext[canonical] = nv
    return ext


def identity_for_clash_proxy(proxy: dict) -> str | None:
    """Clash dict → identity（OpenRay identity + 行为字段哈希）。

    对外签名不变。内部 extensions 构建委托给 _normalize_extensions，依次落实：
      - B1：默认即 false 的布尔行为字段（tfo/mptcp/udp/udp-over-tcp/xudp）与
        "根本没写"等价，丢弃不进键——消除"写法/默认值差异"造成的假重复。
      - C1：值类型书写归一（udp-over-tcp-version / routing-mark 的 int/str 等价）。
      - A1：canonical 别名折叠（multiplex↔smux、xudp↔packet-encoding），冲突时
        保守不折叠——消除"新旧写法各一条"造成的假重复，且不误合并配置矛盾项。
    无归一化器也无别名映射的字段（如 dialer-proxy / interface-name / smux）保留原值。
    """
    uri = clash_dict_to_uri(proxy)
    if uri is None:
        return None
    try:
        parsed = parse_uri(uri)
    except (ParseError, UnicodeError):
        return None
    base_identity = parsed.identity
    # 【本轮修改 B1 + C1 + A1】extensions 构建统一走 _normalize_extensions
    extensions = _normalize_extensions(proxy)
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

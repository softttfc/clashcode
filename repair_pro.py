#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
repair.py - 节点标准化 + 消除重复节点（仅去重，不重命名）

功能：
    读取 Clash 节点配置文件，对 proxies 列表执行：
        1. 节点标准化：补全缺失字段，确保符合 Clash 标准。
        2. 消除重复节点：基于复合键去重。
    输出清洗后的配置，节点名称不变。

【本次修改概览】
    - 方案一：去重字段分层（--dedup-level 0/1/2/3，默认 1）
        0: 旧 7 字段 (server, port, type, identifier, sni, ws-path, grpc-service-name)
        1: + network / security / flow / skip-cert-verify（默认，堵住 4 个高危误删）
        2: + alpn / fp(client-fingerprint) / cipher
        3: + reality-opts 的 public-key / short-id + ws-opts.headers.Host
    - 方案二：多副本保留策略（--keep first/best，默认 first）
        first: 保留首次出现的副本（原行为，向后兼容）
        best : 按名字质量评分保留最佳副本（与 dupconfig.py --keep best 语义一致）
    - 新增 --no-dedup     : 只标准化，不去重
    - 新增 --warn-on-conflict : 打印因新增字段而分开保留的组及原因字段

用法：
    python repair.py <input_file> <output_file> [选项]

    # 默认：level=1，保留第一个
    python repair.py input.yaml output.yaml

    # 保留名字质量最佳的副本
    python repair.py input.yaml output.yaml --keep best

    # 更严格去重（含 alpn/fp/cipher）
    python repair.py input.yaml output.yaml --dedup-level 2

    # 恢复旧行为（7 字段）
    python repair.py input.yaml output.yaml --dedup-level 0

    # 只标准化，不去重
    python repair.py input.yaml output.yaml --no-dedup

    # 打印因新增字段而分开保留的组
    python repair.py input.yaml output.yaml --warn-on-conflict

依赖：
    pip install pyyaml
"""

import sys
import os
import json
import hashlib
# 【本次新增】argparse 用于命令行参数解析，替代原有的手工 sys.argv 检查
import argparse
# 【本次新增】defaultdict / Counter 用于 warn_on_conflict 的统计
from collections import defaultdict, Counter
from typing import List, Dict, Any, Optional, Set, Union
import yaml


# ===================== 节点标准化 =====================
def normalize_node(node: Dict[str, Any]) -> Dict[str, Any]:
    """
    将节点标准化为 Clash 标准格式，补全缺失字段，类型转换。
    不修改原始节点，返回新字典。
    """
    if not isinstance(node, dict):
        return {}

    n = node.copy()
    n.setdefault("name", "unknown")
    n.setdefault("type", "")
    n.setdefault("server", "")
    n.setdefault("port", 0)

    if "port" in n:
        try:
            n["port"] = int(n["port"])
        except (ValueError, TypeError):
            n["port"] = 0

    proto = n.get("type", "").lower()

    # ---------- VMess ----------
    if proto == "vmess":
        n.setdefault("uuid", "")
        n.setdefault("alterId", 0)
        try:
            n["alterId"] = int(n["alterId"])
        except (ValueError, TypeError):
            n["alterId"] = 0
        n.setdefault("cipher", "auto")
        n.setdefault("network", "tcp")
        n.setdefault("tls", False)
        n.setdefault("sni", "")
        if n.get("network") == "ws":
            if "ws-opts" not in n or not isinstance(n["ws-opts"], dict):
                n["ws-opts"] = {}
            n["ws-opts"].setdefault("path", "")
            if "headers" not in n["ws-opts"] or not isinstance(n["ws-opts"]["headers"], dict):
                n["ws-opts"]["headers"] = {}
            n["ws-opts"]["headers"].setdefault("Host", "")
        else:
            n.pop("ws-opts", None)

    # ---------- VLESS ----------
    elif proto == "vless":
        n.setdefault("uuid", "")
        n.setdefault("security", "none")
        n.setdefault("tls", False)
        n.setdefault("sni", "")
        n.setdefault("skip-cert-verify", False)
        n.setdefault("network", "tcp")
        if n.get("network") == "ws":
            if "ws-opts" not in n or not isinstance(n["ws-opts"], dict):
                n["ws-opts"] = {}
            n["ws-opts"].setdefault("path", "")
            if "headers" not in n["ws-opts"] or not isinstance(n["ws-opts"]["headers"], dict):
                n["ws-opts"]["headers"] = {}
            n["ws-opts"]["headers"].setdefault("Host", "")
        else:
            n.pop("ws-opts", None)
        if n.get("network") == "grpc":
            if "grpc-opts" not in n or not isinstance(n["grpc-opts"], dict):
                n["grpc-opts"] = {}
            n["grpc-opts"].setdefault("grpc-service-name", "")
        else:
            n.pop("grpc-opts", None)

    # ---------- Trojan ----------
    elif proto == "trojan":
        n.setdefault("password", "")
        n.setdefault("sni", "")
        n.setdefault("skip-cert-verify", False)

    # ---------- Shadowsocks ----------
    elif proto == "ss":
        n.setdefault("cipher", "")
        n.setdefault("password", "")
        n.setdefault("udp", True)

    # ---------- Hysteria2 ----------
    elif proto == "hysteria2":
        n.setdefault("password", "")
        n.setdefault("auth", n["password"])
        n.setdefault("sni", "")
        n.setdefault("skip-cert-verify", False)

    # 布尔值转换
    bool_fields = ["tls", "skip-cert-verify", "udp"]
    for field in bool_fields:
        if field in n:
            if isinstance(n[field], str):
                n[field] = n[field].lower() in ("true", "1", "yes")
            elif not isinstance(n[field], bool):
                n[field] = bool(n[field])

    return n


# ============================================================================
# 【本次新增】去重字段归一化工具
# ----------------------------------------------------------------------------
# 说明：
#   新增的 4 个高危字段（network / security / flow / skip-cert-verify）在
#   不同上游写法下可能有多种等价形式，直接比较原值会产生"伪差异"。
#   归一化后再比较，才能准确反映"连接是否同一"。
# ============================================================================

def _normalize_network(node: Dict[str, Any]) -> str:
    """归一化 network 字段。

    mihomo 中 tcp / raw / 空字符串 三者等价，统一为 "tcp"。
    其他取值（ws / grpc / h2 / http / xhttp 等）保留原值（小写去空白）。
    """
    net = str(node.get("network") or "tcp").lower().strip()
    return "tcp" if net in ("", "tcp", "raw") else net


def _normalize_security(node: Dict[str, Any]) -> str:
    """归一化 security 字段（tls / reality / 无）。

    优先级：
      1. 有 reality-opts 且 public-key 非空  → "reality"
      2. security 字段为 "tls" / "reality"     → 取该值
      3. tls 字段为真值（True / "true" / 1）  → "tls"
      4. 其他                                  → ""

    说明：
      优先级 1 优先于 security 字段，因为 Reality 服务端必然需要 pbk，
      有 reality-opts 就一定是 Reality 连接，即使上游误写 security: none。
      优先级 3 兼容 tls 被写成字符串 "true" 或整数 1 的情况。
    """
    reality = node.get("reality-opts")
    if isinstance(reality, dict) and reality.get("public-key"):
        return "reality"

    sec = str(node.get("security") or "").lower().strip()
    if sec in ("tls", "reality"):
        return sec

    tls = node.get("tls")
    if isinstance(tls, bool):
        if tls:
            return "tls"
    elif isinstance(tls, str) and tls.lower() in ("true", "1", "yes"):
        return "tls"
    elif isinstance(tls, (int, float)) and tls != 0:
        return "tls"

    return ""


def _normalize_alpn(node: Dict[str, Any]) -> tuple:
    """归一化 alpn 字段（仅在 --dedup-level >= 2 时使用）。

    alpn 可能是列表或逗号分隔的字符串。归一化为排序后的 tuple，
    使 ["h2", "http/1.1"] 与 "h2,http/1.1" 与 ["http/1.1", "h2"] 等价。
    """
    alpn = node.get("alpn")
    if isinstance(alpn, list):
        return tuple(sorted(str(a).strip() for a in alpn if a))
    if isinstance(alpn, str):
        return tuple(sorted(a.strip() for a in alpn.split(",") if a.strip()))
    return ()


# ===================== 消除重复节点 =====================
def get_node_key(node: Dict[str, Any], level: int = 1) -> tuple:
    """生成用于去重的复合键（不包含 name）。

    【本次修改】增加 level 参数，分层控制字段覆盖范围：
        level=0: 旧 7 字段（向后兼容路径）
        level=1: + network / security / flow / skip-cert-verify（默认）
        level=2: + alpn / fp / cipher
        level=3: + reality-opts.public-key / short-id / ws-opts.headers.Host

    为什么要分层：
        4 个高危字段（network / security / flow / skip-cert-verify）缺失时，
        同 server:port 上"tcp vs ws"、"tls vs reality"、"有 flow vs 无 flow"、
        "skip-cert-verify true vs false" 会被误合并为同一节点，导致误删。
        level=1 是"正确性修复"的最小充分集；2/3 是"进一步保守"的可选项。
    """
    server = node.get("server", "")
    port = node.get("port", 0)
    ptype = node.get("type", "")
    identifier = node.get("uuid") or node.get("password") or ""
    sni = node.get("sni", "")
    # WebSocket 路径
    ws_opts = node.get("ws-opts", {})
    path = ws_opts.get("path", "") if isinstance(ws_opts, dict) else ""
    # gRPC service name
    grpc_opts = node.get("grpc-opts", {})
    grpc_service = grpc_opts.get("grpc-service-name", "") if isinstance(grpc_opts, dict) else ""

    base = (server, port, ptype, identifier, sni, path, grpc_service)

    # 【本次新增】level=0：旧 7 字段，保留为显式回退路径
    if level == 0:
        return base

    # 【本次新增】Layer 1：4 个高危字段
    network = _normalize_network(node)
    security = _normalize_security(node)
    flow = str(node.get("flow") or "").strip()
    skip_verify = bool(node.get("skip-cert-verify", False))

    layer1 = base + (network, security, flow, skip_verify)

    if level == 1:
        return layer1

    # 【本次新增】Layer 2：alpn / fp / cipher
    alpn = _normalize_alpn(node)
    fp = str(node.get("client-fingerprint") or node.get("fingerprint") or "").strip()
    cipher = str(node.get("cipher") or "").strip()

    layer2 = layer1 + (alpn, fp, cipher)

    if level == 2:
        return layer2

    # 【本次新增】Layer 3：reality 详细字段 + ws Host
    reality = node.get("reality-opts") or {}
    pbk = str(reality.get("public-key") or "") if isinstance(reality, dict) else ""
    sid = str(reality.get("short-id") or "") if isinstance(reality, dict) else ""
    headers = ws_opts.get("headers") if isinstance(ws_opts, dict) else None
    ws_host = ""
    if isinstance(headers, dict):
        ws_host = str(headers.get("Host") or headers.get("host") or "")

    return layer2 + (pbk, sid, ws_host)


def deduplicate_nodes(nodes: List[Dict[str, Any]],
                      keep: str = "first",
                      level: int = 1) -> List[Dict[str, Any]]:
    """按复合键去重。

    【本次修改】新增 keep 和 level 参数：
        keep="first"（默认）：保留首次出现的副本，原行为不变
        keep="best"         ：按名字质量评分保留最佳副本（与 dupconfig.py 一致）
        level               ：去重字段层级，见 get_node_key

    为什么默认 keep="first"：
        保持向后兼容，不改变现有行为；需要名字质量优选时显式 --keep best。

    名字质量评分说明（--keep best 时生效）：
        与 dupconfig.py 的 pick_best 完全一致（含国旗 +10 / 长度适中 +5 /
        含广告词 -20）。评分的是"名字质量"而非"可用性"——保留的副本
        名字好看，但不保证该副本能连上服务器。
    """
    # ---- keep="first"：原遍历逻辑，行为完全等价 ----
    if keep == "first":
        seen = set()
        unique = []
        for node in nodes:
            key = get_node_key(node, level=level)
            if key not in seen:
                seen.add(key)
                unique.append(node)
        return unique

    # ---- keep="best"：分组后按名字质量优选 ----
    groups = {}
    order = []
    for node in nodes:
        key = get_node_key(node, level=level)
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(node)

    def score(p: Dict[str, Any]) -> int:
        """名字质量评分，与 dupconfig.py 的 pick_best 保持一致。"""
        name = str(p.get("name", ""))
        s = 0
        # 含国旗 emoji +10
        if any(0x1F1E6 <= ord(c) <= 0x1F1FF for c in name):
            s += 10
        # 长度 5~30 +5
        if 5 <= len(name) <= 30:
            s += 5
        # 含广告/推广词 -20
        for w in ("订阅", "加入", "频道", "telegram", "@", "http"):
            if w in name.lower():
                s -= 20
        return s

    result = []
    for key in order:
        candidates = groups[key]
        if len(candidates) == 1:
            result.append(candidates[0])
        else:
            result.append(max(candidates, key=score))
    return result


# ============================================================================
# 【本次新增】冲突告警：打印因新增字段而分开保留的组
# ----------------------------------------------------------------------------
# 用途：
#   当去重层级从 0 升到 1/2/3 后，一些"level=0 会合并、level=N 会分开"的组
#   会被保留下来。用户可通过 --warn-on-conflict 查看：
#       - 有多少组因新增字段而分开保留
#       - 具体是哪些字段导致的（network / security / flow / skip-cert-verify）
#   这个告警不是错误，是信息——让用户知道修复了多少潜在的误删。
# ============================================================================
def warn_on_conflict(nodes: List[Dict[str, Any]], level: int) -> None:
    """打印因 level>0 新增字段而分开保留的组。"""
    if level == 0 or not nodes:
        return

    # 按 level=0 的 key 分组（每组对应"原版会合并到同一节点"）
    groups_base = defaultdict(list)
    for n in nodes:
        if not isinstance(n, dict):
            continue
        groups_base[get_node_key(n, level=0)].append(n)

    split_groups = 0
    field_diffs: Counter = Counter()

    for base_key, group in groups_base.items():
        if len(group) <= 1:
            continue
        # 检查 level=N 下是否仍为同一组
        level_keys = {get_node_key(n, level=level) for n in group}
        if len(level_keys) <= 1:
            continue  # level=N 下仍合并，无冲突

        split_groups += 1

        # 统计 Layer 1 的 4 个高危字段哪些发生了变化
        for field in ("network", "security", "flow", "skip-cert-verify"):
            values = set()
            for n in group:
                if field == "network":
                    values.add(_normalize_network(n))
                elif field == "security":
                    values.add(_normalize_security(n))
                elif field == "flow":
                    values.add(str(n.get("flow") or "").strip())
                elif field == "skip-cert-verify":
                    values.add(bool(n.get("skip-cert-verify", False)))
            if len(values) > 1:
                field_diffs[field] += 1

    if split_groups:
        print(f"ℹ️ 共 {split_groups} 组在 level={level} 下被分开保留"
              f"（原 level=0 会合并，修复了潜在误删）")
        if field_diffs:
            print("  导致分开的字段统计：")
            for field, cnt in field_diffs.most_common():
                print(f"    {field}: {cnt} 组")
    else:
        print(f"ℹ️ 未发现因 level={level} 新增字段而分开保留的组")


# ===================== 文件读写 =====================
def load_config(file_path: str) -> Dict[str, Any]:
    ext = os.path.splitext(file_path)[1].lower()
    with open(file_path, 'r', encoding='utf-8') as f:
        if ext in ('.yaml', '.yml'):
            return yaml.safe_load(f) or {}
        elif ext == '.json':
            return json.load(f)
        else:
            try:
                return yaml.safe_load(f) or {}
            except:
                f.seek(0)
                return json.load(f)


def save_config(file_path: str, data: Dict[str, Any]):
    ext = os.path.splitext(file_path)[1].lower()
    with open(file_path, 'w', encoding='utf-8') as f:
        if ext in ('.yaml', '.yml'):
            yaml.dump(data, f, allow_unicode=True, sort_keys=False, default_flow_style=False)
        elif ext == '.json':
            json.dump(data, f, ensure_ascii=False, indent=2)
        else:
            yaml.dump(data, f, allow_unicode=True, sort_keys=False)


# ===================== 主流程 =====================
def main():
    # 【本次修改】用 argparse 替代手工 sys.argv 解析
    # 兼容旧用法：python repair.py input_file output_file
    # 新增可选参数：--keep / --dedup-level / --no-dedup / --warn-on-conflict
    parser = argparse.ArgumentParser(
        prog="repair",
        description="节点标准化 + 消除重复节点",
    )
    parser.add_argument("input_file", help="输入文件（YAML 或 JSON）")
    parser.add_argument("output_file", help="输出文件（YAML 或 JSON）")
    parser.add_argument(
        "--keep", choices=("first", "best"), default="first",
        help="多副本保留策略：first=保留第一个（默认），best=保留名字质量最佳的",
    )
    parser.add_argument(
        "--dedup-level", type=int, default=1, choices=(0, 1, 2, 3),
        help=(
            "去重字段层级："
            "0=旧7字段，"
            "1=+network/security/flow/skip-cert-verify（默认），"
            "2=+alpn/fp/cipher，"
            "3=+reality pbk/sid + ws host"
        ),
    )
    parser.add_argument(
        "--no-dedup", action="store_true",
        help="只做标准化，不去重",
    )
    parser.add_argument(
        "--warn-on-conflict", action="store_true",
        help="打印因新增字段而分开保留的组及原因字段",
    )
    args = parser.parse_args()

    input_file = args.input_file
    output_file = args.output_file

    if not os.path.exists(input_file):
        print(f"错误：输入文件 '{input_file}' 不存在。")
        sys.exit(1)

    try:
        config = load_config(input_file)
    except Exception as e:
        print(f"读取文件失败: {e}")
        sys.exit(1)

    if not config:
        print("警告：配置文件为空。")
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write('')
        sys.exit(0)

    if "proxies" not in config:
        print("错误：配置文件不包含 'proxies' 字段。")
        sys.exit(1)

    proxies = config["proxies"]
    if not isinstance(proxies, list):
        print("错误：'proxies' 字段不是列表。")
        sys.exit(1)

    if not proxies:
        print("警告：'proxies' 列表为空，直接输出空文件。")
        save_config(output_file, config)
        sys.exit(0)

    print(f"原始节点数量: {len(proxies)}")

    # 1. 标准化每个节点
    normalized = []
    for idx, node in enumerate(proxies):
        if not isinstance(node, dict):
            print(f"警告：第 {idx+1} 个节点不是字典，跳过。")
            continue
        norm_node = normalize_node(node)
        if norm_node:
            normalized.append(norm_node)
    print(f"标准化后有效节点: {len(normalized)}")

    # 2. 去重（或跳过）
    # 【本次修改】根据 --no-dedup / --keep / --dedup-level 决定行为
    if args.no_dedup:
        deduped = normalized
        print(f"跳过去重（--no-dedup）：保持 {len(deduped)} 个节点")
    else:
        deduped = deduplicate_nodes(
            normalized,
            keep=args.keep,
            level=args.dedup_level,
        )
        print(f"去重后节点: {len(deduped)} "
              f"(level={args.dedup_level}, keep={args.keep}，名称保持不变)")

        # 【本次新增】冲突告警（在去重统计之后打印，便于理解）
        if args.warn_on_conflict:
            warn_on_conflict(normalized, args.dedup_level)

    # 3. 更新配置并保存
    config["proxies"] = deduped
    try:
        save_config(output_file, config)
        print(f"清洗完成，结果已保存至: {output_file}")
    except Exception as e:
        print(f"保存文件失败: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()

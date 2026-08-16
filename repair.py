#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
repair.py - 节点标准化 + 消除重复节点（仅去重，不重命名）

功能：
    读取 Clash 节点配置文件，对 proxies 列表执行：
        1. 节点标准化：补全缺失字段，确保符合 Clash 标准。
        2. 消除重复节点：基于复合键 (server, port, type, identifier, sni, ws-path, grpc-service-name) 去重。
    输出清洗后的配置，节点名称不变。

用法：
    python repair.py input_file output_file

依赖：
    pip install pyyaml
"""

import sys
import os
import json
import hashlib
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


# ===================== 消除重复节点 =====================
def get_node_key(node: Dict[str, Any]) -> tuple:
    """
    生成用于去重的复合键（不包含 name）
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
    return (server, port, ptype, identifier, sni, path, grpc_service)


def deduplicate_nodes(nodes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    使用复合键去除完全重复的节点，保留首次出现的节点。
    """
    seen = set()
    unique = []
    for node in nodes:
        key = get_node_key(node)
        if key not in seen:
            seen.add(key)
            unique.append(node)
    return unique


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
    if len(sys.argv) != 3:
        print("用法: python repair.py <input_file> <output_file>")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]

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

    # 2. 仅去重（不重命名）
    deduped = deduplicate_nodes(normalized)
    print(f"去重后节点: {len(deduped)} (基于复合键去重，名称保持不变)")

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

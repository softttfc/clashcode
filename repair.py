#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
repair.py - 节点标准化、名称去重、消除重复节点（修复版）

功能：
    读取已有的 Clash 节点配置文件（支持 .yaml / .yml / .json），
    对 proxies 列表中的每个节点执行：
        1. 节点标准化：补全缺失字段、类型转换，确保符合 Clash 标准。
        2. 名称去重：基于节点属性生成确定性后缀，确保名称唯一。
        3. 消除重复节点：使用复合键（server, port, type, uuid/password, sni, path, grpc-service-name）精确去重。
    输出清洗后的配置文件。

用法：
    python repair.py input_file output_file

示例：
    python repair.py old.yml new.yml
    python repair.py clash.json clash_clean.json

依赖：
    pip install pyyaml

注：
    - 输入文件必须包含顶层键 "proxies"，其值为节点列表。
    - 输出文件格式与输入文件扩展名一致（.yml -> YAML, .json -> JSON）。
    - 若输入为 JSON，则输出 JSON；若为 YAML，则输出 YAML。
    - 其他顶层字段（如 port、rules 等）保持不变。
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
    将给定的节点字典标准化为 Clash 标准格式。
    补全缺失字段、类型转换，并确保结构一致。
    不修改原始节点，返回新的字典。
    """
    # 如果节点为空或不是字典，直接返回空
    if not isinstance(node, dict):
        return {}

    # 复制一份，避免修改原数据
    n = node.copy()

    # 1. 确保核心字段存在
    n.setdefault("name", "unknown")
    n.setdefault("type", "")
    n.setdefault("server", "")
    n.setdefault("port", 0)

    # 2. 类型转换
    if "port" in n:
        try:
            n["port"] = int(n["port"])
        except (ValueError, TypeError):
            n["port"] = 0

    # 3. 根据协议类型补全特定字段
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
        # 如果 network 是 ws，确保 ws-opts 存在且格式正确
        if n.get("network") == "ws":
            if "ws-opts" not in n or not isinstance(n["ws-opts"], dict):
                n["ws-opts"] = {}
            n["ws-opts"].setdefault("path", "")
            if "headers" not in n["ws-opts"] or not isinstance(n["ws-opts"]["headers"], dict):
                n["ws-opts"]["headers"] = {}
            n["ws-opts"]["headers"].setdefault("Host", "")
        else:
            # 如果不是 ws，删除 ws-opts（如果有）
            n.pop("ws-opts", None)

    # ---------- VLESS ----------
    elif proto == "vless":
        n.setdefault("uuid", "")
        n.setdefault("security", "none")
        n.setdefault("tls", False)
        n.setdefault("sni", "")
        n.setdefault("skip-cert-verify", False)
        n.setdefault("network", "tcp")
        # 如果 network 是 ws
        if n.get("network") == "ws":
            if "ws-opts" not in n or not isinstance(n["ws-opts"], dict):
                n["ws-opts"] = {}
            n["ws-opts"].setdefault("path", "")
            if "headers" not in n["ws-opts"] or not isinstance(n["ws-opts"]["headers"], dict):
                n["ws-opts"]["headers"] = {}
            n["ws-opts"]["headers"].setdefault("Host", "")
        else:
            n.pop("ws-opts", None)
        # 如果 network 是 grpc
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
        n.setdefault("auth", n["password"])  # 有些版本用 auth
        n.setdefault("sni", "")
        n.setdefault("skip-cert-verify", False)

    # ---------- 其他类型（如 HTTP, SOCKS5, WireGuard 等） ----------
    # 仅做基本字段保证，不添加额外字段

    # 4. 布尔值转换（确保为 bool）
    bool_fields = ["tls", "skip-cert-verify", "udp"]
    for field in bool_fields:
        if field in n:
            if isinstance(n[field], str):
                n[field] = n[field].lower() in ("true", "1", "yes")
            elif not isinstance(n[field], bool):
                n[field] = bool(n[field])

    # 5. 移除空字符串（可选项），但保留字段
    # 此处不删除，让用户决定

    return n


# ===================== 名称去重 =====================

def generate_unique_name(node: Dict[str, Any], used_names: Set[str]) -> str:
    """
    基于节点属性生成确定性唯一名称。
    策略：基础名称 + 后缀（MD5 前 6 位），若冲突则追加数字。
    """
    base_name = node.get("name", "unknown")
    # 构造标识字符串：server, port, type, uuid/password, sni, path, grpc-service-name
    key_parts = [
        node.get("server", ""),
        str(node.get("port", 0)),
        node.get("type", ""),
        node.get("uuid") or node.get("password") or "",
        node.get("sni", ""),
        node.get("ws-opts", {}).get("path", "") if isinstance(node.get("ws-opts"), dict) else "",
        node.get("grpc-opts", {}).get("grpc-service-name", "") if isinstance(node.get("grpc-opts"), dict) else "",
    ]
    key_str = "|".join(key_parts)
    hash_suffix = hashlib.md5(key_str.encode('utf-8')).hexdigest()[:6]
    new_name = base_name
    counter = 0
    while new_name in used_names:
        if counter == 0:
            new_name = f"{base_name}-{hash_suffix}"
        else:
            new_name = f"{base_name}-{hash_suffix}-{counter}"
        counter += 1
        # 防止死循环
        if counter > 100:
            new_name = f"{base_name}-{hash_suffix}-{counter}"
            break
    used_names.add(new_name)
    return new_name


def resolve_names(nodes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    为所有节点赋予唯一名称，修改节点的 'name' 字段。
    返回新的节点列表（不修改原始列表）。
    """
    used_names: Set[str] = set()
    result = []
    for node in nodes:
        new_node = node.copy()  # 避免修改原数据
        new_name = generate_unique_name(new_node, used_names)
        new_node["name"] = new_name
        result.append(new_node)
    return result


# ===================== 消除重复节点 =====================

def get_node_key(node: Dict[str, Any]) -> tuple:
    """
    生成用于去重的复合键。
    包含：server, port, type, 标识符(uuid/password), sni, ws-opts.path, grpc-opts.service-name
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


# ===================== 主流程 =====================

def load_config(file_path: str) -> Dict[str, Any]:
    """根据扩展名加载配置文件（YAML 或 JSON）"""
    ext = os.path.splitext(file_path)[1].lower()
    with open(file_path, 'r', encoding='utf-8') as f:
        if ext in ('.yaml', '.yml'):
            return yaml.safe_load(f) or {}
        elif ext == '.json':
            return json.load(f)
        else:
            # 尝试 YAML
            try:
                return yaml.safe_load(f) or {}
            except:
                f.seek(0)
                return json.load(f)


def save_config(file_path: str, data: Dict[str, Any]):
    """根据扩展名保存配置文件"""
    ext = os.path.splitext(file_path)[1].lower()
    with open(file_path, 'w', encoding='utf-8') as f:
        if ext in ('.yaml', '.yml'):
            yaml.dump(data, f, allow_unicode=True, sort_keys=False, default_flow_style=False)
        elif ext == '.json':
            json.dump(data, f, ensure_ascii=False, indent=2)
        else:
            # 默认 YAML
            yaml.dump(data, f, allow_unicode=True, sort_keys=False)


def main():
    if len(sys.argv) != 3:
        print("用法: python repair.py <input_file> <output_file>")
        print("示例: python repair.py old.yml new.yml")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]

    if not os.path.exists(input_file):
        print(f"错误：输入文件 '{input_file}' 不存在。")
        sys.exit(1)

    # 1. 读取配置
    try:
        config = load_config(input_file)
    except Exception as e:
        print(f"读取文件失败: {e}")
        sys.exit(1)

    if not config:
        print("警告：配置文件为空。")
        with open(output_file, 'w') as f:
            f.write('')
        sys.exit(0)

    # 2. 提取 proxies
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

    # 3. 标准化每个节点
    normalized = []
    for idx, node in enumerate(proxies):
        if not isinstance(node, dict):
            print(f"警告：第 {idx+1} 个节点不是字典，跳过。")
            continue
        norm_node = normalize_node(node)
        if norm_node:
            normalized.append(norm_node)
    print(f"标准化后有效节点: {len(normalized)}")

    # 4. 名称去重
    named = resolve_names(normalized)
    print(f"名称去重后节点: {len(named)} (所有名称唯一)")

    # 5. 消除重复节点
    deduped = deduplicate_nodes(named)
    print(f"消除重复后节点: {len(deduped)} (基于复合键去重)")

    # 6. 更新配置
    config["proxies"] = deduped

    # 7. 保存
    try:
        save_config(output_file, config)
        print(f"清洗完成，结果已保存至: {output_file}")
    except Exception as e:
        print(f"保存文件失败: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()

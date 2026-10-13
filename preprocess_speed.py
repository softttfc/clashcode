#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
preprocess_speed.py - 测速前预处理脚本
================================================================================

【用途】
    在 speed_pro1.py 之前运行，对 fetch_pro3.py 生成的 list.meta.yml 做一次
    安全化处理，生成 list.meta.safe.yml，避免 speed_pro1.py 因以下原因崩溃或
    误判：
        1. YAML 语法错误（节点名以 "..." 结尾、含未加引号的 # & * 等）
        2. 节点名重复，导致延迟结果按 name 错配
        3. network 字段被 # URL fragment 污染
        4. VLESS security: none 与 reality-opts 字段冲突
        5. IPv6 地址带方括号
        6. 输出 YAML 含锚点/别名

【与 speed_pro1.py 的关系】
    speed_pro1.py 使用 name 作为 delay_status 的键，节点名重复会导致测速结果
    错配。本脚本保证输出节点名唯一。
    speed_pro1.py 直接使用 yaml.safe_load 读取，若输入非法会直接崩溃。本脚本
    保证输出 YAML 语法合法。

【用法】
    python preprocess_speed.py <输入文件> <输出文件>
    默认:
        python preprocess_speed.py list.meta.yml list.meta.safe.yml

【典型调用位置】
    GitHub Actions workflow:
        - name: 执行任务
          run: python ./fetch_pro3.py
        - name: 预处理测速文件
          run: python ./preprocess_speed.py list.meta.yml list.meta.safe.yml
        - name: 测试节点连通性延迟性
          run: python ./speed_pro1.py --delay list.meta.safe.yml list.metaspeed.yml
          continue-on-error: true

【依赖】
    pip install pyyaml

【退出码】
    0  成功
    1  用法错误或文件不存在
    2  YAML 解析错误或根元素不是字典
================================================================================
"""

import sys
import os
import re
import yaml
from collections import Counter


# ============================================================================
# 全局配置
# ============================================================================

# network 字段合法值白名单
VALID_NETWORKS = {
    'tcp', 'ws', 'grpc', 'h2', 'http', 'httpupgrade', 'xhttp', 'raw',
    'udp', 'quic', '',
}

# 需要从节点名中清理的字符（替换为全角形式，避免破坏可读性）
NAME_REPLACE_MAP = {
    '...': '…',    # YAML 文档结束符
    '#': '＃',     # YAML 注释符
    '&': '＆',     # YAML 锚点符
    '*': '＊',     # YAML 别名符
    '|': '｜',     # YAML 块标量符
    '>': '＞',
    '<': '＜',
}

# 允许的节点协议类型（用于剔除明显无效节点）
ALLOWED_TYPES = {
    'ss', 'ssr', 'vmess', 'vless', 'trojan',
    'hysteria', 'hysteria2', 'hy2', 'tuic', 'anytls',
    'http', 'https', 'socks5', 'socks5h',
    'snell', 'wireguard', 'mieru', 'ssh', 'juicity',
}


# ============================================================================
# 自定义 YAML Dumper：禁止锚点/别名，特殊字符串自动加引号
# ============================================================================
class NoAliasDumper(yaml.SafeDumper):
    """禁止 YAML 锚点/别名，特殊字符串使用双引号"""

    def ignore_aliases(self, data):
        return True

    def represent_str(self, data):
        style = None
        # 包含 YAML 特殊字符时强制使用双引号
        if any(ch in data for ch in '&*#...|>@`?:{}[],!%^'):
            style = '"'
        return self.represent_scalar('tag:yaml.org,2002:str', data, style=style)


NoAliasDumper.add_representer(str, NoAliasDumper.represent_str)


# ============================================================================
# 工具函数
# ============================================================================

def sanitize_name(name):
    """
    清理节点名中的危险字符。
    替换 YAML 特殊字符为全角形式，避免破坏 YAML 解析。
    过滤控制字符。
    """
    if not isinstance(name, str):
        return "未命名"

    # 先替换特殊字符
    for old, new in NAME_REPLACE_MAP.items():
        name = name.replace(old, new)

    # 过滤控制字符（保留空格）
    name = ''.join(ch for ch in name if ord(ch) >= 0x20 or ch == ' ')

    name = name.strip()
    return name or "未命名"


def clean_network(proxy):
    """
    清理 network 字段：
      - 去除 # 后的 URL fragment
      - 去除 & 后的参数
      - 非白名单值重置为 'tcp'
    返回是否修改。
    """
    if 'network' not in proxy:
        return False
    original = proxy['network']
    if not isinstance(original, str):
        proxy['network'] = 'tcp'
        return True

    net = original.split('#')[0].split('&')[0].strip().lower()
    if net not in VALID_NETWORKS:
        net = 'tcp'

    if net != original:
        proxy['network'] = net
        return True
    return False


def clean_server(proxy):
    """
    清理 server 字段：
      - 去除 IPv6 地址两端的方括号（Clash 规范要求去掉）
      - 去除首尾空白
    返回是否修改。
    """
    if 'server' not in proxy:
        return False
    srv = proxy['server']
    if not isinstance(srv, str):
        return False

    original = srv
    srv = srv.strip()
    if srv.startswith('[') and srv.endswith(']'):
        srv = srv[1:-1]

    if srv != original:
        proxy['server'] = srv
        return True
    return False


def fix_vless_reality(proxy):
    """
    修复 VLESS 节点的 reality-opts 与 security 冲突。
    若存在 reality-opts，则 security 必须为 reality，且 tls 必须为 true。
    返回是否修改。
    """
    if proxy.get('type') != 'vless':
        return False
    if 'reality-opts' not in proxy:
        return False

    fixed = False
    if proxy.get('security') != 'reality':
        proxy['security'] = 'reality'
        fixed = True
    if proxy.get('tls') is not True:
        proxy['tls'] = True
        fixed = True
    return fixed


def is_valid_proxy(proxy):
    """
    判断节点是否结构上有效（保留供筛选使用）。
    要求：dict、type 在白名单、server 非空、port 有效。
    """
    if not isinstance(proxy, dict):
        return False
    ptype = proxy.get('type')
    if not ptype or not isinstance(ptype, str):
        return False
    if ptype.lower() not in ALLOWED_TYPES:
        return False
    if not proxy.get('server'):
        return False
    try:
        port = int(proxy.get('port', 0))
    except (ValueError, TypeError):
        return False
    if port <= 0 or port > 65535:
        return False
    return True


def deduplicate_names(proxies):
    """
    确保节点名全局唯一。
    对重名节点添加序号后缀 "(2)"、"(3)" 等。
    返回 (去重后数量, 重命名数量)。
    """
    seen = set()
    renamed = 0
    for p in proxies:
        if not isinstance(p, dict):
            continue
        name = p.get('name', '未命名')
        if name not in seen:
            seen.add(name)
            continue
        # 重名，加后缀
        suffix = 2
        new_name = f"{name} ({suffix})"
        while new_name in seen:
            suffix += 1
            new_name = f"{name} ({suffix})"
        p['name'] = new_name
        seen.add(new_name)
        renamed += 1
    return len(seen), renamed


def safe_load_yaml(path):
    """安全读取 YAML 文件，返回 (data, error_msg)。"""
    if not os.path.exists(path):
        return None, f"文件不存在: {path}"
    try:
        with open(path, 'r', encoding='utf-8') as f:
            text = f.read()
    except UnicodeDecodeError as e:
        return None, f"文件不是有效的 UTF-8: {e}"
    except Exception as e:
        return None, f"读取失败: {e}"

    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as e:
        return None, f"YAML 解析失败: {e}"

    if data is None:
        return None, "YAML 内容为空"
    if not isinstance(data, dict):
        return None, f"根元素不是字典: {type(data).__name__}"
    return data, None


# ============================================================================
# 主流程
# ============================================================================

def main():
    # ---------- 参数解析 ----------
    if len(sys.argv) != 3:
        print("用法: python preprocess_speed.py <输入文件> <输出文件>")
        print("示例: python preprocess_speed.py list.meta.yml list.meta.safe.yml")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]

    print(f"📂 输入: {input_file}")
    print(f"📂 输出: {output_file}")

    # ---------- 读取 YAML ----------
    config, err = safe_load_yaml(input_file)
    if err:
        print(f"❌ {err}")
        sys.exit(2)

    # ---------- 处理 proxies ----------
    proxies = config.get('proxies', [])
    if not isinstance(proxies, list):
        print(f"⚠️ proxies 不是列表（{type(proxies).__name__}），重置为空列表")
        proxies = []
        config['proxies'] = proxies

    original_count = len(proxies)
    cleaned = []
    dropped = 0
    fixed_name = 0
    fixed_network = 0
    fixed_server = 0
    fixed_reality = 0

    for p in proxies:
        if not isinstance(p, dict):
            dropped += 1
            continue
        if not is_valid_proxy(p):
            # 结构无效的节点直接剔除，避免测速脚本崩溃
            dropped += 1
            continue

        # 清理 name
        old_name = p.get('name', '未命名')
        p['name'] = sanitize_name(old_name)
        if p['name'] != old_name:
            fixed_name += 1

        # 清理 network
        if clean_network(p):
            fixed_network += 1

        # 清理 server
        if clean_server(p):
            fixed_server += 1

        # 修复 VLESS reality
        if fix_vless_reality(p):
            fixed_reality += 1

        cleaned.append(p)

    # 名称唯一化
    unique_count, renamed = deduplicate_names(cleaned)

    config['proxies'] = cleaned

    # ---------- 写出 ----------
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            yaml.dump(
                config,
                f,
                Dumper=NoAliasDumper,
                allow_unicode=True,
                sort_keys=False,
                default_flow_style=False,
            )
    except Exception as e:
        print(f"❌ 写出失败: {e}")
        sys.exit(1)

    # ---------- 报告 ----------
    print("─" * 60)
    print(f"📊 原始节点数    : {original_count}")
    print(f"📊 有效节点数    : {len(cleaned)}")
    print(f"📊 剔除无效节点  : {dropped}")
    print(f"📊 唯一名称数    : {unique_count}")
    print(f"📊 重命名节点    : {renamed}")
    print(f"📊 修复 name      : {fixed_name}")
    print(f"📊 修复 network   : {fixed_network}")
    print(f"📊 修复 server    : {fixed_server}")
    print(f"📊 修复 reality   : {fixed_reality}")
    print("─" * 60)
    print(f"✅ 预处理完成: {output_file}")


if __name__ == '__main__':
    main()

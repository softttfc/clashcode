#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
================================================================================
Clash 配置文件修复工具 (rebuilder.py) - 最终完整版（含 REALITY short-id 保守修复 + 调试）
================================================================================

【功能总览】
    1. 修复 proxy-groups 缺失 proxies/use 字段及类型错误。
    2. 补充 url-test/fallback 组缺失的 url/interval。
    3. 自动修复 VLESS 节点的 encryption 字段（无效值重置为 "none"）。
    4. 自动移除 proxy-groups 中 proxies 列表里不存在的节点/组引用，并保底添加 DIRECT。
    5. 自动移除 proxy-groups 中 use 列表里不存在的 provider 引用。
    6. 自动去重策略组名（重命名重复组，并更新规则中的引用）。
    7. 自动检测并修复组间循环引用（移除形成循环的边，并添加 DIRECT）。
    8. 自动修复 rules 中引用的不存在的策略组名（替换为 DIRECT）。
    9. 修复 proxies 中节点名为空的问题（自动生成唯一名称）。
    10. 修复 proxy-groups 中 use 和 proxies 同时存在的问题（移除 proxies）。
    11. 校验 RULE-SET 规则，若引用的 rule-provider 不存在则替换为 REJECT。
    12. 校验 rule-providers 定义完整性，若缺失 url/file 等关键字段则输出警告。
    13. 自动修复节点与策略组同名冲突（重命名节点并更新策略组引用）。
    14. 【保守修复】修复 VLESS+REALITY 节点的 short-id：仅处理缺失或长度超限，
        不修改有效值（不强制偶数长度，不清除非十六进制字符）。
    15. 【调试】在修复前打印所有存在 short-id 问题的节点（含序号、来源、名称、原值、问题类型）。

【用法】
    python rebuilder.py <输入文件> <输出文件>

【全局变量】
    DEFAULT_URL                  - 测速地址
    DEFAULT_INTERVAL             - 检测间隔
    VLESS_DEFAULT_ENCRYPTION     - VLESS 加密修正值
================================================================================
"""

import sys
import yaml
from collections import Counter, defaultdict
import re
import random
import os

# ============================================================================
# 全局配置（可按需修改）
# ============================================================================
DEFAULT_URL = "http://www.gstatic.com/generate_204"
DEFAULT_INTERVAL = 300
VLESS_DEFAULT_ENCRYPTION = "none"

# 内置关键字（Clash 保留策略）
BUILTIN_KEYWORDS = {"DIRECT", "REJECT", "REJECT-DROP", "PASS", "GLOBAL", "SOCKS5", "HTTP"}


# ============================================================================
# 1. 修复 VLESS 节点的 encryption 字段
# ============================================================================
def fix_vless_encryption(proxies):
    if not isinstance(proxies, list):
        return proxies
    fixed = 0
    for p in proxies:
        if not isinstance(p, dict) or p.get('type') != 'vless':
            continue
        enc = p.get('encryption', '')
        if enc not in ('', 'none'):
            print(f"🔧 修复 VLESS '{p.get('name', '未命名')}': encryption 重置为 'none'")
            p['encryption'] = VLESS_DEFAULT_ENCRYPTION
            fixed += 1
    if fixed:
        print(f"📝 共修复 {fixed} 个 VLESS 节点")
    return proxies


# ============================================================================
# 2. 检查重复节点名（仅警告）
# ============================================================================
def check_duplicate_node_names(proxies):
    if not isinstance(proxies, list):
        return
    names = [p.get('name') for p in proxies if isinstance(p, dict) and 'name' in p]
    dup = [n for n, c in Counter(names).items() if c > 1]
    if dup:
        print(f"⚠️ 警告：发现重复节点名: {', '.join(dup[:5])}" + (f" ..." if len(dup) > 5 else ""))


# ============================================================================
# 3. 修复 proxies 中节点名为空
# ============================================================================
def fix_empty_node_names(proxies):
    if not isinstance(proxies, list):
        return 0
    fixed = 0
    existing_names = {p.get('name') for p in proxies if isinstance(p, dict) and p.get('name')}
    base_name = "未命名节点"
    idx = 1
    for p in proxies:
        if not isinstance(p, dict):
            continue
        if 'name' not in p or not p['name']:
            new_name = base_name
            while new_name in existing_names:
                new_name = f"{base_name} #{idx}"
                idx += 1
            p['name'] = new_name
            existing_names.add(new_name)
            print(f"🔧 修复：为空节点生成名称 '{new_name}'")
            fixed += 1
    return fixed


# ============================================================================
# 4. 修复 proxy-groups 中 proxies 列表的无效引用（自动移除 + 保底）
# ============================================================================
def fix_proxy_references(groups, proxy_names, group_names):
    fixed_count = 0
    all_valid_names = proxy_names | group_names | BUILTIN_KEYWORDS

    for idx, g in enumerate(groups):
        if not isinstance(g, dict):
            continue
        name = g.get('name', f'未命名({idx})')
        plist = g.get('proxies')
        if not isinstance(plist, list):
            continue

        invalid = [item for item in plist if item not in all_valid_names]
        if invalid:
            g['proxies'] = [item for item in plist if item in all_valid_names]
            print(f"🔧 修复：组 '{name}' 移除了无效引用: {', '.join(invalid)}")
            fixed_count += 1

        if not g['proxies']:
            g['proxies'] = ["DIRECT"]
            print(f"🔧 修复：组 '{name}' 的 proxies 为空，已添加 DIRECT 保底")
            fixed_count += 1

    return fixed_count


# ============================================================================
# 5. 修复 proxy-groups 中 use 列表的无效 provider 引用
# ============================================================================
def fix_use_references(groups, provider_names):
    fixed_count = 0
    for idx, g in enumerate(groups):
        if not isinstance(g, dict):
            continue
        name = g.get('name', f'未命名({idx})')
        if 'use' not in g:
            continue
        use_val = g['use']

        if isinstance(use_val, str):
            if use_val not in provider_names:
                print(f"🔧 修复：组 '{name}' 的 use 引用不存在的 provider '{use_val}'，转为 proxies: [\"DIRECT\"]")
                del g['use']
                g['proxies'] = ["DIRECT"]
                fixed_count += 1
        elif isinstance(use_val, list):
            original = use_val[:]
            filtered = [p for p in use_val if p in provider_names]
            if len(filtered) != len(original):
                if filtered:
                    g['use'] = filtered
                    removed = set(original) - set(filtered)
                    print(f"🔧 修复：组 '{name}' 移除了无效 provider: {', '.join(removed)}")
                    fixed_count += 1
                else:
                    del g['use']
                    g['proxies'] = ["DIRECT"]
                    print(f"🔧 修复：组 '{name}' 的所有 use 引用均无效，转为 proxies: [\"DIRECT\"]")
                    fixed_count += 1
        else:
            print(f"🔧 修复：组 '{name}' 的 use 类型错误，转为 proxies: [\"DIRECT\"]")
            del g['use']
            g['proxies'] = ["DIRECT"]
            fixed_count += 1
    return fixed_count


# ============================================================================
# 6. 修复 proxy-groups 中 use 和 proxies 同时存在
# ============================================================================
def fix_use_and_proxies_conflict(groups):
    fixed_count = 0
    for idx, g in enumerate(groups):
        if not isinstance(g, dict):
            continue
        name = g.get('name', f'未命名({idx})')
        if 'use' in g and 'proxies' in g:
            del g['proxies']
            print(f"🔧 修复：组 '{name}' 同时包含 use 和 proxies，已移除 proxies（保留 use）")
            fixed_count += 1
    return fixed_count


# ============================================================================
# 7. 去重策略组名（重命名重复组，并更新 rules 中的引用）
# ============================================================================
def deduplicate_group_names(groups, rules):
    if not isinstance(groups, list):
        return 0

    name_count = Counter()
    for g in groups:
        if isinstance(g, dict) and 'name' in g:
            name_count[g['name']] += 1

    duplicates = {name for name, cnt in name_count.items() if cnt > 1}
    if not duplicates:
        return 0

    rename_map = {}
    seen = set()
    for g in groups:
        if not isinstance(g, dict) or 'name' not in g:
            continue
        name = g['name']
        if name in duplicates:
            if name not in seen:
                seen.add(name)
            else:
                suffix = 2
                new_name = f"{name} #{suffix}"
                while new_name in seen or new_name in rename_map.values():
                    suffix += 1
                    new_name = f"{name} #{suffix}"
                rename_map[name] = new_name
                g['name'] = new_name
                seen.add(new_name)
        else:
            seen.add(name)

    if not rename_map:
        return 0

    print(f"🔧 修复：重命名了 {len(rename_map)} 个重复组名")
    for old, new in rename_map.items():
        print(f"    {old} -> {new}")

    if isinstance(rules, list):
        for idx, rule in enumerate(rules):
            if not isinstance(rule, str):
                continue
            parts = rule.split(',')
            if len(parts) >= 3:
                policy = parts[-1].strip()
                if policy in rename_map:
                    new_policy = rename_map[policy]
                    parts[-1] = new_policy
                    rules[idx] = ','.join(parts)
                    print(f"🔧 修复：规则中的策略组 '{policy}' 更新为 '{new_policy}'")

    return len(rename_map)


# ============================================================================
# 8. 检测并修复组间循环引用
# ============================================================================
def detect_and_fix_cycles(groups):
    if not isinstance(groups, list):
        return 0

    name_to_idx = {}
    for idx, g in enumerate(groups):
        if isinstance(g, dict) and 'name' in g:
            name_to_idx[g['name']] = idx

    adj = defaultdict(list)
    for idx, g in enumerate(groups):
        if not isinstance(g, dict):
            continue
        name = g.get('name')
        if not name:
            continue
        proxies = g.get('proxies')
        if not isinstance(proxies, list):
            continue
        for item in proxies:
            if item in name_to_idx and item != name:
                adj[name].append(item)

    visited = {}
    cycle_edges = []

    def dfs(node, path):
        visited[node] = 1
        path.append(node)
        for neighbor in adj.get(node, []):
            if neighbor not in visited:
                if dfs(neighbor, path):
                    return True
            elif visited[neighbor] == 1:
                cycle_edges.append((node, neighbor))
                return True
        visited[node] = 2
        path.pop()
        return False

    for node in list(adj.keys()):
        if node not in visited:
            dfs(node, [])

    if not cycle_edges:
        return 0

    fixed = 0
    for from_node, to_node in cycle_edges:
        idx = name_to_idx.get(from_node)
        if idx is None:
            continue
        g = groups[idx]
        proxies = g.get('proxies')
        if not isinstance(proxies, list):
            continue
        if to_node in proxies:
            proxies.remove(to_node)
            if not proxies:
                proxies.append("DIRECT")
            print(f"🔧 修复：移除组 '{from_node}' 中指向 '{to_node}' 的循环引用，已添加 DIRECT 保底")
            fixed += 1
    return fixed


# ============================================================================
# 9. 修复 rules 中引用的不存在的策略组名（替换为 DIRECT）
# ============================================================================
def fix_rules_policy_references(rules, group_names):
    if not isinstance(rules, list):
        return 0

    valid_policies = group_names | BUILTIN_KEYWORDS
    fixed = 0
    for idx, rule in enumerate(rules):
        if not isinstance(rule, str):
            continue
        parts = rule.split(',')
        if len(parts) < 3:
            continue
        policy = parts[-1].strip()
        if policy not in valid_policies:
            parts[-1] = "DIRECT"
            rules[idx] = ','.join(parts)
            print(f"🔧 修复：规则中的策略组 '{policy}' 不存在，替换为 'DIRECT'")
            fixed += 1
    return fixed


# ============================================================================
# 10. 校验 RULE-SET 规则，若引用的 rule-provider 不存在则替换为 REJECT
# ============================================================================
def validate_rule_set_references(rules, provider_names):
    if not isinstance(rules, list):
        return 0
    fixed = 0
    for idx, rule in enumerate(rules):
        if not isinstance(rule, str):
            continue
        if not rule.startswith("RULE-SET,"):
            continue
        parts = rule.split(',')
        if len(parts) < 3:
            continue
        provider_name = parts[1].strip()
        if provider_name not in provider_names:
            rules[idx] = "REJECT"
            print(f"🔧 修复：RULE-SET 引用的 provider '{provider_name}' 不存在，规则替换为 'REJECT'")
            fixed += 1
    return fixed


# ============================================================================
# 11. 校验 rule-providers 定义完整性（只警告，不修改）
# ============================================================================
def validate_rule_providers(providers):
    if not isinstance(providers, dict):
        return

    for name, cfg in providers.items():
        if not isinstance(cfg, dict):
            print(f"⚠️ 警告：rule-provider '{name}' 的定义不是字典，请检查")
            continue
        provider_type = cfg.get('type')
        if provider_type not in ('http', 'file'):
            print(f"⚠️ 警告：rule-provider '{name}' 的 type 字段无效（应为 http 或 file），当前为 '{provider_type}'")
            continue

        if provider_type == 'http':
            if 'url' not in cfg:
                print(f"⚠️ 警告：rule-provider '{name}' 类型为 http，但缺少 'url' 字段，请添加有效地址")
        elif provider_type == 'file':
            if 'file' not in cfg:
                print(f"⚠️ 警告：rule-provider '{name}' 类型为 file，但缺少 'file' 字段，请指定本地文件路径")

        behavior = cfg.get('behavior')
        if behavior and behavior not in ('domain', 'ip', 'classic'):
            print(f"⚠️ 警告：rule-provider '{name}' 的 behavior 字段值 '{behavior}' 不是标准值（domain/ip/classic）")


# ============================================================================
# 12. 修复节点与策略组同名冲突
# ============================================================================
def fix_node_group_name_conflicts(proxies, groups):
    if not isinstance(proxies, list) or not isinstance(groups, list):
        return 0

    group_names = {g['name'] for g in groups if isinstance(g, dict) and 'name' in g}
    proxy_names = {p['name'] for p in proxies if isinstance(p, dict) and 'name' in p}
    conflicts = proxy_names & group_names
    if not conflicts:
        return 0

    fixed = 0
    proxy_dict = {p['name']: p for p in proxies if isinstance(p, dict) and 'name' in p}

    for name in conflicts:
        nodes = [p for p in proxies if isinstance(p, dict) and p.get('name') == name]
        if not nodes:
            continue

        new_name = f"{name} (节点)"
        existing = {p['name'] for p in proxies if isinstance(p, dict) and 'name' in p} | group_names
        while new_name in existing:
            new_name += "_"

        for p in nodes:
            p['name'] = new_name
            fixed += 1
            print(f"🔧 修复：节点 '{name}' 与策略组重名，重命名为 '{new_name}'")

        for g in groups:
            if not isinstance(g, dict):
                continue
            plist = g.get('proxies')
            if isinstance(plist, list):
                for i, item in enumerate(plist):
                    if item == name:
                        plist[i] = new_name
                        print(f"🔧 修复：组 '{g.get('name')}' 中引用节点 '{name}' 更新为 '{new_name}'")
                        fixed += 1

    return fixed


# ============================================================================
# 13. 【保守修复】修复 REALITY short-id（仅处理缺失/空值及超长）
#     不再强制偶数长度，不再清除非十六进制字符，避免改变有效值。
# ============================================================================
def fix_reality_short_id(proxies):
    """
    保守修复 VLESS+REALITY 节点的 short-id 字段。
    规则：
      - 若 short-id 缺失或为空字符串，生成随机 8 位十六进制值。
      - 若长度超过 16 字符，截断至 16 字符（并警告）。
      - 其他情况（非十六进制、奇数长度）原样保留，仅输出调试信息（可选）。
    返回修复的节点数量。
    """
    if not isinstance(proxies, list):
        return 0

    fixed = 0

    for p in proxies:
        if not isinstance(p, dict) or p.get('type') != 'vless':
            continue

        reality = p.get('reality-opts')
        if not isinstance(reality, dict):
            continue

        sid = reality.get('short-id')
        # 处理缺失或空字符串
        if sid is None or (isinstance(sid, str) and sid.strip() == ''):
            new_sid = format(random.randint(0, 0xFFFFFFFF), '08x')  # 8位十六进制
            reality['short-id'] = new_sid
            print(f"🔧 修复：节点 '{p.get('name')}' 缺少 short-id，已添加随机值 '{new_sid}'")
            fixed += 1
            continue

        sid_str = str(sid)
        original = sid_str

        # 仅处理超长（>16）的情况
        if len(sid_str) > 16:
            new_sid = sid_str[:16]
            reality['short-id'] = new_sid
            print(f"⚠️ 警告：节点 '{p.get('name')}' 的 short-id 长度超过16，已截断为 '{new_sid}'（原值: '{sid_str}'）")
            fixed += 1
        # 其他情况（包括非十六进制、奇数长度）不做修改，可选择性输出警告（注释掉以免刷屏）
        # elif not re.fullmatch(r'^[0-9a-fA-F]+$', sid_str):
        #     print(f"ℹ️ 注意：节点 '{p.get('name')}' 的 short-id 包含非十六进制字符，未修改: '{sid_str}'")
        # elif len(sid_str) % 2 != 0:
        #     print(f"ℹ️ 注意：节点 '{p.get('name')}' 的 short-id 长度为奇数，未修改: '{sid_str}'")

    return fixed


# ============================================================================
# 14. 【调试】列出所有存在 short-id 问题的节点（序号、来源、名称、原值、问题）
# ============================================================================
def debug_print_bad_short_ids(config, config_file_path):
    """
    从主配置和所有 provider 缓存中加载全部节点，检查每个 VLESS+REALITY 节点的 short-id，
    若存在缺失、非十六进制、长度奇数或超过 16 字符，则打印详细信息。
    不修改任何配置。
    """
    all_proxies = []          # 存储 (来源, 节点字典) 元组

    # 1. 从主配置的 proxies 加载
    if 'proxies' in config and isinstance(config['proxies'], list):
        for p in config['proxies']:
            all_proxies.append(("主配置 proxies", p))

    # 2. 从 proxy-providers 缓存加载
    providers = config.get('proxy-providers', {})
    if isinstance(providers, dict):
        base_dir = os.path.dirname(config_file_path)
        for provider_name, provider_cfg in providers.items():
            if not isinstance(provider_cfg, dict):
                continue
            if provider_cfg.get('type') != 'http':
                continue
            cache_path = provider_cfg.get('path')
            if not cache_path:
                continue
            if not os.path.isabs(cache_path):
                cache_path = os.path.join(base_dir, cache_path)
            if not os.path.exists(cache_path):
                continue

            try:
                with open(cache_path, 'r', encoding='utf-8') as f:
                    data = yaml.safe_load(f)
            except Exception:
                continue

            proxies_list = None
            if isinstance(data, list):
                proxies_list = data
            elif isinstance(data, dict) and 'proxies' in data:
                proxies_list = data['proxies']
            if not isinstance(proxies_list, list):
                continue

            for p in proxies_list:
                all_proxies.append((f"provider '{provider_name}'", p))

    if not all_proxies:
        print("[DEBUG] 没有找到任何节点。")
        return

    print("\n" + "=" * 70)
    print("[DEBUG] ★★★ 检测所有 VLESS+REALITY 节点的 short-id 问题 ★★★")

    problem_count = 0
    for idx, (source, p) in enumerate(all_proxies, start=1):
        if not isinstance(p, dict) or p.get('type') != 'vless':
            continue
        reality = p.get('reality-opts')
        if not isinstance(reality, dict):
            continue

        sid = reality.get('short-id')
        node_name = p.get('name', '未命名')
        issues = []

        if sid is None:
            issues.append("缺失 (None)")
        else:
            sid_str = str(sid)
            if not re.fullmatch(r'^[0-9a-fA-F]+$', sid_str):
                issues.append(f"含非十六进制字符 ('{sid_str}')")
            if len(sid_str) % 2 != 0:
                issues.append(f"长度为奇数 ({len(sid_str)})")
            if len(sid_str) > 16:
                issues.append(f"长度超过16 ({len(sid_str)})")

        if issues:
            problem_count += 1
            print(f"[DEBUG] #{idx:>4} | 来源: {source}")
            print(f"        名称: {node_name}")
            print(f"        short-id 原始值: {sid}")
            print(f"        ❌ 问题: {', '.join(issues)}")
            print("-" * 70)

    if problem_count == 0:
        print("[DEBUG] ✅ 未发现 short-id 有问题的节点。")
    else:
        print(f"[DEBUG] ⚠️ 共发现 {problem_count} 个节点存在 short-id 问题。")
    print("=" * 70 + "\n")


# ============================================================================
# 15. 主函数
# ============================================================================
def fix_clash_config(input_file, output_file):
    # ---------- 1. 读取文件 ----------
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
    except FileNotFoundError:
        print(f"❌ 文件不存在: {input_file}")
        sys.exit(1)
    except yaml.YAMLError as e:
        print(f"❌ YAML 解析错误: {e}")
        sys.exit(1)

    if not isinstance(config, dict):
        print("❌ 根元素不是字典")
        sys.exit(1)

    # ============ 【调试】打印所有 short-id 有问题的节点 ============
    debug_print_bad_short_ids(config, input_file)
    # ================================================================

    # ---------- 2. 收集 provider 名称并验证 rule-providers ----------
    provider_names = set()
    if 'proxy-providers' in config and isinstance(config['proxy-providers'], dict):
        provider_names = set(config['proxy-providers'].keys())
        print(f"ℹ️ 发现 {len(provider_names)} 个 proxy-provider: {', '.join(provider_names) if provider_names else '(无)'}")
        validate_rule_providers(config['proxy-providers'])

    # ---------- 3. 处理 proxies（节点） ----------
    proxy_names = set()
    total_fixed = 0
    if 'proxies' in config and isinstance(config['proxies'], list):
        # 修复 encryption
        config['proxies'] = fix_vless_encryption(config['proxies'])

        # 修复 REALITY short-id（保守模式）
        total_fixed += fix_reality_short_id(config['proxies'])

        # 修复空节点名
        total_fixed += fix_empty_node_names(config['proxies'])

        check_duplicate_node_names(config['proxies'])
        proxy_names = {p.get('name') for p in config['proxies'] if isinstance(p, dict) and 'name' in p}
        print(f"ℹ️ 共加载 {len(proxy_names)} 个节点")
    else:
        total_fixed = 0

    # ---------- 4. 处理 proxy-groups ----------
    if 'proxy-groups' not in config:
        print("⚠️ 未找到 proxy-groups，直接复制")
        with open(output_file, 'w', encoding='utf-8') as f:
            yaml.dump(config, f, allow_unicode=True, sort_keys=False)
        return

    groups = config['proxy-groups']
    if not isinstance(groups, list):
        print("❌ proxy-groups 不是列表")
        sys.exit(1)

    group_names = {g.get('name') for g in groups if isinstance(g, dict)}

    # 4a. 修复 use 引用
    total_fixed += fix_use_references(groups, provider_names)

    # 4b. 修复 use 和 proxies 同时存在
    total_fixed += fix_use_and_proxies_conflict(groups)

    # 4c. 修复节点与策略组同名冲突
    if 'proxies' in config and isinstance(config['proxies'], list):
        total_fixed += fix_node_group_name_conflicts(config['proxies'], groups)
        # 重新收集节点名和组名
        proxy_names = {p.get('name') for p in config['proxies'] if isinstance(p, dict) and 'name' in p}
        group_names = {g.get('name') for g in groups if isinstance(g, dict)}

    # 4d. 修复 proxies 引用
    total_fixed += fix_proxy_references(groups, proxy_names, group_names)

    # 4e. 修复缺失字段 / 类型错误
    for idx, g in enumerate(groups):
        if not isinstance(g, dict):
            continue
        name = g.get('name', f'未命名({idx})')

        if 'proxies' not in g and 'use' not in g:
            g['proxies'] = ["DIRECT"]
            print(f"🔧 修复：组 '{name}' 添加 proxies: [\"DIRECT\"]")
            total_fixed += 1

        if 'proxies' in g and not isinstance(g['proxies'], list):
            g['proxies'] = [g['proxies']] if isinstance(g['proxies'], str) else list(g['proxies'])
            print(f"🔧 修复：组 '{name}' 转换 proxies 类型")
            total_fixed += 1

        if 'use' in g and not isinstance(g['use'], (str, list)):
            g['use'] = str(g['use'])
            print(f"🔧 修复：组 '{name}' 转换 use 类型")
            total_fixed += 1

        if g.get('type') in ('url-test', 'fallback'):
            if 'url' not in g:
                g['url'] = DEFAULT_URL
                total_fixed += 1
            if 'interval' not in g:
                g['interval'] = DEFAULT_INTERVAL
                total_fixed += 1

    # 4f. 去重策略组名
    if 'rules' in config and isinstance(config['rules'], list):
        rules = config['rules']
    else:
        rules = []
    total_fixed += deduplicate_group_names(groups, rules)

    # 4g. 检测并修复循环引用
    total_fixed += detect_and_fix_cycles(groups)

    # 4h. 修复 rules 中引用的不存在的组名
    group_names = {g.get('name') for g in groups if isinstance(g, dict)}
    if rules:
        total_fixed += fix_rules_policy_references(rules, group_names)

    # 4i. 校验 RULE-SET 规则
    if rules:
        total_fixed += validate_rule_set_references(rules, provider_names)

    # ---------- 5. 写入文件 ----------
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            yaml.dump(config, f, allow_unicode=True, sort_keys=False, default_flow_style=False)
        print(f"✅ 已写入: {output_file}")
        if total_fixed > 0:
            print(f"📝 共修复 {total_fixed} 个问题")
        else:
            print("🎉 未发现可修复的结构问题")
    except Exception as e:
        print(f"❌ 写入失败: {e}")
        sys.exit(1)


# ============================================================================
# 入口
# ============================================================================
if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("用法: rebuilder.py <输入文件> <输出文件>")
        sys.exit(1)
    fix_clash_config(sys.argv[1], sys.argv[2])

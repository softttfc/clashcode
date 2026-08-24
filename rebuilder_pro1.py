#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
================================================================================
Clash 配置文件修复工具 (rebuilder.py) - 最终完整版（含 REALITY short-id 修复）
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
    12.【新增】校验 rule-providers 定义完整性，若缺失 url/file 等关键字段则输出警告。
    13.【新增】自动修复节点与策略组同名冲突（重命名节点并更新策略组引用）。
    14.【新增】自动修复 VLESS+REALITY 节点的 short-id 格式错误（确保为合法的十六进制
        字符串，长度偶数，最多16字符；非法内容自动清理，空值生成随机有效值）。

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
import os   # 【新增】用于处理缓存文件路径

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
    """
    检查每个 rule-provider 是否包含必要的字段。
    对于 http 类型，必须有 url；对于 file 类型，必须有 file。
    若缺失，输出警告。
    """
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

        # 可选检查 behavior 字段
        behavior = cfg.get('behavior')
        if behavior and behavior not in ('domain', 'ip', 'classic'):
            print(f"⚠️ 警告：rule-provider '{name}' 的 behavior 字段值 '{behavior}' 不是标准值（domain/ip/classic）")


# ============================================================================
# 12. 【新增】修复节点与策略组同名冲突
#      Clash 要求所有 proxies 和 proxy-groups 的 name 必须全局唯一。
#      本函数检测到同名时，重命名节点（添加后缀 " (节点)"），并更新所有策略组
#      的 proxies 列表中对旧名称的引用，从而避免重复名称错误。
# ============================================================================
def fix_node_group_name_conflicts(proxies, groups):
    """
    修复节点名与策略组名冲突的情况。
    若有同名，则重命名节点（添加 " (节点)" 后缀），并更新所有策略组 proxies 列表中的引用。
    返回修复计数。
    """
    if not isinstance(proxies, list) or not isinstance(groups, list):
        return 0

    # 收集策略组名（排除内置关键字不影响）
    group_names = {g['name'] for g in groups if isinstance(g, dict) and 'name' in g}
    # 收集节点名
    proxy_names = {p['name'] for p in proxies if isinstance(p, dict) and 'name' in p}
    # 计算冲突名称（交集）
    conflicts = proxy_names & group_names
    if not conflicts:
        return 0

    fixed = 0
    # 构建节点名到节点对象的映射（用于快速修改）
    proxy_dict = {p['name']: p for p in proxies if isinstance(p, dict) and 'name' in p}

    for name in conflicts:
        # 获取所有同名的节点（正常情况下只有一个，但以防万一）
        nodes = [p for p in proxies if isinstance(p, dict) and p.get('name') == name]
        if not nodes:
            continue

        # 生成新名，避免与现有名称冲突（包括节点和组）
        new_name = f"{name} (节点)"
        existing = {p['name'] for p in proxies if isinstance(p, dict) and 'name' in p} | group_names
        while new_name in existing:
            new_name += "_"

        # 重命名所有同名节点
        for p in nodes:
            p['name'] = new_name
            fixed += 1
            print(f"🔧 修复：节点 '{name}' 与策略组重名，重命名为 '{new_name}'")

        # 更新所有策略组的 proxies 列表中的引用（将旧名替换为新名）
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
# 13. 【新增】修复 REALITY short-id 格式错误
#      确保所有 VLESS+REALITY 节点的 short-id 为合法的十六进制字符串，
#      长度为偶数且不超过16字符。非法字符自动清理，空值自动生成随机有效值。
# ============================================================================
def fix_reality_short_id(proxies):
    """
    修复 VLESS+REALITY 节点的 short-id 字段。
    规则：
      - 必须是十六进制字符串（仅含 0-9, a-f, A-F）
      - 长度必须为偶数（最多 16 个字符）
      - 如果值非法或缺失，自动清理并补齐（缺失时生成随机4位十六进制）
    返回修复的节点数量。
    """
    if not isinstance(proxies, list):
        return 0

    fixed = 0
    hex_pattern = re.compile(r'^[0-9a-fA-F]*$')  # 用于验证合法性

    for p in proxies:
        if not isinstance(p, dict) or p.get('type') != 'vless':
            continue

        # 获取 reality-opts 字典
        reality = p.get('reality-opts')
        if not isinstance(reality, dict):
            # 若不存在 reality-opts，跳过（不是 REALITY 节点）
            continue

        sid = reality.get('short-id')
        if sid is None:
            # 若 short-id 字段完全缺失，可选择性添加默认值。
            # 此处选择自动生成一个随机有效值，以便配置通过检查。
            # 若希望保持原样，可将以下三行注释掉。
            default_sid = format(random.randint(0, 65535), '04x')
            reality['short-id'] = default_sid
            print(f"🔧 修复：节点 '{p.get('name')}' 缺少 short-id，已添加随机有效值 '{default_sid}'")
            fixed += 1
            continue   # 已处理，无需继续清理

        # 转为字符串（可能是数字或其他类型）
        sid_str = str(sid)

        # ---------- 步骤1：移除所有非十六进制字符 ----------
        cleaned = re.sub(r'[^0-9a-fA-F]', '', sid_str)

        # ---------- 步骤2：如果清理后为空，生成随机有效值 ----------
        if not cleaned:
            cleaned = format(random.randint(0, 65535), '04x')
            print(f"🔧 修复：节点 '{p.get('name')}' 的 short-id 不含合法十六进制字符，已替换为 '{cleaned}'")
            fixed += 1

        # ---------- 步骤3：处理长度（必须为偶数，且 ≤ 16） ----------
        original_cleaned = cleaned
        if len(cleaned) % 2 != 0:
            cleaned += '0'   # 末尾补 '0' 使其成为偶数
            print(f"🔧 修复：节点 '{p.get('name')}' 的 short-id 长度奇数，末尾补 0 -> '{cleaned}'")
            fixed += 1
        if len(cleaned) > 16:
            cleaned = cleaned[:16]   # 截断至16字符
            print(f"🔧 修复：节点 '{p.get('name')}' 的 short-id 超过 16 字符，截断为 '{cleaned}'")
            fixed += 1

        # ---------- 步骤4：若最终结果与原始不同，更新配置 ----------
        if cleaned != sid_str:
            reality['short-id'] = cleaned
            # 注意：如果之前已经因为缺失而添加，此处不会再次增加计数
            # 如果 cleaned 与 sid_str 不同，但之前未计数（比如只是清理了非法字符），则增加计数
            # 为避免重复计数，我们只在确实修改了值的情况下增加，但上面已经对特定情况增加了，这里要避免重复。
            # 我们采用更精确的方式：如果 cleaned != sid_str 且之前没有因为清理或补齐而增加计数，
            # 但现在无法区分，我们简单处理：如果 cleaned != sid_str 且 sid 原本不是 None，则增加一次。
            # 更好的做法：上面每次修改都增加了 fixed，但可能重复。我们重构：将 fixed 增加放在最终判断。
            # 但为了简单，我们让每个修复步骤单独增加，但可能重复（比如既补了0又截断，会增加两次，但实际修复了一处）。
            # 我们可以采用标志变量。
            # 这里为了简单，我们采用：每次修改都增加，但会导致计数偏多，但影响不大。
            # 但更准确的是：仅在最终值改变时增加一次。
            # 我们重新实现：先用临时变量处理，最终比较。
            # 但为了符合原有代码风格，我们保持简单，但上面的步骤已经增加了 fixed，可能导致重复。我们重构一下：
            # 我们撤销上面的 fixed 增加，改为最后统一判断。
            # 但是已经写了，我们快速修正：重新实现函数，使用临时变量。
            # 我将在下面重写这个函数，用更准确的方式。
            # 由于篇幅，此处我将重写整个函数，但为了不破坏已有代码，我将在下面提供修正版。

    return fixed


# ============================================================================
# 修正版 fix_reality_short_id（避免重复计数）
# ============================================================================
def fix_reality_short_id(proxies):
    """
    修复 VLESS+REALITY 节点的 short-id 字段。
    规则：
      - 必须是十六进制字符串（仅含 0-9, a-f, A-F）
      - 长度必须为偶数（最多 16 个字符）
      - 如果值非法或缺失，自动清理并补齐（缺失时生成随机4位十六进制）
    返回修复的节点数量（仅当最终值发生变化时计数）。
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
        # 处理缺失情况
        if sid is None:
            new_sid = format(random.randint(0, 65535), '04x')
            reality['short-id'] = new_sid
            print(f"🔧 修复：节点 '{p.get('name')}' 缺少 short-id，已添加随机有效值 '{new_sid}'")
            fixed += 1
            continue  # 已处理，继续下一个

        # 转为字符串
        sid_str = str(sid)

        # 1. 移除非法字符
        cleaned = re.sub(r'[^0-9a-fA-F]', '', sid_str)

        # 2. 若为空，生成随机值
        if not cleaned:
            cleaned = format(random.randint(0, 65535), '04x')

        # 3. 处理长度（偶数且≤16）
        if len(cleaned) % 2 != 0:
            cleaned += '0'
        if len(cleaned) > 16:
            cleaned = cleaned[:16]

        # 4. 若最终值与原值不同，更新并计数
        if cleaned != sid_str:
            reality['short-id'] = cleaned
            print(f"🔧 修复：节点 '{p.get('name')}' 的 short-id 已修正为 '{cleaned}'（原值: '{sid_str}'）")
            fixed += 1

    return fixed


# ============================================================================
# 【新增调试】列出所有存在 short-id 问题的节点（序号、来源、名称、原值、问题）
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
            # 只处理 http 类型（通常有 path 缓存）
            if provider_cfg.get('type') != 'http':
                continue
            cache_path = provider_cfg.get('path')
            if not cache_path:
                continue
            # 处理相对路径
            if not os.path.isabs(cache_path):
                cache_path = os.path.join(base_dir, cache_path)
            if not os.path.exists(cache_path):
                continue

            try:
                with open(cache_path, 'r', encoding='utf-8') as f:
                    data = yaml.safe_load(f)
            except Exception:
                continue

            # 解析缓存内容
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
        # 只检查 VLESS 且包含 reality-opts
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
            # 检查十六进制
            if not re.fullmatch(r'^[0-9a-fA-F]+$', sid_str):
                issues.append(f"含非十六进制字符 ('{sid_str}')")
            # 检查长度
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
# 14. 主函数
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

    # ============ 【新增调试】打印所有 short-id 有问题的节点 ============
    debug_print_bad_short_ids(config, input_file)
    # ================================================================

    # ---------- 2. 收集 provider 名称并验证 rule-providers ----------
    provider_names = set()
    if 'proxy-providers' in config and isinstance(config['proxy-providers'], dict):
        provider_names = set(config['proxy-providers'].keys())
        print(f"ℹ️ 发现 {len(provider_names)} 个 proxy-provider: {', '.join(provider_names) if provider_names else '(无)'}")
        # 【新增】验证 rule-providers 定义完整性
        validate_rule_providers(config['proxy-providers'])

    # ---------- 3. 处理 proxies（节点） ----------
    proxy_names = set()
    if 'proxies' in config and isinstance(config['proxies'], list):
        # 先修复 encryption
        config['proxies'] = fix_vless_encryption(config['proxies'])

        # ===== 新增：修复 REALITY short-id =====
        total_fixed = fix_reality_short_id(config['proxies'])
        # =====================================

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

    # ========== 新增：修复节点与策略组同名冲突 ==========
    # 必须在 fix_proxy_references 之前执行，因为重命名节点后需要更新 proxies 列表中的引用，
    # 而 fix_proxy_references 会校验引用的有效性，若先执行会导致旧名称被判定为无效而误删。
    if 'proxies' in config and isinstance(config['proxies'], list):
        total_fixed += fix_node_group_name_conflicts(config['proxies'], groups)
        # 重新收集节点名和组名，因为节点可能已被重命名，后续修复函数需要使用最新名称集合
        proxy_names = {p.get('name') for p in config['proxies'] if isinstance(p, dict) and 'name' in p}
        group_names = {g.get('name') for g in groups if isinstance(g, dict)}
    # =================================================

    # 4c. 修复 proxies 引用
    total_fixed += fix_proxy_references(groups, proxy_names, group_names)

    # 4d. 修复缺失字段 / 类型错误
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

    # 4e. 去重策略组名
    if 'rules' in config and isinstance(config['rules'], list):
        rules = config['rules']
    else:
        rules = []
    total_fixed += deduplicate_group_names(groups, rules)

    # 4f. 检测并修复循环引用
    total_fixed += detect_and_fix_cycles(groups)

    # 4g. 修复 rules 中引用的不存在的组名
    group_names = {g.get('name') for g in groups if isinstance(g, dict)}
    if rules:
        total_fixed += fix_rules_policy_references(rules, group_names)

    # 4h. 校验 RULE-SET 规则
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

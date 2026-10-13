#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
================================================================================
Clash 配置文件修复工具 (rebuilder_pro1.py) - 最终完整版
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
    14.【本次新增】最终安全化：
        - 节点名清理（...、#、&、*、|、>、< 等危险字符）
        - network 字段清理（去除 # 污染、非白名单值重置为 tcp）
        - VLESS security: none 与 reality-opts 冲突修复
        - Adblock 规则残留符号清理（^、||、@@）
        - 使用 NoAliasDumper 禁止 YAML 锚点/别名输出

【用法】
    python rebuilder_pro.py <输入文件> <输出文件>

【全局变量】
    DEFAULT_URL                  - 测速地址
    DEFAULT_INTERVAL             - 检测间隔
    VLESS_DEFAULT_ENCRYPTION     - VLESS 加密修正值
    VALID_NETWORKS               - network 字段合法值白名单
================================================================================
"""

import sys
import re
import yaml
from collections import Counter, defaultdict

# ============================================================================
# 全局配置（可按需修改）
# ============================================================================
DEFAULT_URL = "http://www.gstatic.com/generate_204"
DEFAULT_INTERVAL = 300
VLESS_DEFAULT_ENCRYPTION = "none"

# 内置关键字（Clash 保留策略）
BUILTIN_KEYWORDS = {"DIRECT", "REJECT", "REJECT-DROP", "PASS", "GLOBAL", "SOCKS5", "HTTP"}

# 【新增】network 字段合法值白名单
VALID_NETWORKS = {
    'tcp', 'ws', 'grpc', 'h2', 'http', 'httpupgrade', 'xhttp', 'raw',
    'udp', 'quic', '',
}


# ============================================================================
# 【新增】YAML 安全 Dumper：禁止锚点/别名，特殊字符串自动加引号
# ============================================================================
class NoAliasDumper(yaml.SafeDumper):
    """禁止 YAML 锚点/别名输出，避免 Clash Verge 解析异常。"""

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

        behavior = cfg.get('behavior')
        if behavior and behavior not in ('domain', 'ip', 'classic'):
            print(f"⚠️ 警告：rule-provider '{name}' 的 behavior 字段值 '{behavior}' 不是标准值（domain/ip/classic）")


# ============================================================================
# 12. 修复节点与策略组同名冲突
# ============================================================================
def fix_node_group_name_conflicts(proxies, groups):
    """
    修复节点名与策略组名冲突的情况。
    若有同名，则重命名节点（添加 " (节点)" 后缀），并更新所有策略组 proxies 列表中的引用。
    返回修复计数。
    """
    if not isinstance(proxies, list) or not isinstance(groups, list):
        return 0

    group_names = {g['name'] for g in groups if isinstance(g, dict) and 'name' in g}
    proxy_names = {p['name'] for p in proxies if isinstance(p, dict) and 'name' in p}
    conflicts = proxy_names & group_names
    if not conflicts:
        return 0

    fixed = 0

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
# 14.【本次新增】最终安全化
#     功能：
#       1. 节点名清理（...、#、&、*、|、>、< 等危险字符）
#       2. network 字段清理（去除 # 污染、非白名单值重置为 tcp）
#       3. VLESS security: none 与 reality-opts 冲突修复
#       4. Adblock 规则残留符号清理（^、||、@@）
#       5. IPv6 server 去方括号
#     说明：
#       本函数在写入最终文件前调用，作为最后一道防线。
#       原有 13 个修复函数已处理结构性引用问题，本函数只负责 YAML 语法安全
#       和字段合法性，不改变原有流程。
# ============================================================================
def sanitize_final_config(config):
    """
    最终安全化处理。返回修复计数。
    """
    fixed = 0

    # ---------- 4.1 节点名清理 + network 清理 + VLESS reality 修复 ----------
    proxies = config.get('proxies', [])
    if isinstance(proxies, list):
        for p in proxies:
            if not isinstance(p, dict):
                continue

            # 4.1.1 节点名清理
            if 'name' in p and isinstance(p['name'], str):
                old = p['name']
                new = old.replace('...', '…').replace('#', '＃').replace('&', '＆') \
                         .replace('*', '＊').replace('|', '｜').replace('>', '＞').replace('<', '＜')
                new = ''.join(ch for ch in new if ord(ch) >= 0x20 or ch == ' ')
                new = new.strip() or "未命名"
                if new != old:
                    p['name'] = new
                    fixed += 1

            # 4.1.2 network 字段清理
            if 'network' in p:
                net = str(p['network']).split('#')[0].split('&')[0].strip().lower()
                if net not in VALID_NETWORKS:
                    net = 'tcp'
                if net != p['network']:
                    p['network'] = net
                    fixed += 1

            # 4.1.3 IPv6 server 去方括号
            if 'server' in p and isinstance(p['server'], str):
                srv = p['server']
                if srv.startswith('[') and srv.endswith(']'):
                    p['server'] = srv[1:-1]
                    fixed += 1

            # 4.1.4 VLESS security 与 reality 冲突修复
            if p.get('type') == 'vless' and 'reality-opts' in p:
                if p.get('security') != 'reality':
                    p['security'] = 'reality'
                    fixed += 1
                if p.get('tls') is not True:
                    p['tls'] = True
                    fixed += 1

    # ---------- 4.2 Adblock 规则残留符号清理 ----------
    rules = config.get('rules', [])
    if isinstance(rules, list):
        for i, rule in enumerate(rules):
            if not isinstance(rule, str):
                continue
            parts = rule.split(',')
            if len(parts) >= 3 and parts[0] in ('DOMAIN-SUFFIX', 'DOMAIN-KEYWORD', 'DOMAIN'):
                match = parts[1]
                if '^' in match or '||' in match or '@@' in match or '|' in match:
                    match = re.sub(r'[\^|@]', '', match)
                    if '||' in match:
                        match = match.split('||')[0]
                    match = match.strip()
                    if not match:
                        # 清空后无法恢复，丢弃该条规则
                        rules[i] = "REJECT"
                        fixed += 1
                        continue
                    parts[1] = match
                    rules[i] = ','.join(parts)
                    fixed += 1

    return fixed


# ============================================================================
# 13. 主函数
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

    # ---------- 2. 收集 provider 名称并验证 rule-providers ----------
    provider_names = set()
    if 'proxy-providers' in config and isinstance(config['proxy-providers'], dict):
        provider_names = set(config['proxy-providers'].keys())
        print(f"ℹ️ 发现 {len(provider_names)} 个 proxy-provider: {', '.join(provider_names) if provider_names else '(无)'}")
        validate_rule_providers(config['proxy-providers'])

    # ---------- 3. 处理 proxies（节点） ----------
    proxy_names = set()
    if 'proxies' in config and isinstance(config['proxies'], list):
        config['proxies'] = fix_vless_encryption(config['proxies'])
        total_fixed = fix_empty_node_names(config['proxies'])
        check_duplicate_node_names(config['proxies'])
        proxy_names = {p.get('name') for p in config['proxies'] if isinstance(p, dict) and 'name' in p}
        print(f"ℹ️ 共加载 {len(proxy_names)} 个节点")
    else:
        total_fixed = 0

    # ---------- 4. 处理 proxy-groups ----------
    if 'proxy-groups' not in config:
        print("⚠️ 未找到 proxy-groups，直接复制")
        # 仍进行最终安全化，保证输出合法
        total_fixed = total_fixed if 'total_fixed' in dir() else 0
        total_fixed += sanitize_final_config(config)
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                yaml.dump(config, f, Dumper=NoAliasDumper,
                          allow_unicode=True, sort_keys=False, default_flow_style=False)
            print(f"✅ 已写入: {output_file}（共修复 {total_fixed} 个问题）")
        except Exception as e:
            print(f"❌ 写入失败: {e}")
            sys.exit(1)
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

    # ========== 修复节点与策略组同名冲突 ==========
    if 'proxies' in config and isinstance(config['proxies'], list):
        total_fixed += fix_node_group_name_conflicts(config['proxies'], groups)
        proxy_names = {p.get('name') for p in config['proxies'] if isinstance(p, dict) and 'name' in p}
        group_names = {g.get('name') for g in groups if isinstance(g, dict)}
    # ============================================

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

    # ---------- 5. 【本次新增】最终安全化 ----------
    print("\n🧹 执行最终安全化...")
    sanitize_count = sanitize_final_config(config)
    if sanitize_count:
        print(f"📝 最终安全化修复 {sanitize_count} 处")
    total_fixed += sanitize_count

    # ---------- 6. 写入文件（使用 NoAliasDumper） ----------
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
        print("用法: rebuilder_pro.py <输入文件> <输出文件>")
        sys.exit(1)
    fix_clash_config(sys.argv[1], sys.argv[2])

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
check.py - Clash 节点文件校验工具

用法:
    python check.py <节点文件.yml> <错误日志输出.txt>

功能:
    1.  YAML 语法解析（锚点/别名检测降级为 INFO）
    2.  proxies 段结构校验
    3.  每个节点的必填字段、协议字段校验
    4.  节点名合法性（#、...、特殊字符、未加引号等）
    5.  节点名重复检测
    6.  proxy-groups 引用有效性
    7.  rules 引用有效性、语法合法性
    8.  已知会导致 Clash Verge 报 "invalid yaml" 的问题

输出:
    错误日志分级为 [FATAL] / [ERROR] / [WARN] / [INFO]
    FATAL 和 ERROR 是导致 Clash Verge 拒绝加载的直接原因

本次修改（相对旧版）:
    - YAML 锚点/别名检测由 WARN 降级为 INFO（mihomo 官方支持锚点）
    - PyYAML 标签 !!str/!!int/!!bool 检测由 ERROR 降级为 INFO
    - 从 KNOWN_PROXY_TYPES 中移除 shadowtls（非独立代理类型）
    - 其余检查逻辑保持不变
"""

import sys
import os
import re
import yaml
from collections import Counter, defaultdict


# ============================================================================
# 常量
# ============================================================================
BUILTIN_POLICIES = {
    'DIRECT', 'REJECT', 'REJECT-DROP', 'PASS', 'GLOBAL',
    'SOCKS5', 'HTTP', 'COMPATIBLE',
}

# mihomo 支持的 type
# 注意: shadowtls 不是独立代理类型，而是 VLESS/AnyTLS 的 TLS 伪装选项，因此不列入
KNOWN_PROXY_TYPES = {
    'ss', 'ssr', 'vmess', 'vless', 'trojan',
    'hysteria', 'hysteria2', 'hy2', 'tuic', 'anytls',
    'http', 'https', 'socks5', 'socks5h', 'snell', 'wireguard',
    'mieru', 'ssh', 'juicity',
}

# 较新的协议，老版本 mihomo 不支持，会直接拒绝
NEW_PROXY_TYPES = {'anytls', 'mieru', 'juicity', 'hysteria2', 'tuic'}

# 合法 network 值
VALID_NETWORKS = {
    'tcp', 'ws', 'grpc', 'h2', 'http', 'httpupgrade', 'xhttp', 'raw', '',
}

# 合法 rule type
VALID_RULE_TYPES = {
    'DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD', 'DOMAIN-REGEX',
    'GEOSITE', 'GEOIP', 'IP-CIDR', 'IP-CIDR6', 'IP-SUFFIX', 'IP-ASN',
    'SRC-GEOIP', 'SRC-IP-CIDR', 'SRC-IP-SUFFIX', 'SRC-PORT',
    'DST-PORT', 'IN-PORT', 'IN-TYPE', 'IN-USER', 'IN-NAME',
    'PROCESS-PATH', 'PROCESS-PATH-REGEX', 'PROCESS-NAME', 'PROCESS-NAME-REGEX',
    'UID', 'NETWORK', 'DSCP', 'RULE-SET', 'AND', 'OR', 'NOT',
    'SUB-RULE', 'MATCH',
}


# ============================================================================
# 报告器
# ============================================================================
class Reporter:
    def __init__(self, out_file):
        self.out = out_file
        self.counts = {'FATAL': 0, 'ERROR': 0, 'WARN': 0, 'INFO': 0}

    def log(self, level, category, msg, location=''):
        self.counts[level] = self.counts.get(level, 0) + 1
        loc = f' @ {location}' if location else ''
        line = f'[{level}] [{category}] {msg}{loc}'
        print(line)
        self.out.write(line + '\n')

    def fatal(self, cat, msg, loc=''): self.log('FATAL', cat, msg, loc)
    def error(self, cat, msg, loc=''): self.log('ERROR', cat, msg, loc)
    def warn(self, cat, msg, loc=''):  self.log('WARN',  cat, msg, loc)
    def info(self, cat, msg, loc=''):  self.log('INFO',  cat, msg, loc)

    def summary(self):
        self.out.write('\n')
        self.out.write('=' * 70 + '\n')
        self.out.write('汇总\n')
        self.out.write('=' * 70 + '\n')
        self.out.write(f"FATAL: {self.counts['FATAL']}\n")
        self.out.write(f"ERROR: {self.counts['ERROR']}\n")
        self.out.write(f"WARN : {self.counts['WARN']}\n")
        self.out.write(f"INFO : {self.counts['INFO']}\n")
        if self.counts['FATAL'] == 0 and self.counts['ERROR'] == 0:
            self.out.write('\n结论: 未发现会导致 Clash 拒绝加载的问题。\n')
        else:
            self.out.write('\n结论: 存在 FATAL/ERROR，这会导致 Clash Verge 报 "invalid yaml"。\n')


# ============================================================================
# 1. YAML 解析与锚点检测
# ============================================================================
def check_yaml_parse(path, rep):
    try:
        text = open(path, 'r', encoding='utf-8').read()
    except UnicodeDecodeError as e:
        rep.fatal('YAML', f'文件不是有效的 UTF-8: {e}')
        return None, None

    # 锚点 / 别名检测
    # mihomo 使用 gopkg.in/yaml.v3，官方支持 YAML 锚点/别名，不应据此拒绝
    # 因此降级为 INFO，仅供用户参考
    anchor_lines = []
    for i, line in enumerate(text.splitlines(), 1):
        if re.search(r'&\w+', line) or re.search(r'(?<![\w*])\*\w+', line):
            anchor_lines.append((i, line.rstrip()))
    if anchor_lines:
        rep.info('YAML', f'检测到 {len(anchor_lines)} 处 YAML 锚点/别名，'
                         f'mihomo 支持锚点，但建议使用 NoAliasDumper 避免兼容性问题。')
        for ln, content in anchor_lines[:5]:
            rep.info('YAML', f'  第 {ln} 行: {content[:100]}')

    # PyYAML 标签 !!str / !!int / !!bool
    # 这些都是标准 YAML 标签，mihomo 能正确解析为对应类型，不应据此拒绝
    # 因此降级为 INFO
    tag_lines = []
    for i, line in enumerate(text.splitlines(), 1):
        if '!!str' in line or '!!int' in line or '!!bool' in line:
            tag_lines.append((i, line.rstrip()))
    if tag_lines:
        rep.info('YAML', f'检测到 {len(tag_lines)} 处标准 YAML 标签（!!str 等），'
                         f'mihomo 可正确解析，但建议避免手工输出这些标签。')
        for ln, content in tag_lines[:5]:
            rep.info('YAML', f'  第 {ln} 行: {content[:100]}')

    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as e:
        rep.fatal('YAML', f'YAML 解析失败: {e}')
        return None, text

    return data, text


# ============================================================================
# 2. 节点字段校验
# ============================================================================
def check_proxy(proxy, idx, name_set, rep):
    loc = f'proxies[{idx}]'
    if not isinstance(proxy, dict):
        rep.error('PROXY', f'节点不是字典: {type(proxy).__name__}', loc)
        return

    name = proxy.get('name')
    ptype = proxy.get('type')
    server = proxy.get('server')
    port = proxy.get('port')

    # 必填
    if not name:
        rep.error('PROXY', '缺少 name 字段', loc)
    elif not isinstance(name, str):
        rep.error('PROXY', f'name 不是字符串: {type(name).__name__}', loc)
    else:
        # 节点名里的危险字符
        if name.endswith('...'):
            rep.error('PROXY', f'name 以 "..." 结尾，YAML 会当成文档结束符: {name!r}', loc)
        if '...' in name:
            rep.warn('PROXY', f'name 含 "..."，部分解析器会误判: {name!r}', loc)
        if '#' in name and not name.startswith('#'):
            # 若原始 YAML 没加引号，# 后内容会被当注释
            rep.warn('PROXY', f'name 含 "#"，如未加引号会被当成注释: {name!r}', loc)
        if '\n' in name or '\r' in name or '\t' in name:
            rep.error('PROXY', f'name 含控制字符（\\n/\\r/\\t）: {name!r}', loc)
        # 不可见字符（除常见空格）
        for ch in name:
            if ord(ch) < 0x20 and ch != ' ':
                rep.error('PROXY', f'name 含不可见控制字符 U+{ord(ch):04X}: {name!r}', loc)
                break

    if not ptype:
        rep.error('PROXY', '缺少 type 字段', loc)
    elif isinstance(ptype, str):
        if ptype.lower() not in KNOWN_PROXY_TYPES:
            rep.error('PROXY', f'未知协议类型: {ptype!r}', loc)
        elif ptype.lower() in NEW_PROXY_TYPES:
            rep.warn('PROXY', f'较新协议 {ptype!r}，老版本 Clash 核心可能不支持', loc)

    if not server:
        rep.error('PROXY', '缺少 server 字段', loc)
    elif isinstance(server, str):
        if ' ' in server or '\t' in server:
            rep.error('PROXY', f'server 含空白字符: {server!r}', loc)
        if server.startswith('[') and server.endswith(']'):
            rep.info('PROXY', f'server 是带方括号的 IPv6: {server!r}，'
                              f'Clash 规范要求去掉方括号', loc)

    if not port:
        rep.error('PROXY', '缺少 port 字段', loc)
    else:
        try:
            p = int(port)
            if p <= 0 or p > 65535:
                rep.error('PROXY', f'port 超出范围: {port}', loc)
        except (ValueError, TypeError):
            rep.error('PROXY', f'port 不是整数: {port!r}', loc)

    # network 字段
    net = proxy.get('network')
    if net is not None:
        if not isinstance(net, str):
            rep.error('PROXY', f'network 不是字符串: {net!r}', loc)
        else:
            n = net.strip().lower()
            if '#' in n:
                rep.error('PROXY', f'network 被 URL fragment 污染: {net!r}', loc)
            elif n not in VALID_NETWORKS:
                rep.error('PROXY', f'network 非法值: {net!r}', loc)

    # vless 的 security 与 reality 冲突
    if isinstance(ptype, str) and ptype.lower() == 'vless':
        if proxy.get('security') == 'none' and 'reality-opts' in proxy:
            rep.warn('PROXY', f'vless 同时存在 security: none 和 reality-opts，'
                              f'部分 mihomo 版本会判为字段冲突', loc)

    # ws-opts / grpc-opts 结构
    for opt in ('ws-opts', 'grpc-opts', 'h2-opts', 'http-opts', 'xhttp-opts', 'reality-opts'):
        if opt in proxy and not isinstance(proxy[opt], dict):
            rep.error('PROXY', f'{opt} 不是字典: {type(proxy[opt]).__name__}', loc)

    # name 重复
    if isinstance(name, str) and name:
        name_set[name].append(idx)


# ============================================================================
# 3. proxy-groups 校验
# ============================================================================
def check_groups(groups, proxy_names, rep):
    if not isinstance(groups, list):
        rep.fatal('GROUP', f'proxy-groups 不是列表: {type(groups).__name__}')
        return set()

    group_names = set()
    group_name_list = []
    for idx, g in enumerate(groups):
        loc = f'proxy-groups[{idx}]'
        if not isinstance(g, dict):
            rep.error('GROUP', f'组不是字典: {type(g).__name__}', loc)
            continue
        name = g.get('name')
        if not name:
            rep.error('GROUP', '缺少 name', loc)
            continue
        if not isinstance(name, str):
            rep.error('GROUP', f'name 不是字符串: {name!r}', loc)
            continue
        if name in group_names:
            rep.error('GROUP', f'组名重复: {name!r}', loc)
        group_names.add(name)
        group_name_list.append(name)

        gtype = g.get('type')
        if not gtype:
            rep.error('GROUP', f'组 {name!r} 缺少 type', loc)
        elif gtype not in ('select', 'url-test', 'fallback', 'load-balance', 'relay'):
            rep.error('GROUP', f'组 {name!r} 的 type 非法: {gtype!r}', loc)

        if gtype in ('url-test', 'fallback', 'load-balance'):
            if 'url' not in g:
                rep.warn('GROUP', f'组 {name!r} 是 {gtype} 但没有 url', loc)
            if 'interval' not in g:
                rep.info('GROUP', f'组 {name!r} 是 {gtype} 但没有 interval', loc)

        # proxies 列表
        plist = g.get('proxies')
        if plist is None:
            if 'use' not in g:
                rep.warn('GROUP', f'组 {name!r} 既没有 proxies 也没有 use', loc)
            continue
        if not isinstance(plist, list):
            rep.error('GROUP', f'组 {name!r} 的 proxies 不是列表', loc)
            continue
        if not plist:
            rep.warn('GROUP', f'组 {name!r} 的 proxies 为空', loc)

    # 引用有效性
    valid = proxy_names | group_names | BUILTIN_POLICIES
    for idx, g in enumerate(groups):
        if not isinstance(g, dict):
            continue
        name = g.get('name', f'?[{idx}]')
        for item in g.get('proxies') or []:
            if not isinstance(item, str):
                rep.error('GROUP', f'组 {name!r} 引用了非字符串: {item!r}')
                continue
            if item not in valid:
                rep.fatal('GROUP',
                          f'组 {name!r} 引用了不存在的节点/组: {item!r}  '
                          f'<-- 这是 Clash Verge 报 invalid yaml 的最常见原因')

    return group_names


# ============================================================================
# 4. rules 校验
# ============================================================================
def check_rules(rules, proxy_names, group_names, rep):
    if not isinstance(rules, list):
        rep.fatal('RULE', f'rules 不是列表: {type(rules).__name__}')
        return
    valid_policy = proxy_names | group_names | BUILTIN_POLICIES

    for idx, rule in enumerate(rules):
        loc = f'rules[{idx}]'
        if not isinstance(rule, str):
            rep.error('RULE', f'规则不是字符串: {rule!r}', loc)
            continue
        parts = rule.split(',')
        rtype = parts[0].strip()

        if rtype not in VALID_RULE_TYPES:
            rep.error('RULE', f'未知规则类型: {rtype!r}', loc)
            continue

        # MATCH 只有一个参数
        if rtype == 'MATCH':
            if len(parts) < 2:
                rep.error('RULE', f'MATCH 规则缺少策略: {rule!r}', loc)
                continue
            policy = parts[-1].strip()
            if policy not in valid_policy:
                rep.fatal('RULE', f'MATCH 规则引用了不存在的策略: {policy!r}', loc)
            continue

        if len(parts) < 3:
            rep.error('RULE', f'规则至少需要 3 个字段: {rule!r}', loc)
            continue

        # 检查匹配字段是否含非法字符
        match_field = parts[1].strip()
        if rtype.startswith('DOMAIN') or rtype == 'GEOSITE':
            if '^' in match_field or '||' in match_field or '|' in match_field:
                rep.error('RULE',
                          f'{rtype} 的匹配字段含 Adblock 语法符号 (^/|): {match_field!r}',
                          loc)
            if match_field.startswith('@@'):
                rep.error('RULE', f'{rtype} 的匹配字段含 Adblock 白名单前缀 @@: {match_field!r}', loc)

        # 策略是否有效
        policy = parts[-1].strip()
        if policy not in valid_policy:
            rep.fatal('RULE', f'规则引用了不存在的策略: {policy!r}  ({rule!r})', loc)


# ============================================================================
# 主流程
# ============================================================================
def main():
    if len(sys.argv) != 3:
        print('用法: python check.py <节点文件.yml> <错误日志输出.txt>')
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]

    if not os.path.exists(input_file):
        print(f'错误: 输入文件不存在: {input_file}')
        sys.exit(1)

    with open(output_file, 'w', encoding='utf-8') as fout:
        rep = Reporter(fout)

        fout.write('=' * 70 + '\n')
        fout.write(f'check.py 校验报告\n')
        fout.write(f'输入文件: {input_file}\n')
        fout.write('=' * 70 + '\n\n')

        # ---------- 1. YAML 解析 ----------
        print('[1/5] YAML 解析...')
        data, text = check_yaml_parse(input_file, rep)
        if data is None:
            print(f'\nYAML 无法解析，错误已写入 {output_file}')
            rep.summary()
            sys.exit(2)

        if not isinstance(data, dict):
            rep.fatal('ROOT', f'根元素不是字典: {type(data).__name__}')
            rep.summary()
            sys.exit(2)

        # ---------- 2. proxies ----------
        print('[2/5] 校验 proxies...')
        proxies = data.get('proxies')
        if proxies is None:
            rep.warn('PROXY', '配置中没有 proxies 段')
            proxies = []
        elif not isinstance(proxies, list):
            rep.fatal('PROXY', f'proxies 不是列表: {type(proxies).__name__}')
            proxies = []

        name_set = defaultdict(list)
        for i, p in enumerate(proxies):
            check_proxy(p, i, name_set, rep)
        proxy_names = {p.get('name') for p in proxies
                       if isinstance(p, dict) and p.get('name')}

        # 节点名重复
        for name, idxs in name_set.items():
            if len(idxs) > 1:
                rep.error('PROXY',
                          f'节点名重复 {name!r} 出现在索引 {idxs}，'
                          f'Clash 会因引用不明确而拒绝')

        # ---------- 3. proxy-groups ----------
        print('[3/5] 校验 proxy-groups...')
        groups = data.get('proxy-groups') or []
        group_names = check_groups(groups, proxy_names, rep)

        # ---------- 4. rules ----------
        print('[4/5] 校验 rules...')
        rules = data.get('rules') or []
        check_rules(rules, proxy_names, group_names, rep)

        # ---------- 5. 未使用的节点（提示） ----------
        print('[5/5] 统计未使用的节点...')
        used = set()
        for g in groups:
            if isinstance(g, dict):
                for x in g.get('proxies') or []:
                    used.add(x)
        unused = proxy_names - used
        if unused:
            rep.info('PROXY', f'{len(unused)} 个节点未被任何 proxy-group 引用（不影响加载）')

        # ---------- 汇总 ----------
        rep.summary()

    print(f'\n报告已写入: {output_file}')
    print(f"FATAL={rep.counts['FATAL']}  ERROR={rep.counts['ERROR']}  "
          f"WARN={rep.counts['WARN']}  INFO={rep.counts['INFO']}")
    if rep.counts['FATAL'] or rep.counts['ERROR']:
        sys.exit(2)
    sys.exit(0)


if __name__ == '__main__':
    main()

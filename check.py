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
    9.  ws-opts / grpc-opts / h2-opts 详细字段校验
        - ws-opts.headers.Host 内容合法性（mihomo 严格校验）
        - ws-opts.path 合法性
        - grpc-opts.grpc-service-name 合法性
        - h2-opts.host / path 合法性

输出:
    错误日志分级为 [FATAL] / [ERROR] / [WARN] / [INFO]
    FATAL 和 ERROR 是导致 Clash Verge 拒绝加载的直接原因
    每个 ERROR/WARN 都会带 proxies[N] 索引和节点名，方便定位

本次修改（相对旧版）:
    - YAML 锚点/别名检测由 WARN 降级为 INFO（mihomo 官方支持锚点）
    - PyYAML 标签 !!str/!!int/!!bool 检测由 ERROR 降级为 INFO
    - 从 KNOWN_PROXY_TYPES 中移除 shadowtls（非独立代理类型）
    - 【本次新增】ws-opts.headers.Host 内容合法性检查
    - 【本次新增】ws-opts.path / grpc-opts / h2-opts 字段校验
    - 【本次新增】错误信息带节点名，方便定位
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

# ws-opts.headers 中 mihomo 严格校验的特殊字段
# mihomo 会对这些字段做 host 合法性检查
WS_HEADER_STRICT_FIELDS = {'Host'}

# Host 类字段禁止出现的字符
HOST_FORBIDDEN_CHARS = set(' \t\r\n\\/?#,;')

# Host 类字段禁止出现的子串
HOST_FORBIDDEN_SUBSTRINGS = ('://',)


# ============================================================================
# 报告器
# ============================================================================
class Reporter:
    def __init__(self, out_file):
        self.out = out_file
        self.counts = {'FATAL': 0, 'ERROR': 0, 'WARN': 0, 'INFO': 0}
        # 记录所有 ERROR/WARN 定位信息，方便统计
        self.error_locations = []

    def log(self, level, category, msg, location=''):
        self.counts[level] = self.counts.get(level, 0) + 1
        loc = f' @ {location}' if location else ''
        line = f'[{level}] [{category}] {msg}{loc}'
        print(line)
        self.out.write(line + '\n')

    def fatal(self, cat, msg, loc=''): self.log('FATAL', cat, msg, loc)
    def error(self, cat, msg, loc=''):
        self.log('ERROR', cat, msg, loc)
        if loc:
            self.error_locations.append((loc, msg))
    def warn(self, cat, msg, loc=''):
        self.log('WARN', cat, msg, loc)
        if loc:
            self.error_locations.append((loc, msg))
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

        # 汇总定位信息
        if self.error_locations:
            self.out.write('\n' + '-' * 70 + '\n')
            self.out.write('错误/警告定位汇总（按出现顺序）\n')
            self.out.write('-' * 70 + '\n')
            for loc, msg in self.error_locations:
                self.out.write(f'  {loc}: {msg[:120]}\n')

        if self.counts['FATAL'] == 0 and self.counts['ERROR'] == 0:
            self.out.write('\n结论: 未发现会导致 Clash 拒绝加载的问题。\n')
        else:
            self.out.write('\n结论: 存在 FATAL/ERROR，这会导致 Clash Verge 报 "invalid yaml"。\n')
            self.out.write('提示: 请根据 "错误/警告定位汇总" 部分定位到 proxies[N] 索引，\n')
            self.out.write('      然后在 YAML 文件中查找对应的 - name: 节点。\n')


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
# 1.5 新增：ws-opts / grpc-opts / h2-opts 详细校验
# ============================================================================

def _describe_value(v, max_len=80):
    """生成值的简短描述，用于日志"""
    if isinstance(v, str):
        s = repr(v)
        if len(s) > max_len:
            s = s[:max_len] + '...'
        return f"{s} (str, {len(v)} 字符)"
    if isinstance(v, (list, tuple)):
        return f"{repr(v)[:max_len]} (list, {len(v)} 项)"
    if isinstance(v, dict):
        return f"{repr(v)[:max_len]} (dict, {len(v)} 键)"
    return f"{repr(v)[:max_len]} ({type(v).__name__})"


def _check_host_like(value, field_name, loc, rep, node_name):
    """
    校验 host 类字段（如 ws-opts.headers.Host、h2-opts.host 的每个元素）。

    mihomo 拒绝条件：
        - 非字符串
        - 空字符串 / 纯空白
        - 含空白、/、\\、?、#、,、; 等
        - 含 ://
        - 含控制字符

    返回:
        True  -> 合法
        False -> 非法（已记录错误）
    """
    prefix = f"[节点: {node_name}] " if node_name else ""

    # 类型检查
    if value is None:
        rep.error('PROXY',
                  f'{prefix}{field_name} 为 None（mihomo 会报 "invalid"）',
                  loc)
        return False

    if not isinstance(value, str):
        rep.error('PROXY',
                  f'{prefix}{field_name} 不是字符串: {_describe_value(value)}',
                  loc)
        return False

    if not value:
        rep.error('PROXY',
                  f'{prefix}{field_name} 为空字符串（mihomo 会报 "invalid"）',
                  loc)
        return False

    if not value.strip():
        rep.error('PROXY',
                  f'{prefix}{field_name} 为纯空白: {value!r}',
                  loc)
        return False

    # 前后空白
    if value != value.strip():
        rep.error('PROXY',
                  f'{prefix}{field_name} 有前后空白: {value!r} '
                  f'（建议改为 {value.strip()!r}）',
                  loc)
        return False

    # 协议前缀
    for sub in HOST_FORBIDDEN_SUBSTRINGS:
        if sub in value:
            pos = value.index(sub)
            rep.error('PROXY',
                      f'{prefix}{field_name} 含协议前缀 {sub!r} '
                      f'（位置 {pos}）: {value!r} '
                      f'（建议改为 {value.split(sub, 1)[1].split("/", 1)[0]!r}）',
                      loc)
            return False

    # 非法字符
    for i, c in enumerate(value):
        if c in HOST_FORBIDDEN_CHARS:
            rep.error('PROXY',
                      f'{prefix}{field_name} 含非法字符 {c!r} '
                      f'（位置 {i}）: {value!r} '
                      f'（合法前缀: {value[:i]!r}）',
                      loc)
            return False
        if not c.isprintable():
            rep.error('PROXY',
                      f'{prefix}{field_name} 含控制字符 U+{ord(c):04X} '
                      f'（位置 {i}）: {value!r}',
                      loc)
            return False

    # 尾随点
    if value.endswith('.'):
        rep.warn('PROXY',
                 f'{prefix}{field_name} 以点结尾: {value!r}',
                 loc)

    return True


def check_ws_opts(proxy, loc, rep, node_name):
    """
    校验 ws-opts 的详细字段。

    mihomo 严格校验：
        - ws-opts.headers.Host
        - ws-opts.path
        - ws-opts.headers 里的其他自定义字段（部分版本也校验）
    """
    ws = proxy.get('ws-opts')
    if ws is None:
        return
    if not isinstance(ws, dict):
        # 已在主流程里报过"不是字典"
        return

    # ---- headers ----
    headers = ws.get('headers')
    if headers is not None:
        if not isinstance(headers, dict):
            rep.error('PROXY',
                      f'ws-opts.headers 不是字典: {_describe_value(headers)}',
                      loc)
        else:
            for hkey, hval in headers.items():
                if not isinstance(hkey, str):
                    rep.error('PROXY',
                              f'ws-opts.headers 键不是字符串: {hkey!r}',
                              loc)
                    continue
                # Host 类字段严格校验
                if hkey in WS_HEADER_STRICT_FIELDS:
                    _check_host_like(
                        hval,
                        f'ws-opts.headers[{hkey}]',
                        loc, rep, node_name
                    )
                else:
                    # 其他字段宽松一些：至少要是字符串
                    if not isinstance(hval, str):
                        rep.error('PROXY',
                                  f'ws-opts.headers[{hkey}] 不是字符串: '
                                  f'{_describe_value(hval)}',
                                  loc)

    # ---- path ----
    path = ws.get('path')
    if path is not None:
        if not isinstance(path, str):
            rep.error('PROXY',
                      f'ws-opts.path 不是字符串: {_describe_value(path)}',
                      loc)
        elif not path:
            rep.warn('PROXY',
                     f'ws-opts.path 为空字符串（建议改为 "/"）',
                     loc)
        elif not path.startswith('/'):
            rep.warn('PROXY',
                     f'ws-opts.path 不以 / 开头: {path!r}',
                     loc)
        # path 里不能有控制字符
        for i, c in enumerate(path):
            if not c.isprintable():
                rep.error('PROXY',
                          f'ws-opts.path 含控制字符 U+{ord(c):04X} '
                          f'（位置 {i}）: {path!r}',
                          loc)
                break


def check_grpc_opts(proxy, loc, rep, node_name):
    """校验 grpc-opts 的详细字段"""
    grpc = proxy.get('grpc-opts')
    if grpc is None:
        return
    if not isinstance(grpc, dict):
        return

    svc = grpc.get('grpc-service-name')
    if svc is not None:
        if not isinstance(svc, str):
            rep.error('PROXY',
                      f'grpc-opts.grpc-service-name 不是字符串: '
                      f'{_describe_value(svc)}',
                      loc)
        elif not svc:
            rep.warn('PROXY',
                     f'grpc-opts.grpc-service-name 为空字符串',
                     loc)


def check_h2_opts(proxy, loc, rep, node_name):
    """校验 h2-opts 的详细字段"""
    h2 = proxy.get('h2-opts')
    if h2 is None:
        return
    if not isinstance(h2, dict):
        return

    # host 必须是列表
    host = h2.get('host')
    if host is not None:
        if not isinstance(host, list):
            rep.error('PROXY',
                      f'h2-opts.host 不是列表: {_describe_value(host)}',
                      loc)
        else:
            for i, h in enumerate(host):
                _check_host_like(
                    h,
                    f'h2-opts.host[{i}]',
                    loc, rep, node_name
                )

    # path 必须是字符串
    path = h2.get('path')
    if path is not None:
        if not isinstance(path, str):
            rep.error('PROXY',
                      f'h2-opts.path 不是字符串: {_describe_value(path)}',
                      loc)


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

    # 节点名（后续用于错误信息里标注）
    node_name = name if isinstance(name, str) else None

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
            rep.warn('PROXY', f'name 含 "#"，如未加引号会被当成注释: {name!r}', loc)
        if '\n' in name or '\r' in name or '\t' in name:
            rep.error('PROXY', f'name 含控制字符（\\n/\\r/\\t）: {name!r}', loc)
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

    # ws-opts / grpc-opts / h2-opts 结构
    for opt in ('ws-opts', 'grpc-opts', 'h2-opts', 'http-opts', 'xhttp-opts', 'reality-opts'):
        if opt in proxy and not isinstance(proxy[opt], dict):
            rep.error('PROXY', f'{opt} 不是字典: {type(proxy[opt]).__name__}', loc)

    # ---- 新增：详细字段校验 ----
    check_ws_opts(proxy, loc, rep, node_name)
    check_grpc_opts(proxy, loc, rep, node_name)
    check_h2_opts(proxy, loc, rep, node_name)
    # ---------------------------

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

        match_field = parts[1].strip()
        if rtype.startswith('DOMAIN') or rtype == 'GEOSITE':
            if '^' in match_field or '||' in match_field or '|' in match_field:
                rep.error('RULE',
                          f'{rtype} 的匹配字段含 Adblock 语法符号 (^/|): {match_field!r}',
                          loc)
            if match_field.startswith('@@'):
                rep.error('RULE',
                          f'{rtype} 的匹配字段含 Adblock 白名单前缀 @@: {match_field!r}',
                          loc)

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

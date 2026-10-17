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
    10. 节点特征诊断（用于定位"延迟测试全部失败"的根因）
    11. 【本次新增】Q1: 节点数对不上相关诊断
        - Q1.1 proxies 名称全角清洗字符残留
        - Q1.2 proxy-groups 引用名 vs proxies 实际名"近似匹配"
        - Q1.3 各 proxy-group 的 proxies 长度分布
        - Q1.4 未被引用的节点统计
    12. 【本次新增】Q2: 延迟全失败相关诊断
        - Q2.1 ws-opts.path 含 URL 编码 (%2F 等)
        - Q2.2 VLESS XUDP(Vision) 与非 TCP 传输冲突
        - Q2.3 VLESS UUID 被替换为默认值
        - Q2.4 REALITY 字段完整性（public-key/short-id/fp）
        - Q2.5 grpc-opts.grpc-service-name 空值
    13. 【本次新增】REALITY 字段 ERROR 级校验（check_reality_opts）
        - public-key：必须是 43 位 base64url 字符串
        - short-id：必须是十六进制字符串，长度偶数且 ≤ 16
        - 命中即 FATAL/ERROR，能在 error_locations 里看到 proxies[N] 索引
        - 目的：定位 mihomo 报 "invalid REALITY short ID"
                / "invalid REALITY public key" 的具体节点

输出:
    错误日志分级为 [FATAL] / [ERROR] / [WARN] / [INFO] / [DIAG]
    FATAL 和 ERROR 是导致 Clash Verge 拒绝加载的直接原因
    每个 ERROR/WARN 都会带 proxies[N] 索引和节点名，方便定位
    DIAG 是诊断信息，不计入错误统计
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

# fetch_pro3.py 中用于替换非法 UUID 的默认值
# 若节点文件里大量出现这个 UUID，说明上游脚本做了错误的 UUID 替换，
# 会导致 mihomo 用错误 UUID 去认证，必然失败
DEFAULT_UUID = '88888888-8888-8888-8888-888888888888'

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

# preprocess/rebuilder 用来清洗 name 的全角替换字符集
SANITIZE_CHARS = {'＃', '＆', '＊', '｜', '＞', '＜', '…'}

# ============================================================================
# 【本次新增】REALITY 字段校验相关常量
# ============================================================================
# REALITY public-key 合法字符集（base64url 无 padding）
VALID_PUBLIC_KEY_CHARS = set(
    'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    'abcdefghijklmnopqrstuvwxyz'
    '0123456789-_'
)

# REALITY public-key 标准长度（mihomo 严格校验）
PUBLIC_KEY_LEN = 43

# REALITY short-id 合法字符集（十六进制，大小写均可）
VALID_SHORT_ID_CHARS = set('0123456789abcdefABCDEF')


# ============================================================================
# 报告器
# ============================================================================
class Reporter:
    def __init__(self, out_file):
        self.out = out_file
        # DIAG 单独计数，不计入错误
        self.counts = {'FATAL': 0, 'ERROR': 0, 'WARN': 0, 'INFO': 0, 'DIAG': 0}
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
    def diag(self, msg, loc=''):       self.log('DIAG',  'DIAG', msg, loc)

    def summary(self):
        self.out.write('\n')
        self.out.write('=' * 70 + '\n')
        self.out.write('汇总\n')
        self.out.write('=' * 70 + '\n')
        self.out.write(f"FATAL: {self.counts['FATAL']}\n")
        self.out.write(f"ERROR: {self.counts['ERROR']}\n")
        self.out.write(f"WARN : {self.counts['WARN']}\n")
        self.out.write(f"INFO : {self.counts['INFO']}\n")
        self.out.write(f"DIAG : {self.counts['DIAG']}  （诊断信息，非错误）\n")

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
# 1.5 ws-opts / grpc-opts / h2-opts 详细校验
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
        elif '%' in path:
            # 【本次修改】含 URL 编码时升级为 ERROR
            # 因为 mihomo 不会自动解码 %2F 等，WS 握手必然失败
            rep.error('PROXY',
                      f'ws-opts.path 含 URL 编码（mihomo 不会解码，'
                      f'WS 握手必然失败）: {path!r}',
                      loc)
        elif not path.startswith('/'):
            # 【本次修改】不以 / 开头由 WARN 升级为 ERROR
            # 因为 mihomo 会拒绝连接
            rep.error('PROXY',
                      f'ws-opts.path 不以 / 开头（mihomo 会拒绝连接）: {path!r}',
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
# 【本次新增】1.6 reality-opts 详细校验
# ============================================================================
def check_reality_opts(proxy, loc, rep, node_name):
    """
    校验 reality-opts 的详细字段。

    mihomo 严格校验：
        - public-key：必须是 43 位 base64url 字符串
        - short-id：必须是十六进制字符串，长度偶数且 ≤ 16
        - 否则会报：
            * "invalid REALITY public key"
            * "invalid REALITY short ID"

    覆盖范围：
        - vless / anytls 等支持 reality 的协议
        - 仅当 reality-opts 是 dict 时才校验
        - 其他协议若出现 reality-opts 也检查（防御性）
    """
    ro = proxy.get('reality-opts')
    if ro is None:
        return
    if not isinstance(ro, dict):
        rep.error('PROXY',
                  f'reality-opts 不是字典: {_describe_value(ro)}',
                  loc)
        return

    prefix = f"[节点: {node_name}] " if node_name else ""

    # ---- public-key 校验 ----
    pk = ro.get('public-key')
    if pk is None:
        rep.warn('PROXY',
                 f'{prefix}reality-opts 缺少 public-key 字段',
                 loc)
    elif not isinstance(pk, str):
        rep.error('PROXY',
                  f'{prefix}reality-opts.public-key 不是字符串 '
                  f'(mihomo 会报 invalid REALITY public key): '
                  f'{_describe_value(pk)}',
                  loc)
    else:
        # 长度必须为 43
        if len(pk) != PUBLIC_KEY_LEN:
            rep.error('PROXY',
                      f'{prefix}reality-opts.public-key 长度必须为 {PUBLIC_KEY_LEN} '
                      f'(mihomo 会报 invalid REALITY public key)，'
                      f'实际 {len(pk)}: {pk!r}',
                      loc)
        # 字符集校验
        invalid_chars = [c for c in pk if c not in VALID_PUBLIC_KEY_CHARS]
        if invalid_chars:
            rep.error('PROXY',
                      f'{prefix}reality-opts.public-key 含非法字符 '
                      f'(仅允许 A-Z a-z 0-9 - _): {invalid_chars[:5]!r}  '
                      f'原值: {pk!r}',
                      loc)

    # ---- short-id 校验 ----
    sid = ro.get('short-id')
    if sid is not None:
        if not isinstance(sid, str):
            # 例如 YAML 里写成不带引号的 2351e1 被解析为浮点数
            rep.error('PROXY',
                      f'{prefix}reality-opts.short-id 必须是字符串 '
                      f'(mihomo 会报 invalid REALITY short ID，'
                      f'YAML 里请加双引号): {_describe_value(sid)}',
                      loc)
        elif sid:  # 非空字符串才检查格式
            # 长度上限 16
            if len(sid) > 16:
                rep.error('PROXY',
                          f'{prefix}reality-opts.short-id 长度必须 ≤ 16 '
                          f'(mihomo 会报 invalid REALITY short ID)，'
                          f'实际 {len(sid)}: {sid!r}',
                          loc)
            # 长度必须是偶数
            if len(sid) % 2 != 0:
                rep.error('PROXY',
                          f'{prefix}reality-opts.short-id 长度必须为偶数 '
                          f'(hex 解码要求，mihomo 会报 invalid REALITY short ID)，'
                          f'实际 {len(sid)}: {sid!r}',
                          loc)
            # 必须是十六进制
            bad_hex = [c for c in sid if c not in VALID_SHORT_ID_CHARS]
            if bad_hex:
                rep.error('PROXY',
                          f'{prefix}reality-opts.short-id 必须是十六进制字符 '
                          f'(mihomo 会报 invalid REALITY short ID)，'
                          f'非法字符: {bad_hex[:5]!r}  原值: {sid!r}',
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

    # ---- 详细字段校验 ----
    check_ws_opts(proxy, loc, rep, node_name)
    check_grpc_opts(proxy, loc, rep, node_name)
    check_h2_opts(proxy, loc, rep, node_name)
    # 【本次新增】reality-opts 详细校验（ERROR 级，进入 FATAL/ERROR 计数）
    check_reality_opts(proxy, loc, rep, node_name)
    # ---------------------------

    # name 重复
    if isinstance(name, str) and name:
        name_set[name].append(idx)


# ============================================================================
# 2.5 节点特征诊断
#     目的：定位"Clash Verge 里所有节点延迟测试都 Error"的原因
# ============================================================================
def diagnose_proxies(proxies, rep):
    """
    对 proxies 做特征统计，输出诊断报告。
    """
    if not isinstance(proxies, list):
        return

    rep.info('DIAG', '=' * 62)
    rep.info('DIAG', '节点特征诊断（用于定位"延迟测试全部失败"的原因）')
    rep.info('DIAG', '=' * 62)

    # ---------- 1. 协议分布 ----------
    type_dist = Counter()
    for p in proxies:
        if isinstance(p, dict):
            type_dist[p.get('type', '?')] += 1

    rep.info('DIAG', '【1. 协议分布】')
    total = len(proxies)
    for t, c in type_dist.most_common():
        pct = c / total * 100 if total else 0
        rep.info('DIAG', f'  {t}: {c} ({pct:.1f}%)')

    # ---------- 只针对 vless 做详细统计 ----------
    vless = [p for p in proxies
             if isinstance(p, dict) and p.get('type') == 'vless']
    if not vless:
        rep.info('DIAG', '【VLESS 节点】无')
        rep.info('DIAG', '=' * 62)
        return

    vless_total = len(vless)
    rep.info('DIAG', '')
    rep.info('DIAG', f'【2. VLESS 节点】共 {vless_total} 个')

    # ---- 2.1 flow 分布 ----
    flow_dist = Counter()
    for p in vless:
        flow = p.get('flow', '(无)')
        if flow is None or flow == '':
            flow = '(空)'
        flow_dist[flow] += 1

    rep.info('DIAG', '  flow 分布:')
    for f, c in flow_dist.most_common():
        pct = c / vless_total * 100
        rep.info('DIAG', f'    {f}: {c} ({pct:.1f}%)')

    # ---- 2.2 UUID 被替换成默认值的数量 ----
    default_uuid_count = sum(1 for p in vless if p.get('uuid') == DEFAULT_UUID)
    if default_uuid_count:
        pct = default_uuid_count / vless_total * 100
        rep.warn('DIAG',
                 f'  ⚠️ UUID 被替换成默认值 ({DEFAULT_UUID}) 的节点: '
                 f'{default_uuid_count} ({pct:.1f}%)')
        rep.warn('DIAG', f'     <-- 假设 1：这些节点认证必然失败')

    # ---- 2.3 UUID 长度分布 ----
    uuid_len_dist = Counter()
    for p in vless:
        uuid = p.get('uuid')
        if isinstance(uuid, str):
            uuid_len_dist[len(uuid)] += 1
        else:
            uuid_len_dist['非字符串'] += 1

    rep.info('DIAG', '  UUID 长度分布:')
    for l, c in uuid_len_dist.most_common():
        rep.info('DIAG', f'    长度 {l}: {c}')

    # ---- 2.4 sni/servername 缺失 ----
    no_sni_count = 0
    for p in vless:
        sni = p.get('sni') or p.get('servername')
        if not sni:
            no_sni_count += 1
    if no_sni_count:
        pct = no_sni_count / vless_total * 100
        rep.warn('DIAG',
                 f'  无 sni/servername 的节点: {no_sni_count} ({pct:.1f}%)')
        rep.warn('DIAG', f'     <-- 假设 2：TLS 握手可能失败')

    # ---- 2.5 network 分布 ----
    net_dist = Counter()
    for p in vless:
        net_dist[p.get('network', '(无)')] += 1
    rep.info('DIAG', '  network 分布:')
    for n, c in net_dist.most_common():
        rep.info('DIAG', f'    {n}: {c}')

    # ---- 2.6 tls 字段分布 ----
    tls_dist = Counter()
    for p in vless:
        tls = p.get('tls', '(无)')
        if isinstance(tls, bool):
            tls = 'true' if tls else 'false'
        tls_dist[tls] += 1
    rep.info('DIAG', '  tls 分布:')
    for t, c in tls_dist.most_common():
        rep.info('DIAG', f'    {t}: {c}')

    # ---- 2.7 security 分布 ----
    sec_dist = Counter()
    for p in vless:
        sec_dist[p.get('security', '(无)')] += 1
    rep.info('DIAG', '  security 分布:')
    for s, c in sec_dist.most_common():
        rep.info('DIAG', f'    {s}: {c}')

    # ---- 2.8 XUDP 节点统计 ----
    xudp_count = sum(
        1 for p in vless
        if p.get('flow') in ('xtls-rprx-vision', 'xtls-rprx-vision-udp443')
    )
    if xudp_count:
        pct = xudp_count / vless_total * 100
        rep.warn('DIAG',
                 f'  XUDP 节点 (flow=xtls-rprx-vision*): '
                 f'{xudp_count} ({pct:.1f}%)')
        rep.warn('DIAG', f'     <-- 假设 3：需要服务端支持 Vision 流控')

    # ---- 2.9 诊断结论 ----
    rep.info('DIAG', '')
    rep.info('DIAG', '【3. 诊断结论】')

    issues = []
    if default_uuid_count > 0:
        issues.append(
            f'UUID 被替换为默认值的节点 {default_uuid_count} 个 → '
            f'认证必然失败（最可能是主因）'
        )
    if xudp_count > 0:
        issues.append(
            f'XUDP 节点 {xudp_count} 个 → '
            f'需服务端支持 Vision 流控，普通节点会握手失败'
        )
    if no_sni_count > 0:
        issues.append(
            f'无 sni/servername 的节点 {no_sni_count} 个 → '
            f'TLS 握手可能失败'
        )

    if issues:
        for i, issue in enumerate(issues, 1):
            rep.info('DIAG', f'  {i}. {issue}')
    else:
        rep.info('DIAG', '  未发现明显的共性问题，可能是节点源质量问题')

    rep.info('DIAG', '=' * 62)


# ============================================================================
# 2.6【新增】Q1.1 proxies 名称全角清洗字符残留诊断
# ============================================================================
def diagnose_sanitized_names(proxies, rep):
    """
    如果 proxies 里出现 ＃ ｜ ＆ 等全角字符，说明上游（preprocess/rebuilder）
    已对 name 做过 sanitize；若 proxy-groups 未同步更新，就会导致引用失配。
    """
    if not isinstance(proxies, list):
        return

    sanitized = []
    for idx, p in enumerate(proxies):
        if not isinstance(p, dict):
            continue
        name = p.get('name', '')
        if isinstance(name, str) and any(c in name for c in SANITIZE_CHARS):
            sanitized.append((idx, name))

    rep.info('DIAG', '')
    rep.info('DIAG', '=' * 62)
    rep.info('DIAG', '【Q1.1】proxies 名称全角清洗字符诊断')
    rep.info('DIAG', '=' * 62)
    if not sanitized:
        rep.info('DIAG', '  ✅ proxies 中没有全角清洗字符')
        rep.info('DIAG', '     说明 proxies 的 name 是"原生"的，没有被 sanitize')
    else:
        rep.warn('DIAG',
                 f'⚠️ 发现 {len(sanitized)} 个节点 name 含清洗字符 '
                 f'（＃ ＆ ＊ ｜ ＞ ＜ …）')
        rep.warn('DIAG',
                 '     说明上游脚本已对 proxies.name 做了 sanitize。'
                 '若 proxy-groups 未同步，就会导致引用失配。')
        rep.info('DIAG', '  前 10 个示例:')
        for idx, name in sanitized[:10]:
            rep.info('DIAG', f'    proxies[{idx}] {name!r}')
    rep.info('DIAG', '=' * 62)


# ============================================================================
# 2.7【新增】Q1.2 proxy-groups 引用名 vs proxies 实际名"近似匹配"诊断
# ============================================================================
def _to_halfwidth(s):
    """把常见全角清洗字符还原为半角，用于近似匹配"""
    if not isinstance(s, str):
        return s
    return (s.replace('＃', '#').replace('＆', '&')
             .replace('＊', '*').replace('｜', '|')
             .replace('＞', '>').replace('＜', '<')
             .replace('…', '...'))


def diagnose_reference_mismatch(groups, proxy_names, rep):
    """
    验证"引用名与节点名只因半角/全角差异而不匹配"的数量。
    这是 preprocess_speed.py 清洗 proxies.name 但未同步 proxy-groups 的
    直接证据。
    """
    if not isinstance(groups, list):
        return

    normalized = {}
    for n in proxy_names:
        normalized.setdefault(_to_halfwidth(n), n)

    # 收集所有组名（供合法引用检查）
    all_group_names = set()
    for g in groups:
        if isinstance(g, dict):
            n = g.get('name')
            if isinstance(n, str):
                all_group_names.add(n)

    total_refs = 0
    missing_refs = []
    near_miss = []

    for g in groups:
        if not isinstance(g, dict):
            continue
        gname = g.get('name', '未命名组')
        plist = g.get('proxies')
        if not isinstance(plist, list):
            continue
        for item in plist:
            total_refs += 1
            if not isinstance(item, str):
                continue
            # 精确匹配：命中 proxy_names 或 组名 或 内置
            if item in proxy_names:
                continue
            if item in all_group_names:
                continue
            if item in BUILTIN_POLICIES:
                continue
            # 记录"真正缺失"的引用
            missing_refs.append((gname, item))
            # 判断是否只是"全角/半角"差异
            half = _to_halfwidth(item)
            if half in normalized:
                near_miss.append((gname, item, normalized[half]))

    rep.info('DIAG', '')
    rep.info('DIAG', '=' * 62)
    rep.info('DIAG', '【Q1.2】proxy-groups 引用 vs proxies 实际名 匹配诊断')
    rep.info('DIAG', '=' * 62)
    rep.info('DIAG', f'  proxy-groups 的总引用条目数: {total_refs}')
    rep.info('DIAG', f'  精确匹配失败（缺失引用）: {len(missing_refs)}')
    rep.info('DIAG', f'  其中"近似匹配"（仅全角/半角不同）: {len(near_miss)}')

    if near_miss:
        rep.warn('DIAG',
                 f'⚠️ 发现 {len(near_miss)} 处"仅因全角/半角差异"导致的引用失配！')
        rep.warn('DIAG',
                 '     这是 preprocess_speed.py 清洗 proxies.name '
                 '但未同步 proxy-groups 的直接证据。')
        rep.info('DIAG', '  前 20 处示例:')
        for gname, ref, actual in near_miss[:20]:
            rep.info('DIAG', f'    组 {gname!r}')
            rep.info('DIAG', f'      groups 里引用: {ref!r}')
            rep.info('DIAG', f'      proxies 里实际: {actual!r}')
        if len(near_miss) > 20:
            rep.info('DIAG', f'    ... 还有 {len(near_miss) - 20} 处')

    if missing_refs and not near_miss:
        rep.warn('DIAG',
                 f'⚠️ 有 {len(missing_refs)} 处引用完全找不到对应节点'
                 f'（不只是半角/全角问题）')

    if not missing_refs:
        rep.info('DIAG', '  ✅ 所有 proxy-groups 引用均能精确匹配到节点')
    rep.info('DIAG', '=' * 62)


# ============================================================================
# 2.8【新增】Q1.3/1.4 节点引用使用统计
# ============================================================================
def diagnose_node_usage(proxies, groups, rep):
    """
    量化"有多少 proxies 里的节点被组引用"，
    直接回答"为什么 Clash 只显示 2773 个，而 proxies 里有 11221 个"。
    """
    if not isinstance(proxies, list) or not isinstance(groups, list):
        return

    proxy_names = {p.get('name') for p in proxies
                   if isinstance(p, dict) and p.get('name')}
    used = set()
    for g in groups:
        if not isinstance(g, dict):
            continue
        for item in g.get('proxies') or []:
            if isinstance(item, str):
                used.add(item)

    unused = proxy_names - used
    used_actually = proxy_names & used

    rep.info('DIAG', '')
    rep.info('DIAG', '=' * 62)
    rep.info('DIAG', '【Q1.3/1.4】节点引用使用统计')
    rep.info('DIAG', '=' * 62)
    rep.info('DIAG', f'  proxies 中节点总数:        {len(proxy_names)}')
    rep.info('DIAG', f'  被 proxy-groups 引用的:    {len(used_actually)}')
    rep.info('DIAG', f'  未被任何组引用:            {len(unused)}')
    if proxy_names:
        rep.info('DIAG',
                 f'  实际使用率: {len(used_actually)/len(proxy_names)*100:.1f}%')

    if unused and len(unused) > len(used_actually):
        rep.warn('DIAG',
                 f'⚠️ 超过一半节点未被引用！')
        rep.warn('DIAG',
                 '     Clash 只会加载并显示"被 proxy-groups 引用到的节点"，'
                 '所以界面上看到的数量会远小于 proxies 里的总数。')
    rep.info('DIAG', '=' * 62)


# ============================================================================
# 2.9【新增】Q1.3 各 proxy-group 的 proxies 长度分布
# ============================================================================
def diagnose_group_sizes(groups, rep):
    """
    从组的角度看"哪个组引用被大量移除"。
    """
    if not isinstance(groups, list):
        return

    rep.info('DIAG', '')
    rep.info('DIAG', '=' * 62)
    rep.info('DIAG', '【Q1.3】各 proxy-group 的 proxies 长度分布')
    rep.info('DIAG', '=' * 62)
    rows = []
    for g in groups:
        if not isinstance(g, dict):
            continue
        name = g.get('name', '未命名组')
        gtype = g.get('type', '?')
        plist = g.get('proxies')
        n = len(plist) if isinstance(plist, list) else 0
        has_use = 'use' in g
        rows.append((name, gtype, n, has_use))

    for name, gtype, n, has_use in rows:
        flag = ''
        if n == 0:
            flag = '  ← 空！'
        elif n <= 5:
            flag = '  ← 极少'
        if has_use:
            flag += '  [含 use]'
        rep.info('DIAG', f'    {name!r} (type={gtype}) -> {n} 个引用{flag}')
    rep.info('DIAG', '=' * 62)


# ============================================================================
# 2.10【新增】Q2.1 WebSocket 路径 URL 编码诊断
# ============================================================================
def diagnose_ws_path_encoding(proxies, rep):
    """
    验证 ws-opts.path 是否含 URL 编码 (%2F/%3F 等)。
    mihomo 不会自动解码，WS 握手必然失败。
    """
    if not isinstance(proxies, list):
        return

    total_ws = 0
    with_percent = []
    not_slash = []
    empty_path = []

    for idx, p in enumerate(proxies):
        if not isinstance(p, dict):
            continue
        ws = p.get('ws-opts')
        if not isinstance(ws, dict):
            continue
        total_ws += 1
        path = ws.get('path')
        name = p.get('name', '未命名')
        if not isinstance(path, str):
            continue
        if path == '':
            empty_path.append((idx, name))
        elif '%' in path:
            with_percent.append((idx, name, path))
        elif not path.startswith('/'):
            not_slash.append((idx, name, path))

    rep.info('DIAG', '')
    rep.info('DIAG', '=' * 62)
    rep.info('DIAG', '【Q2.1】WebSocket 路径 URL 编码诊断')
    rep.info('DIAG', '=' * 62)
    rep.info('DIAG', f'  含 ws-opts 的节点总数: {total_ws}')
    rep.info('DIAG', f'  ├ path 含 "%" (URL编码): {len(with_percent)}')
    rep.info('DIAG', f'  ├ path 不以 "/" 开头:     {len(not_slash)}')
    rep.info('DIAG', f'  └ path 为空字符串:         {len(empty_path)}')

    if with_percent:
        rep.warn('DIAG',
                 f'⚠️ 发现 {len(with_percent)} 个节点 path 含 URL 编码，'
                 f'mihomo 不会自动解码，WS 握手必然失败！')
        rep.info('DIAG', '  前 10 个示例:')
        for idx, name, path in with_percent[:10]:
            rep.info('DIAG', f'    proxies[{idx}] {name!r}')
            rep.info('DIAG', f'        path = {path!r}')
        if len(with_percent) > 10:
            rep.info('DIAG', f'    ... 还有 {len(with_percent) - 10} 个')

    if not_slash:
        rep.warn('DIAG',
                 f'⚠️ 发现 {len(not_slash)} 个节点 path 不以 "/" 开头 '
                 f'(mihomo 可能拒绝)。')
    rep.info('DIAG', '=' * 62)


# ============================================================================
# 2.11【新增】Q2.2 VLESS XUDP(Vision) 与传输层冲突诊断
# ============================================================================
def diagnose_xudp_conflict(proxies, rep):
    """
    xtls-rprx-vision 必须搭配 network=tcp，
    配合 ws/grpc/h2/httpupgrade 时 mihomo 会拒绝连接。
    """
    vless = [p for p in proxies
             if isinstance(p, dict) and p.get('type') == 'vless']
    if not vless:
        return

    xudp_total = 0
    xudp_by_net = Counter()
    conflicts = []

    for p in vless:
        flow = p.get('flow', '') or ''
        net = p.get('network', 'tcp') or 'tcp'
        if 'xtls-rprx-vision' in flow:
            xudp_total += 1
            xudp_by_net[net] += 1
            if net != 'tcp':
                conflicts.append((p.get('name', '未命名'), flow, net))

    rep.info('DIAG', '')
    rep.info('DIAG', '=' * 62)
    rep.info('DIAG', '【Q2.2】VLESS XUDP(Vision) 与传输层冲突诊断')
    rep.info('DIAG', '=' * 62)
    rep.info('DIAG', f'  VLESS 节点总数: {len(vless)}')
    rep.info('DIAG', f'  XUDP(Vision) 节点总数: {xudp_total}')
    if xudp_total:
        rep.info('DIAG', '  XUDP 节点的 network 分布:')
        for n, c in xudp_by_net.most_common():
            rep.info('DIAG', f'    {n}: {c}')

    if conflicts:
        rep.warn('DIAG',
                 f'⚠️ 致命冲突: {len(conflicts)} 个 XUDP 节点使用了非 TCP 传输！')
        rep.warn('DIAG',
                 '    (xtls-rprx-vision 必须搭配 network=tcp，'
                 '否则 mihomo 会直接握手失败)')
        rep.info('DIAG', '  前 10 个示例:')
        for name, flow, net in conflicts[:10]:
            rep.info('DIAG', f'    {name!r}: flow={flow!r}, network={net!r}')
        if len(conflicts) > 10:
            rep.info('DIAG', f'    ... 还有 {len(conflicts) - 10} 个')
    else:
        rep.info('DIAG', '  ✅ 未发现 XUDP 与非 TCP 传输冲突的节点')
    rep.info('DIAG', '=' * 62)


# ============================================================================
# 2.12【新增】Q2.3 VLESS UUID 默认值诊断（含示例）
# ============================================================================
def diagnose_default_uuid(proxies, rep):
    """
    统计 VLESS 节点中 UUID=8888... 的数量，这些节点认证必然失败。
    """
    if not isinstance(proxies, list):
        return
    vless = [p for p in proxies
             if isinstance(p, dict) and p.get('type') == 'vless']
    if not vless:
        return

    bad = []
    for idx, p in enumerate(proxies):
        if not isinstance(p, dict):
            continue
        if p.get('type') != 'vless':
            continue
        if p.get('uuid') == DEFAULT_UUID:
            bad.append((idx, p.get('name', '未命名')))

    rep.info('DIAG', '')
    rep.info('DIAG', '=' * 62)
    rep.info('DIAG', '【Q2.3】VLESS UUID 默认值诊断')
    rep.info('DIAG', '=' * 62)
    rep.info('DIAG', f'  VLESS 节点总数: {len(vless)}')
    rep.info('DIAG', f'  UUID=默认值(8888...) 的节点数: {len(bad)}')
    if bad:
        rep.warn('DIAG', '⚠️ 这些节点认证必然失败:')
        for idx, name in bad[:10]:
            rep.info('DIAG', f'    proxies[{idx}] {name!r}')
        if len(bad) > 10:
            rep.info('DIAG', f'    ... 还有 {len(bad) - 10} 个')
    rep.info('DIAG', '=' * 62)


# ============================================================================
# 2.13【新增】Q2.4 REALITY 字段完整性诊断
# ============================================================================
def diagnose_reality_fields(proxies, rep):
    """
    验证 public-key 长度、short-id 字符、client-fingerprint 是否齐全。
    """
    vless = [p for p in proxies
             if isinstance(p, dict) and p.get('type') == 'vless']
    reality_nodes = []
    for p in vless:
        ro = p.get('reality-opts')
        if isinstance(ro, dict):
            reality_nodes.append((p, ro))

    rep.info('DIAG', '')
    rep.info('DIAG', '=' * 62)
    rep.info('DIAG', '【Q2.4】REALITY 字段完整性诊断')
    rep.info('DIAG', '=' * 62)

    if not reality_nodes:
        rep.info('DIAG', '  无 REALITY 节点')
        rep.info('DIAG', '=' * 62)
        return

    pk_lens = Counter()
    pk_bad = []
    sid_bad = []
    no_fp = 0

    for p, ro in reality_nodes:
        pk = ro.get('public-key', '')
        if isinstance(pk, str):
            pk_lens[len(pk)] += 1
            if len(pk) != 43:
                pk_bad.append((p.get('name', '未命名'), pk))
        else:
            pk_lens['非字符串'] += 1
            pk_bad.append((p.get('name', '未命名'), repr(pk)))

        sid = ro.get('short-id')
        if isinstance(sid, str) and sid:
            if not all(c in '0123456789abcdef' for c in sid.lower()):
                sid_bad.append((p.get('name', '未命名'), sid))

        if not p.get('client-fingerprint'):
            no_fp += 1

    rep.info('DIAG', f'  REALITY 节点总数: {len(reality_nodes)}')
    rep.info('DIAG', '  public-key 长度分布:')
    for l, c in pk_lens.most_common():
        rep.info('DIAG', f'    {l}: {c}')
    if pk_bad:
        rep.warn('DIAG',
                 f'  ⚠️ public-key 长度≠43 的节点: {len(pk_bad)}')
        for name, pk in pk_bad[:5]:
            rep.info('DIAG', f'      {name!r}: pk={pk!r}')

    if sid_bad:
        rep.warn('DIAG',
                 f'  ⚠️ short-id 含非 hex 字符的节点: {len(sid_bad)}')
        for name, sid in sid_bad[:5]:
            rep.info('DIAG', f'      {name!r}: sid={sid!r}')

    if no_fp:
        rep.warn('DIAG',
                 f'  ⚠️ 缺少 client-fingerprint 的 REALITY 节点: {no_fp}')
    rep.info('DIAG', '=' * 62)


# ============================================================================
# 2.14【新增】Q2.5 gRPC service-name 空值诊断
# ============================================================================
def diagnose_grpc_empty(proxies, rep):
    """
    统计 grpc-opts.grpc-service-name 为空的节点。
    这些节点 mihomo 无法握手。
    """
    if not isinstance(proxies, list):
        return
    grpc_nodes = 0
    empty_svc = []
    for idx, p in enumerate(proxies):
        if not isinstance(p, dict):
            continue
        grpc = p.get('grpc-opts')
        if not isinstance(grpc, dict):
            continue
        grpc_nodes += 1
        svc = grpc.get('grpc-service-name')
        if svc is None or (isinstance(svc, str) and svc == ''):
            empty_svc.append((idx, p.get('name', '未命名')))

    rep.info('DIAG', '')
    rep.info('DIAG', '=' * 62)
    rep.info('DIAG', '【Q2.5】gRPC service-name 空值诊断')
    rep.info('DIAG', '=' * 62)
    rep.info('DIAG', f'  含 grpc-opts 的节点总数: {grpc_nodes}')
    if empty_svc:
        rep.warn('DIAG',
                 f'⚠️ grpc-service-name 为空的节点: {len(empty_svc)} '
                 f'(mihomo 无法握手)')
        for idx, name in empty_svc[:10]:
            rep.info('DIAG', f'    proxies[{idx}] {name!r}')
    else:
        rep.info('DIAG', '  ✅ 所有 gRPC 节点都有 service-name')
    rep.info('DIAG', '=' * 62)


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
        print('[1] YAML 解析...')
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
        print('[2] 校验 proxies...')
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

        # ---------- 2.5 节点特征诊断 ----------
        print('[2.5] 诊断节点特征...')
        diagnose_proxies(proxies, rep)

        # ---------- 2.6 Q1: 节点数对不上相关 ----------
        print('[2.6] 诊断 Q1: 节点名称清洗 & 全角残留...')
        diagnose_sanitized_names(proxies, rep)

        # ---------- 2.7 Q2: 延迟失败相关（节点维度） ----------
        print('[2.7] 诊断 Q2.1: WS 路径 URL 编码...')
        diagnose_ws_path_encoding(proxies, rep)

        print('[2.8] 诊断 Q2.2: XUDP 与传输层冲突...')
        diagnose_xudp_conflict(proxies, rep)

        print('[2.9] 诊断 Q2.3: UUID 默认值...')
        diagnose_default_uuid(proxies, rep)

        print('[2.10] 诊断 Q2.4: REALITY 字段...')
        diagnose_reality_fields(proxies, rep)

        print('[2.11] 诊断 Q2.5: gRPC service-name 空值...')
        diagnose_grpc_empty(proxies, rep)

        # ---------- 3. proxy-groups ----------
        print('[3] 校验 proxy-groups...')
        groups = data.get('proxy-groups') or []
        group_names = check_groups(groups, proxy_names, rep)

        # ---------- 3.5 Q1 续: 引用 vs 实际名匹配 ----------
        print('[3.5] 诊断 Q1.2: 引用名 vs 实际名匹配...')
        diagnose_reference_mismatch(groups, proxy_names, rep)

        # ---------- 3.6 Q1 续: 节点使用统计 ----------
        print('[3.6] 诊断 Q1.3/1.4: 节点引用使用统计...')
        diagnose_node_usage(proxies, groups, rep)

        # ---------- 3.7 Q1 续: 各组引用长度 ----------
        print('[3.7] 诊断 Q1.3: 各 proxy-group 引用长度...')
        diagnose_group_sizes(groups, rep)

        # ---------- 4. rules ----------
        print('[4] 校验 rules...')
        rules = data.get('rules') or []
        check_rules(rules, proxy_names, group_names, rep)

        # ---------- 5. 未使用的节点（提示） ----------
        print('[5] 统计未使用的节点...')
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
          f"WARN={rep.counts['WARN']}  INFO={rep.counts['INFO']}  "
          f"DIAG={rep.counts['DIAG']}")
    if rep.counts['FATAL'] or rep.counts['ERROR']:
        sys.exit(2)
    sys.exit(0)


if __name__ == '__main__':
    main()

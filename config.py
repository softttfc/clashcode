#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# =============================================================================
# config.py 说明
# =============================================================================
#
# 一、功能
# -----------------------------------------------------------------------------
# 本脚本用于将 Clash 格式的 list.yaml 转换为 Clash Meta 格式的 list.meta.yml。
# 同时生成：
#   - 按地区分类的节点片段：snippets/nodes_*.yml
#   - 按地区分类的 Meta 节点片段：snippets/nodes_*.meta.yml
#   - 主节点片段：snippets/nodes.meta.yml
#   - 规则片段：snippets/rules_*.yml
#   - snippets/rules.yml / snippets/rules_online.yml
#   - Adblock 规则合并
#
# 二、运行方式
# -----------------------------------------------------------------------------
#   python config.py list.yaml list.meta.yml
#
#   - list.yaml     : 输入文件（Clash 格式，含 proxies）
#   - list.meta.yml : 输出文件（Clash Meta 格式）
#
# 三、GitHub Actions 中使用
# -----------------------------------------------------------------------------
#   - name: 生成 Meta 配置
#     run: python config.py list.yaml list.meta.yml
#
# 四、支持的协议（Clash Verge）
# -----------------------------------------------------------------------------
#   vmess、ss、ssr、trojan、vless、hysteria2、tuic、http、https、socks5
#
# 五、全局变量
# -----------------------------------------------------------------------------
#   CONFIG_TEMPLATE : 模板文件名（Meta 配置骨架）
#   SNIPPETS_DIR    : 片段输出目录
#
# 六、依赖
# -----------------------------------------------------------------------------
#   pip install pyyaml requests requests-file
#七、目录
#   project/
# ├── config.py              # 本脚本
# ├── config.yml             # Meta 配置模板（必须）
# ├── list.yaml              # 输入文件（Clash 格式）
# ├── list.meta.yml          # 输出文件（Meta 格式）
# ├── abpwhite.txt           # 可选：Adblock 白名单
# ├── local_proxy.conf       # 可选：本地代理
# ├── local_NO_ADBLOCK       # 可选：跳过 Adblock
# └── snippets/              # 输出片段目录
#     ├── nodes_美国.meta.yml
#     ├── nodes_日本.meta.yml
#     ├── nodes.meta.yml
#     ├── rules_广告拦截.yml
#     ├── rules.yml
#     ├── rules_online.yml
#     └── example.yml       #可选：规则片段模板
# =============================================================================

import sys
import os
import copy
import base64
import binascii
import datetime
import traceback
from urllib.parse import quote, unquote, urlparse
from typing import Dict, List, Set, Any, Optional, Union, Callable, Iterable, TypedDict

import yaml
import requests
from requests_file import FileAdapter

# =============================================================================
# 全局配置（可调参数）
# =============================================================================

# ---------- 文件路径 ----------
CONFIG_TEMPLATE = "config.yml"    # Meta 配置模板文件名（必须存在）
SNIPPETS_DIR    = "snippets"      # 片段输出目录
LOCAL_PROXY_CONF = "local_proxy.conf"  # 可选：本地代理配置

# ---------- 名称显示控制 ----------
NAME_SHOW_TYPE = False   # 是否在节点名中显示协议类型，例如 [Vless] xxx
NAME_NO_FLAGS  = False   # 是否移除国旗 emoji
NAME_SHOW_SRC  = False   # 是否显示节点来源（本脚本保留但未启用）

# ---------- Adblock 规则来源 ----------
ABFURLS = (
    "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/ChineseFilter/sections/adservers.txt",
    "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/ChineseFilter/sections/adservers_firstparty.txt",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_224_Chinese/filter.txt",
    "https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/AWAvenue-Ads-Rule.txt",
    "https://raw.githubusercontent.com/d3ward/toolz/master/src/d3host.adblock",
    "https://raw.githubusercontent.com/afwfv/DD-AD/main/rule/DD-AD.txt",
)
ABFWHITE = (
    "https://raw.githubusercontent.com/privacy-protection-tools/dead-horse/master/anti-ad-white-list.txt",
    "file:///./abpwhite.txt",
)

# 调试开关：若存在 local_NO_ADBLOCK 文件，则跳过 Adblock 抓取
DEBUG_NO_ADBLOCK = os.path.exists("local_NO_ADBLOCK")

# =============================================================================
# 工具函数
# =============================================================================

def b64encodes(s: str) -> str:
    """标准 Base64 编码"""
    return base64.b64encode(s.encode('utf-8')).decode('utf-8')


def b64encodes_safe(s: str) -> str:
    """URL 安全 Base64 编码"""
    return base64.urlsafe_b64encode(s.encode('utf-8')).decode('utf-8')


def b64decodes(s: str) -> str:
    """标准 Base64 解码（自动补齐 padding）"""
    ss = s + '=' * ((4 - len(s) % 4) % 4)
    return base64.b64decode(ss.encode('utf-8')).decode('utf-8')


def b64decodes_safe(s: str) -> str:
    """URL 安全 Base64 解码（自动补齐 padding）"""
    ss = s + '=' * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode(ss.encode('utf-8')).decode('utf-8')


def normpath(url: str) -> str:
    """规范化 file:// 路径，支持本地 abpwhite.txt"""
    if url.startswith('file://'):
        basedir = os.path.dirname(os.path.abspath(__file__))
        return url.replace('/./', '/' + basedir.lstrip('/').replace(os.sep, '/') + '/')
    return url


def raw2fastly(url: str) -> str:
    """将 raw.githubusercontent.com 转为 fastly.jsdelivr.net 镜像"""
    if url.startswith("https://raw.githubusercontent.com/"):
        parts = url[34:].split('/')
        if len(parts) >= 3:
            parts[1] += '@' + parts[2]
            del parts[2]
            return "https://fastly.jsdelivr.net/gh/" + ('/'.join(parts))
    return url


# =============================================================================
# 常量表
# =============================================================================

# VMess 默认 UUID
DEFAULT_UUID = '8' * 8 + '-8888' * 3 + '-' + '8' * 12

# VMess ↔ Clash 字段映射
CLASH2VMESS = {
    'name': 'ps', 'server': 'add', 'port': 'port', 'uuid': 'id',
    'alterId': 'aid', 'cipher': 'scy', 'network': 'net', 'servername': 'sni',
}
VMESS2CLASH: Dict[str, str] = {}
for k, v in CLASH2VMESS.items():
    VMESS2CLASH[v] = k

# VMess 模板（用于 URL 生成，config.py 保留以兼容 Node 类）
VMESS_TEMPLATE = {
    "v": "2", "ps": "", "add": "0.0.0.0", "port": "0", "aid": "0", "scy": "auto",
    "net": "tcp", "type": "none", "tls": "", "id": DEFAULT_UUID,
}

# Clash 支持的加密方式
CLASH_CIPHER_VMESS = "auto aes-128-gcm chacha20-poly1305 none".split()
CLASH_CIPHER_SS = (
    "aes-128-gcm aes-192-gcm aes-256-gcm aes-128-cfb aes-192-cfb "
    "aes-256-cfb aes-128-ctr aes-192-ctr aes-256-ctr rc4-md5 chacha20-ietf "
    "xchacha20 chacha20-ietf-poly1305 xchacha20-ietf-poly1305"
).split()
CLASH_SSR_OBFS = (
    "plain http_simple http_post random_head tls1.2_ticket_auth tls1.2_ticket_fastauth"
).split()
CLASH_SSR_PROTOCOL = (
    "origin auth_sha1_v4 auth_aes128_md5 auth_aes128_sha1 auth_chain_a auth_chain_b"
).split()

# 假节点过滤
FAKE_IPS = "8.8.8.8; 8.8.4.4; 4.2.2.2; 4.2.2.1; 114.114.114.114; 127.0.0.1; 0.0.0.0".split('; ')
FAKE_DOMAINS = ".google.com .github.com".split()

# 屏蔽词（Base64 编码，避免直接出现敏感词）
BANNED_WORDS = b64decodes(
    '5rOV6L2uIOi9ruWtkCDova4g57uDIOawlCDlip8g5L2/5YqyIOWKsiDliqrlipsg5Yqg5rK5IOWlsyDmnYMg6L+Q5YqoIG9uZ3RhaXdhbg=='
).split()

# 请求超时
FETCH_TIMEOUT = (6, 15)


# =============================================================================
# HTTP 会话
# =============================================================================

session = requests.Session()
session.trust_env = False
session.headers["User-Agent"] = (
    'Mozilla/5.0 (X11; Linux x86_64) Clash-verge/v2.4.2 '
    'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 '
    'Safari/537.36 Edg/140.0.0.0'
)
session.mount('file://', FileAdapter())

# 本地代理支持（可选）
try:
    PROXY = open(LOCAL_PROXY_CONF).read().strip()
except FileNotFoundError:
    PROXY = None
if PROXY and PROXY != 'NONE':
    session.proxies = {'http': PROXY, 'https': PROXY}


# =============================================================================
# 异常类
# =============================================================================

class UnsupportedType(Exception):
    """不支持的节点类型"""
    pass


class NotANode(Exception):
    """不是有效的节点链接"""
    pass


# =============================================================================
# Node 类：统一的节点数据模型
# =============================================================================

class Node:
    """
    节点对象，支持从 dict（Clash 格式）或 str（V2Ray 链接）初始化。

    主要属性：
        data  : 节点数据字典（Clash 格式）
        type  : 协议类型
        names : 节点名称集合（用于合并同名节点）
    """

    gNames: Set[str] = set()  # 全局节点名集合，用于去重

    class DATA_TYPE(TypedDict):
        name: str
        type: str
        server: str
        port: int

    def __init__(self, data: Union[DATA_TYPE, str]) -> None:
        if isinstance(data, dict):
            self.data: Node.DATA_TYPE = data
            self.type = data['type']
        elif isinstance(data, str):
            self.load_url(data)
        else:
            raise TypeError(f"Got {type(data)}")

        if not self.data['name']:
            self.data['name'] = "未命名"
        if 'password' in self.data:
            self.data['password'] = str(self.data['password'])
        self.data['type'] = self.type
        self.names: Set[str] = {self.data['name']}

    def __str__(self):
        return self.url

    def __hash__(self):
        """节点 Hash，用于去重"""
        data = self.data
        try:
            path = ""
            if self.type == 'vmess':
                net: str = data.get('network', '')
                path = net + ':'
                if not net:
                    pass
                elif net == 'ws':
                    opts: Dict[str, Any] = data.get('ws-opts', {})
                    path += opts.get('headers', {}).get('Host', '')
                    path += '/' + opts.get('path', '')
                elif net == 'h2':
                    opts: Dict[str, Any] = data.get('h2-opts', {})
                    path += ','.join(opts.get('host', []))
                    path += '/' + opts.get('path', '')
                elif net == 'grpc':
                    path += data.get('grpc-opts', {}).get('grpc-service-name', '')
            elif self.type == 'ss':
                opts: Dict[str, Any] = data.get('plugin-opts', {})
                path = opts.get('host', '')
                path += '/' + opts.get('path', '')
            elif self.type == 'ssr':
                path = data.get('obfs-param', '')
            elif self.type == 'trojan':
                path = data.get('sni', '') + ':'
                net: str = data.get('network', '')
                if not net:
                    pass
                elif net == 'ws':
                    opts: Dict[str, Any] = data.get('ws-opts', {})
                    path += opts.get('headers', {}).get('Host', '')
                    path += '/' + opts.get('path', '')
                elif net == 'grpc':
                    path += data.get('grpc-opts', {}).get('grpc-service-name', '')
            elif self.type == 'vless':
                path = data.get('sni', '') + ':'
                net: str = data.get('network', '')
                if not net:
                    pass
                elif net == 'ws':
                    opts: Dict[str, Any] = data.get('ws-opts', {})
                    path += opts.get('headers', {}).get('Host', '')
                    path += '/' + opts.get('path', '')
                elif net == 'grpc':
                    path += data.get('grpc-opts', {}).get('grpc-service-name', '')
            elif self.type == 'hysteria2':
                path = data.get('sni', '') + ':'
                path += data.get('obfs-password', '') + ':'
            path += '@' + ','.join(data.get('alpn', [])) + '@' + \
                data.get('password', '') + data.get('uuid', '')
            hashstr = f"{self.type}:{data['server']}:{data['port']}:{path}"
            return hash(hashstr)
        except Exception:
            print("节点 Hash 计算失败！", file=sys.stderr)
            traceback.print_exc(file=sys.stderr)
            return hash(self.url)

    def __eq__(self, other: Union['Node', Any]):
        if isinstance(other, self.__class__):
            return hash(self) == hash(other)
        return False

    # ---------- URL 解析 ----------

    @staticmethod
    def urlparse(url: str, scheme='', allow_fragments=True):
        """自定义 URL 解析，支持 fragment 保留"""
        if allow_fragments and '#' in url:
            segs = url.split('#')
            fragment = segs[-1]
            url = '#'.join(segs[:-1])
        else:
            fragment = None
        res = urlparse(url, scheme, allow_fragments=False)
        if fragment:
            res = res._replace(fragment=fragment)
        return res

    def load_url(self, url: str):
        """从 V2Ray 链接加载节点"""
        try:
            self.type, dt = url.split("://", 1)
        except ValueError:
            raise NotANode(url)
        if not self.type.isascii():
            self.type = ''.join([_ for _ in self.type if _.isascii()])
            url = self.type + '://' + url.split("://")[1]
        if self.type == 'hy2':
            self.type = 'hysteria2'
        loader: Optional[Callable[[str, str], None]] = getattr(self, '_load_' + self.type, None)
        if loader:
            loader(url, dt)
        else:
            raise UnsupportedType(self.type)
        # IPv6 地址加方括号
        if ('server' in self.data and ':' in self.data['server'] and
                not self.data['server'].startswith('[')):
            self.data['server'] = f"[{self.data['server']}]"

    def _load_vmess(self, url: str, dt: str):
        """解析 vmess:// 链接"""
        v = VMESS_TEMPLATE.copy()
        try:
            v.update(json.loads(b64decodes(dt)))
        except Exception:
            raise UnsupportedType('vmess', 'SP')
        self.data = {}
        for key, val in v.items():
            if key in VMESS2CLASH:
                self.data[VMESS2CLASH[key]] = val
        self.data['tls'] = (v['tls'] == 'tls')
        self.data['alterId'] = int(self.data['alterId'])
        if v['net'] == 'ws':
            opts = {}
            if 'path' in v:
                opts['path'] = v['path']
            if 'host' in v:
                opts['headers'] = {'Host': v['host']}
            self.data['ws-opts'] = opts
        elif v['net'] == 'h2':
            opts = {}
            if 'path' in v:
                opts['path'] = v['path']
            if 'host' in v:
                opts['host'] = v['host'].split(',')
            self.data['h2-opts'] = opts
        elif v['net'] == 'grpc' and 'path' in v:
            self.data['grpc-opts'] = {'grpc-service-name': v['path']}

    def _load_ss(self, url: str, dt: str):
        """解析 ss:// 链接"""
        info = dt.split('@')
        srvname = info.pop()
        if '#' in srvname:
            srv, name = srvname.split('#')
        else:
            srv = srvname
            name = ''
        segs = srv.split(':')
        port = segs[-1]
        server = ':'.join(segs[:-1])
        try:
            port = int(port)
        except ValueError:
            raise UnsupportedType('ss', 'SP')
        info = '@'.join(info)
        if ':' not in info:
            info = b64decodes_safe(info)
        if ':' in info:
            cipher, passwd = info.split(':')
        else:
            cipher = info
            passwd = ''
        self.data = {
            'name': unquote(name), 'server': server,
            'port': port, 'type': 'ss', 'password': passwd, 'cipher': cipher,
        }

    def _load_ssr(self, url: str, dt: str):
        """解析 ssr:// 链接"""
        if '?' in url:
            parts = dt.split(':')
        else:
            parts = b64decodes_safe(dt).split(':')
        try:
            passwd, info = parts[-1].split('/?')
        except Exception:
            raise
        passwd = b64decodes_safe(passwd)
        self.data = {
            'type': 'ssr', 'server': parts[0], 'port': parts[1],
            'protocol': parts[2], 'cipher': parts[3], 'obfs': parts[4],
            'password': passwd, 'name': '',
        }
        for kv in info.split('&'):
            k_v = kv.split('=', 1)
            if len(k_v) != 2:
                k = k_v[0]
                v = ''
            else:
                k, v = k_v
            if k == 'remarks':
                self.data['name'] = v
            elif k == 'group':
                self.data['group'] = v
            elif k == 'obfsparam':
                self.data['obfs-param'] = v
            elif k == 'protoparam':
                self.data['protocol-param'] = v

    def _load_trojan(self, url: str, dt: str):
        """解析 trojan:// 链接"""
        parsed = self.urlparse(url)
        self.data = {
            'name': unquote(parsed.fragment), 'server': parsed.hostname,
            'port': parsed.port, 'type': 'trojan',
            'password': unquote(parsed.username),
        }
        if not parsed.query:
            return
        for kv in parsed.query.split('&'):
            k, v = kv.split('=', 1)
            if k in ('allowInsecure', 'insecure'):
                self.data['skip-cert-verify'] = (v != '0')
            elif k == 'sni':
                self.data['sni'] = v
            elif k == 'alpn':
                self.data['alpn'] = unquote(v).split(',')
            elif k == 'type':
                self.data['network'] = v
            elif k == 'serviceName':
                if 'grpc-opts' not in self.data:
                    self.data['grpc-opts'] = {}
                self.data['grpc-opts']['grpc-service-name'] = v
            elif k == 'host':
                if 'ws-opts' not in self.data:
                    self.data['ws-opts'] = {}
                if 'headers' not in self.data['ws-opts']:
                    self.data['ws-opts']['headers'] = {}
                self.data['ws-opts']['headers']['Host'] = v
            elif k == 'path':
                if 'ws-opts' not in self.data:
                    self.data['ws-opts'] = {}
                self.data['ws-opts']['path'] = v

    def _load_vless(self, url: str, dt: str):
        """解析 vless:// 链接"""
        parsed = self.urlparse(url)
        self.data = {
            'name': unquote(parsed.fragment), 'server': parsed.hostname,
            'port': parsed.port, 'type': 'vless',
            'uuid': unquote(parsed.username),
        }
        self.data['tls'] = False
        if not parsed.query:
            return
        for kv in parsed.query.split('&'):
            k, v = kv.split('=', 1)
            if k in ('allowInsecure', 'insecure'):
                self.data['skip-cert-verify'] = (v != '0')
            elif k == 'sni':
                self.data['servername'] = v
            elif k == 'alpn':
                self.data['alpn'] = unquote(v).split(',')
            elif k == 'type':
                self.data['network'] = v
            elif k == 'serviceName':
                if 'grpc-opts' not in self.data:
                    self.data['grpc-opts'] = {}
                self.data['grpc-opts']['grpc-service-name'] = v
            elif k == 'host':
                if 'ws-opts' not in self.data:
                    self.data['ws-opts'] = {}
                if 'headers' not in self.data['ws-opts']:
                    self.data['ws-opts']['headers'] = {}
                self.data['ws-opts']['headers']['Host'] = v
            elif k == 'path':
                if 'ws-opts' not in self.data:
                    self.data['ws-opts'] = {}
                self.data['ws-opts']['path'] = v
            elif k == 'flow':
                if v.endswith('-udp443'):
                    self.data['flow'] = v
                else:
                    self.data['flow'] = v + '!'
            elif k == 'fp':
                self.data['client-fingerprint'] = v
            elif k == 'security' and v == 'tls':
                self.data['tls'] = True
            elif k == 'pbk':
                if 'reality-opts' not in self.data:
                    self.data['reality-opts'] = {}
                self.data['reality-opts']['public-key'] = v
            elif k == 'sid':
                if 'reality-opts' not in self.data:
                    self.data['reality-opts'] = {}
                self.data['reality-opts']['short-id'] = v

    def _load_hysteria2(self, url: str, dt: str):
        """解析 hysteria2:// 链接"""
        parsed = self.urlparse(url)
        self.data = {
            'name': unquote(parsed.fragment), 'server': parsed.hostname,
            'type': 'hysteria2', 'password': unquote(parsed.username),
        }
        if ':' in parsed.netloc:
            ports = parsed.netloc.split(':')[1]
            if ',' in ports:
                _, self.data['ports'] = ports.split(',', 1)
            else:
                self.data['port'] = ports
            try:
                self.data['port'] = int(self.data['port'])
            except ValueError:
                self.data['port'] = 443
        else:
            self.data['port'] = 443
        self.data['tls'] = False
        if not parsed.query:
            return
        k = v = ''
        for kv in parsed.query.split('&'):
            if '=' in kv:
                k, v = kv.split('=', 1)
            else:
                v += '&' + kv
            if k == 'insecure':
                self.data['skip-cert-verify'] = (v != '0')
            elif k == 'alpn':
                self.data['alpn'] = unquote(v).split(',')
            elif k in ('sni', 'obfs', 'obfs-password'):
                self.data[k] = v
            elif k == 'fp':
                self.data['client-fingerprint'] = v

    def _load_tuic(self, url: str, dt: str):
        """解析 tuic:// 链接"""
        parsed = self.urlparse(url)
        self.data = {
            'name': unquote(parsed.fragment), 'server': parsed.hostname,
            'type': 'tuic', 'uuid': unquote(parsed.username),
            'password': unquote(parsed.password), 'port': parsed.port or 136,
        }
        if not parsed.query:
            return
        k = v = ''
        for kv in parsed.query.split('&'):
            if '=' in kv:
                k, v = kv.split('=', 1)
            else:
                v += '&' + kv
            if k == 'allow_insecure':
                self.data['skip-cert-verify'] = (v != '0')
            elif k == 'alpn':
                self.data['alpn'] = unquote(v).split(',')
            elif k in ('sni', 'udp_relay_mode'):
                self.data[k.replace('_', '-')] = v
            elif k == 'fp':
                self.data['client-fingerprint'] = v
            elif k == 'congestion_control':
                self.data['congestion-controller'] = v

    def _load__legacy(self, url: str, dt: str):
        """解析 http:// https:// socks5:// 链接"""
        parsed = urlparse(url)
        self.data = {
            'name': unquote(parsed.fragment),
            'type': 'socks5' if self.type.startswith('socks') else 'http',
            'tls': parsed.scheme == 'https',
            'server': parsed.hostname,
            'port': parsed.port,
            'username': parsed.username,
            'password': parsed.password,
        }
        self.data = {k: v for k, v in self.data.items() if v is not None}
        if self.type.startswith('socks'):
            self.type = self.data['type']

    _load_http   = _load__legacy
    _load_https  = _load__legacy
    _load_socks5 = _load__legacy
    _load_socks  = _load__legacy

    # ---------- 合并与名称 ----------

    def update(self, node: 'Node'):
        """合并同 Hash 节点：数据更新、名称合并"""
        self.data.update(node.data)
        self.names.union(node.names)

    @property
    def name(self):
        """从 names 集合中挑选最佳名称"""
        def rate(name: str):
            r = 0
            if name.startswith('@'):
                r -= 5
            if any(127462 <= ord(c) <= 127487 for c in name):
                r += 6
            if '\N{RIGHT-TO-LEFT MARK}' in name:
                r -= 3
            if any(word in name for word in BANNED_WORDS):
                r -= 100
            return r
        return sorted(list(self.names), key=rate)[0]

    def format_name(self, max_len=30):
        """格式化节点名称：Unicode 归一化、去重、长度裁剪"""
        name = [ord(c) for c in self.name]
        # 数学粗体大写 → 普通大写
        for ch in '\N{MATHEMATICAL BOLD CAPITAL A}\N{MATHEMATICAL SANS-SERIF BOLD CAPITAL A}':
            name = [
                c - ord(ch) + ord('A') if ord(ch) <= c < ord(ch) + 26 else c
                for c in name
            ]
        # 数学粗体小写 / 国旗 → 普通小写（NAME_NO_FLAGS 控制）
        for ch in ('\N{MATHEMATICAL BOLD SMALL A}\N{MATHEMATICAL SANS-SERIF BOLD SMALL A}'
                   + '\N{REGIONAL INDICATOR SYMBOL LETTER A}' * NAME_NO_FLAGS):
            name = [
                c - ord(ch) + ord('a') if ord(ch) <= c < ord(ch) + 26 else c
                for c in name
            ]
        name = ''.join([chr(c) for c in name])
        name = name.replace(chr(10144), '->')
        for word in BANNED_WORDS:
            name = name.replace(word, '*' * len(word))
        if len(name) > max_len:
            name = name[:max_len]
            if '\N{RIGHT-TO-LEFT MARK}' in name:
                name += '\N{LEFT-TO-RIGHT MARK}'
            name += '...'
        if NAME_SHOW_TYPE:
            if self.type in ('ss', 'ssr', 'vless', 'tuic'):
                tp = self.type.upper()
            else:
                tp = self.type.title()
            name = f'[{tp}] ' + name
        # 全局去重
        if name in Node.gNames:
            i = 0
            new = name
            while new in Node.gNames:
                i += 1
                new = f"{name} #{i}"
            name = new
        self.data['name'] = name

    # ---------- 有效性检查 ----------

    @property
    def isfake(self) -> bool:
        """检查是否为假节点"""
        try:
            if 'server' not in self.data:
                return True
            if self.data['server'] in FAKE_IPS:
                return True
            if int(str(self.data['port'])) < 20:
                return True
            for domain in FAKE_DOMAINS:
                if self.data['server'] == domain.lstrip('.'):
                    return True
                if self.data['server'].endswith(domain):
                    return True
            if 'sni' in self.data and 'google.com' in self.data['sni'].lower():
                self.data['sni'] = 'www.bing.com'
        except Exception:
            print("无法验证的节点！", file=sys.stderr)
            traceback.print_exc(file=sys.stderr)
        return False

    # ---------- V2Ray URL 生成（保留，兼容性） ----------

    @property
    def url(self) -> str:
        handler: Optional[Callable[[Node.DATA_TYPE], str]] = getattr(self, '_url_' + self.type, None)
        if handler:
            return handler(self.data)
        raise UnsupportedType(self.type)

    def _url_vmess(self, data: DATA_TYPE) -> str:
        v = VMESS_TEMPLATE.copy()
        for key, val in data.items():
            if key in CLASH2VMESS:
                v[CLASH2VMESS[key]] = val
        if v['net'] == 'ws' and 'ws-opts' in data:
            try:
                v['host'] = data['ws-opts']['headers']['Host']
            except KeyError:
                pass
            if 'path' in data['ws-opts']:
                v['path'] = data['ws-opts']['path']
        elif v['net'] == 'h2' and 'h2-opts' in data:
            if 'host' in data['h2-opts']:
                v['host'] = ','.join(data['h2-opts']['host'])
            if 'path' in data['h2-opts']:
                v['path'] = data['h2-opts']['path']
        elif v['net'] == 'grpc' and 'grpc-opts' in data:
            if 'grpc-service-name' in data['grpc-opts']:
                v['path'] = data['grpc-opts']['grpc-service-name']
        if data.get('tls'):
            v['tls'] = 'tls'
        return 'vmess://' + b64encodes(json.dumps(v, ensure_ascii=False))

    def _url_ss(self, data: DATA_TYPE) -> str:
        passwd = b64encodes_safe(data['cipher'] + ':' + data['password'])
        return f"ss://{passwd}@{data['server']}:{data['port']}#{quote(data['name'])}"

    def _url_ssr(self, data: DATA_TYPE) -> str:
        ret = (':'.join([str(data[_]) for _ in ('server', 'port', 'protocol', 'cipher', 'obfs')]) +
               b64encodes_safe(data['password']) +
               f"remarks={b64encodes_safe(data['name'])}")
        for k, urlk in (('obfs-param', 'obfsparam'), ('protocol-param', 'protoparam'), ('group', 'group')):
            if k in data:
                ret += '&' + urlk + '=' + b64encodes_safe(data[k])
        return "ssr://" + ret

    def _url_trojan(self, data: DATA_TYPE) -> str:
        passwd = quote(data['password'])
        name = quote(data['name'])
        ret = f"trojan://{passwd}@{data['server']}:{data['port']}?"
        if 'skip-cert-verify' in data:
            ret += f"allowInsecure={int(data['skip-cert-verify'])}&"
        if 'sni' in data:
            ret += f"sni={data['sni']}&"
        if 'alpn' in data:
            ret += f"alpn={quote(','.join(data['alpn']))}&"
        if 'network' in data:
            if data['network'] == 'grpc':
                ret += f"type=grpc&serviceName={data['grpc-opts']['grpc-service-name']}"
            elif data['network'] == 'ws':
                ret += f"type=ws&"
                if 'ws-opts' in data:
                    try:
                        ret += f"host={data['ws-opts']['headers']['Host']}&"
                    except KeyError:
                        pass
                    if 'path' in data['ws-opts']:
                        ret += f"path={data['ws-opts']['path']}"
        ret = ret.rstrip('&') + '#' + name
        return ret

    def _url_vless(self, data: DATA_TYPE) -> str:
        passwd = quote(data['uuid'])
        name = quote(data['name'])
        ret = f"vless://{passwd}@{data['server']}:{data['port']}?"
        if 'skip-cert-verify' in data:
            ret += f"allowInsecure={int(data['skip-cert-verify'])}&"
        if 'servername' in data:
            ret += f"sni={data['servername']}&"
        if 'alpn' in data:
            ret += f"alpn={quote(','.join(data['alpn']))}&"
        if 'network' in data:
            if data['network'] == 'grpc':
                ret += f"type=grpc&"
                try:
                    ret += f"serviceName={data['grpc-opts']['grpc-service-name']}&"
                except KeyError:
                    pass
            elif data['network'] == 'ws':
                ret += f"type=ws&"
                if 'ws-opts' in data:
                    try:
                        ret += f"host={data['ws-opts']['headers']['Host']}&"
                    except KeyError:
                        pass
                    if 'path' in data['ws-opts']:
                        ret += f"path={data['ws-opts']['path']}"
        if 'flow' in data:
            flow: str = data['flow']
            if flow.endswith('!'):
                ret += f"flow={flow[:-1]}&"
            else:
                ret += f"flow={flow}-udp443&"
        if 'client-fingerprint' in data:
            ret += f"fp={data['client-fingerprint']}&"
        if data.get('tls'):
            ret += f"security=tls&"
        elif 'reality-opts' in data:
            opts: Dict[str, str] = data['reality-opts']
            ret += f"security=reality&pbk={opts.get('public-key', '')}&sid={opts.get('short-id', '')}&"
        ret = ret.rstrip('&') + '#' + name
        return ret

    def _url_hysteria2(self, data: DATA_TYPE) -> str:
        passwd = quote(data['password'])
        name = quote(data['name'])
        ret = f"hysteria2://{passwd}@{data['server']}:{data['port']}"
        if 'ports' in data:
            ret += ',' + data['ports']
        ret += '?'
        if 'skip-cert-verify' in data:
            ret += f"insecure={int(data['skip-cert-verify'])}&"
        if 'alpn' in data:
            ret += f"alpn={quote(','.join(data['alpn']))}&"
        if 'client-fingerprint' in data:
            ret += f"fp={data['client-fingerprint']}&"
        for k in ('sni', 'obfs', 'obfs-password'):
            if k in data:
                ret += f"{k}={data[k]}&"
        ret = ret.rstrip('&') + '#' + name
        return ret

    def _url_tuic(self, data: DATA_TYPE) -> str:
        passwd = quote(data['password'])
        uuid = quote(data['uuid'])
        name = quote(data['name'])
        ret = f"tuic://{uuid}:{passwd}@{data['server']}:{data['port']}?"
        if 'skip-cert-verify' in data:
            ret += f"allow_insecure={int(data['skip-cert-verify'])}&"
        if 'alpn' in data:
            ret += f"alpn={quote(','.join(data['alpn']))}&"
        if 'client-fingerprint' in data:
            ret += f"fp={data['client-fingerprint']}&"
        if 'congestion-controller' in data:
            ret += f"congestion_control={data['congestion-controller']}&"
        for k in ('sni', 'udp-relay-mode'):
            if k in data:
                ret += f"{k.replace('-', '_')}={data[k]}&"
        ret = ret.rstrip('&') + '#' + name
        return ret

    def _url__legacy(self, data: DATA_TYPE) -> str:
        tp = 'https' if self.type == 'http' and data.get('tls') else self.type
        part = ''
        if 'username' in data:
            part += data['username']
        if 'password' in data:
            part += ':' + data['password']
        if part:
            part += '@'
        return f"{tp}://{part}{data['server']}:{data['port']}"

    _url_http   = _url__legacy
    _url_https  = _url__legacy
    _url_socks5 = _url__legacy

    # ---------- Clash 数据输出 ----------

    @property
    def clash_data(self) -> DATA_TYPE:
        """输出为 Clash 节点字典"""
        ret = self.data.copy()
        # 去除 IPv6 方括号
        if 'server' in ret and ret['server'].startswith('['):
            ret['server'] = ret['server'][1:-1]
        # 数字密码转字符串
        if 'password' in ret and ret['password'].isdigit():
            ret['password'] = '!!str ' + ret['password']
        # UUID 长度校验
        if 'uuid' in ret and len(ret['uuid']) != len(DEFAULT_UUID):
            ret['uuid'] = DEFAULT_UUID
        if 'group' in ret:
            del ret['group']
        if 'cipher' in ret and not ret['cipher']:
            ret['cipher'] = 'auto'
        # vless flow 去除 udp443 后缀
        if self.type == 'vless' and 'flow' in ret:
            if ret['flow'].endswith('-udp443'):
                ret['flow'] = ret['flow'][:-7]
            elif ret['flow'].endswith('!'):
                ret['flow'] = ret['flow'][:-1]
        # alpn 字符串转列表
        if 'alpn' in ret and isinstance(ret['alpn'], str):
            ret['alpn'] = ret['alpn'].replace(' ', '').split(',')
        # reality short-id 转字符串
        if 'reality-opts' in ret and 'short-id' in ret['reality-opts']:
            ret['reality-opts']['short-id'] = '!!str ' + ret['reality-opts']['short-id']
        if 'reality-opts' in ret:
            ret['tls'] = True
        return ret

    # ---------- 协议支持判断 ----------

    def supports_clash(self, meta=False) -> bool:
        """判断节点是否被 Clash / Clash Meta 支持"""
        if self.isfake:
            return False
        if 'obfs' in self.data and 'obfs-password' not in self.data:
            return False
        if self.type == 'vmess':
            supported = CLASH_CIPHER_VMESS
        elif self.type == 'ss' or self.type == 'ssr':
            supported = CLASH_CIPHER_SS
        elif self.type == 'trojan':
            return True
        elif not meta:
            return False
        else:
            # meta=True 时，vless / hysteria2 / tuic / http / socks5 全部通过
            return True
        if 'network' in self.data and self.data['network'] in ('h2', 'grpc'):
            self.data['tls'] = True
        if 'cipher' not in self.data:
            return True
        if not self.data['cipher']:
            return True
        if self.data['cipher'] not in supported:
            return False
        try:
            if self.type == 'ssr':
                if 'obfs' in self.data and self.data['obfs'] not in CLASH_SSR_OBFS:
                    return False
                if 'protocol' in self.data and self.data['protocol'] not in CLASH_SSR_PROTOCOL:
                    return False
            if 'plugin-opts' in self.data and 'mode' in self.data['plugin-opts'] \
                    and not self.data['plugin-opts']['mode']:
                return False
        except Exception:
            print("无法验证的 Clash 节点！", file=sys.stderr)
            traceback.print_exc(file=sys.stderr)
            return False
        return True

    def supports_meta(self) -> bool:
        """判断节点是否被 Clash Meta 支持"""
        return self.supports_clash(meta=True)

    def supports_ray(self) -> bool:
        """判断节点是否被 V2Ray 支持"""
        if self.isfake:
            return False
        if self.type == 'socks5' and self.data.get('tls'):
            return False
        return True


# =============================================================================
# DomainTree：域名后缀树（用于 Adblock 规则合并）
# =============================================================================

class DomainTree:
    def __init__(self) -> None:
        self.children: Dict[str, 'DomainTree'] = {}
        self.here: bool = False

    def insert(self, domain: str):
        segs = domain.split('.')
        segs.reverse()
        self._insert(segs)

    def _insert(self, segs: List[str]):
        if not segs:
            self.here = True
            return
        if segs[0] not in self.children:
            self.children[segs[0]] = DomainTree()
        child = self.children[segs[0]]
        del segs[0]
        child._insert(segs)

    def remove(self, domain: str):
        segs = domain.split('.')
        segs.reverse()
        self._remove(segs)

    def _remove(self, segs: List[str]):
        self.here = False
        if not segs:
            self.children.clear()
            return
        if segs[0] in self.children:
            child = self.children[segs[0]]
            del segs[0]
            child._remove(segs)

    def get(self) -> List[str]:
        ret: List[str] = []
        for name, child in self.children.items():
            if child.here:
                ret.append(name)
            else:
                ret.extend([_ + '.' + name for _ in child.get()])
        return ret


# =============================================================================
# Adblock 规则合并
# =============================================================================

def merge_adblock(adblock_name: str, rules: Dict[str, str]):
    """
    从 ABFURLS / ABFWHITE 抓取 Adblock 规则，合并到 rules 字典。
    规则格式：{"DOMAIN-SUFFIX,xxx": adblock_name, ...}
    """
    print("正在解析 Adblock 列表... ", end='', flush=True)
    blocked: Set[str] = set()
    unblock: Set[str] = set()

    # 1. 抓取广告域名
    for url in ABFURLS:
        url = raw2fastly(url)
        try:
            res = session.get(normpath(url))
        except requests.exceptions.RequestException as e:
            try:
                print(f"{url} 下载失败：{e.args[0].reason}")
            except Exception:
                print(f"{url} 下载失败：无法解析的错误！")
                traceback.print_exc()
            continue
        if res.status_code != 200:
            print(url, res.status_code)
            continue
        for line in res.text.strip().splitlines():
            line = line.strip()
            if not line or line[0] in '!#':
                continue
            elif line[:2] == '@@':
                unblock.add(line.split('^')[0].strip('@|^'))
            elif line[:2] == '||' and ('/' not in line) and ('?' not in line) and \
                    (line[-1] == '^' or line.endswith("$all")):
                blocked.add(line.strip('al').strip('|^$'))

    # 2. 抓取白名单
    for url in ABFWHITE:
        url = raw2fastly(url)
        try:
            res = session.get(normpath(url))
        except requests.exceptions.RequestException as e:
            try:
                print(f"{url} 下载失败：{e.args[0].reason}")
            except Exception:
                print(f"{url} 下载失败：无法解析的错误！")
                traceback.print_exc()
            continue
        if res.status_code != 200:
            print(url, res.status_code)
            continue
        for line in res.text.strip().splitlines():
            line = line.strip()
            if not line or line[0] == '!':
                continue
            else:
                unblock.add(line.split('^')[0].strip('|^'))

    # 3. 构建域名树
    domain_root = DomainTree()
    domain_keys: Set[str] = set()
    for domain in blocked:
        if '/' in domain:
            continue
        if '*' in domain:
            domain = domain.strip('*')
            if '*' not in domain:
                domain_keys.add(domain)
            continue
        segs = domain.split('.')
        if len(segs) == 4 and domain.replace('.', '').isdigit():
            for seg in segs:
                if not seg:
                    break
                if seg[0] == '0' and seg != '0':
                    break
            else:
                rules[f'IP-CIDR,{domain}/32'] = adblock_name
        else:
            domain_root.insert(domain)
    for domain in unblock:
        domain_root.remove(domain)

    for domain in domain_keys:
        rules[f'DOMAIN-KEYWORD,{domain}'] = adblock_name

    for domain in domain_root.get():
        for key in domain_keys:
            if key in domain:
                break
        else:
            rules[f'DOMAIN-SUFFIX,{domain}'] = adblock_name

    print(f"共有 {len(rules)} 条规则")


# =============================================================================
# 从 list.yaml 读取节点
# =============================================================================

def load_nodes_from_yaml(input_file: str) -> Dict[int, Node]:
    """
    从 Clash YAML 文件读取 proxies，重建 Node 对象。

    返回：
        Dict[int, Node]  : Hash → Node 映射
    """
    if not os.path.exists(input_file):
        print(f"❌ 输入文件 {input_file} 不存在", file=sys.stderr)
        sys.exit(1)

    with open(input_file, encoding="utf-8") as f:
        conf = yaml.full_load(f)

    if not conf or 'proxies' not in conf:
        print(f"⚠️ {input_file} 中未找到 proxies 字段", file=sys.stderr)
        return {}

    proxies = conf['proxies'] or []
    print(f"📖 从 {input_file} 读取到 {len(proxies)} 个节点")

    Node.gNames = set()
    merged: Dict[int, Node] = {}

    for p in proxies:
        if not isinstance(p, dict):
            print(f"⚠️ 跳过非字典节点: {p}", file=sys.stderr)
            continue
        try:
            node = Node(p)
        except Exception:
            print(f"⚠️ 解析节点失败: {p.get('name', 'unknown')}", file=sys.stderr)
            traceback.print_exc(file=sys.stderr)
            continue
        try:
            node.format_name()
        except Exception:
            print(f"⚠️ 格式化节点名失败: {node.name}", file=sys.stderr)
            traceback.print_exc(file=sys.stderr)
        Node.gNames.add(node.data['name'])
        hashn = hash(node)
        if hashn not in merged:
            merged[hashn] = node
        else:
            merged[hashn].update(node)

    print(f"🔀 去重后共 {len(merged)} 个节点")
    return merged


# =============================================================================
# 主函数
# =============================================================================

def main():
    # ---------- 解析命令行参数 ----------
    input_file  = sys.argv[1] if len(sys.argv) > 1 else "list.yaml"
    output_file = sys.argv[2] if len(sys.argv) > 2 else "list.meta.yml"

    print(f"📥 输入文件: {input_file}")
    print(f"📤 输出文件: {output_file}")
    print(f"📄 模板文件: {CONFIG_TEMPLATE}")
    print(f"📁 片段目录: {SNIPPETS_DIR}")
    print()

    # ---------- 1. 读取输入节点 ----------
    merged = load_nodes_from_yaml(input_file)
    if not merged:
        print("❌ 未读取到任何节点，退出", file=sys.stderr)
        sys.exit(1)

    # ---------- 2. 读取 config.yml 模板 ----------
    if not os.path.exists(CONFIG_TEMPLATE):
        print(f"❌ 模板文件 {CONFIG_TEMPLATE} 不存在", file=sys.stderr)
        sys.exit(1)

    with open(CONFIG_TEMPLATE, encoding="utf-8") as f:
        conf: Dict[str, Any] = yaml.full_load(f)

    # ---------- 3. 合并 Adblock 规则 ----------
    rules: Dict[str, str] = {}
    if DEBUG_NO_ADBLOCK:
        print("!!! 警告：已关闭 Adblock 规则抓取 !!!")
    else:
        merge_adblock(conf['proxy-groups'][-2]['name'], rules)

    # ---------- 4. 读取 NoMoreWalls 配置并分类节点 ----------
    snip_conf: Dict[str, Dict[str, Any]] = {}
    ctg_nodes: Dict[str, List[Node.DATA_TYPE]] = {}
    ctg_nodes_meta: Dict[str, List[Node.DATA_TYPE]] = {}
    categories: Dict[str, List[str]] = {}

    try:
        snip_conf = conf['NoMoreWalls']
    except KeyError:
        print("⚠️ config.yml 未设置 NoMoreWalls 片段配置", file=sys.stderr)
    else:
        del conf['NoMoreWalls']
        print("正在按地区分类节点...")
        categories = snip_conf['categories']
        for ctg in categories:
            ctg_nodes[ctg] = []
            ctg_nodes_meta[ctg] = []

        for node in merged.values():
            if node.supports_meta():
                ctgs: List[str] = []
                for ctg, keys in categories.items():
                    for key in keys:
                        if key in node.name:
                            ctgs.append(ctg)
                            break
                    if ctgs and keys[-1] == 'OVERALL':
                        break
                if len(ctgs) == 1:
                    try:
                        if node.supports_clash():
                            ctg_nodes[ctgs[0]].append(node.clash_data)
                        ctg_nodes_meta[ctgs[0]].append(node.clash_data)
                    except Exception:
                        traceback.print_exc()

        # 写出分类节点片段
        os.makedirs(SNIPPETS_DIR, exist_ok=True)
        for ctg, proxies in ctg_nodes.items():
            with open(os.path.join(SNIPPETS_DIR, "nodes_" + ctg + ".yml"), 'w', encoding="utf-8") as f:
                yaml.dump({'proxies': proxies}, f, allow_unicode=True)
        for ctg, proxies in ctg_nodes_meta.items():
            with open(os.path.join(SNIPPETS_DIR, "nodes_" + ctg + ".meta.yml"), 'w', encoding="utf-8") as f:
                yaml.dump({'proxies': proxies}, f, allow_unicode=True)

    # ---------- 5. 处理规则（合并 Adblock 到 conf['rules']） ----------
    keywords: List[str] = []
    suffixes: List[str] = []
    match_rule = None
    for rule in conf['rules']:
        rule: str
        tmp = rule.strip().split(',')
        if len(tmp) == 2 and tmp[0] == 'MATCH':
            match_rule = rule
            break
        if len(tmp) == 3:
            rtype, rargument, rpolicy = tmp
            if rtype == 'DOMAIN-KEYWORD':
                keywords.append(rargument)
            elif rtype == 'DOMAIN-SUFFIX':
                suffixes.append(rargument)
        elif len(tmp) == 4:
            rtype, rargument, rpolicy, rresolve = tmp
            rpolicy += ',' + rresolve
        else:
            print("规则 '" + rule + "' 无法被解析！")
            continue
        # 去重：如果已被更泛化的规则覆盖，则跳过
        for kwd in keywords:
            if kwd in rargument and kwd != rargument:
                break
        else:
            for sfx in suffixes:
                if ('.' + rargument).endswith('.' + sfx) and sfx != rargument:
                    break
            else:
                k = rtype + ',' + rargument
                if k not in rules:
                    rules[k] = rpolicy

    conf['rules'] = [','.join(_) for _ in rules.items()] + [match_rule]

    # ---------- 6. 构建 Meta 配置 ----------
    global_fp: Optional[str] = conf.get('global-client-fingerprint', None)
    proxies_meta: List[Node.DATA_TYPE] = []
    proxies_meta_snip: List[Node.DATA_TYPE] = []
    ctg_base: Dict[str, Any] = conf['proxy-groups'][3].copy()
    names_clash_meta: Set[str] = set()

    for p in merged.values():
        if p.supports_meta():
            clash_data = p.clash_data
            clash_data_snip = clash_data.copy()
            # 移除与全局相同的 client-fingerprint
            if ('client-fingerprint' in clash_data and
                    clash_data['client-fingerprint'] == global_fp):
                del clash_data['client-fingerprint']
            proxies_meta.append(clash_data)
            proxies_meta_snip.append(clash_data_snip)
            names_clash_meta.add(p.data['name'])

    names_clash_meta = list(names_clash_meta)

    conf['proxies'] = proxies_meta
    for group in conf['proxy-groups']:
        if not group['proxies']:
            group['proxies'] = names_clash_meta

    # 添加地区组
    if snip_conf:
        conf['proxy-groups'][-1]['proxies'] = []
        ctg_selects: List[str] = conf['proxy-groups'][-1]['proxies']
        ctg_disp: Dict[str, str] = snip_conf['categories_disp']
        for ctg, payload in ctg_nodes_meta.items():
            if ctg in ctg_disp:
                disp = ctg_base.copy()
                disp['name'] = ctg_disp[ctg]
                if not payload:
                    proxy_list = ['REJECT']
                else:
                    proxy_list = [_['name'] for _ in payload]
                # 过滤组名冲突
                group_names = [g.get('name') for g in conf['proxy-groups']]
                exclude = set(group_names)
                exclude.add(disp['name'])
                if payload:
                    filtered_names = [name for name in proxy_list if name not in exclude]
                    if not filtered_names:
                        filtered_names = ['REJECT']
                else:
                    filtered_names = ['REJECT']
                disp['proxies'] = filtered_names
                conf['proxy-groups'].append(disp)
                ctg_selects.append(disp['name'])

    # 通用过滤：所有 url-test / fallback 组移除组名元素
    all_group_names = set(g['name'] for g in conf['proxy-groups'])
    for g in conf['proxy-groups']:
        if g.get('type') in ('url-test', 'fallback'):
            original = g.get('proxies', [])
            if isinstance(original, list):
                filtered = [p for p in original if p not in all_group_names]
                g['proxies'] = filtered

    # ---------- 7. 写出 list.meta.yml ----------
    with open(output_file, 'w', encoding="utf-8") as f:
        f.write(datetime.datetime.now().strftime('# Update: %Y-%m-%d %H:%M\n'))
        f.write(yaml.dump(conf, allow_unicode=True).replace('!!str ', ''))

    # ---------- 8. 写出主节点片段 ----------
    os.makedirs(SNIPPETS_DIR, exist_ok=True)
    with open(os.path.join(SNIPPETS_DIR, "nodes.meta.yml"), 'w', encoding="utf-8") as f:
        f.write(yaml.dump({'proxies': proxies_meta_snip}, allow_unicode=True).replace('!!str ', ''))

    # ---------- 9. 写出规则片段 ----------
    if snip_conf:
        print("正在写出配置片段...")
        name_map: Dict[str, str] = snip_conf['name-map']
        snippets: Dict[str, List[str]] = {}
        for rpolicy in name_map.values():
            snippets[rpolicy] = []
        for rule, rpolicy in rules.items():
            if ',' in rpolicy:
                rpolicy = rpolicy.split(',')[0]
            if rpolicy in name_map:
                snippets[name_map[rpolicy]].append(rule)
        for name, payload in snippets.items():
            with open(os.path.join(SNIPPETS_DIR, name + ".yml"), 'w', encoding="utf-8") as f:
                yaml.dump({'payload': payload}, f, allow_unicode=True)

        # 生成 rules.yml / rules_online.yml
        example_path = os.path.join(SNIPPETS_DIR, "example.yml")
        if os.path.exists(example_path):
            with open(example_path, encoding="utf-8") as f:
                template: Dict[str, Any] = yaml.full_load(f)
            template = {
                k: v for k, v in template.items()
                if k in ('dns', 'proxy-groups', 'rule-providers', 'rules')
            }
            for group in template['proxy-groups']:
                group: Dict[str, Any]
                if 'use' in group:
                    del group['use']
                    group['include-all'] = True
            with open(os.path.join(SNIPPETS_DIR, "rules_online.yml"), 'w', encoding="utf-8") as f:
                yaml.dump(template, f, allow_unicode=True)

            del template['rule-providers']
            template['rules'] = conf['rules']
            with open(os.path.join(SNIPPETS_DIR, "rules.yml"), 'w', encoding="utf-8") as f:
                yaml.dump(template, f, allow_unicode=True)

    print(f"✅ 写出完成：{output_file}")


if __name__ == '__main__':
    main()

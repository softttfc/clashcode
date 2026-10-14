#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# =============================================================================
# crawler_pro.py 说明
# =============================================================================
#
# 一、功能
# -----------------------------------------------------------------------------
# 网页爬虫 + 订阅解析 + 节点测通 + Clash 配置生成。
# 支持 11 种协议：vmess / vless / ss / ssr / trojan /
#               hysteria / hysteria2 / tuic / http / https / socks5
#
# 二、本次修改内容（协议扩展 + 隐患修复）
# -----------------------------------------------------------------------------
# 1. 新增解析函数：
#    parse_ssr / parse_hysteria2 / parse_hysteria / parse_tuic / parse_http_socks
# 2. 新增 QUIC 握手测试（修复 UDP 协议节点被 TCP 测通误杀）：
#    - test_quic_for_crawler / _quic_handshake_async
#    - UDP_TYPES 中的协议不做 TCP 测通，改走 QUIC 握手
#    - aioquic 未安装时保守保留节点，不误杀
# 3. 新增 clean_ipv6()：TCP / QUIC 测试前去除 IPv6 方括号
# 4. NODE_PREFIXES 全局常量：统一 Base64 解码、按行解析、raw 回退的前缀判断
# 5. node_link_regex 扩展：网页内嵌节点链接可识别新协议
# 6. 名称生成加协议前缀：避免不同协议同 server 节点重名
# 7. skip-cert-verify 字段统一：
#    - 解析时同时保留 allowInsecure（兼容）+ skip-cert-verify（标准）
#    - 输出时统一判断 skip-cert-verify
# 8. alpn 类型统一：解析存字符串，输出转列表
# 9. vless reality-opts 补全：pbk / sid / fp
# 10. hysteria2 多端口支持：443,8443 形式
#
# 三、URL 识别策略（本次新增）
# -----------------------------------------------------------------------------
# 本脚本对节点 URL 采用分级识别策略，平衡覆盖率和误判率：
#
# 【第一层】无条件识别（误判率接近 0）：
#     vmess:// / vless:// / ss:// / ssr:// / trojan://
#     hysteria:// / hysteria2:// / hy2:// / tuic://
#     socks5:// / socks5h:// / socks://
#
# 【第二层】严格识别（误判率 < 1%）：
#     http:// / https:// 满足以下任一条件时识别为代理：
#       A1: 有认证信息 user:pass@ + 无路径（或路径为 /）
#       A2: 有认证信息 user:pass@ + 有显式端口 + 无查询参数
#
# 【第三层】不识别：
#     其他 http:// / https:// URL（视为网页 URL）
#
# 实现要点：
#   - NODE_PREFIXES 用于第一层的 Base64 解码和按行解析
#   - HTTP_PREFIXES 单独处理，需经过 is_definitely_proxy_url 校验
#   - node_link_regex（网页抓取）不包含 http/https，避免网页 URL 污染
#   - parse_subscription_content（订阅解析）中 http/https 需校验
#
# 四、原有逻辑保持不变
# -----------------------------------------------------------------------------
# - Crawler 类爬取逻辑、process_sources 通配符处理、download_subscription
# - fetch_content / fetch_binary
# - nodes_to_clash_yaml / nodes_to_base64 主流程
# - 原有 4 种协议的解析、去重、导出分支
#
# =============================================================================

import os
import sys
import requests
import re
import yaml
import base64
import json
import socket
import asyncio
from urllib.parse import urljoin, urlparse, parse_qs, unquote
from datetime import datetime
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from bs4 import BeautifulSoup
import time
import hashlib

#直接订阅	以 .yaml / .yml / .txt 结尾	直接下载，不爬取	https://example.com/sub.yaml → 立即下载并解析节点
#普通页面	不含 *，且非直接订阅	作为爬取起点（深度=1），可绑定通配符	https://example.com/index → 入队，patterns 可能来自通配符绑定
#通配符项	含 *	不单独入队，而是与普通页面绑定；若无法绑定则自身作为起点	https://example.com/api/*/list → 
#             可能绑定到 https://example.com/api/v2/list（若存在），否则自身 https://example.com/api/ 作为起点
#动态日期	以 +date 开头	格式化后按上述规则继续分类	+date https://example.com/%Y%m%d → 2026-08-15 → https://example.com/20260815
# ======================== 全局配置（可调参数） ========================
# 爬虫控制
MAX_DEPTH = 5               # 爬取深度（从起始页算起）。增大可发现更多链接，但增加请求数。建议 2~5
MAX_REQUESTS = 400         # 总请求数上限（含页面和订阅）。控制资源消耗，避免超时。建议 100~500
KEYWORDS = ['node', 'subscri', 'feed', '.yaml', '.yml', '.txt']  # 用于识别订阅链接的关键词（URL 包含即视为订阅）

# 网络请求
REQUEST_TIMEOUT = 15        # HTTP 请求超时（秒）。增大可应对慢速服务器，减小可加快失败检测。建议 15~60
FETCH_RETRIES = 2           # 获取内容失败后的重试次数。建议 2~5
FETCH_DELAY = 2             # 重试间隔（秒）。建议 0.5~2

# 节点测通（TCP 握手）
CONNECT_TIMEOUT = 4         # TCP 握手超时（秒）。增大可减少网络波动误判，但延长总验证时间。建议 3~10
TEST_RETRIES = 2            # 测通失败后的重试次数。建议 1~3
TEST_WORKERS = 10           # 测通并发线程数。增大可加快验证，但可能因资源竞争导致失败率上升。建议 5~20
MAX_DELAY = 3000            # 节点最大可接受延迟（毫秒），超过则丢弃。调低可提高质量，但可能减少节点数。建议 2000~5000

# QUIC 握手测试超时（秒），用于 hysteria / hysteria2 / tuic 等 UDP 协议
# 建议范围: 2~5，过短易误判，过长拖慢 CI
QUIC_TIMEOUT = 2

# 导出文件
OUTPUT_YAML = 'crawclash.yaml'   # Clash 配置文件输出路径
OUTPUT_TXT = 'crawsub.txt'       # Base64 订阅文件输出路径
SOURCE_FILE = 'crawler.list'     # 起始源列表文件路径

# ======================== 协议常量（新增） ========================
# 第一层：无条件识别的节点链接前缀
# 用于 Base64 解码、按行解析、raw 回退判断
NODE_PREFIXES = (
    'vmess://', 'vless://', 'ss://', 'ssr://', 'trojan://',
    'hysteria://', 'hysteria2://', 'hy2://', 'tuic://',
    'socks5://', 'socks5h://', 'socks://',
)

# 第二层：需经过 is_definitely_proxy_url 校验的 http/https 前缀
HTTP_PREFIXES = ('http://', 'https://')

# UDP 协议：不做 TCP 测通，走 QUIC 握手
UDP_TYPES = {'hysteria', 'hysteria2', 'hy2', 'tuic'}

# 节点名称前缀映射（当 ps 为空时用于生成默认名称）
NAME_PREFIX_MAP = {
    'vmess': 'VMess',
    'vless': 'VLESS',
    'ss': 'SS',
    'ssr': 'SSR',
    'trojan': 'Trojan',
    'hysteria': 'HY',
    'hysteria2': 'HY2',
    'tuic': 'TUIC',
    'http': 'HTTP',
    'socks5': 'SOCKS5',
}

# ======================== 辅助函数（解析与导出） ========================

def clean_url(url):
    if not url:
        return url
    return re.sub(r'[:,.?!;]+$', '', url.strip())

def safe_urljoin(base, url):
    if not url:
        return None
    try:
        return urljoin(base, url)
    except:
        return None

def clean_ipv6(server):
    """
    去除 IPv6 地址的方括号。
    例如: "[::1]" -> "::1"
    """
    if server and isinstance(server, str) and server.startswith("[") and server.endswith("]"):
        return server[1:-1]
    return server

def _alpn_to_list(alpn):
    """
    将 alpn 统一转为列表（Clash 输出要求）。
    输入:
        "h3" 或 "h3,h2" 或 ["h3", "h2"] 或 None
    输出:
        ["h3"] 或 ["h3", "h2"] 或 None
    """
    if not alpn:
        return None
    if isinstance(alpn, str):
        items = [x.strip() for x in alpn.split(',') if x.strip()]
        return items if items else None
    if isinstance(alpn, list):
        items = [str(x).strip() for x in alpn if str(x).strip()]
        return items if items else None
    return None

def is_definitely_proxy_url(url):
    """
    判断 http/https URL 是否"非常确定"是代理节点。

    等级 A 规则（满足任一即可）：
        A1: 有认证信息 user:pass@ + 无路径（或路径为 /）
        A2: 有认证信息 user:pass@ + 有显式端口 + 无查询参数

    误判率 < 1%。

    参数:
        url: 待判断的 URL

    返回:
        True  -> 非常确定是代理
        False -> 不确定（可能是网页）
    """
    if not url:
        return False
    try:
        parsed = urlparse(url)
    except Exception:
        return False

    scheme = parsed.scheme.lower()

    # 只处理 http/https
    if scheme not in ('http', 'https'):
        return False

    # 必须有主机名
    if not parsed.hostname:
        return False

    # 核心判据：必须有认证信息
    if not (parsed.username or parsed.password):
        return False

    path = parsed.path or ''
    no_path = (path == '' or path == '/')
    has_port = bool(parsed.port)
    no_query = not parsed.query

    # A1: 有认证 + 无路径
    if no_path:
        return True

    # A2: 有认证 + 有显式端口 + 无查询
    if has_port and no_query:
        return True

    return False

def is_direct_subscription(url):
    if not url:
        return False
    lower = url.lower()
    return lower.endswith(('.yaml', '.yml', '.txt'))

def is_node_link(url):
    if not url:
        return False
    lower = url.lower()
    if lower.endswith(('.yaml', '.yml', '.txt')):
        return True
    for kw in KEYWORDS:
        if kw.lower() in lower:
            return True
    return False

def fetch_content(url, retries=FETCH_RETRIES, delay=FETCH_DELAY):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
    }
    for i in range(retries):
        try:
            resp = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
            resp.raise_for_status()
            if resp.encoding is None:
                resp.encoding = 'utf-8'
            return resp.text
        except Exception as e:
            if i < retries - 1:
                time.sleep(delay)
                continue
            raise
    return None

def fetch_binary(url, retries=FETCH_RETRIES, delay=FETCH_DELAY):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    }
    for i in range(retries):
        try:
            resp = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
            resp.raise_for_status()
            return resp.content
        except Exception as e:
            if i < retries - 1:
                time.sleep(delay)
                continue
            raise
    return None

def parse_vmess(vmess_url):
    """解析 VMess 链接，返回标准节点字典"""
    if not vmess_url.startswith('vmess://'):
        return None
    try:
        b64 = vmess_url[8:]
        b64 += '=' * (4 - len(b64) % 4)
        decoded = base64.b64decode(b64).decode('utf-8')
        data = json.loads(decoded)
        node = {
            'type': 'vmess',
            'add': data.get('add', ''),
            'port': int(data.get('port', 0)),
            'uuid': data.get('id', ''),
            'alterId': int(data.get('aid', 0)),
            'cipher': data.get('scy', 'auto'),
            'network': data.get('net', 'tcp'),
            'tls': data.get('tls', '') == 'tls',
            'sni': data.get('sni', ''),
            'host': data.get('host', ''),
            'path': data.get('path', ''),
            'ps': data.get('ps', ''),
            'raw': vmess_url,
        }
        if not node['add'] or not node['port'] or not node['uuid']:
            return None
        return node
    except Exception:
        return None

def parse_vless(vless_url):
    """解析 VLESS 链接（含 reality-opts 补全）"""
    if not vless_url.startswith('vless://'):
        return None
    try:
        parsed = urlparse(vless_url)
        uuid = parsed.username or ''
        host = parsed.hostname or ''
        port = parsed.port or 443
        query = parse_qs(parsed.query)
        node = {
            'type': 'vless',
            'add': host,
            'port': port,
            'uuid': uuid,
            'network': query.get('type', ['tcp'])[0],
            'tls': query.get('security', [''])[0] == 'tls',
            'sni': query.get('sni', [''])[0],
            'flow': query.get('flow', [''])[0],
            'encryption': query.get('encryption', ['none'])[0],
            'ps': query.get('remark', [''])[0] or f"VLESS-{host}",
            'raw': vless_url,
        }
        # ---- reality / client-fingerprint / alpn 补全 ----
        if query.get('fp', [''])[0]:
            node['client-fingerprint'] = query.get('fp', [''])[0]
        if query.get('alpn', [''])[0]:
            node['alpn'] = unquote(query.get('alpn', [''])[0])
        security = query.get('security', [''])[0]
        if security == 'reality':
            node['tls'] = True
            node['reality-opts'] = {}
            if query.get('pbk', [''])[0]:
                node['reality-opts']['public-key'] = query.get('pbk', [''])[0]
            if query.get('sid', [''])[0]:
                node['reality-opts']['short-id'] = query.get('sid', [''])[0]
        # -----------------------------------------------------
        if not node['uuid']:
            return None
        return node
    except Exception:
        return None

def parse_ss(ss_url):
    """解析 Shadowsocks 链接"""
    if not ss_url.startswith('ss://'):
        return None
    try:
        content = ss_url[5:]
        if '@' in content:
            prefix, suffix = content.split('@', 1)
            b64 = prefix.replace('-', '+').replace('_', '/')
            b64 += '=' * (4 - len(b64) % 4)
            decoded = base64.b64decode(b64).decode('utf-8')
            if ':' in decoded:
                method, password = decoded.split(':', 1)
            else:
                method, password = decoded.split(':', 1)
            if '?' in suffix:
                host_port, _ = suffix.split('?', 1)
            else:
                host_port = suffix
            host, port = host_port.split(':')
            port = int(port)
        else:
            b64 = content.replace('-', '+').replace('_', '/')
            b64 += '=' * (4 - len(b64) % 4)
            decoded = base64.b64decode(b64).decode('utf-8')
            if '@' not in decoded:
                return None
            method_pass, host_port = decoded.split('@', 1)
            method, password = method_pass.split(':', 1)
            if '?' in host_port:
                host_port, _ = host_port.split('?', 1)
            host, port = host_port.split(':')
            port = int(port)

        node = {
            'type': 'ss',
            'add': host,
            'port': port,
            'method': method,
            'password': password,
            'ps': f"SS-{host}",
            'raw': ss_url,
        }
        return node
    except Exception:
        return None

# ======================== 新增解析函数（5 个） ========================

def parse_ssr(ssr_url):
    """
    解析 ShadowsocksR 链接。
    格式: ssr://base64(server:port:protocol:cipher:obfs:base64(password)/?params)
    """
    if not ssr_url.startswith('ssr://'):
        return None
    try:
        content = ssr_url[6:]
        b64 = content.replace('-', '+').replace('_', '/')
        b64 += '=' * (4 - len(b64) % 4)
        decoded = base64.b64decode(b64).decode('utf-8')
        # 分割密码与参数
        if '/?' in decoded:
            head, params_str = decoded.split('/?', 1)
        else:
            head, params_str = decoded, ''
        parts = head.split(':')
        if len(parts) < 6:
            return None
        server, port, protocol, cipher, obfs = parts[:5]
        passwd_b64 = ':'.join(parts[5:])
        passwd_b64 = passwd_b64.replace('-', '+').replace('_', '/')
        passwd_b64 += '=' * (4 - len(passwd_b64) % 4)
        try:
            password = base64.b64decode(passwd_b64).decode('utf-8', errors='ignore')
        except Exception:
            password = ''

        node = {
            'type': 'ssr',
            'add': server,
            'port': int(port),
            'protocol': protocol,
            'cipher': cipher,
            'obfs': obfs,
            'password': password,
            'ps': f"SSR-{server}",
            'raw': ssr_url,
        }
        # 解析额外参数
        if params_str:
            for kv in params_str.split('&'):
                if '=' not in kv:
                    continue
                k, v = kv.split('=', 1)
                v_b64 = v.replace('-', '+').replace('_', '/')
                v_b64 += '=' * (4 - len(v_b64) % 4)
                try:
                    v_dec = base64.b64decode(v_b64).decode('utf-8', errors='ignore')
                except Exception:
                    v_dec = v
                if k == 'remarks':
                    node['ps'] = v_dec
                elif k == 'obfsparam':
                    node['obfs-param'] = v_dec
                elif k == 'protoparam':
                    node['protocol-param'] = v_dec
                elif k == 'group':
                    node['group'] = v_dec
        if not node['add'] or not node['password']:
            return None
        return node
    except Exception:
        return None


def parse_hysteria2(hy2_url):
    """
    解析 Hysteria2 链接。
    格式: hysteria2://password@host:port[,port2][?params]
    """
    if not hy2_url.startswith(('hysteria2://', 'hy2://')):
        return None
    try:
        parsed = urlparse(hy2_url)
        node = {
            'type': 'hysteria2',
            'add': parsed.hostname or '',
            'password': parsed.username or '',
            'ps': parsed.fragment or f"HY2-{parsed.hostname}",
            'raw': hy2_url,
        }
        # 处理多端口: 443,8443 这种
        netloc = parsed.netloc
        if '@' in netloc:
            netloc = netloc.split('@', 1)[1]
        if ':' in netloc and not netloc.startswith('['):
            port_part = netloc.rsplit(':', 1)[-1]
            if ',' in port_part:
                first_port, rest = port_part.split(',', 1)
                try:
                    node['port'] = int(first_port)
                except (ValueError, TypeError):
                    node['port'] = 443
                node['ports'] = rest
            else:
                try:
                    node['port'] = int(port_part)
                except (ValueError, TypeError):
                    node['port'] = 443
        else:
            node['port'] = 443

        query = parse_qs(parsed.query)
        if query.get('sni', [''])[0]:
            node['sni'] = query.get('sni', [''])[0]
        if query.get('insecure', ['0'])[0] == '1':
            node['skip-cert-verify'] = True
        if query.get('obfs', [''])[0]:
            node['obfs'] = query.get('obfs', [''])[0]
        if query.get('obfs-password', [''])[0]:
            node['obfs-password'] = query.get('obfs-password', [''])[0]
        if query.get('alpn', [''])[0]:
            node['alpn'] = unquote(query.get('alpn', [''])[0])
        if query.get('fp', [''])[0]:
            node['client-fingerprint'] = query.get('fp', [''])[0]

        if not node['add'] or not node['password']:
            return None
        return node
    except Exception:
        return None


def parse_hysteria(hy_url):
    """
    解析 Hysteria v1 链接。
    格式: hysteria://host:port?auth=xxx&peer=xxx&...
    """
    if not hy_url.startswith('hysteria://'):
        return None
    try:
        parsed = urlparse(hy_url)
        query = parse_qs(parsed.query)
        node = {
            'type': 'hysteria',
            'add': parsed.hostname or '',
            'port': parsed.port or 443,
            'auth': query.get('auth', [''])[0],
            'protocol': query.get('protocol', ['udp'])[0],
            'sni': query.get('peer', [''])[0] or parsed.hostname,
            'ps': parsed.fragment or f"HY-{parsed.hostname}",
            'raw': hy_url,
        }
        if query.get('insecure', ['0'])[0] == '1':
            node['skip-cert-verify'] = True
        if query.get('upmbps', [''])[0]:
            node['up'] = query.get('upmbps', [''])[0]
        if query.get('downmbps', [''])[0]:
            node['down'] = query.get('downmbps', [''])[0]
        if query.get('alpn', [''])[0]:
            node['alpn'] = unquote(query.get('alpn', [''])[0])
        if not node['add']:
            return None
        return node
    except Exception:
        return None


def parse_tuic(tuic_url):
    """
    解析 TUIC 链接。
    格式: tuic://uuid:password@host:port[?params]
    """
    if not tuic_url.startswith('tuic://'):
        return None
    try:
        parsed = urlparse(tuic_url)
        node = {
            'type': 'tuic',
            'add': parsed.hostname or '',
            'port': parsed.port or 136,
            'uuid': parsed.username or '',
            'password': parsed.password or '',
            'ps': parsed.fragment or f"TUIC-{parsed.hostname}",
            'raw': tuic_url,
        }
        query = parse_qs(parsed.query)
        if query.get('sni', [''])[0]:
            node['sni'] = query.get('sni', [''])[0]
        if query.get('allow_insecure', ['0'])[0] == '1':
            node['skip-cert-verify'] = True
        if query.get('alpn', [''])[0]:
            node['alpn'] = unquote(query.get('alpn', [''])[0])
        if query.get('congestion_control', [''])[0]:
            node['congestion_control'] = query.get('congestion_control', [''])[0]
        if query.get('udp_relay_mode', [''])[0]:
            node['udp_relay_mode'] = query.get('udp_relay_mode', [''])[0]
        if not node['add'] or not node['uuid']:
            return None
        return node
    except Exception:
        return None


def parse_http_socks(url, strict_http=True):
    """
    解析 http:// / https:// / socks5:// / socks5h:// / socks:// 节点链接。

    strict_http=True（默认）:
        - socks 系列：只要有主机名 + 端口即可（宽松）
        - http/https：必须满足 is_definitely_proxy_url（严格）
    strict_http=False:
        - http/https 只要有端口即识别（不推荐，仅供内部调用）

    注意：
        - 本函数从 URL 路径调用（parse_node_link / parse_subscription_content）
        - YAML 路径由 parse_subscription_content 的 proxies 分支处理
    """
    try:
        parsed = urlparse(url)
        scheme = parsed.scheme.lower()

        if scheme not in ('http', 'https', 'socks5', 'socks5h', 'socks'):
            return None

        if not parsed.hostname:
            return None

        # socks 系列：宽松处理，只需主机名 + 端口
        if scheme.startswith('socks'):
            if not parsed.port:
                return None
        else:
            # http/https：严格模式
            if strict_http:
                if not is_definitely_proxy_url(url):
                    return None
            else:
                if not parsed.port:
                    return None

        # 默认端口
        default_port = 443 if scheme == 'https' else 80
        port = parsed.port or default_port

        node_type = 'socks5' if scheme.startswith('socks') else 'http'
        node = {
            'type': node_type,
            'add': parsed.hostname,
            'port': port,
            'username': parsed.username or '',
            'password': parsed.password or '',
            'tls': scheme == 'https',
            'ps': parsed.fragment or f"{scheme.upper()}-{parsed.hostname}",
            'raw': url,
        }
        return node
    except Exception:
        return None

# ======================== parse_node_link（增量扩展） ========================

def parse_node_link(link):
    """
    解析节点链接为 dict。

    第一层无条件识别：vmess / vless / ss / ssr / trojan /
                    hysteria / hysteria2 / hy2 / tuic /
                    socks5 / socks5h / socks
    第二层严格识别：http / https（需通过 is_definitely_proxy_url 校验）
    """
    if link.startswith('vmess://'):
        return parse_vmess(link)
    elif link.startswith('vless://'):
        return parse_vless(link)
    elif link.startswith('ss://'):
        return parse_ss(link)
    # ---- 长前缀优先，避免 ss 误匹配 ssr ----
    elif link.startswith('ssr://'):
        return parse_ssr(link)
    elif link.startswith('trojan://'):
        return parse_trojan(link)
    elif link.startswith(('hysteria2://', 'hy2://')):
        return parse_hysteria2(link)
    elif link.startswith('hysteria://'):
        return parse_hysteria(link)
    elif link.startswith('tuic://'):
        return parse_tuic(link)
    # ---- 第一层：socks 系列（宽松） ----
    elif link.startswith(('socks5://', 'socks5h://', 'socks://')):
        return parse_http_socks(link, strict_http=False)
    # ---- 第二层：http/https（严格，仅识别"非常确定"的） ----
    elif link.startswith(('http://', 'https://')):
        if is_definitely_proxy_url(link):
            return parse_http_socks(link, strict_http=True)
        return None
    else:
        return None

def parse_subscription_content(content, url_hint=''):
    """
    解析订阅内容，返回节点列表。
    支持：
    - 标准 Clash YAML（proxies 字段）
    - Clash 配置（proxy-providers）
    - Base64 编码的节点链接
    - 每行一个节点链接的纯文本
    返回的每个节点字典包含 'raw' 字段（原始链接字符串）及 'ps'（备注名）
    """
    nodes = []
    if not content:
        return nodes

    # ---------- 第一步：尝试作为 Clash YAML 解析 ----------
    try:
        data = yaml.safe_load(content)
        if isinstance(data, dict):
            # 1. 标准 proxies 字段
            proxy_list = data.get('proxies') or data.get('Proxy') or data.get('proxy')
            if proxy_list and isinstance(proxy_list, list):
                for proxy in proxy_list:
                    if not isinstance(proxy, dict):
                        continue
                    ptype = proxy.get('type', '').lower()
                    # ---- 白名单扩展 ----
                    if ptype not in ('vmess', 'vless', 'ss', 'ssr', 'trojan',
                                     'hysteria', 'hysteria2', 'tuic',
                                     'http', 'socks5'):
                        continue
                    node = {
                        'type': ptype,
                        'add': proxy.get('server', ''),
                        'port': int(proxy.get('port', 0)),
                        'ps': proxy.get('name', ''),
                        'raw': f"{ptype}://{proxy.get('server', '')}:{proxy.get('port', 0)}"
                    }
                    if ptype in ('vmess', 'vless'):
                        uuid = proxy.get('uuid') or proxy.get('id', '')
                        node['uuid'] = uuid
                        node['alterId'] = int(proxy.get('alterId', 0)) if ptype == 'vmess' else 0
                        node['cipher'] = proxy.get('cipher', 'auto')
                        node['network'] = proxy.get('network', 'tcp')
                        node['tls'] = proxy.get('tls', False)
                        node['sni'] = proxy.get('sni', '')
                        node['host'] = proxy.get('host', '')
                        node['path'] = proxy.get('path', '')
                        if ptype == 'vless':
                            node['flow'] = proxy.get('flow', '')
                            node['encryption'] = proxy.get('encryption', 'none')
                            # ---- 新增 vless 字段 ----
                            if proxy.get('reality-opts'):
                                node['reality-opts'] = proxy['reality-opts']
                            if proxy.get('client-fingerprint'):
                                node['client-fingerprint'] = proxy['client-fingerprint']
                        if proxy.get('alpn'):
                            alpn = proxy['alpn']
                            node['alpn'] = ','.join(alpn) if isinstance(alpn, list) else alpn
                    elif ptype == 'ss':
                        node['method'] = proxy.get('cipher', '')
                        node['password'] = proxy.get('password', '')
                    elif ptype == 'ssr':
                        # ---- 新增 ssr ----
                        node['protocol'] = proxy.get('protocol', 'origin')
                        node['obfs'] = proxy.get('obfs', 'plain')
                        node['cipher'] = proxy.get('cipher', '')
                        node['password'] = proxy.get('password', '')
                        if proxy.get('obfs-param'):
                            node['obfs-param'] = proxy['obfs-param']
                        if proxy.get('protocol-param'):
                            node['protocol-param'] = proxy['protocol-param']
                    elif ptype == 'trojan':
                        node['password'] = proxy.get('password', '')
                        node['sni'] = proxy.get('sni', '')
                        # ---- 统一 skip-cert-verify ----
                        if proxy.get('skip-cert-verify'):
                            node['skip-cert-verify'] = True
                            node['allowInsecure'] = True
                        if proxy.get('alpn'):
                            alpn = proxy['alpn']
                            node['alpn'] = ','.join(alpn) if isinstance(alpn, list) else alpn
                    elif ptype == 'hysteria2':
                        # ---- 新增 hysteria2 ----
                        node['password'] = proxy.get('password', '')
                        node['sni'] = proxy.get('sni', '')
                        if proxy.get('skip-cert-verify'):
                            node['skip-cert-verify'] = True
                        if proxy.get('obfs'):
                            node['obfs'] = proxy['obfs']
                            node['obfs-password'] = proxy.get('obfs-password', '')
                        if proxy.get('ports'):
                            node['ports'] = proxy['ports']
                        if proxy.get('alpn'):
                            alpn = proxy['alpn']
                            node['alpn'] = ','.join(alpn) if isinstance(alpn, list) else alpn
                    elif ptype == 'hysteria':
                        # ---- 新增 hysteria v1 ----
                        node['auth'] = proxy.get('auth-str', '') or proxy.get('auth', '')
                        node['sni'] = proxy.get('sni', '')
                        if proxy.get('skip-cert-verify'):
                            node['skip-cert-verify'] = True
                        if proxy.get('up'):
                            node['up'] = proxy['up']
                        if proxy.get('down'):
                            node['down'] = proxy['down']
                        if proxy.get('alpn'):
                            alpn = proxy['alpn']
                            node['alpn'] = ','.join(alpn) if isinstance(alpn, list) else alpn
                    elif ptype == 'tuic':
                        # ---- 新增 tuic ----
                        node['uuid'] = proxy.get('uuid', '')
                        node['password'] = proxy.get('password', '')
                        node['sni'] = proxy.get('sni', '')
                        if proxy.get('skip-cert-verify'):
                            node['skip-cert-verify'] = True
                        if proxy.get('congestion-controller'):
                            node['congestion_control'] = proxy['congestion-controller']
                        if proxy.get('udp-relay-mode'):
                            node['udp_relay_mode'] = proxy['udp-relay-mode']
                        if proxy.get('alpn'):
                            alpn = proxy['alpn']
                            node['alpn'] = ','.join(alpn) if isinstance(alpn, list) else alpn
                    elif ptype == 'http':
                        # ---- 新增 http/https ----
                        node['username'] = proxy.get('username', '')
                        node['password'] = proxy.get('password', '')
                        node['tls'] = proxy.get('tls', False)
                        if proxy.get('sni'):
                            node['sni'] = proxy['sni']
                    elif ptype == 'socks5':
                        # ---- 新增 socks5 ----
                        node['username'] = proxy.get('username', '')
                        node['password'] = proxy.get('password', '')
                    if node['add'] and node['port']:
                        nodes.append(node)
                if nodes:
                    return nodes

            # 2. proxy-providers
            if 'proxy-providers' in data:
                providers = data['proxy-providers']
                for provider_name, provider_config in providers.items():
                    if not isinstance(provider_config, dict):
                        continue
                    if provider_config.get('type') == 'http':
                        provider_url = provider_config.get('url')
                        if provider_url:
                            print(f"  Found proxy-provider '{provider_name}', downloading: {provider_url}")
                            try:
                                provider_content = fetch_binary(provider_url)
                                if provider_content:
                                    provider_text = provider_content.decode('utf-8', errors='ignore')
                                    sub_nodes = parse_subscription_content(provider_text, provider_url)
                                    nodes.extend(sub_nodes)
                                    print(f"  -> Got {len(sub_nodes)} nodes from provider")
                            except Exception as e:
                                print(f"  -> Error downloading provider {provider_url}: {e}")
                if nodes:
                    return nodes
    except Exception:
        pass

    # ---------- 第二步：尝试 Base64 解码 ----------
    try:
        b64_clean = re.sub(r'\s+', '', content)
        if re.match(r'^[A-Za-z0-9+/=_-]+$', b64_clean):
            b64_clean += '=' * (4 - len(b64_clean) % 4)
            decoded = base64.b64decode(b64_clean, altchars='-_').decode('utf-8', errors='ignore')
            for line in decoded.splitlines():
                line = line.strip()
                if not line:
                    continue
                # 第一层：NODE_PREFIXES（无条件识别）
                if line.startswith(NODE_PREFIXES):
                    node = parse_node_link(line)
                    if node:
                        node['raw'] = line
                        nodes.append(node)
                # 第二层：http/https（严格校验）
                elif line.startswith(HTTP_PREFIXES):
                    if is_definitely_proxy_url(line):
                        node = parse_node_link(line)
                        if node:
                            node['raw'] = line
                            nodes.append(node)
            if nodes:
                return nodes
    except Exception:
        pass

    # ---------- 第三步：按行解析节点链接 ----------
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        # 第一层：NODE_PREFIXES（无条件识别）
        if line.startswith(NODE_PREFIXES):
            node = parse_node_link(line)
            if node:
                node['raw'] = line
                nodes.append(node)
        # 第二层：http/https（严格校验）
        elif line.startswith(HTTP_PREFIXES):
            if is_definitely_proxy_url(line):
                node = parse_node_link(line)
                if node:
                    node['raw'] = line
                    nodes.append(node)

    return nodes

# ======================== 去重与测通 ========================

def normalize_node_key(node):
    """
    生成节点去重指纹。
    新增协议：ssr / hysteria / hysteria2 / tuic / http / socks5
    """
    t = node.get('type')
    if t == 'vmess':
        key = f"vmess_{node.get('add')}_{node.get('port')}_{node.get('uuid')}"
    elif t == 'vless':
        key = f"vless_{node.get('add')}_{node.get('port')}_{node.get('uuid')}"
    elif t == 'ss':
        key = f"ss_{node.get('add')}_{node.get('port')}_{node.get('method')}_{node.get('password')}"
    elif t == 'ssr':
        key = (f"ssr_{node.get('add')}_{node.get('port')}_"
               f"{node.get('protocol')}_{node.get('obfs')}_{node.get('password')}")
    elif t == 'trojan':
        key = f"trojan_{node.get('add')}_{node.get('port')}_{node.get('password')}"
    elif t == 'hysteria2':
        key = (f"hy2_{node.get('add')}_{node.get('port')}_"
               f"{node.get('password')}_{node.get('obfs-password', '')}")
    elif t == 'hysteria':
        key = f"hy_{node.get('add')}_{node.get('port')}_{node.get('auth')}"
    elif t == 'tuic':
        key = f"tuic_{node.get('add')}_{node.get('port')}_{node.get('uuid')}"
    elif t in ('http', 'socks5'):
        key = f"{t}_{node.get('add')}_{node.get('port')}_{node.get('username', '')}"
    else:
        key = f"{t}_{node.get('add')}_{node.get('port')}"
    return hashlib.md5(key.encode()).hexdigest()


# ---------- QUIC 握手测试（新增，用于 UDP 协议） ----------

async def _quic_handshake_async(server, port, timeout):
    """
    异步 QUIC 握手测试。
    使用 aioquic 高层 API 发起 QUIC 连接。
    wait_connected=False 允许 0-RTT 启动；verify_mode=0 跳过证书验证
    （代理节点常用自签证书）。
    """
    from aioquic.asyncio import connect
    from aioquic.quic.configuration import QuicConfiguration

    config = QuicConfiguration(is_client=True)
    config.verify_mode = 0
    config.alpn_protocols = ["h3"]

    try:
        async with connect(
            server,
            port,
            configuration=config,
            wait_connected=False,
            local_port=0,
        ) as client:
            await asyncio.wait_for(client.wait_connected(), timeout=timeout)
        return True
    except asyncio.TimeoutError:
        return False
    except Exception:
        return False


def test_quic_for_crawler(node):
    """
    UDP 协议节点的 QUIC 握手测试。
    返回 (可达, 延迟) 格式，与 test_node_connectivity 保持一致。

    - aioquic 未安装：保守返回 (True, 0)，保留节点，避免误杀
    - 握手成功：返回 (True, 0)
    - 握手失败：返回 (False, -1)
    """
    try:
        import aioquic  # noqa: F401
    except ImportError:
        # aioquic 未安装，保守保留节点
        node['delay'] = 0
        return True, 0

    server = clean_ipv6(node.get('add', ''))
    port = node.get('port', 0)
    if not server or not port:
        node['delay'] = -1
        return False, -1
    try:
        port = int(port)
    except (ValueError, TypeError):
        node['delay'] = -1
        return False, -1

    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            ok = loop.run_until_complete(
                _quic_handshake_async(server, port, QUIC_TIMEOUT)
            )
        finally:
            loop.close()
        node['delay'] = 0
        return ok, 0
    except Exception:
        node['delay'] = -1
        return False, -1


def test_node_connectivity(node, retries=TEST_RETRIES):
    """
    测试节点连通性，返回 (是否可达, 延迟毫秒)。
    并更新节点字典中的 'delay' 字段。

    新增：UDP 协议（hysteria / hysteria2 / tuic）走 QUIC 握手测试，
         不做 TCP 测通，避免误杀。
    IPv6 地址去方括号后再测试。
    """
    # ---- UDP 协议走 QUIC 测试 ----
    if node.get('type') in UDP_TYPES:
        return test_quic_for_crawler(node)

    host = clean_ipv6(node.get('add', ''))
    port = node.get('port', 0)
    if not host or not port:
        node['delay'] = -1
        return False, -1

    for attempt in range(retries):
        start = time.time()
        try:
            ip = socket.gethostbyname(host)
            with socket.create_connection((ip, port), timeout=CONNECT_TIMEOUT):
                delay = int((time.time() - start) * 1000)
                node['delay'] = delay
                return True, delay
        except Exception:
            if attempt < retries - 1:
                time.sleep(0.5)   # 重试间隔 0.5 秒
                continue
    node['delay'] = -1
    return False, -1


def node_to_vmess_link(node):
    """将节点对象还原为原始链接字符串（用于 Base64 导出）"""
    # ---- raw 回退：NODE_PREFIXES 或 HTTP 严格校验通过 ----
    if node.get('raw'):
        raw = node['raw']
        if raw.startswith(NODE_PREFIXES):
            return raw
        if raw.startswith(HTTP_PREFIXES) and is_definitely_proxy_url(raw):
            return raw

    ntype = node.get('type', '')
    if ntype == 'vmess':
        data = {
            'v': '2',
            'ps': node.get('ps', ''),
            'add': node.get('add', ''),
            'port': node.get('port', 0),
            'id': node.get('uuid', ''),
            'aid': node.get('alterId', 0),
            'net': node.get('network', 'tcp'),
            'type': 'none',
            'host': node.get('host', ''),
            'path': node.get('path', ''),
            'tls': 'tls' if node.get('tls') else '',
            'sni': node.get('sni', ''),
        }
        b64 = base64.b64encode(json.dumps(data).encode()).decode()
        return 'vmess://' + b64
    elif ntype == 'vless':
        uuid = node.get('uuid', '')
        host = node.get('add', '')
        port = node.get('port', 443)
        params = []
        if node.get('network'):
            params.append(f"type={node.get('network')}")
        if node.get('tls'):
            params.append("security=tls")
        if node.get('sni'):
            params.append(f"sni={node.get('sni')}")
        if node.get('flow'):
            params.append(f"flow={node.get('flow')}")
        if node.get('encryption') and node['encryption'] != 'none':
            params.append(f"encryption={node.get('encryption')}")
        # ---- reality-opts 输出 ----
        if node.get('reality-opts'):
            params.append("security=reality")
            if node['reality-opts'].get('public-key'):
                params.append(f"pbk={node['reality-opts']['public-key']}")
            if node['reality-opts'].get('short-id'):
                params.append(f"sid={node['reality-opts']['short-id']}")
        if node.get('client-fingerprint'):
            params.append(f"fp={node.get('client-fingerprint')}")
        query = '&'.join(params)
        return f"vless://{uuid}@{host}:{port}?{query}" if query else f"vless://{uuid}@{host}:{port}"
    elif ntype == 'ss':
        auth = f"{node.get('method','')}:{node.get('password','')}"
        auth_b64 = base64.b64encode(auth.encode()).decode()
        return f"ss://{auth_b64}@{node.get('add','')}:{node.get('port',0)}"
    elif ntype == 'ssr':
        # ---- ssr 输出 ----
        try:
            passwd_b64 = base64.urlsafe_b64encode(
                (node.get('password', '') or '').encode()
            ).decode().rstrip('=')
            head = f"{node.get('add','')}:{node.get('port',0)}:" \
                   f"{node.get('protocol','origin')}:{node.get('cipher','')}:" \
                   f"{node.get('obfs','plain')}:{passwd_b64}"
            params = []
            if node.get('ps'):
                params.append('remarks=' + base64.urlsafe_b64encode(
                    node['ps'].encode()).decode().rstrip('='))
            if node.get('obfs-param'):
                params.append('obfsparam=' + base64.urlsafe_b64encode(
                    node['obfs-param'].encode()).decode().rstrip('='))
            if node.get('protocol-param'):
                params.append('protoparam=' + base64.urlsafe_b64encode(
                    node['protocol-param'].encode()).decode().rstrip('='))
            raw_str = head
            if params:
                raw_str += '/?' + '&'.join(params)
            b64 = base64.urlsafe_b64encode(raw_str.encode()).decode().rstrip('=')
            return f"ssr://{b64}"
        except Exception:
            return node.get('raw', '')
    elif ntype == 'trojan':
        netloc = f"{node.get('password','')}@{node.get('add','')}:{node.get('port',443)}"
        params = []
        if node.get('sni'):
            params.append(f"sni={node.get('sni')}")
        if node.get('skip-cert-verify') or node.get('allowInsecure') == '1' or node.get('allowInsecure') is True:
            params.append("allowInsecure=1")
        query = '&'.join(params)
        return f"trojan://{netloc}?{query}" if query else f"trojan://{netloc}"
    elif ntype == 'hysteria2':
        # ---- hysteria2 输出 ----
        pwd = node.get('password', '')
        host = node.get('add', '')
        port = node.get('port', 443)
        url = f"hysteria2://{pwd}@{host}:{port}"
        if node.get('ports'):
            url += ',' + str(node['ports'])
        params = []
        if node.get('sni'):
            params.append(f"sni={node.get('sni')}")
        if node.get('skip-cert-verify'):
            params.append("insecure=1")
        if node.get('obfs'):
            params.append(f"obfs={node.get('obfs')}")
            if node.get('obfs-password'):
                params.append(f"obfs-password={node.get('obfs-password')}")
        if node.get('alpn'):
            params.append(f"alpn={node.get('alpn')}")
        query = '&'.join(params)
        return f"{url}?{query}" if query else url
    elif ntype == 'hysteria':
        # ---- hysteria v1 输出 ----
        host = node.get('add', '')
        port = node.get('port', 443)
        params = []
        if node.get('auth'):
            params.append(f"auth={node.get('auth')}")
        if node.get('sni'):
            params.append(f"peer={node.get('sni')}")
        if node.get('skip-cert-verify'):
            params.append("insecure=1")
        if node.get('up'):
            params.append(f"upmbps={node.get('up')}")
        if node.get('down'):
            params.append(f"downmbps={node.get('down')}")
        query = '&'.join(params)
        return f"hysteria://{host}:{port}?{query}" if query else f"hysteria://{host}:{port}"
    elif ntype == 'tuic':
        # ---- tuic 输出 ----
        uuid = node.get('uuid', '')
        pwd = node.get('password', '')
        host = node.get('add', '')
        port = node.get('port', 443)
        params = []
        if node.get('sni'):
            params.append(f"sni={node.get('sni')}")
        if node.get('skip-cert-verify'):
            params.append("allow_insecure=1")
        if node.get('alpn'):
            params.append(f"alpn={node.get('alpn')}")
        if node.get('congestion_control'):
            params.append(f"congestion_control={node.get('congestion_control')}")
        if node.get('udp_relay_mode'):
            params.append(f"udp_relay_mode={node.get('udp_relay_mode')}")
        query = '&'.join(params)
        return f"tuic://{uuid}:{pwd}@{host}:{port}?{query}" if query else f"tuic://{uuid}:{pwd}@{host}:{port}"
    elif ntype in ('http', 'socks5'):
        # ---- http/socks5 输出 ----
        scheme = 'socks5' if ntype == 'socks5' else ('https' if node.get('tls') else 'http')
        user = node.get('username', '')
        pwd = node.get('password', '')
        auth = ''
        if user:
            auth = user
            if pwd:
                auth += ':' + pwd
            auth += '@'
        return f"{scheme}://{auth}{node.get('add')}:{node.get('port')}"
    else:
        return node.get('raw', '')

def is_node_valid(node):
    """检查节点是否包含 Clash 必需字段"""
    node_type = node.get('type', '').lower()
    if not node_type:
        return False
    # ---- 白名单扩展 ----
    if node_type not in ('vmess', 'vless', 'ss', 'ssr', 'trojan',
                         'hysteria', 'hysteria2', 'tuic', 'http', 'socks5'):
        return False
    if node_type == 'vmess':
        if not node.get('uuid'):
            return False
    elif node_type == 'vless':
        if not node.get('uuid'):
            return False
    elif node_type == 'ss':
        if not node.get('method') or not node.get('password'):
            return False
    elif node_type == 'ssr':
        # ---- ssr 校验 ----
        if not node.get('protocol') or not node.get('password'):
            return False
    elif node_type == 'trojan':
        if not node.get('password'):
            return False
    elif node_type == 'hysteria2':
        # ---- hysteria2 校验 ----
        if not node.get('password'):
            return False
    elif node_type == 'hysteria':
        # ---- hysteria 校验 ----
        if not node.get('auth'):
            return False
    elif node_type == 'tuic':
        # ---- tuic 校验 ----
        if not node.get('uuid') or not node.get('password'):
            return False
    return True

# ======================== 导出函数（支持 11 种协议） ========================

def to_clash_proxy(node):
    """
    将节点转换为 Clash proxy 字典，支持：
    vmess / vless / ss / ssr / trojan / hysteria / hysteria2 / tuic / http / socks5
    """
    ntype = node.get('type')
    if ntype == 'vmess':
        proxy = {
            'name': '',
            'type': 'vmess',
            'server': node.get('add', ''),
            'port': int(node.get('port', 0)),
            'uuid': node.get('uuid', ''),
            'alterId': int(node.get('alterId', 0)),
            'cipher': node.get('cipher', 'auto'),
            'tls': bool(node.get('tls', False)),
            'network': node.get('network', 'tcp'),
        }
        if node.get('network') == 'ws':
            ws_opts = {
                'path': node.get('path') or '/',
                'headers': {
                    'Host': node.get('host') or node.get('add')
                }
            }
            proxy['ws-opts'] = ws_opts
        if node.get('sni'):
            proxy['sni'] = node.get('sni')
        # ---- alpn ----
        alpn = _alpn_to_list(node.get('alpn'))
        if alpn:
            proxy['alpn'] = alpn
        return proxy

    elif ntype == 'vless':
        proxy = {
            'name': '',
            'type': 'vless',
            'server': node.get('add', ''),
            'port': int(node.get('port', 0)),
            'uuid': node.get('uuid', ''),
            'network': node.get('network', 'tcp'),
            'tls': bool(node.get('tls', False)),
            'flow': node.get('flow', ''),
            'encryption': node.get('encryption', 'none'),
        }
        if node.get('sni'):
            proxy['sni'] = node.get('sni')
        # ---- reality-opts ----
        if node.get('reality-opts'):
            proxy['reality-opts'] = node['reality-opts']
            proxy['tls'] = True
        if node.get('client-fingerprint'):
            proxy['client-fingerprint'] = node['client-fingerprint']
        # ---- alpn ----
        alpn = _alpn_to_list(node.get('alpn'))
        if alpn:
            proxy['alpn'] = alpn
        return proxy

    elif ntype == 'ss':
        return {
            'name': '',
            'type': 'ss',
            'server': node.get('add', ''),
            'port': int(node.get('port', 0)),
            'cipher': node.get('method', ''),
            'password': node.get('password', ''),
        }

    # ---- ssr ----
    elif ntype == 'ssr':
        proxy = {
            'name': '',
            'type': 'ssr',
            'server': node.get('add', ''),
            'port': int(node.get('port', 0)),
            'cipher': node.get('cipher', ''),
            'password': node.get('password', ''),
            'protocol': node.get('protocol', 'origin'),
            'obfs': node.get('obfs', 'plain'),
        }
        if node.get('obfs-param'):
            proxy['obfs-param'] = node['obfs-param']
        if node.get('protocol-param'):
            proxy['protocol-param'] = node['protocol-param']
        return proxy

    elif ntype == 'trojan':
        proxy = {
            'name': '',
            'type': 'trojan',
            'server': node.get('add', ''),
            'port': int(node.get('port', 0)),
            'password': node.get('password', ''),
        }
        if node.get('sni'):
            proxy['sni'] = node.get('sni')
        # ---- 统一 skip-cert-verify 判断 ----
        if node.get('skip-cert-verify') or node.get('allowInsecure') == '1' or node.get('allowInsecure') is True:
            proxy['skip-cert-verify'] = True
        # ---- alpn ----
        alpn = _alpn_to_list(node.get('alpn'))
        if alpn:
            proxy['alpn'] = alpn
        return proxy

    # ---- hysteria2 ----
    elif ntype == 'hysteria2':
        proxy = {
            'name': '',
            'type': 'hysteria2',
            'server': node.get('add', ''),
            'port': int(node.get('port', 443)),
            'password': node.get('password', ''),
        }
        if node.get('sni'):
            proxy['sni'] = node['sni']
        if node.get('skip-cert-verify'):
            proxy['skip-cert-verify'] = True
        if node.get('obfs'):
            proxy['obfs'] = node['obfs']
            if node.get('obfs-password'):
                proxy['obfs-password'] = node['obfs-password']
        if node.get('ports'):
            proxy['ports'] = node['ports']
        alpn = _alpn_to_list(node.get('alpn'))
        if alpn:
            proxy['alpn'] = alpn
        return proxy

    # ---- hysteria v1 ----
    elif ntype == 'hysteria':
        proxy = {
            'name': '',
            'type': 'hysteria',
            'server': node.get('add', ''),
            'port': int(node.get('port', 443)),
            'auth-str': node.get('auth', ''),
            'protocol': node.get('protocol', 'udp'),
        }
        if node.get('sni'):
            proxy['sni'] = node['sni']
        if node.get('skip-cert-verify'):
            proxy['skip-cert-verify'] = True
        if node.get('up'):
            proxy['up'] = node['up']
        if node.get('down'):
            proxy['down'] = node['down']
        alpn = _alpn_to_list(node.get('alpn'))
        if alpn:
            proxy['alpn'] = alpn
        return proxy

    # ---- tuic ----
    elif ntype == 'tuic':
        proxy = {
            'name': '',
            'type': 'tuic',
            'server': node.get('add', ''),
            'port': int(node.get('port', 443)),
            'uuid': node.get('uuid', ''),
            'password': node.get('password', ''),
        }
        if node.get('sni'):
            proxy['sni'] = node['sni']
        if node.get('skip-cert-verify'):
            proxy['skip-cert-verify'] = True
        alpn = _alpn_to_list(node.get('alpn'))
        if alpn:
            proxy['alpn'] = alpn
        if node.get('congestion_control'):
            proxy['congestion-controller'] = node['congestion_control']
        if node.get('udp_relay_mode'):
            proxy['udp-relay-mode'] = node['udp_relay_mode']
        return proxy

    # ---- http/https ----
    elif ntype == 'http':
        proxy = {
            'name': '',
            'type': 'http',
            'server': node.get('add', ''),
            'port': int(node.get('port', 80)),
        }
        if node.get('username'):
            proxy['username'] = node['username']
        if node.get('password'):
            proxy['password'] = node['password']
        if node.get('tls'):
            proxy['tls'] = True
            proxy['sni'] = node.get('sni') or node.get('add', '')
        return proxy

    # ---- socks5 ----
    elif ntype == 'socks5':
        proxy = {
            'name': '',
            'type': 'socks5',
            'server': node.get('add', ''),
            'port': int(node.get('port', 1080)),
        }
        if node.get('username'):
            proxy['username'] = node['username']
        if node.get('password'):
            proxy['password'] = node['password']
        return proxy

    else:
        return None

def nodes_to_clash_yaml(nodes):
    """
    将节点列表转换为完整的 Clash 配置文件 YAML 字符串。
    支持 11 种协议，输出格式与原 JavaScript 版本一致。
    """
    if not nodes:
        return ""

    proxies = []
    used_names = {}

    for node in nodes:
        if not is_node_valid(node):
            print(f"⚠️ 跳过无效节点: {node.get('add', 'unknown')} (type: {node.get('type', '')})")
            continue

        # ---- 名称生成：新增协议前缀 ----
        base_name = node.get('ps', '').strip()
        if not base_name:
            t = node.get('type', '')
            prefix = NAME_PREFIX_MAP.get(t, t.upper())
            base_name = f"{prefix}-{node.get('add')}:{node.get('port')}"
        # ----------------------------------

        delay = node.get('delay', -1)
        if delay > 0:
            name = f"{base_name} - {delay}ms"
        else:
            name = base_name

        # 去重（与 JavaScript 一致）
        original_name = name
        counter = 1
        while name in used_names:
            name = f"{original_name}_{counter}"
            counter += 1
        used_names[name] = True

        # 构建 Clash proxy
        proxy = to_clash_proxy(node)
        if proxy is None:
            continue
        proxy['name'] = name
        proxies.append(proxy)

    if not proxies:
        print("⚠️ 没有有效节点，无法生成 Clash 配置")
        return ""

    # 构建完整配置（与 JavaScript 完全一致）
    proxy_names = [p['name'] for p in proxies]
    config = {
        'port': 7890,
        'socks-port': 7891,
        'allow-lan': True,
        'mode': 'Rule',
        'log-level': 'info',
        'external-controller': '127.0.0.1:9090',
        'proxies': proxies,
        'proxy-groups': [
            {
                'name': 'Auto Select',
                'type': 'url-test',
                'proxies': proxy_names,
                'url': 'http://www.gstatic.com/generate_204',
                'interval': 300
            },
            {
                'name': 'Proxy',
                'type': 'select',
                'proxies': ['Auto Select'] + proxy_names
            }
        ],
        'rules': [
            'MATCH,Proxy'
        ]
    }

    return yaml.dump(config, default_flow_style=False, allow_unicode=True)

def nodes_to_base64(nodes):
    """将节点列表转换为 Base64 订阅字符串"""
    links = []
    for node in nodes:
        link = node_to_vmess_link(node)
        if link:
            links.append(link)
    raw = '\n'.join(links)
    return base64.b64encode(raw.encode()).decode()

# ======================== 主爬虫类 ========================

class Crawler:
    def __init__(self):
        self.visited_urls = set()
        self.queue = deque()
        self.all_nodes = []
        self.request_count = 0

    def process_sources(self, lines):
        wildcard_items = []
        direct_urls = []
        plain_pages_set = set()

        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if line.startswith('+date'):
                parts = line.split(maxsplit=1)
                if len(parts) < 2:
                    continue
                url_template = parts[1].strip()
                try:
                    url = datetime.now().strftime(url_template)
                except:
                    url = url_template
            else:
                url = line

            if '*' in url:
                pattern = re.escape(url).replace('\\*', '.*')
                regex = re.compile('^' + pattern + '$', re.IGNORECASE)
                wildcard_items.append((url, regex))
            else:
                if is_direct_subscription(url):
                    direct_urls.append(url)
                else:
                    clean = url.rstrip('/')
                    plain_pages_set.add(clean)

        wildcard_map = {}
        for url, regex in wildcard_items:
            base_part = url.split('*', 1)[0].rstrip('/')
            matched_base = None
            if base_part in plain_pages_set:
                matched_base = base_part
            else:
                candidates = [p for p in plain_pages_set if p.startswith(base_part) and p != base_part]
                if candidates:
                    matched_base = max(candidates, key=len)
                else:
                    parsed = urlparse(base_part)
                    root_url = f"{parsed.scheme}://{parsed.netloc}".rstrip('/')
                    if root_url in plain_pages_set:
                        matched_base = root_url
            if matched_base:
                if matched_base not in wildcard_map:
                    wildcard_map[matched_base] = []
                wildcard_map[matched_base].append(regex)
            else:
                if base_part not in wildcard_map:
                    wildcard_map[base_part] = []
                wildcard_map[base_part].append(regex)

        plain_pages = list(plain_pages_set)
        return wildcard_map, direct_urls, plain_pages

    def enqueue(self, url, depth, patterns):
        if url in self.visited_urls:
            return
        if self.request_count >= MAX_REQUESTS:
            return
        self.queue.append((url, depth, patterns))

    def download_subscription(self, url):
        if url in self.visited_urls:
            return
        self.visited_urls.add(url)
        self.request_count += 1
        print(f"[{self.request_count}/{MAX_REQUESTS}] Downloading subscription: {url}")
        try:
            content = fetch_binary(url)
            if content is None:
                print(f"  -> No content (fetch failed)")
                return
            try:
                text = content.decode('utf-8', errors='ignore')
            except:
                text = ''
            if not text:
                print(f"  -> Empty content")
                return
            nodes = parse_subscription_content(text, url)
            if nodes:
                for node in nodes:
                    if 'raw' not in node or not node['raw']:
                        node['raw'] = node_to_vmess_link(node)
                self.all_nodes.extend(nodes)
                print(f"  -> Found {len(nodes)} nodes")
            else:
                print(f"  -> No nodes parsed")
        except Exception as e:
            print(f"  -> Error: {e}")

    def parse_page(self, html, base_url, depth, patterns):
        if patterns and not isinstance(patterns, list):
            patterns = [patterns]

        soup = BeautifulSoup(html, 'html.parser')

        if patterns:
            text = soup.get_text()
            url_regex = re.compile(r'https?://[^\s<>"\'{}|\\^`\[\]]+', re.IGNORECASE)
            for match in url_regex.findall(text):
                url = clean_url(match)
                if url in self.visited_urls:
                    continue
                for pattern in patterns:
                    if pattern.match(url):
                        print(f"  Found wildcard-matched URL from text: {url}")
                        if depth < MAX_DEPTH:
                            self.enqueue(url, depth + 1, patterns)
                        break

        for a in soup.find_all('a', href=True):
            href = a['href']
            full_url = safe_urljoin(base_url, href)
            if not full_url:
                continue
            full_url = clean_url(full_url)
            if full_url in self.visited_urls:
                continue

            matched = False
            if patterns:
                for pattern in patterns:
                    if pattern.match(full_url):
                        matched = True
                        break

            if matched:
                print(f"  Found wildcard-matched URL from href: {full_url}")
                if depth < MAX_DEPTH:
                    self.enqueue(full_url, depth + 1, patterns)
                continue

            if is_node_link(full_url):
                self.download_subscription(full_url)
                if depth < MAX_DEPTH and full_url not in self.visited_urls:
                    self.enqueue(full_url, depth + 1, patterns)

        text = soup.get_text()
        url_regex = re.compile(r'https?://[^\s<>"\'{}|\\^`\[\]]+', re.IGNORECASE)
        for match in url_regex.findall(text):
            url = clean_url(match)
            if url in self.visited_urls:
                continue

            already_matched = False
            if patterns:
                for pattern in patterns:
                    if pattern.match(url):
                        already_matched = True
                        break
            if already_matched:
                continue

            if is_node_link(url):
                self.download_subscription(url)
                if depth < MAX_DEPTH and url not in self.visited_urls:
                    self.enqueue(url, depth + 1, patterns)

        # ---- node_link_regex 前缀扩展 ----
        # 注意：
        #   1. 顺序：长前缀在前（ssr 在 ss 前，socks5h 在 socks5 前，socks5 在 socks 前）
        #   2. 不包含 http/https，避免网页 URL 污染
        node_link_regex = re.compile(
            r'(vmess|vless|ssr|ss|trojan|hysteria2|hy2|hysteria|tuic|'
            r'socks5h|socks5|socks)://[^\s<>"\'{}|\\^`\[\]]+',
            re.IGNORECASE
        )
        for match in node_link_regex.finditer(text):
            link = match.group(0).strip()
            node = parse_node_link(link)
            if node:
                node['raw'] = link
                self.all_nodes.append(node)
                print(f"  Found direct node link: {link[:50]}...")

    def crawl(self, source_lines):
        wildcard_map, direct_urls, plain_pages = self.process_sources(source_lines)

        for url in direct_urls:
            self.download_subscription(url)

        for url in plain_pages:
            patterns = wildcard_map.pop(url, None)
            if patterns:
                self.enqueue(url, 1, patterns)
            else:
                self.enqueue(url, 1, None)

        for base_url, patterns in wildcard_map.items():
            self.enqueue(base_url, 1, patterns)

        print(f"📋 Initial queue size: {len(self.queue)}")

        while self.queue and self.request_count < MAX_REQUESTS:
            url, depth, patterns = self.queue.popleft()
            if url in self.visited_urls:
                continue
            self.visited_urls.add(url)
            self.request_count += 1
            print(f"[{self.request_count}/{MAX_REQUESTS}] Crawling: {url} (depth={depth})")
            try:
                html = fetch_content(url)
                if html is None:
                    continue
                self.parse_page(html, url, depth, patterns)
            except Exception as e:
                print(f"  Error crawling {url}: {e}")

        print(f"🏁 Crawl finished. Total requests: {self.request_count}, Nodes collected: {len(self.all_nodes)}")

    def dedupe_and_test(self):
        print("🔄 Deduplicating...")
        unique = {}
        for node in self.all_nodes:
            key = normalize_node_key(node)
            if key not in unique:
                unique[key] = node
        nodes = list(unique.values())
        print(f"   After dedupe: {len(nodes)} nodes")

        # ---- 协议分布统计 ----
        from collections import Counter
        type_dist = Counter(n.get('type') for n in nodes)
        print(f"   Protocol distribution: {dict(type_dist)}")
        # ------------------------------

        print(f"🌐 Testing connectivity (timeout={CONNECT_TIMEOUT}s, retries={TEST_RETRIES}, workers={TEST_WORKERS})...")
        valid_nodes = []
        with ThreadPoolExecutor(max_workers=TEST_WORKERS) as executor:
            future_to_node = {executor.submit(test_node_connectivity, node): node for node in nodes}
            for future in as_completed(future_to_node):
                node = future_to_node[future]
                try:
                    reachable, delay = future.result()
                    if reachable and delay <= MAX_DELAY:
                        node['delay'] = delay
                        valid_nodes.append(node)
                        print(f"   ✅ {node.get('add')}:{node.get('port')} - {delay}ms")
                    elif reachable and delay > MAX_DELAY:
                        print(f"   ⏱️  Too slow: {node.get('add')}:{node.get('port')} - {delay}ms (exceeds {MAX_DELAY}ms)")
                    else:
                        print(f"   ❌ Unreachable: {node.get('add')}:{node.get('port')}")
                except Exception as e:
                    print(f"   ⚠️  Test error: {e}")
        print(f"   After connectivity test: {len(valid_nodes)} nodes (filtered by max delay {MAX_DELAY}ms)")
        return valid_nodes

    def run(self):
        if not os.path.exists(SOURCE_FILE):
            print(f"❌ Error: Source file '{SOURCE_FILE}' not found.")
            sys.exit(1)

        with open(SOURCE_FILE, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        self.crawl(lines)

        if not self.all_nodes:
            print("❌ No nodes collected. Check your sources and network.")
            return

        valid_nodes = self.dedupe_and_test()

        if not valid_nodes:
            print("❌ No valid nodes after testing. No output files generated.")
            return

        clash_yaml = nodes_to_clash_yaml(valid_nodes)
        if clash_yaml:
            with open(OUTPUT_YAML, 'w', encoding='utf-8') as f:
                f.write(clash_yaml)
            print(f"✅ Clash YAML written to {OUTPUT_YAML}")
        else:
            print("❌ No valid nodes to write to Clash YAML")

        base64_str = nodes_to_base64(valid_nodes)
        with open(OUTPUT_TXT, 'w', encoding='utf-8') as f:
            f.write(base64_str)
        print(f"✅ Base64 subscription written to {OUTPUT_TXT}")

# ======================== 主入口 ========================
if __name__ == '__main__':
    crawler = Crawler()
    crawler.run()

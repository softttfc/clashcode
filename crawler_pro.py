#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import requests
import re
import yaml
import base64
import json
import socket
from urllib.parse import urljoin, urlparse, parse_qs
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
MAX_DEPTH = 3               # 爬取深度（从起始页算起）。增大可发现更多链接，但增加请求数。建议 2~5
MAX_REQUESTS = 210          # 总请求数上限（含页面和订阅）。控制资源消耗，避免超时。建议 100~500
KEYWORDS = ['node', 'subscri', 'feed', '.yaml', '.yml', '.txt']  # 用于识别订阅链接的关键词（URL 包含即视为订阅）

# 网络请求
REQUEST_TIMEOUT = 15        # HTTP 请求超时（秒）。增大可应对慢速服务器，减小可加快失败检测。建议 15~60
FETCH_RETRIES = 2           # 获取内容失败后的重试次数。建议 2~5
FETCH_DELAY = 1             # 重试间隔（秒）。建议 0.5~2

# 节点测通（TCP 握手）
CONNECT_TIMEOUT = 2         # TCP 握手超时（秒）。增大可减少网络波动误判，但延长总验证时间。建议 3~10
TEST_RETRIES = 1            # 测通失败后的重试次数。建议 1~3
TEST_WORKERS = 15           # 测通并发线程数。增大可加快验证，但可能因资源竞争导致失败率上升。建议 5~20
MAX_DELAY = 3000            # 节点最大可接受延迟（毫秒），超过则丢弃。调低可提高质量，但可能减少节点数。建议 2000~5000

# 导出文件
OUTPUT_YAML = 'crawclash.yaml'   # Clash 配置文件输出路径
OUTPUT_TXT = 'crawsub.txt'       # Base64 订阅文件输出路径
SOURCE_FILE = 'crawler.list'     # 起始源列表文件路径

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
    """解析 VLESS 链接"""
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

def parse_trojan(trojan_url):
    """解析 Trojan 链接"""
    if not trojan_url.startswith('trojan://'):
        return None
    try:
        parsed = urlparse(trojan_url)
        password = parsed.username or ''
        host = parsed.hostname or ''
        port = parsed.port or 443
        query = parse_qs(parsed.query)
        node = {
            'type': 'trojan',
            'add': host,
            'port': port,
            'password': password,
            'sni': query.get('sni', [host])[0],
            'allowInsecure': query.get('allowInsecure', ['0'])[0] == '1',
            'ps': f"Trojan-{host}",
            'raw': trojan_url,
        }
        if not node['password']:
            return None
        return node
    except Exception:
        return None

def parse_node_link(link):
    if link.startswith('vmess://'):
        return parse_vmess(link)
    elif link.startswith('vless://'):
        return parse_vless(link)
    elif link.startswith('ss://'):
        return parse_ss(link)
    elif link.startswith('trojan://'):
        return parse_trojan(link)
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
                    if ptype not in ('vmess', 'vless', 'ss', 'trojan', 'http', 'socks5'):
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
                    elif ptype == 'ss':
                        node['method'] = proxy.get('cipher', '')
                        node['password'] = proxy.get('password', '')
                    elif ptype == 'trojan':
                        node['password'] = proxy.get('password', '')
                        node['sni'] = proxy.get('sni', '')
                        node['allowInsecure'] = proxy.get('skip-cert-verify', False)
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
                if line and line.startswith(('vmess://', 'vless://', 'ss://', 'trojan://')):
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
        if line and line.startswith(('vmess://', 'vless://', 'ss://', 'trojan://')):
            node = parse_node_link(line)
            if node:
                node['raw'] = line
                nodes.append(node)

    return nodes

def normalize_node_key(node):
    """生成节点去重指纹"""
    if node.get('type') == 'vmess':
        key = f"vmess_{node.get('add')}_{node.get('port')}_{node.get('uuid')}"
    elif node.get('type') == 'vless':
        key = f"vless_{node.get('add')}_{node.get('port')}_{node.get('uuid')}"
    elif node.get('type') == 'ss':
        key = f"ss_{node.get('add')}_{node.get('port')}_{node.get('method')}_{node.get('password')}"
    elif node.get('type') == 'trojan':
        key = f"trojan_{node.get('add')}_{node.get('port')}_{node.get('password')}"
    else:
        key = f"{node.get('type')}_{node.get('add')}_{node.get('port')}"
    return hashlib.md5(key.encode()).hexdigest()

def test_node_connectivity(node, retries=TEST_RETRIES):
    """
    测试节点 TCP 连通性（支持重试），返回 (是否可达, 延迟毫秒)
    并更新节点字典中的 'delay' 字段
    """
    host = node.get('add', '')
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
    if node.get('raw') and node['raw'].startswith(('vmess://', 'vless://', 'ss://', 'trojan://')):
        return node['raw']

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
        query = '&'.join(params)
        return f"vless://{uuid}@{host}:{port}?{query}" if query else f"vless://{uuid}@{host}:{port}"
    elif ntype == 'ss':
        auth = f"{node.get('method','')}:{node.get('password','')}"
        auth_b64 = base64.b64encode(auth.encode()).decode()
        return f"ss://{auth_b64}@{node.get('add','')}:{node.get('port',0)}"
    elif ntype == 'trojan':
        netloc = f"{node.get('password','')}@{node.get('add','')}:{node.get('port',443)}"
        params = []
        if node.get('sni'):
            params.append(f"sni={node.get('sni')}")
        if node.get('allowInsecure') == '1':
            params.append("allowInsecure=1")
        query = '&'.join(params)
        return f"trojan://{netloc}?{query}" if query else f"trojan://{netloc}"
    else:
        return node.get('raw', '')

def is_node_valid(node):
    """检查节点是否包含 Clash 必需字段"""
    node_type = node.get('type', '').lower()
    if not node_type:
        return False
    if node_type not in ('vmess', 'vless', 'ss', 'trojan', 'http', 'socks5'):
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
    elif node_type == 'trojan':
        if not node.get('password'):
            return False
    return True

# ======================== 导出函数（支持 VMess/VLESS/SS/Trojan） ========================

def to_clash_proxy(node):
    """
    将节点转换为 Clash proxy 字典，支持 vmess, vless, ss, trojan。
    完全模仿 JavaScript 的 toClashProxy 逻辑，并补齐 ws-opts 默认值。
    """
    ntype = node.get('type')
    if ntype == 'vmess':
        proxy = {
            'name': '',   # 名称由外部设置
            'type': 'vmess',
            'server': node.get('add', ''),
            'port': int(node.get('port', 0)),
            'uuid': node.get('uuid', ''),
            'alterId': int(node.get('alterId', 0)),
            'cipher': node.get('cipher', 'auto'),
            'tls': bool(node.get('tls', False)),
            'network': node.get('network', 'tcp'),
        }
        # 处理 ws 传输（始终添加 ws-opts，并设默认值，与 JS 一致）
        if node.get('network') == 'ws':
            ws_opts = {
                'path': node.get('path') or '/',   # 默认 '/'
                'headers': {
                    'Host': node.get('host') or node.get('add')   # 默认 server
                }
            }
            proxy['ws-opts'] = ws_opts

        if node.get('sni'):
            proxy['sni'] = node.get('sni')
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
        if node.get('allowInsecure') == '1' or node.get('allowInsecure') is True:
            proxy['skip-cert-verify'] = True
        return proxy

    else:
        return None

def nodes_to_clash_yaml(nodes):
    """
    将节点列表转换为完整的 Clash 配置文件 YAML 字符串，
    支持 VMess/VLESS/SS/Trojan，完全模仿 JavaScript 的 exportClash 输出格式。
    """
    if not nodes:
        return ""

    proxies = []
    used_names = {}

    for node in nodes:
        if not is_node_valid(node):
            print(f"⚠️ 跳过无效节点: {node.get('add', 'unknown')} (type: {node.get('type', '')})")
            continue

        # 生成基础名称（优先 ps）
        base_name = node.get('ps', '').strip()
        if not base_name:
            base_name = f"{node.get('add')}:{node.get('port')}"

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

        node_link_regex = re.compile(r'(vmess|ss|trojan)://[^\s<>"\'{}|\\^`\[\]]+', re.IGNORECASE)
        for match in node_link_regex.findall(text):
            link = match.strip()
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

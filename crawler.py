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

# ======================== 全局配置 ========================
MAX_DEPTH = 3
MAX_REQUESTS = 300
REQUEST_TIMEOUT = 30
KEYWORDS = ['node','subscri', 'feed', '.yaml', '.yml', '.txt']
OUTPUT_YAML = 'crawclash.yaml'
OUTPUT_TXT = 'crawsub.txt'
SOURCE_FILE = 'crawler.list'
CONNECT_TIMEOUT = 3
TEST_WORKERS = 20

# ======================== 辅助函数 ========================

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
    """严格判断是否为直接订阅链接（仅基于扩展名）"""
    if not url:
        return False
    lower = url.lower()
    return lower.endswith(('.yaml', '.yml', '.txt'))

def is_node_link(url):
    """判断 URL 是否可能是节点订阅链接（基于扩展名或关键字）"""
    if not url:
        return False
    lower = url.lower()
    if lower.endswith(('.yaml', '.yml', '.txt')):
        return True
    for kw in KEYWORDS:
        if kw.lower() in lower:
            return True
    return False

def fetch_content(url, retries=3, delay=1):
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

def fetch_binary(url, retries=3, delay=1):
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
            'id': data.get('id', ''),
            'aid': int(data.get('aid', 0)),
            'net': data.get('net', 'tcp'),
            'type': data.get('type', 'none'),
            'host': data.get('host', ''),
            'path': data.get('path', ''),
            'tls': data.get('tls', ''),
            'sni': data.get('sni', ''),
        }
        return node
    except:
        return None

def parse_ss(ss_url):
    if not ss_url.startswith('ss://'):
        return None
    try:
        content = ss_url[5:]
        if '@' in content:
            prefix, suffix = content.split('@', 1)
            b64 = prefix.replace('-', '+').replace('_', '/')
            b64 += '=' * (4 - len(b64) % 4)
            decoded = base64.b64decode(b64).decode('utf-8')
            method, password = decoded.split(':', 1)
            host, port = suffix.split(':')
            port = int(port)
        else:
            b64 = content.replace('-', '+').replace('_', '/')
            b64 += '=' * (4 - len(b64) % 4)
            decoded = base64.b64decode(b64).decode('utf-8')
            method, password, host, port = re.split(r'[:@]', decoded)
            port = int(port)
        node = {
            'type': 'ss',
            'add': host,
            'port': port,
            'method': method,
            'password': password,
        }
        return node
    except:
        return None

def parse_trojan(trojan_url):
    if not trojan_url.startswith('trojan://'):
        return None
    try:
        parsed = urlparse(trojan_url)
        password = parsed.username or ''
        host = parsed.hostname or ''
        port = parsed.port or 443
        node = {
            'type': 'trojan',
            'add': host,
            'port': port,
            'password': password,
            'sni': parsed.hostname,
            'allowInsecure': parse_qs(parsed.query).get('allowInsecure', ['0'])[0],
        }
        return node
    except:
        return None

def parse_node_link(link):
    if link.startswith('vmess://'):
        return parse_vmess(link)
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
    - Clash 配置（proxy-providers 字段，自动下载 http 类型 provider 的 url）
    - Base64 编码的节点链接
    - 每行一个节点链接的纯文本
    """
    nodes = []
    if not content:
        return nodes

    # ---------- 第一步：尝试作为 Clash YAML 解析 ----------
    try:
        data = yaml.safe_load(content)
        if isinstance(data, dict):
            # 1. 标准 proxies 字段
            proxy_list = data.get('proxies') or data.get('Proxy') or data.get('proxy') or []
            if proxy_list:
                for proxy in proxy_list:
                    node = {
                        'type': proxy.get('type', ''),
                        'add': proxy.get('server', ''),
                        'port': int(proxy.get('port', 0)),
                        'uuid': proxy.get('uuid', ''),
                        'aid': proxy.get('alterId', 0),
                        'cipher': proxy.get('cipher', ''),
                        'net': proxy.get('network', 'tcp'),
                        'tls': proxy.get('tls', False),
                        'sni': proxy.get('sni', ''),
                        'host': proxy.get('host', ''),
                        'path': proxy.get('path', ''),
                        'raw': f"{proxy.get('type', '')}://{proxy.get('server', '')}:{proxy.get('port', '')}"
                    }
                    nodes.append(node)
                return nodes  # 如果找到 proxies，直接返回，不再处理 provider

            # 2. proxy-providers 字段（新增支持）
            if 'proxy-providers' in data:
                providers = data['proxy-providers']
                for provider_name, provider_config in providers.items():
                    if not isinstance(provider_config, dict):
                        continue
                    # 只处理 http 类型的 provider
                    if provider_config.get('type') == 'http':
                        provider_url = provider_config.get('url')
                        if provider_url:
                            print(f"  Found proxy-provider '{provider_name}', downloading: {provider_url}")
                            try:
                                # 下载 provider 内容
                                provider_content = fetch_binary(provider_url)
                                if provider_content:
                                    try:
                                        provider_text = provider_content.decode('utf-8', errors='ignore')
                                    except:
                                        provider_text = ''
                                    # 递归解析（但注意避免无限循环，这里只递归一层）
                                    sub_nodes = parse_subscription_content(provider_text, provider_url)
                                    if sub_nodes:
                                        nodes.extend(sub_nodes)
                                        print(f"  -> Got {len(sub_nodes)} nodes from provider")
                            except Exception as e:
                                print(f"  -> Error downloading provider {provider_url}: {e}")
                    # 可以扩展支持 file 类型（需读取本地文件，但一般不适用于远程抓取）
                # 如果从 provider 中获取到了节点，返回
                if nodes:
                    return nodes
    except Exception as e:
        # YAML 解析失败，继续尝试其他格式
        pass

    # ---------- 第二步：尝试 Base64 解码 ----------
    try:
        b64_clean = content.replace('\n', '').replace('\r', '').replace(' ', '')
        if re.match(r'^[A-Za-z0-9+/=]+$', b64_clean) and len(b64_clean) % 4 == 0:
            decoded = base64.b64decode(b64_clean).decode('utf-8', errors='ignore')
            for line in decoded.splitlines():
                line = line.strip()
                if line and (line.startswith(('vmess://', 'ss://', 'trojan://'))):
                    node = parse_node_link(line)
                    if node:
                        node['raw'] = line
                        nodes.append(node)
            if nodes:
                return nodes
    except:
        pass

    # ---------- 第三步：按行解析节点链接 ----------
    for line in content.splitlines():
        line = line.strip()
        if line and (line.startswith(('vmess://', 'ss://', 'trojan://'))):
            node = parse_node_link(line)
            if node:
                node['raw'] = line
                nodes.append(node)

    return nodes

def normalize_node_key(node):
    if node.get('type') == 'vmess':
        key = f"vmess_{node.get('add')}_{node.get('port')}_{node.get('id')}"
    elif node.get('type') == 'ss':
        key = f"ss_{node.get('add')}_{node.get('port')}_{node.get('method')}_{node.get('password')}"
    elif node.get('type') == 'trojan':
        key = f"trojan_{node.get('add')}_{node.get('port')}_{node.get('password')}"
    else:
        key = f"{node.get('type')}_{node.get('add')}_{node.get('port')}"
    return hashlib.md5(key.encode()).hexdigest()

def test_node_connectivity(node):
    host = node.get('add', '')
    port = node.get('port', 0)
    if not host or not port:
        return False
    try:
        ip = socket.gethostbyname(host)
        with socket.create_connection((ip, port), timeout=CONNECT_TIMEOUT):
            return True
    except:
        return False

def node_to_vmess_link(node):
    if node.get('type') == 'vmess':
        if node.get('raw') and node['raw'].startswith('vmess://'):
            return node['raw']
        data = {
            'v': '2',
            'ps': '',
            'add': node.get('add', ''),
            'port': node.get('port', 0),
            'id': node.get('id', ''),
            'aid': node.get('aid', 0),
            'net': node.get('net', 'tcp'),
            'type': node.get('type', 'none'),
            'host': node.get('host', ''),
            'path': node.get('path', ''),
            'tls': node.get('tls', ''),
            'sni': node.get('sni', ''),
        }
        b64 = base64.b64encode(json.dumps(data).encode()).decode()
        return 'vmess://' + b64
    elif node.get('type') == 'ss':
        if node.get('raw') and node['raw'].startswith('ss://'):
            return node['raw']
        auth = f"{node.get('method','')}:{node.get('password','')}"
        auth_b64 = base64.b64encode(auth.encode()).decode()
        return f"ss://{auth_b64}@{node.get('add','')}:{node.get('port',0)}"
    elif node.get('type') == 'trojan':
        if node.get('raw') and node['raw'].startswith('trojan://'):
            return node['raw']
        netloc = f"{node.get('password','')}@{node.get('add','')}:{node.get('port',443)}"
        return f"trojan://{netloc}"
    else:
        return node.get('raw', '')

def nodes_to_clash_yaml(nodes):
    proxies = []
    for idx, node in enumerate(nodes):
        proxy = {
            'name': f"node-{idx+1}",
            'type': node.get('type', 'vmess'),
            'server': node.get('add', ''),
            'port': node.get('port', 0),
        }
        if node.get('type') == 'vmess':
            proxy['uuid'] = node.get('id', '')
            proxy['alterId'] = node.get('aid', 0)
            proxy['cipher'] = node.get('cipher', 'auto')
            proxy['network'] = node.get('net', 'tcp')
            if node.get('tls'):
                proxy['tls'] = True
            if node.get('sni'):
                proxy['sni'] = node.get('sni')
            if node.get('host'):
                proxy['host'] = node.get('host')
            if node.get('path'):
                proxy['path'] = node.get('path')
        elif node.get('type') == 'ss':
            proxy['cipher'] = node.get('method', '')
            proxy['password'] = node.get('password', '')
        elif node.get('type') == 'trojan':
            proxy['password'] = node.get('password', '')
            if node.get('sni'):
                proxy['sni'] = node.get('sni')
            if node.get('allowInsecure') == '1':
                proxy['skip-cert-verify'] = True
        proxies.append(proxy)
    clash_data = {'proxies': proxies}
    return yaml.dump(clash_data, default_flow_style=False, allow_unicode=True)

def nodes_to_base64(nodes):
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
        """
        预处理所有源，建立配对关系
        增强配对逻辑：
        1. 精确匹配 base
        2. 查找以 base 为前缀的更具体的 plain_page（路径更长）
        3. 回退到根域名匹配
        直接订阅判断：仅当 URL 以 .yaml/.yml/.txt 结尾时才视为直接订阅
        """
        wildcard_items = []  # (原始url, pattern_regex)
        direct_urls = []
        plain_pages_set = set()

        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            # 处理 +date
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
                # 严格判断：只有以 .yaml/.yml/.txt 结尾的才视为直接订阅
                if is_direct_subscription(url):
                    direct_urls.append(url)
                else:
                    clean = url.rstrip('/')
                    plain_pages_set.add(clean)

        # 建立通配符配对
        wildcard_map = {}  # base_url -> [patterns]
        for url, regex in wildcard_items:
            base_part = url.split('*', 1)[0].rstrip('/')
            matched_base = None

            # 1. 精确匹配
            if base_part in plain_pages_set:
                matched_base = base_part
            else:
                # 2. 查找以 base_part 为前缀的 plain_page（更具体路径）
                candidates = [p for p in plain_pages_set if p.startswith(base_part) and p != base_part]
                if candidates:
                    # 选择路径最长的（最具体）
                    matched_base = max(candidates, key=len)
                else:
                    # 3. 回退到根域名匹配
                    parsed = urlparse(base_part)
                    root_url = f"{parsed.scheme}://{parsed.netloc}".rstrip('/')
                    if root_url in plain_pages_set:
                        matched_base = root_url

            if matched_base:
                if matched_base not in wildcard_map:
                    wildcard_map[matched_base] = []
                wildcard_map[matched_base].append(regex)
            else:
                # 无匹配，使用自身的 base
                if base_part not in wildcard_map:
                    wildcard_map[base_part] = []
                wildcard_map[base_part].append(regex)

        # 将 plain_pages_set 转为列表
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
        """解析页面，patterns可以是单个正则或列表"""
        if patterns and not isinstance(patterns, list):
            patterns = [patterns]

        soup = BeautifulSoup(html, 'html.parser')

        # ========== 新增：从页面纯文本中提取所有符合通配符模式的 URL ==========
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
        # ====================================================================

        # 处理 a[href]
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
                # ====== 修改 ======
                # 原因：通配符匹配的 URL 可能是普通网页，而不是直接订阅。
                # 若此处调用 download_subscription，会导致将普通网页当作订阅下载，
                # 从而无法解析页面内部的真正订阅链接（如 .yaml）。
                # 解决：仅入队作为网页爬取，真正的订阅链接会在后续的 is_node_link 判断中被捕获。
                # 删除下面两行注释代码，不再在此处下载。
                # if is_node_link(full_url):
                #     self.download_subscription(full_url)
                # ====== 修改结束 ======
                continue

            if is_node_link(full_url):
                self.download_subscription(full_url)
                if depth < MAX_DEPTH and full_url not in self.visited_urls:
                    self.enqueue(full_url, depth + 1, patterns)

        # 从纯文本提取URL（跳过已匹配通配符的）
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

        # 提取直接节点链接
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

        # 处理直接订阅
        for url in direct_urls:
            self.download_subscription(url)

        # 处理普通网页（含配对逻辑）
        for url in plain_pages:
            patterns = wildcard_map.pop(url, None)
            if patterns:
                self.enqueue(url, 1, patterns)
            else:
                self.enqueue(url, 1, None)

        # 处理剩余未配对的通配符（其base不在plain_pages中）
        for base_url, patterns in wildcard_map.items():
            self.enqueue(base_url, 1, patterns)

        print(f"📋 Initial queue size: {len(self.queue)}")

        # 执行爬取队列
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

        print("🌐 Testing connectivity...")
        valid_nodes = []
        with ThreadPoolExecutor(max_workers=TEST_WORKERS) as executor:
            future_to_node = {executor.submit(test_node_connectivity, node): node for node in nodes}
            for future in as_completed(future_to_node):
                node = future_to_node[future]
                try:
                    if future.result():
                        valid_nodes.append(node)
                    else:
                        print(f"   ❌ Unreachable: {node.get('add')}:{node.get('port')}")
                except Exception as e:
                    print(f"   ⚠️  Test error: {e}")
        print(f"   After connectivity test: {len(valid_nodes)} nodes")
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
        with open(OUTPUT_YAML, 'w', encoding='utf-8') as f:
            f.write(clash_yaml)
        print(f"✅ Clash YAML written to {OUTPUT_YAML}")

        base64_str = nodes_to_base64(valid_nodes)
        with open(OUTPUT_TXT, 'w', encoding='utf-8') as f:
            f.write(base64_str)
        print(f"✅ Base64 subscription written to {OUTPUT_TXT}")

# ======================== 主入口 ========================
if __name__ == '__main__':
    crawler = Crawler()
    crawler.run()

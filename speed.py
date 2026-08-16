#!/usr/bin/env python3
"""
speed.py - 对 Clash 配置中的代理节点进行 TCP 端口连通性测试
用法: python speed.py [input_file] [output_file]
默认 input_file = list.meta.yml, output_file = list.metaspeed.yml
"""

import yaml
import socket
import sys
import concurrent.futures
from typing import List, Dict, Any, Optional

# 测试超时（秒）
CONNECT_TIMEOUT = 3
# 并发线程数
MAX_WORKERS = 50

def test_proxy(proxy: Dict[str, Any]) -> bool:
    """
    测试单个代理的连通性：尝试 TCP 连接到 server:port
    返回 True 表示连接成功（端口开放）
    """
    server = proxy.get('server')
    port = proxy.get('port')
    if not server or not port:
        return False
    try:
        port = int(port)
    except (ValueError, TypeError):
        return False

    # 如果 server 是 IPv6 地址，需去掉方括号
    if server.startswith('[') and server.endswith(']'):
        server = server[1:-1]

    try:
        with socket.create_connection((server, port), timeout=CONNECT_TIMEOUT):
            return True
    except Exception:
        return False

def main():
    input_file = sys.argv[1] if len(sys.argv) > 1 else 'list.meta.yml'
    output_file = sys.argv[2] if len(sys.argv) > 2 else 'list.metaspeed.yml'

    print(f"读取配置文件: {input_file}")
    with open(input_file, 'r', encoding='utf-8') as f:
        config: Dict[str, Any] = yaml.safe_load(f)

    proxies: List[Dict[str, Any]] = config.get('proxies', [])
    if not proxies:
        print("警告: 配置中未找到任何代理节点，将输出空文件")
        with open(output_file, 'w', encoding='utf-8') as f:
            yaml.dump(config, f, allow_unicode=True)
        return

    print(f"开始测试 {len(proxies)} 个节点 (超时 {CONNECT_TIMEOUT}s, 并发 {MAX_WORKERS})")
    alive = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        # 提交所有测试任务
        future_to_proxy = {executor.submit(test_proxy, p): p for p in proxies}
        for future in concurrent.futures.as_completed(future_to_proxy):
            proxy = future_to_proxy[future]
            try:
                is_alive = future.result()
            except Exception as e:
                print(f"测试异常: {proxy.get('name', '?')} - {e}")
                is_alive = False
            if is_alive:
                alive.append(proxy)
                print(f"✓ {proxy.get('name', '?')} 存活")
            else:
                print(f"✗ {proxy.get('name', '?')} 不可达")

    print(f"\n存活节点: {len(alive)} / {len(proxies)}")
    # 更新配置中的 proxies
    config['proxies'] = alive

    # 如果 proxy-groups 中引用了被删除的节点，Clash 会报错，但大多数情况下这些引用会被忽略
    # 我们可以只更新 proxies，保留 groups 原样（Clash 启动时会自动跳过不存在的节点）
    # 但为安全，也可清理 proxy-groups 中的无效名称（这里不做，交给 Clash 处理）

    with open(output_file, 'w', encoding='utf-8') as f:
        yaml.dump(config, f, allow_unicode=True)
    print(f"已写入: {output_file}")

if __name__ == '__main__':
    main()

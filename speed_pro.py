#!/usr/bin/env python3
"""
speed.py - 对 Clash 配置中的代理节点进行 TCP 端口连通性测试 + HTTP 延迟测试

用法:
    python speed.py [--delay] [input_file] [output_file]

参数:
    --delay       启用 HTTP 延迟测试（默认仅做 TCP 连通性测试）
    input_file    输入 YAML 配置文件路径（默认: list.meta.yml）
    output_file   输出 YAML 配置文件路径（默认: list.metaspeed.yml）

依赖:
    pip install requests pysocks pyyaml

功能说明:
    1. 先对所有节点进行 TCP 端口连通性测试（快速筛选失效节点）。
    2. 若启用 --delay，再对支持 HTTP/SOCKS5 代理协议的存活节点进行 HTTP 延迟测试，
       延迟失败的节点将被剔除，但不支持测速的类型（如 VMess）则保留。
    3. 最终输出所有存活节点（以及延迟测试成功的可测节点），不添加延迟字段，不排序。
"""

import yaml
import socket
import sys
import concurrent.futures
import time
from typing import List, Dict, Any, Optional

# ============================================================================
# 全局常量配置（可根据需要调整）
# ============================================================================

# -------------------- 超时与并发设置 --------------------
# TCP 连通性测试超时（秒）
# 建议范围: 1~3，数值越小淘汰越快，但可能误判网络抖动
CONNECT_TIMEOUT = 1

# HTTP 延迟测试超时（秒）
# 建议范围: 2~5，数值越大越能测出高延迟节点，但耗时增加
DELAY_TIMEOUT = 2

# 并发测试线程数
# 建议范围: 10~50，取决于网络环境和系统资源，过大可能触发防火墙限制
MAX_WORKERS = 15

# -------------------- 延迟测试目标 URL --------------------
# 使用轻量级 204 响应，减少传输时间，更准确反映代理节点到目标的往返延迟
# 建议使用 Google 或 Cloudflare 的稳定端点，确保全球可达
DELAY_TEST_URL = "http://www.gstatic.com/generate_204"

# 延迟测试期望的 HTTP 状态码
# gstatic.com/generate_204 返回 204，其他目标可能返回 200
EXPECTED_STATUS = 204

# -------------------- 命令行与文件默认值 --------------------
# 命令行启用延迟测试的标志
DELAY_FLAG = "--delay"

# 默认输入/输出文件名（当命令行未指定时使用）
DEFAULT_INPUT = "list.meta.yml"
DEFAULT_OUTPUT = "list.metaspeed.yml"

# -------------------- 支持的代理类型（用于延迟测试） --------------------
# 仅这些类型的节点会进行 HTTP 延迟测试（其余类型跳过）
# 注意: VMess/VLESS/Trojan 等需要专用客户端，requests 库无法直接支持
HTTP_PROXY_TYPES = ("http", "https")
SOCKS_PROXY_TYPES = ("socks5", "socks5h")
ALLOWED_PROXY_TYPES = HTTP_PROXY_TYPES + SOCKS_PROXY_TYPES

# ============================================================================
# 功能函数
# ============================================================================

def test_proxy(proxy: Dict[str, Any]) -> bool:
    """
    测试单个代理的 TCP 连通性（端口是否开放）

    参数:
        proxy: 代理节点字典，必须包含 'server' 和 'port' 字段

    返回:
        True  -> TCP 连接成功（端口可达）
        False -> 连接失败（超时、拒绝、无法解析等）
    """
    server = proxy.get("server")
    port = proxy.get("port")
    if not server or not port:
        return False
    try:
        port = int(port)
    except (ValueError, TypeError):
        return False

    # 处理 IPv6 地址格式（如 [::1]）
    if server.startswith("[") and server.endswith("]"):
        server = server[1:-1]

    try:
        with socket.create_connection((server, port), timeout=CONNECT_TIMEOUT):
            return True
    except Exception:
        return False


def test_delay(proxy: Dict[str, Any]) -> Optional[float]:
    """
    测试单个代理的 HTTP 延迟（仅支持 HTTP/HTTPS/SOCKS5 类型）

    参数:
        proxy: 代理节点字典

    返回:
        成功 -> 延迟（毫秒）
        失败或类型不支持 -> None
    """
    proxy_type = proxy.get("type", "").lower()
    server = proxy.get("server")
    port = proxy.get("port")
    if not server or not port:
        return None

    # 根据代理类型构建 requests 使用的代理 URL
    if proxy_type in HTTP_PROXY_TYPES:
        proxy_url = f"http://{server}:{port}"
        proxies = {"http": proxy_url, "https": proxy_url}
    elif proxy_type in SOCKS_PROXY_TYPES:
        proxy_url = f"socks5://{server}:{port}"
        proxies = {"http": proxy_url, "https": proxy_url}
    else:
        # 不支持的类型直接跳过
        return None

    try:
        import requests
        start = time.perf_counter()
        resp = requests.get(
            DELAY_TEST_URL,
            proxies=proxies,
            timeout=DELAY_TIMEOUT
        )
        elapsed = (time.perf_counter() - start) * 1000  # 转换为毫秒
        if resp.status_code == EXPECTED_STATUS:
            return elapsed
        else:
            # 状态码不符合预期，视为失败
            return None
    except Exception:
        return None


def main():
    """
    主流程：
        1. 解析命令行参数
        2. 加载 YAML 配置文件
        3. 并发执行 TCP 连通性测试
        4. 若启用 --delay，对可测类型的存活节点进行 HTTP 延迟测试（失败则剔除），
           不可测类型直接保留。
        5. 输出所有保留节点（不添加延迟字段，不排序）
    """
    # ---------- 解析命令行参数 ----------
    args = sys.argv[1:]
    enable_delay = False
    if args and args[0] == DELAY_FLAG:
        enable_delay = True
        args = args[1:]

    input_file = args[0] if args else DEFAULT_INPUT
    output_file = args[1] if len(args) > 1 else DEFAULT_OUTPUT

    # ---------- 读取配置文件 ----------
    print(f"读取配置文件: {input_file}")
    with open(input_file, "r", encoding="utf-8") as f:
        config: Dict[str, Any] = yaml.safe_load(f)

    proxies: List[Dict[str, Any]] = config.get("proxies", [])
    if not proxies:
        print("警告: 配置中未找到任何代理节点，将输出空文件")
        with open(output_file, "w", encoding="utf-8") as f:
            yaml.dump(config, f, allow_unicode=True)
        return

    # ---------- 打印测试参数 ----------
    print(f"开始测试 {len(proxies)} 个节点 (超时 {CONNECT_TIMEOUT}s, 并发 {MAX_WORKERS})")
    if enable_delay:
        print(f"延迟测试目标: {DELAY_TEST_URL} (超时 {DELAY_TIMEOUT}s)")
        # 检查依赖包是否安装
        try:
            import requests
        except ImportError:
            print("错误: 启用延迟测试需要安装 requests 和 pysocks")
            print("请运行: pip install requests pysocks")
            sys.exit(1)

    # ---------- 阶段1: TCP 连通性测试（并发） ----------
    alive = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_proxy = {executor.submit(test_proxy, p): p for p in proxies}
        for future in concurrent.futures.as_completed(future_to_proxy):
            proxy = future_to_proxy[future]
            try:
                is_alive = future.result()
            except Exception as e:
                print(f"连通性测试异常: {proxy.get('name', '?')} - {e}")
                is_alive = False
            if is_alive:
                alive.append(proxy)
                print(f"✓ {proxy.get('name', '?')} 存活")
            else:
                print(f"✗ {proxy.get('name', '?')} 不可达")

    print(f"\n连通性测试完成: 存活节点 {len(alive)} / {len(proxies)}")

    # ---------- 阶段2: HTTP 延迟测试（可选，修改后逻辑） ----------
    if enable_delay and alive:
        # [MODIFIED] 记录测试前节点数
        alive_before = len(alive)
        print(f"\n开始 HTTP 延迟测试 (测试前节点数: {alive_before})...")
        print("(仅对 http/https/socks5 类型节点进行，失败则剔除，不可测类型保留)")

        # 记录每个可测节点的延迟测试是否成功
        delay_status = {}  # name -> True(成功) / False(失败)

        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            # 提交所有存活节点的延迟测试任务
            future_to_proxy = {executor.submit(test_delay, p): p for p in alive}
            for future in concurrent.futures.as_completed(future_to_proxy):
                proxy = future_to_proxy[future]
                name = proxy.get("name", "?")
                try:
                    delay_ms = future.result()
                except Exception as e:
                    print(f"延迟测试异常: {name} - {e}")
                    delay_ms = None

                if delay_ms is not None:
                    delay_status[name] = True
                    print(f"  {name} 延迟测试通过 ({delay_ms:.2f} ms)")
                else:
                    delay_status[name] = False
                    print(f"  {name} 延迟测试失败 (超时或类型不支持)")

        # 根据延迟测试结果筛选节点
        final_proxies = []
        deleted_names = []
        for p in alive:
            name = p.get("name", "?")
            proxy_type = p.get("type", "").lower()
            # 判断是否属于可测类型
            if proxy_type in ALLOWED_PROXY_TYPES:
                # 可测类型必须延迟测试成功才保留
                if delay_status.get(name, False):
                    final_proxies.append(p)
                else:
                    deleted_names.append(name)
                    print(f"  剔除节点: {name} (延迟测试失败)")
            else:
                # 不可测类型直接保留
                final_proxies.append(p)

        alive = final_proxies
        # [MODIFIED] 计算并打印统计信息
        alive_after = len(alive)
        deleted = alive_before - alive_after
        print(f"\n延迟测试完成: 测试前节点 {alive_before} 个, 删除 {deleted} 个, 有效 {alive_after} 个")

    # ---------- 更新配置并保存 ----------
    # 无论是否启用延迟，alive 已是最终要输出的节点列表
    config["proxies"] = alive

    with open(output_file, "w", encoding="utf-8") as f:
        yaml.dump(config, f, allow_unicode=True)
    print(f"\n已写入: {output_file}")


if __name__ == "__main__":
    main()

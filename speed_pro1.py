#!/usr/bin/env python3
# =============================================================================
# speed_pro.py 说明
# =============================================================================
#
# 一、功能
# -----------------------------------------------------------------------------
# 对 Clash 配置中的代理节点进行多阶段连通性测试：
#   阶段 1: TCP 端口连通性测试（针对 TCP 协议节点）
#   阶段 2: QUIC 握手测试（针对 UDP 协议节点: Hysteria2 / TUIC）
#   阶段 3: HTTP 延迟测试（针对可测类型: http / https / socks5）
#
# 用法:
#   python speed_pro.py [--delay] [input_file] [output_file]
#
#   参数:
#       --delay       启用 HTTP 延迟测试（默认仅做连通性测试）
#       input_file    输入 YAML 配置文件路径（默认: list.meta.yml）
#       output_file   输出 YAML 配置文件路径（默认: list.metaspeed.yml）
#
# 依赖:
#   pip install requests pysocks pyyaml aioquic
#
# 二、本次修改内容（A1 + A2 + A4 + A5，不做 A3）
# -----------------------------------------------------------------------------
# A1: https 类型节点的代理 URL 修正
#     原代码将所有 HTTP_PROXY_TYPES（http 和 https）统一拼成 "http://{server}:{port}"，
#     导致 https 类型节点被当作 http 代理测试，误杀。
#     修复：使用显式映射表，https 类型拼为 "https://{server}:{port}"。
#
# A2: 处理代理认证
#     原代码未读取 username / password 字段，带认证的 http/socks5 节点会因认证
#     失败被误杀。
#     修复：在代理 URL 中拼接 "user:pass@" 前缀，用户名和密码经 quote() 编码。
#
# A4: IPv6 地址去方括号
#     TCP 测试和代理 URL 拼接中均需去除 IPv6 地址的方括号，避免解析失败。
#     修复：抽取 clean_ipv6() 工具函数，在 test_proxy / test_quic /
#     build_proxy_url 三处调用。
#
# A5: QUIC 握手测试（针对 UDP 协议节点）
#     原代码对 Hysteria2 / TUIC 等 UDP 协议节点做 TCP 连通性测试，必然失败
#     （UDP 服务不监听 TCP 端口），导致大规模误杀。
#     修复：
#       1. 在 test_proxy 中对 QUIC_TYPES 返回 None，交由阶段 2 处理。
#       2. 新增 test_quic()：对 Hysteria2 / TUIC 节点做字段完整性预检，
#          并通过 aioquic 发起真实 QUIC 握手测试。
#       3. 若 aioquic 未安装，脚本打印警告并保留所有 UDP 节点，不崩溃。
#
# 不做 A3:
#   delay_status 仍以节点 name 作为键。若有同名节点，延迟结果可能错配。
#   依赖输入 YAML 中节点名唯一（fetch_pro2.py 的 format_name 会加 #1、#2 后缀）。
#
# 三、流程
# -----------------------------------------------------------------------------
#   读取 YAML -> 分类节点 -> 阶段 1 TCP -> 阶段 2 QUIC -> 阶段 3 HTTP 延迟
#   -> 输出 YAML
#
# 四、注意事项
# -----------------------------------------------------------------------------
# - QUIC 握手测试的定位是"服务在线探测"，不是"代理可用性测试"。握手成功
#   只证明 QUIC 服务在线，不保证认证凭据正确、出口可用。
# - QUIC_TIMEOUT 默认 3 秒，过短易误判，过长拖慢 CI。
# - 若 CI 环境限制 UDP 出站，QUIC 测试会全部失败，导致 UDP 节点被误杀。
# - 在 GitHub Actions 上运行本脚本不会调用 Mihomo API，无封号风险。
#
# =============================================================================

import yaml
import socket
import sys
import concurrent.futures
import time
import os
import random
import asyncio
from typing import List, Dict, Any, Optional
from urllib.parse import quote

# ============================================================================
# 全局常量配置（可根据需要调整）
# ============================================================================

# -------------------- 超时与并发设置 --------------------
# TCP 连通性测试超时（秒）
# 建议范围: 1~3，数值越小淘汰越快，但可能误判网络抖动
CONNECT_TIMEOUT = float(os.environ.get("CONNECT_TIMEOUT", 1))

# HTTP 延迟测试超时（秒）
# 建议范围: 2~5，数值越大越能测出高延迟节点，但耗时增加
DELAY_TIMEOUT = float(os.environ.get("DELAY_TIMEOUT", 2))

# QUIC 握手测试超时（秒）
# 建议范围: 2~5，过短易误判，过长拖慢 CI
QUIC_TIMEOUT = float(os.environ.get("QUIC_TIMEOUT", 3))

# 并发测试线程数
# 建议范围: 10~50，取决于网络环境和系统资源，过大可能触发防火墙限制
# 与 clash-verge-rev DelayManager 的默认并发保持一致，采用 10
MAX_WORKERS = int(os.environ.get("MAX_WORKERS", 10))

# -------------------- 延迟测试目标 URL --------------------
# 使用轻量级 204 响应，减少传输时间，更准确反映代理节点到目标的往返延迟
# 默认与 Clash Verge 一致使用 Cloudflare 的 204 端点
DELAY_TEST_URL = os.environ.get(
    "DELAY_TEST_URL", "http://cp.cloudflare.com/generate_204"
)

# 延迟测试期望的 HTTP 状态码
EXPECTED_STATUS = int(os.environ.get("DELAY_EXPECTED_STATUS", 204))

# -------------------- 命令行与文件默认值 --------------------
DELAY_FLAG = "--delay"
DEFAULT_INPUT = "list.meta.yml"
DEFAULT_OUTPUT = "list.metaspeed.yml"

# -------------------- 协议分类 --------------------
# 走 TCP 连通性测试的协议
TCP_TYPES = {
    "http", "https", "socks5", "socks5h",
    "vmess", "vless", "trojan", "ss", "ssr",
}

# 走 QUIC 握手测试的协议（UDP 协议，不监听 TCP 端口）
QUIC_TYPES = {"hysteria2", "hy2", "tuic"}

# 可以做 HTTP 延迟测试的协议（requests 库支持）
HTTP_TEST_TYPES = {"http", "https", "socks5", "socks5h"}

# 兼容原有变量名
HTTP_PROXY_TYPES = ("http", "https")
SOCKS_PROXY_TYPES = ("socks5", "socks5h")
ALLOWED_PROXY_TYPES = HTTP_PROXY_TYPES + SOCKS_PROXY_TYPES

# ============================================================================
# 工具函数
# ============================================================================

def clean_ipv6(server: str) -> str:
    """
    A4: 去除 IPv6 地址的方括号。
    例如 "[::1]" -> "::1"
    """
    if server and server.startswith("[") and server.endswith("]"):
        return server[1:-1]
    return server


def build_proxy_url(proxy: Dict[str, Any]) -> Optional[str]:
    """
    根据节点类型构建 requests 可用的代理 URL。

    A1: https 类型正确使用 https:// 前缀，不再统一拼成 http://
    A2: 处理 username/password 认证
    A4: IPv6 去方括号

    参数:
        proxy: 代理节点字典

    返回:
        成功 -> 代理 URL 字符串（如 "socks5://user:pass@1.2.3.4:1080"）
        不支持或字段缺失 -> None
    """
    proxy_type = (proxy.get("type") or "").lower()
    server = clean_ipv6(proxy.get("server") or "")
    port = proxy.get("port")

    if not server or not port:
        return None

    # A1: 显式映射表，https 类型不再被错误拼成 http://
    scheme = {
        "http": "http",
        "https": "https",
        "socks5": "socks5",
        "socks5h": "socks5h",
    }.get(proxy_type)
    if not scheme:
        return None

    # A2: 拼接认证信息
    user = proxy.get("username")
    pwd = proxy.get("password")
    auth = ""
    if user:
        auth = f"{quote(str(user))}:{quote(str(pwd or ''))}@"

    return f"{scheme}://{auth}{server}:{port}"


# ============================================================================
# 阶段 1: TCP 连通性测试
# ============================================================================

def test_proxy(proxy: Dict[str, Any]) -> Optional[bool]:
    """
    TCP 端口连通性测试。

    A5: UDP 协议节点（QUIC_TYPES）返回 None，交由阶段 2 处理。

    参数:
        proxy: 代理节点字典，必须包含 'server' 和 'port' 字段

    返回:
        True  -> TCP 连接成功（端口可达）
        False -> 连接失败（超时、拒绝、无法解析等）
        None  -> 该节点属于 UDP 协议，需要走 QUIC 握手测试
    """
    proxy_type = (proxy.get("type") or "").lower()

    # A5: UDP 协议节点不做 TCP 测试
    if proxy_type in QUIC_TYPES:
        return None

    server = clean_ipv6(proxy.get("server") or "")
    port = proxy.get("port")
    if not server or not port:
        return False
    try:
        port = int(port)
    except (ValueError, TypeError):
        return False

    try:
        with socket.create_connection((server, port), timeout=CONNECT_TIMEOUT):
            return True
    except Exception:
        return False


# ============================================================================
# 阶段 2: QUIC 握手测试 (A5)
# ============================================================================

async def _quic_handshake_async(server: str, port: int, timeout: float) -> bool:
    """
    异步 QUIC 握手测试。

    使用 aioquic 的高层 asyncio API 发起 QUIC 连接。
    wait_connected=False 允许 0-RTT 启动，verify_mode=0 跳过证书验证
    （代理节点常用自签证书）。

    参数:
        server: 服务器地址（已去方括号）
        port: 端口
        timeout: 握手超时（秒）

    返回:
        True  -> 握手成功
        False -> 握手失败（超时、连接拒绝、TLS 错误等）
    """
    from aioquic.asyncio import connect
    from aioquic.quic.configuration import QuicConfiguration

    config = QuicConfiguration(is_client=True)
    config.verify_mode = 0          # 跳过证书验证
    config.alpn_protocols = ["h3"]  # Hysteria2 / TUIC 常用 ALPN

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


def test_quic(proxy: Dict[str, Any]) -> bool:
    """
    A5: QUIC 握手测试。

    对 Hysteria2 / TUIC 节点：
      1. 字段完整性预检（缺失关键字段直接剔除）
      2. 通过 aioquic 发起 QUIC 握手，握手成功即判定服务在线

    注意：握手成功只证明 QUIC 服务在线，不保证代理认证凭据正确、
    出口路由可用。这与 TCP 测试的精度相同，都属于"服务在线"级别的测试。

    参数:
        proxy: 代理节点字典

    返回:
        True  -> 字段完整且 QUIC 握手成功
        False -> 字段缺失或握手失败
    """
    proxy_type = (proxy.get("type") or "").lower()
    server = clean_ipv6(proxy.get("server") or "")
    port = proxy.get("port")
    if not server or not port:
        return False
    try:
        port = int(port)
    except (ValueError, TypeError):
        return False

    # 字段完整性预检
    if proxy_type in ("hysteria2", "hy2"):
        if not proxy.get("password"):
            return False
    elif proxy_type == "tuic":
        if not proxy.get("uuid") or not proxy.get("password"):
            return False

    # 每个测试使用独立 event loop，避免线程池中多线程共用同一 loop
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            result = loop.run_until_complete(
                _quic_handshake_async(server, port, QUIC_TIMEOUT)
            )
        finally:
            loop.close()
        return result
    except ImportError:
        # aioquic 未安装，抛出给上层处理
        raise
    except Exception:
        return False


# ============================================================================
# 阶段 3: HTTP 延迟测试
# ============================================================================

def test_delay(proxy: Dict[str, Any]) -> Optional[float]:
    """
    测试单个代理的 HTTP 延迟（仅支持 HTTP/HTTPS/SOCKS5 类型）

    A1/A2/A4: 代理 URL 通过 build_proxy_url 统一构建，
    https 类型正确使用 https://，认证信息正确拼接，IPv6 正确去括号。

    参数:
        proxy: 代理节点字典

    返回:
        成功 -> 延迟（毫秒）
        失败或类型不支持 -> None
    """
    proxy_url = build_proxy_url(proxy)
    if not proxy_url:
        return None

    proxies = {"http": proxy_url, "https": proxy_url}
    try:
        import requests
        start = time.perf_counter()
        resp = requests.get(
            DELAY_TEST_URL,
            proxies=proxies,
            timeout=DELAY_TIMEOUT,
        )
        elapsed = (time.perf_counter() - start) * 1000  # 转换为毫秒
        if resp.status_code == EXPECTED_STATUS:
            return elapsed
        else:
            return None
    except Exception:
        return None


def test_delay_jitter(proxy: Dict[str, Any]) -> Optional[float]:
    """
    带随机错峰的延迟测试。

    每个请求前等待 0~200ms 的随机时间，避免所有请求同时涌向目标，
    降低触发目标站限流的风险（参照 clash-verge-rev 的错峰策略）。
    """
    time.sleep(random.uniform(0, 0.2))
    return test_delay(proxy)


# ============================================================================
# 主流程
# ============================================================================

def main():
    """
    主流程：
        1. 解析命令行参数
        2. 加载 YAML 配置文件
        3. 阶段 1: TCP 连通性测试
        4. 阶段 2: QUIC 握手测试（针对 UDP 协议节点）
        5. 阶段 3: 若启用 --delay，对可测类型的存活节点进行 HTTP 延迟测试
        6. 输出保留节点
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
    print(f"开始测试 {len(proxies)} 个节点 "
          f"(TCP 超时 {CONNECT_TIMEOUT}s, QUIC 超时 {QUIC_TIMEOUT}s, "
          f"并发 {MAX_WORKERS})")
    if enable_delay:
        print(f"延迟测试目标: {DELAY_TEST_URL} (超时 {DELAY_TIMEOUT}s)")
        try:
            import requests  # noqa: F401
        except ImportError:
            print("错误: 启用延迟测试需要安装 requests 和 pysocks")
            print("请运行: pip install requests pysocks")
            sys.exit(1)

    # ---------- 阶段 1: TCP 连通性测试（并发） ----------
    print("\n[阶段 1] TCP 连通性测试...")
    tcp_alive: List[Dict[str, Any]] = []
    udp_pending: List[Dict[str, Any]] = []
    tcp_dead = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_proxy = {executor.submit(test_proxy, p): p for p in proxies}
        for future in concurrent.futures.as_completed(future_to_proxy):
            proxy = future_to_proxy[future]
            name = proxy.get("name", "?")
            try:
                result = future.result()
            except Exception as e:
                print(f"  连通性测试异常: {name} - {e}")
                result = False

            if result is True:
                tcp_alive.append(proxy)
                print(f"  ✓ {name} TCP 存活")
            elif result is None:
                # A5: UDP 协议节点，交由阶段 2 处理
                udp_pending.append(proxy)
            else:
                tcp_dead += 1
                print(f"  ✗ {name} TCP 不可达")

    print(f"\n[阶段 1] TCP 完成: 存活 {len(tcp_alive)}, "
          f"不可达 {tcp_dead}, 待 QUIC 测试 {len(udp_pending)}")

    # ---------- 阶段 2: QUIC 握手测试（A5） ----------
    udp_alive: List[Dict[str, Any]] = []
    if udp_pending:
        print(f"\n[阶段 2] QUIC 握手测试 ({len(udp_pending)} 个节点)...")
        try:
            import aioquic  # noqa: F401
            aioquic_available = True
        except ImportError:
            print("  警告: aioquic 未安装，UDP 协议节点全部保留")
            print("  安装: pip install aioquic")
            aioquic_available = False

        if aioquic_available:
            with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                future_to_proxy = {executor.submit(test_quic, p): p
                                   for p in udp_pending}
                for future in concurrent.futures.as_completed(future_to_proxy):
                    proxy = future_to_proxy[future]
                    name = proxy.get("name", "?")
                    try:
                        ok = future.result()
                    except ImportError:
                        print("  警告: aioquic 未安装，UDP 节点全部保留")
                        udp_alive = list(udp_pending)
                        break
                    except Exception as e:
                        print(f"  QUIC 测试异常: {name} - {e}")
                        ok = False

                    if ok:
                        udp_alive.append(proxy)
                        print(f"  ✓ {name} QUIC 握手成功")
                    else:
                        print(f"  ✗ {name} QUIC 握手失败")

            print(f"[阶段 2] QUIC 完成: 存活 {len(udp_alive)}/{len(udp_pending)}")
        else:
            udp_alive = list(udp_pending)

    # 合并阶段 1+2 存活节点
    alive = tcp_alive + udp_alive
    print(f"\n连通性测试完成: 存活节点 {len(alive)} / {len(proxies)}")

    # ---------- 阶段 3: HTTP 延迟测试（可选） ----------
    if enable_delay and alive:
        alive_before = len(alive)
        print(f"\n[阶段 3] HTTP 延迟测试 (测试前节点数: {alive_before})...")
        print("(仅对 http/https/socks5 类型节点进行，失败则剔除，不可测类型保留)")

        # 注意: 不做 A3，delay_status 仍以 name 作键
        delay_status: Dict[str, bool] = {}

        # 只对可测类型提交延迟测试任务
        testable = [p for p in alive
                    if (p.get("type") or "").lower() in HTTP_TEST_TYPES]

        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            future_to_proxy = {executor.submit(test_delay_jitter, p): p
                               for p in testable}
            for future in concurrent.futures.as_completed(future_to_proxy):
                proxy = future_to_proxy[future]
                name = proxy.get("name", "?")
                try:
                    delay_ms = future.result()
                except Exception as e:
                    print(f"  延迟测试异常: {name} - {e}")
                    delay_ms = None

                if delay_ms is not None:
                    delay_status[name] = True
                    print(f"  {name} 延迟测试通过 ({delay_ms:.2f} ms)")
                else:
                    delay_status[name] = False
                    print(f"  {name} 延迟测试失败 (超时或类型不支持)")

        # 根据延迟测试结果筛选节点
        final_proxies: List[Dict[str, Any]] = []
        for p in alive:
            name = p.get("name", "?")
            proxy_type = (p.get("type") or "").lower()
            if proxy_type in ALLOWED_PROXY_TYPES:
                # 可测类型必须延迟测试成功才保留
                if delay_status.get(name, False):
                    final_proxies.append(p)
                else:
                    print(f"  剔除节点: {name} (延迟测试失败)")
            else:
                # 不可测类型直接保留
                final_proxies.append(p)

        alive = final_proxies
        alive_after = len(alive)
        deleted = alive_before - alive_after
        print(f"\n[阶段 3] 延迟测试完成: 测试前 {alive_before} 个, "
              f"删除 {deleted} 个, 有效 {alive_after} 个")

    # ---------- 更新配置并保存 ----------
    config["proxies"] = alive

    with open(output_file, "w", encoding="utf-8") as f:
        yaml.dump(config, f, allow_unicode=True)
    print(f"\n已写入: {output_file} ({len(alive)} 个节点)")


if __name__ == "__main__":
    main()

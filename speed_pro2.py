#!/usr/bin/env python3
# =============================================================================
# 配置总览(所有开关与参数集中在此, 方便阅读和定义)
# =============================================================================
# 说明: 下列每一项都可用"同名环境变量"覆盖, 括号内为默认值。真正的赋值语句集中在
#       下方 import 之后的[全局常量配置]区; 这里仅作一览, 要改默认值请到该区改。
#
# [增量开关]  (本次新增, 服务于"仓库每天抓取覆盖昨日节点文件"场景的增量测速)
#   INCREMENT     增量总开关: 1=启用(默认) / 0=关闭, 行为退回原全量测速
#   STATE_FILE    增量状态库文件路径, 默认 speed_state.json
#   PRUNE_STATE   1=每轮把状态库裁剪到当前节点池(默认) / 0=累积全部历史
#
# [运行环境要求]  重要: 决定增量能否真正生效
#   状态库 STATE_FILE 必须能"跨运行持久", 增量才有意义:
#     - 有状态环境(本地 / self-hosted runner / 自有 VPS): 磁盘天然保留上轮结果,
#       第二轮起只测新增, 增量生效。
#     - 无状态托管 runner(GitHub hosted runner): 每次运行都是全新干净虚拟机,
#       上一轮写在磁盘的 speed_state.json 在这一轮根本不存在 -> 每轮读到空库
#       -> 把所有节点当成"新增" -> 增量必然退化为全量(等于没生效)。
#     若确实要在 GitHub hosted runner 上跑增量: 必须用 commit 回写 / actions/cache
#     / artifact 把 speed_state.json 跨运行持久化(把它带回下一轮), 否则每轮空库、
#     增量无意义。详见下方 workflow step 的注释。
#
# [测速超时与并发]
#   CONNECT_TIMEOUT        TCP 连通性测试超时秒, 默认 1 (建议 1~3)
#   DELAY_TIMEOUT          HTTP 延迟测试超时秒, 默认 1 (建议 2~5)
#   QUIC_TIMEOUT           QUIC 握手测试超时秒, 默认 1 (建议 2~5)
#   MAX_WORKERS            并发线程数, 默认 10 (建议 10~50)
#
# [延迟测试目标]
#   DELAY_TEST_URL         延迟探测目标 URL, 默认 Cloudflare generate_204
#   DELAY_EXPECTED_STATUS  期望的 HTTP 状态码, 默认 204
#
# [命令行与文件默认值]
#   --delay      启用 HTTP 延迟测试(默认仅做连通性测试), 对应常量 DELAY_FLAG
#   input_file   输入 YAML 路径, 默认 list.meta.yml (常量 DEFAULT_INPUT)
#   output_file  输出 YAML 路径, 默认 list.metaspeed.yml (常量 DEFAULT_OUTPUT)
# =============================================================================
# =============================================================================
# speed_pro1.py 说明
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
QUIC_TIMEOUT = float(os.environ.get("QUIC_TIMEOUT", 1))

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
# 走 TCP 连通性测试的协议，TCP_TYPES冗余无用
#TCP_TYPES = {
#    "http", "https", "socks5", "socks5h",
#    "vmess", "vless", "trojan", "ss", "ssr",
#}

# 走 QUIC 握手测试的协议（UDP 协议，不监听 TCP 端口）
QUIC_TYPES = {"hysteria2", "hy2", "tuic"}

# 可以做 HTTP 延迟测试的协议（requests 库支持）
HTTP_TEST_TYPES = {"http", "https", "socks5", "socks5h"}

# 兼容原有变量名
#HTTP_PROXY_TYPES = ("http", "https")
#SOCKS_PROXY_TYPES = ("socks5", "socks5h")
#ALLOWED_PROXY_TYPES = HTTP_PROXY_TYPES + SOCKS_PROXY_TYPES
ALLOWED_PROXY_TYPES = HTTP_TEST_TYPES

# -------------------- 增量测速开关(本次新增) --------------------
# 完整含义见文件顶部"配置总览 -> [增量开关] 与 [运行环境要求]"。
# 增量总开关: INCREMENT=0 关闭(行为退回原全量测速)
INCREMENT_ENABLED = os.environ.get("INCREMENT", "1").strip().lower() not in ("0", "false", "no", "")
# 状态库文件路径(跨运行持久; 须放在有状态环境: 本地 / self-hosted / VPS。
#   无状态托管 runner 上每轮读到空库, 增量会退化为全量, 详见顶部"运行环境要求")
STATE_FILE = os.environ.get("STATE_FILE", "speed_state.json")
# 是否每轮把状态库裁剪为"仅保留本轮输入池涉及的 identity"(默认开)。
#   仓库每天覆盖节点文件, 旧后端消失后无需长期堆积其死记录; 开启后状态库大小
#   约等于当前节点池大小, 不随时间膨胀。设 PRUNE_STATE=0 则累积全部历史。
PRUNE_STATE = os.environ.get("PRUNE_STATE", "1").strip().lower() in ("1", "true", "yes", "")

# -------------------- base_identity 依赖导入(增量主键来源) --------------------
# 增量/去重统一以 base_identity(连接等价键)为唯一主键, 取自
# openray_bridge.base_identity_for_clash_proxy。导入失败 -> BRIDGE_OK=False,
# main() 中自动退化为全量测速(不会崩溃)。
try:
    from openray_bridge import base_identity_for_clash_proxy as _bridge_base_identity
    BRIDGE_OK = True
except Exception:
    _bridge_base_identity = None
    BRIDGE_OK = False

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



# ============================================================================
# 增量测速模块（本次新增: 只做增量, 不改变测速方式本身）
# ----------------------------------------------------------------------------
# 适用场景(与你的仓库运行方式严格匹配):
#   仓库每天抓取后会【覆盖】昨天的节点文件, 所以本轮输入 = 今天抓取到的全部节点。
#   我们只需要测其中【昨天没测过的新增部分】, 于是:
#       今天最终保存 = (今天 ∩ 昨天存活) 直接继承  +  (今天新增里测通的部分)
#     —— 与昨天一致且昨天判活的节点: 本轮直接继承、不再外连;
#     —— 昨天已判死的节点(若今天又被抓到): 本轮直接丢弃、不再重连;
#     —— 只有"昨天没进过状态库、即今天新增"的节点才发起测速。
#   据此, 本模块【刻意不做】"到期复验"和"冷却到期重试":
#     节点一旦判活即长期继承、一旦判死即长期丢弃, 不会因时间推移而重新发起连接,
#     因此整个增量逻辑不依赖任何时间戳(去掉了复验窗口与冷却退避两套机制)。
# ----------------------------------------------------------------------------
# 设计口径(与前几轮讨论一致):
#   - 状态库主键 = base_identity(连接等价键), 不是 name、不是完整 identity。
#     base_identity 不含 tfo/udp/smux 等客户端旋钮, 旋钮变化不会触发重测。
#   - 增量判定(按"昨天结果"三分, 仅此三种):
#       state 无此 identity            -> TEST       今天新增, 必须测
#       state 有且 verdict == "alive"  -> SKIP_ALIVE  与昨天一致, 继承存活
#       state 有且 verdict == "dead"   -> SKIP_DEAD   昨天已判死, 直接丢弃
#   - fail-safe: 无法计算 identity(openray 缺失/解析失败)的节点当"新增"测,
#     绝不因测不了就标 dead; 首轮状态库为空时退化为全量(冷启动不可避免)。
#   - 仅做"增量", 测速三阶段(TCP/QUIC/HTTP)逻辑本身保持不变。
# ============================================================================
import json

# 注: 增量相关开关(INCREMENT / STATE_FILE / PRUNE_STATE)与 base_identity 依赖导入,
#     已统一集中到文件顶部[全局常量配置]区, 便于一次性阅读与定义, 此处不再重复;
#     本模块只保留增量算法(决策函数 + 状态库读写)。


def compute_base_identity(proxy):
    """取节点 base_identity 作增量键。任何失败返回 None(调用方按'新增'处理)。"""
    if _bridge_base_identity is None:
        return None
    try:
        return _bridge_base_identity(proxy)
    except Exception:
        return None


def load_state(path):
    """加载状态库, 损坏/缺失返回 {}(fail-safe: 空库 -> 下轮全当新增)。"""
    if not path or not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception as e:
        print(f"  警告: 状态库读取失败({e}), 本轮按全量处理")
        return {}


def save_state(path, state):
    """原子写状态库(临时文件 + os.replace), 避免中断产生半截 JSON。"""
    if not path:
        return
    tmp = path + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(state, f, ensure_ascii=False, indent=2)
        os.replace(tmp, path)
    except Exception as e:
        print(f"  警告: 状态库写入失败({e})")


def classify_node(st):
    """
    增量决策(去掉了到期复验/冷却重试, 只按"昨天结果"三分)。
      返回 (action, reason)。action in {TEST, SKIP_ALIVE, SKIP_DEAD}:
        st is None            -> ("TEST", "new")                今天新增, 须测
        verdict == "alive"    -> ("SKIP_ALIVE", "inherit")       与昨天一致, 继承
        其余(dead / 其它)     -> ("SKIP_DEAD", "dead-yesterday") 昨天已死, 丢弃
      注: 不再接收 now 参数——本版本不依赖任何时间戳做复验或退避。
    """
    if st is None:
        return "TEST", "new"
    if st.get("verdict") == "alive":
        return "SKIP_ALIVE", "inherit"
    return "SKIP_DEAD", "dead-yesterday"


# ============================================================================
# 主流程
# ============================================================================

def main():
    """
    主流程(加入增量层后):
        0. 增量选择: 按 base_identity 把节点划分为 待测(新增) / 继承存活 / 昨日已死丢弃
        1. 解析命令行参数
        2. 加载 YAML
        3. 阶段 1 TCP / 阶段 2 QUIC / 阶段 3 HTTP 延迟  只对【待测集合】跑
        4. 继承存活的节点直接保留进输出(不消耗外连)
        5. 回写状态库(verdict / rtt / last_test_ts), 原子写; 可选裁剪至当前池
        6. 输出: 继承存活 + 本轮测通 的节点
    测速三阶段逻辑本身未改动, 仅把喂入对象从全量 proxies 换成 to_test。
    增量场景: 仓库每天覆盖昨日节点文件, 故只测"昨日未测过的新增"; 不做到期
    复验、不做冷却重试(判活长期继承、判死长期丢弃, 不依赖时间戳)。
    """
    args = sys.argv[1:]
    enable_delay = False
    if args and args[0] == DELAY_FLAG:
        enable_delay = True
        args = args[1:]

    input_file = args[0] if args else DEFAULT_INPUT
    output_file = args[1] if len(args) > 1 else DEFAULT_OUTPUT

    print(f"读取配置文件: {input_file}")
    with open(input_file, "r", encoding="utf-8") as f:
        config: Dict[str, Any] = yaml.safe_load(f)

    proxies: List[Dict[str, Any]] = config.get("proxies", [])
    if not proxies:
        print("警告: 配置中未找到任何代理节点, 将输出空文件")
        with open(output_file, "w", encoding="utf-8") as f:
            yaml.dump(config, f, allow_unicode=True)
        return

    # ---------- 增量选择 ----------
    # 今天抓取的节点(可能已覆盖昨天的文件)逐个按 base_identity 判:
    #   新增 -> 测; 昨日存活 -> 继承不测; 昨日已死 -> 丢弃不测。
    # 注: now 仍保留(仅用于给 state 记录 last_test_ts, 不参与任何到期/冷却判定)。
    now = time.time()
    state = load_state(STATE_FILE) if INCREMENT_ENABLED else {}
    if INCREMENT_ENABLED and not BRIDGE_OK:
        print("警告: 未能导入 openray_bridge.base_identity_for_clash_proxy, "
              "本轮退化为全量测速(无法增量去重)")

    to_test: List[Dict[str, Any]] = []
    inherit_alive: List[Dict[str, Any]] = []
    drop_dead: List[Dict[str, Any]] = []
    ident_of: Dict[int, Optional[str]] = {}
    for p in proxies:
        iid = compute_base_identity(p) if INCREMENT_ENABLED else None
        ident_of[id(p)] = iid
        if not INCREMENT_ENABLED or iid is None:
            # 无增量能力 / 无法解析 -> fail-safe 当新增测(绝不直接丢弃)
            to_test.append(p)
            continue
        action, _reason = classify_node(state.get(iid))
        if action == "TEST":
            to_test.append(p)
        elif action == "SKIP_ALIVE":
            inherit_alive.append(p)
        else:  # SKIP_DEAD 昨日已判死
            drop_dead.append(p)

    if INCREMENT_ENABLED:
        print(f"[增量] 待测(新增) {len(to_test)} | 继承存活 {len(inherit_alive)} | "
              f"昨日已死丢弃 {len(drop_dead)} (总输入 {len(proxies)})")
    else:
        print(f"[增量] 未启用, 全量测速 {len(to_test)} 节点")

    print(f"开始测试 {len(to_test)} 个节点 "
          f"(TCP 超时 {CONNECT_TIMEOUT}s, QUIC 超时 {QUIC_TIMEOUT}s, 并发 {MAX_WORKERS})")
    if enable_delay:
        print(f"延迟测试目标: {DELAY_TEST_URL} (超时 {DELAY_TIMEOUT}s)")
        try:
            import requests  # noqa: F401
        except ImportError:
            print("错误: 启用延迟测试需要安装 requests 和 pysocks")
            print("请运行: pip install requests pysocks")
            sys.exit(1)

    # ---------- 阶段 1: TCP 连通性测试(只对 to_test) ----------
    print("\n[阶段 1] TCP 连通性测试...")
    tcp_alive: List[Dict[str, Any]] = []
    udp_pending: List[Dict[str, Any]] = []
    tcp_dead = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_proxy = {executor.submit(test_proxy, p): p for p in to_test}
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
                print(f"  OK {name} TCP 存活")
            elif result is None:
                udp_pending.append(proxy)
            else:
                tcp_dead += 1
                print(f"  XX {name} TCP 不可达")

    print(f"\n[阶段 1] TCP 完成: 存活 {len(tcp_alive)}, "
          f"不可达 {tcp_dead}, 待 QUIC 测试 {len(udp_pending)}")

    # ---------- 阶段 2: QUIC 握手测试 ----------
    udp_alive: List[Dict[str, Any]] = []
    if udp_pending:
        print(f"\n[阶段 2] QUIC 握手测试 ({len(udp_pending)} 个节点)...")
        try:
            import aioquic  # noqa: F401
            aioquic_available = True
        except ImportError:
            print("  警告: aioquic 未安装, UDP 协议节点全部保留")
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
                        print("  警告: aioquic 未安装, UDP 节点全部保留")
                        udp_alive = list(udp_pending)
                        break
                    except Exception as e:
                        print(f"  QUIC 测试异常: {name} - {e}")
                        ok = False

                    if ok:
                        udp_alive.append(proxy)
                        print(f"  OK {name} QUIC 握手成功")
                    else:
                        print(f"  XX {name} QUIC 握手失败")

            print(f"[阶段 2] QUIC 完成: 存活 {len(udp_alive)}/{len(udp_pending)}")
        else:
            udp_alive = list(udp_pending)

    alive = tcp_alive + udp_alive
    print(f"\n连通性测试完成: 待测节点存活 {len(alive)} / {len(to_test)}")

    # ---------- 阶段 3: HTTP 延迟测试(可选) ----------
    delay_by_id: Dict[int, float] = {}
    if enable_delay and alive:
        alive_before = len(alive)
        print(f"\n[阶段 3] HTTP 延迟测试 (测试前节点数: {alive_before})...")
        print("(仅对 http/https/socks5 类型节点进行, 失败则剔除, 不可测类型保留)")

        delay_status: Dict[str, bool] = {}
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
                    delay_by_id[id(proxy)] = delay_ms
                    print(f"  {name} 延迟测试通过 ({delay_ms:.2f} ms)")
                else:
                    delay_status[name] = False
                    print(f"  {name} 延迟测试失败 (超时或类型不支持)")

        after_delay: List[Dict[str, Any]] = []
        for p in alive:
            name = p.get("name", "?")
            proxy_type = (p.get("type") or "").lower()
            if proxy_type in ALLOWED_PROXY_TYPES:
                if delay_status.get(name, False):
                    after_delay.append(p)
                else:
                    print(f"  剔除节点: {name} (延迟测试失败)")
            else:
                after_delay.append(p)

        alive = after_delay
        print(f"\n[阶段 3] 延迟测试完成: 测试前 {alive_before} 个, "
              f"删除 {alive_before - len(alive)} 个, 有效 {len(alive)} 个")

    # ---------- 合并: 继承存活 + 本轮测通 ----------
    tested_alive = alive
    final_proxies = inherit_alive + tested_alive

    # ---------- 回写状态库 ----------
    if INCREMENT_ENABLED:
        # 1) 本轮实测过的节点: 测通记 alive, 测不通记 dead(下轮起直接丢弃, 不再重连)
        alive_ids = {id(p) for p in tested_alive}
        for p in to_test:
            iid = ident_of.get(id(p))
            if iid is None:
                continue  # 无身份键的节点不入库(下轮仍按新增处理)
            rec = state.get(iid, {})
            if id(p) in alive_ids:
                rec["verdict"] = "alive"
                rtt = delay_by_id.get(id(p))
                if rtt is not None:
                    rec["rtt"] = round(rtt, 2)
            else:
                rec["verdict"] = "dead"
            rec["last_test_ts"] = now
            state[iid] = rec
        # 2) 继承存活的节点本轮没测, 但仍是"今天池里可用的节点",
        #    刷新 last_test_ts 表示"今天仍在池中且可用", 维持其 alive 记录。
        for p in inherit_alive:
            iid = ident_of.get(id(p))
            if iid is None:
                continue
            rec = state.get(iid, {"verdict": "alive"})
            rec["verdict"] = "alive"
            rec["last_test_ts"] = now
            state[iid] = rec
        # 3) 可选裁剪: 仅保留本轮输入池涉及的 identity, 防止死记录随时间膨胀
        #    (仓库每天覆盖节点文件, 已消失的后端无须长期占库)。
        if PRUNE_STATE:
            pool_ids = {iid for iid in ident_of.values() if iid is not None}
            state = {k: v for k, v in state.items() if k in pool_ids}
        save_state(STATE_FILE, state)
        _prune_note = ", 已裁剪至当前池" if PRUNE_STATE else ""
        print(f"\n[增量] 状态库已更新: {STATE_FILE} ({len(state)} 条记录{_prune_note})")

    # ---------- 输出 ----------
    config["proxies"] = final_proxies
    with open(output_file, "w", encoding="utf-8") as f:
        yaml.dump(config, f, allow_unicode=True)
    print(f"\n已写入: {output_file} ({len(final_proxies)} 个节点, "
          f"其中本轮实测 {len(tested_alive)} / 继承 {len(inherit_alive)})")


if __name__ == "__main__":
    main()

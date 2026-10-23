#!/usr/bin/env python3
"""dupconfig.py — Clash Verge YAML 节点去重清洗（桥接 OpenRay identity）

用法:
    python dupconfig.py 源.yaml 输出.yaml
    python dupconfig.py 源.yaml 输出.yaml --keep best
    python dupconfig.py 源.yaml 输出.yaml --clean
    python dupconfig.py 源.yaml 输出.yaml --dry-run

诊断参数:
    --verbose            打印每个被改名节点的详情
    --debug-name NAME    只打印 name == NAME 的节点处理详情（可重复）
    --diagnose           在关键步骤打印重名统计
用法	
python dupconfig.py 源.yaml 输出.yaml	标准去重 + 名称唯一化 + 字段修复（不删节点）
--keep best	多副本时保留"名字质量最好"的那条
--clean	额外剔除 mihomo 无法使用的节点（减 1~3%）
--dry-run	跑完整流程但不写文件（看统计）
--diagnose	在 4 个关键阶段打印重名统计
--debug-name "@xxx"	只打印指定节点的处理详情
--verbose	打印每个被改名节点的详情
--sort	按 identity 排序输出
--no-clean-groups	不清洗 proxy-groups 引用

新增可选参数:
    --protocol-check        用 OpenRay render.supported_params 检查协议兼容性并剔除不兼容节点
    --verify-nodes          逐个启动 mihomo 验证节点加载有效性并剔除失败节点（零出站）
    --verify-workers N      mihomo 验证并发数（默认 VERIFY_WORKERS）
    --verify-budget SEC     mihomo 验证总预算秒数（默认 VERIFY_BUDGET_SECONDS）
    --mihomo-bin PATH       mihomo 二进制路径（默认 VERIFY_MIHOMO_BIN）
    --strict-verify         有节点被 --verify-nodes 剔除时返回非零码

处理流水线:
    1. 按 identity 去重（桥接 OpenRay）
    1.5 协议兼容性检查（--protocol-check 开启，会删节点）
    2. 名称归一化 + 唯一化（'...' 替换 / NFC / 全角→半角 / strip / 同名加 ＃N）
    3. 同步 proxy-groups 引用（字符清洗导致的原名消失）
    4. 字段修复（ws path / security-tls 矛盾 / XUDP 传输层）
    5. 质量清洗（--clean 开启，会删节点）
    5.5 mihomo 本地加载验证（--verify-nodes 开启，会删节点）
    6. 最后一道保险：强制唯一化
    7. 清洗 proxy-groups 引用
    8. 输出 YAML（有重名则 exit 2；--strict-verify 触发则 exit 3）
"""

import argparse
import re
import sys
import unicodedata
from collections import Counter
from pathlib import Path
from urllib.parse import unquote

import yaml

try:
    from openray_bridge import (
        clash_dict_to_proxy,
        dedup_by_identity,
        identity_for_clash_proxy,
    )
except ImportError:
    print("❌ 需要 openray_bridge.py + OpenRay 包（domain.py + render.py）", file=sys.stderr)
    sys.exit(1)


# 被上游错误替换的默认 UUID（认证必然失败）
DEFAULT_UUID = "88888888-8888-8888-8888-888888888888"

# 全角 → 半角映射（唯一化之前先归一，避免"看似不同"）
FULLWIDTH_TRANS = str.maketrans(
    "＃＠＆＊｜＞＜",
    "#@&*|><",
)

# 唯一化后缀使用全角 ＃ 的理由：
#   - rebuilder_pro2.py 会做 '#' → '＃'（半角转全角）
#   - 如果 dupconfig 输出 ' #2'（半角），rebuilder 会变成 ' ＃2'（全角）
#   - 如果 dupconfig 输出 ' ＃2'（全角），rebuilder 不会改（因为已经是全角）
#   - 为了避免"dupconfig 输出唯一，但 rebuilder 处理后重名"的问题，
#     dupconfig 直接用全角 ＃N 作为唯一化后缀
UNIQUE_SUFFIX_OPEN = "＃"  # 全角


# ============================================================================
# 协议检查与 mihomo 本地验证参数（集中定义，只改这里）
# ============================================================================
# 设计说明：
#   - 这两个阶段默认关闭，避免无谓的额外耗时；需要时通过命令行开启。
#   - 所有参数都是模块级只读常量；命令行只做覆盖，不会在运行时修改这些常量。
#   - 零出站请求：
#       * 协议检查是纯函数（openray.render.supported_params）。
#       * mihomo 验证只在本地启动核心、等待 127.0.0.1:<port> 进入 LISTEN 状态，
#         不通过代理端口发起任何外部请求。
#   - 修改默认行为，只需改这里的值；不改代码逻辑。
PROTOCOL_CHECK_ENABLED = False        # --protocol-check 默认关闭
VERIFY_NODES_ENABLED = False          # --verify-nodes 默认关闭
VERIFY_WORKERS = 16                   # 并发 worker 数（参考 OpenRay collector.yml 的 64，本地验证更轻）
VERIFY_TIMEOUT = 10.0                 # 单节点端口就绪硬超时（秒）
VERIFY_BUDGET_SECONDS = 1800          # 验证总预算（秒）；超预算停止并保留剩余节点
VERIFY_MIHOMO_BIN = "mihomo"          # mihomo 二进制路径；可被 --mihomo-bin 覆盖
VERIFY_TEMP_PREFIX = "dupverify-"     # 临时目录前缀
VERIFY_STRICT = False                 # 有节点被剔除时是否返回非零码


# ============================================================================
# 诊断工具
# ============================================================================
def diagnose_duplicates(proxies, label, debug_names=None):
    """打印 proxies 里的重名统计，返回重名组数。"""
    if not isinstance(proxies, list):
        print(f"🔍 [{label}] proxies 不是列表")
        return 0

    names = [(i, p.get("name")) for i, p in enumerate(proxies) if isinstance(p, dict)]
    counter = Counter(n for _, n in names)
    dups = {n: c for n, c in counter.items() if c > 1}

    print(f"🔍 [{label}] {len(proxies)} 个节点, "
          f"{len(counter)} 个唯一名字, 重名 {len(dups)} 个")

    if dups:
        for name, count in list(dups.items())[:20]:
            indices = [i for i, n in names if n == name]
            print(f"    ❌ {name!r} × {count}  位置: {indices[:10]}")
        if len(dups) > 20:
            print(f"    ... 还有 {len(dups) - 20} 个重名")

    if debug_names:
        for target in debug_names:
            matches = [(i, n) for i, n in names if n == target]
            if matches:
                print(f"    🎯 目标 {target!r}: 出现 {len(matches)} 次, "
                      f"位置: {[i for i, _ in matches]}")

    return len(dups)


# ============================================================================
# 1. 名称归一化 + 唯一化
# ============================================================================
def normalize_names(proxies, verbose=False, debug_names=None):
    """
    归一化节点名，并保证每个 name 唯一。

    归一化顺序（关键）:
      1. Unicode NFC（消除 NFD/NFC 差异）
      2. '...' → '…'（YAML 文档结束符）
      3. 全角 → 半角（＃→#、＠→@、＆→&、＊→*、｜→|、＞→>、＜→<）
      4. strip（去首尾空白）
      5. 去不可见控制字符（保留内部空格）
      6. 空字符串 → '未命名'
      7. 唯一化：后缀用全角 ' ＃N'（避免 rebuilder 的 #→＃ 再次冲突）

    返回 (renamed_count, name_map)
    """
    if not isinstance(proxies, list):
        return 0, {}

    debug_names = set(debug_names or [])
    seen = set()
    renamed_count = 0
    name_map = {}

    if verbose or debug_names:
        print(f"🔤 [normalize_names] 开始处理 {len(proxies)} 个节点")

    for idx, p in enumerate(proxies):
        if not isinstance(p, dict):
            continue

        # ---- 拿到原始 name ----
        raw_name = p.get("name")
        original = raw_name if isinstance(raw_name, str) else ""

        # ---- 1. Unicode NFC ----
        name = unicodedata.normalize("NFC", original)

        # ---- 2. '...' → '…' ----
        if "..." in name:
            name = name.replace("...", "…")

        # ---- 3. 全角 → 半角 ----
        name = name.translate(FULLWIDTH_TRANS)

        # ---- 4. strip ----
        name = name.strip()

        # ---- 5. 去不可见字符 ----
        name = "".join(c for c in name if c.isprintable() or c == " ")

        # ---- 6. 空 → '未命名' ----
        if not name:
            name = "未命名"

        # 记录"字符清洗导致"的改名（仅当字符清洗改变了名字）
        if name != original and original and original not in name_map:
            name_map[original] = name

        # ---- 7. 唯一化 ----
        was_in_seen = name in seen
        base = name
        n = 1
        while name in seen:
            n += 1
            name = f"{base} {UNIQUE_SUFFIX_OPEN}{n}"
        seen.add(name)

        # ---- 防御性：无条件写回 ----
        # 即使 name == original，也写一次，避免任何"引用"问题
        p["name"] = name

        # 统计
        if name != original:
            renamed_count += 1

        # 日志
        is_debug = bool(debug_names and original in debug_names)
        if verbose or is_debug:
            tag = "🎯" if is_debug else "  "
            if was_in_seen:
                reason = "同名唯一化"
            elif name != original:
                reason = "字符归一化"
            else:
                reason = "未变"
            if is_debug or reason != "未变":
                print(f"  {tag} [{idx:5d}] {reason}: {original!r} → {name!r}")

    if verbose or debug_names:
        print(f"🔤 [normalize_names] 完成: 改名 {renamed_count} 个节点")

    # 自检：normalize_names 后应该无重名
    diagnose_duplicates(proxies, "normalize_names 之后", debug_names)

    return renamed_count, name_map


def sync_group_references(config, name_map):
    """同步 proxy-groups 里的引用（仅针对字符清洗导致的改名）。"""
    if not name_map:
        return 0
    groups = config.get("proxy-groups") or []
    if not isinstance(groups, list):
        return 0
    synced = 0
    for g in groups:
        if not isinstance(g, dict):
            continue
        members = g.get("proxies")
        if not isinstance(members, list):
            continue
        for i, m in enumerate(members):
            if isinstance(m, str) and m in name_map:
                members[i] = name_map[m]
                synced += 1
    return synced


# ============================================================================
# 2. 最后一道保险：强制唯一化
# ============================================================================
def enforce_unique_names(config, debug_names=None):
    """
    最后一道保险：不管前面发生了什么，直接操作 config['proxies']，强制唯一化。
    后缀同样用全角 ＃N，避免 rebuilder 的 #→＃ 再次冲突。
    """
    proxies = config.get("proxies")
    if not isinstance(proxies, list):
        return 0

    debug_names = set(debug_names or [])
    seen = set()
    fixed = 0

    for idx, p in enumerate(proxies):
        if not isinstance(p, dict):
            continue
        name = p.get("name")
        if not isinstance(name, str):
            name = ""
        name = name.strip()

        base = name
        n = 1
        while name in seen:
            n += 1
            name = f"{base} {UNIQUE_SUFFIX_OPEN}{n}"
        seen.add(name)

        if name != p.get("name"):
            p["name"] = name
            fixed += 1
            if debug_names and p.get("name") in debug_names:
                print(f"  🛡️ 保险 [{idx}] → {name!r}")

    return fixed


# ============================================================================
# 3. 字段修复
# ============================================================================
def fix_ws_path(proxies):
    """修复 ws-opts.path: URL 解码 / 去孤立 % / 补 / / 空值改 /"""
    if not isinstance(proxies, list):
        return 0
    fixed = 0
    for p in proxies:
        if not isinstance(p, dict):
            continue
        ws = p.get("ws-opts")
        if not isinstance(ws, dict):
            continue
        path = ws.get("path")
        if not isinstance(path, str):
            continue
        original = path

        # 多轮解码
        for _ in range(3):
            if "%" not in path:
                break
            try:
                decoded = unquote(path)
                if decoded == path:
                    break
                path = decoded
            except Exception:
                break

        # 去孤立 %（unquote 不处理的非法编码）
        if "%" in path:
            path = re.sub(r"%(?![0-9A-Fa-f]{2})", "", path)

        if not path:
            path = "/"
        elif not path.startswith("/"):
            path = "/" + path

        if path != original:
            ws["path"] = path
            fixed += 1
    return fixed


def fix_security_tls_conflict(proxies):
    """修复 'security: none' + 'tls: true' 的矛盾。"""
    if not isinstance(proxies, list):
        return 0
    fixed = 0
    for p in proxies:
        if not isinstance(p, dict):
            continue
        if p.get("tls") is not True or p.get("security") != "none":
            continue
        has_tls = bool(p.get("servername") or p.get("sni"))
        if not has_tls:
            ws = p.get("ws-opts")
            if isinstance(ws, dict):
                h = ws.get("headers")
                if isinstance(h, dict):
                    has_tls = bool(h.get("Host") or h.get("host"))
        if has_tls:
            p["security"] = "tls"
        else:
            p["tls"] = False
        fixed += 1
    return fixed


def fix_xudp_transport(proxies):
    """XUDP(Vision) 配非 TCP → 强制改为 tcp。"""
    if not isinstance(proxies, list):
        return 0
    fixed = 0
    for p in proxies:
        if not isinstance(p, dict):
            continue
        flow = str(p.get("flow") or "")
        if "xtls-rprx-vision" not in flow:
            continue
        net = str(p.get("network") or "tcp").lower()
        if net in ("tcp", "raw", ""):
            continue
        p["network"] = "tcp"
        fixed += 1
    return fixed


# ============================================================================
# 4. 质量清洗
# ============================================================================
def clean_invalid_nodes(proxies):
    """剔除 mihomo 无法使用的节点。"""
    if not isinstance(proxies, list):
        return [], 0
    cleaned, dropped = [], 0
    for p in proxies:
        if not isinstance(p, dict):
            dropped += 1
            continue
        if not all(p.get(k) for k in ("name", "type", "server", "port")):
            dropped += 1
            continue
        net = str(p.get("network") or "").lower()
        if net == "grpc":
            grpc = p.get("grpc-opts")
            if isinstance(grpc, dict) and not grpc.get("grpc-service-name"):
                dropped += 1
                continue
        uuid = p.get("uuid")
        if isinstance(uuid, str) and uuid.lower() == DEFAULT_UUID:
            dropped += 1
            continue
        cleaned.append(p)
    return cleaned, dropped


# ============================================================================
# 4.5 协议兼容性检查（--protocol-check）
#     依赖：openray.render.supported_params / Unsupported
#     设计：纯函数检查，零出站请求。
# ============================================================================
def filter_by_protocol_compatibility(proxies):
    """用 OpenRay 的 supported_params 检查协议兼容性。

    返回 (valid, removed, unconvertible):
      - valid: 通过检查 + 无法转换的节点（保留）
      - removed: [(name, reason), ...] 协议不兼容被剔除
      - unconvertible: [name, ...] 无法转换为 Proxy 的节点名（保留 + 警告）

    设计要点：
      - clash_dict_to_proxy 返回 None 时保留节点，只警告：
        "无法转成 URI" 是桥接层的覆盖缺口，不等于协议不兼容，直接删会误杀。
      - 只有 supported_params 明确抛 Unsupported 才删除。
      - 逐条记录 name + reason，可审计。
    """
    if not isinstance(proxies, list):
        return [], [], []

    try:
        from openray.render import supported_params, Unsupported
    except ImportError as e:
        print(f"❌ --protocol-check 需要 openray.render: {e}", file=sys.stderr)
        return proxies, [], []

    valid, removed, unconvertible = [], [], []
    for p in proxies:
        if not isinstance(p, dict):
            unconvertible.append("<non-dict>")
            valid.append(p)
            continue
        proxy = clash_dict_to_proxy(p)
        if proxy is None:
            # 转换失败 ≠ 协议不兼容：保留 + 警告，不误杀
            unconvertible.append(p.get("name", "<unknown>"))
            valid.append(p)
            continue
        try:
            supported_params(proxy)
            valid.append(p)
        except Unsupported as e:
            removed.append((p.get("name", "<unknown>"), str(e)))

    return valid, removed, unconvertible


# ============================================================================
# 4.6 mihomo 本地加载验证（--verify-nodes）
#     依赖：openray.validation.CoreWorker / candidate_config
#     设计：零出站请求。
#       CoreWorker._start 内部调用 candidate_config 生成最小 mihomo 配置：
#         {"port": <reserved>, "bind-address": "127.0.0.1", "allow-lan": false,
#          "authentication": ["openray:<token>"], "log-level": "silent",
#          "mode": "rule", "proxies": [outbound], "rules": ["MATCH,<name>"]}
#       无 proxy-groups、无 url-test、无 external-controller。
#       只轮询本地 127.0.0.1:<port> 是否 LISTEN。
# ============================================================================
def _verify_one(proxy_dict, mihomo_bin, timeout):
    """同步包装 CoreWorker.start，验证单个节点能否被 mihomo 加载并进入监听状态。

    返回 (ok, msg)：
      - ok=True：通过（或无法转换，保留节点）
      - ok=False：mihomo 加载失败 / 端口未就绪 / 异常
    """
    import asyncio
    import os
    import shutil
    import tempfile
    import time
    from pathlib import Path

    # 规范化 mihomo 路径：绝对路径优先，其次 PATH 查找
    if not os.path.isabs(mihomo_bin):
        abs_candidate = os.path.abspath(mihomo_bin)
        if os.path.isfile(abs_candidate):
            mihomo_bin = abs_candidate
        else:
            found = shutil.which(mihomo_bin)
            if found:
                mihomo_bin = found
            else:
                return False, f"找不到 mihomo 二进制: {mihomo_bin}"

    proxy = clash_dict_to_proxy(proxy_dict)
    if proxy is None:
        return True, "无法转换为 OpenRay Proxy，跳过验证保留节点"

    async def _run():
        with tempfile.TemporaryDirectory(prefix=VERIFY_TEMP_PREFIX) as tmp:
            root = Path(tmp)
            try:
                from openray.config import Settings
                from openray.validation import CoreWorker
            except ImportError as e:
                return False, f"缺少 openray.validation/config: {e}"

            settings = Settings(
                root=root,
                database=root / "state.sqlite3",
                sources=root / "sources.txt",
            )
            worker = CoreWorker(settings, root / "worker")
            try:
                deadline = time.monotonic() + timeout
                await worker.start(proxy, "mihomo", mihomo_bin, deadline, False)
                return True, "端口就绪"
            except TimeoutError:
                return False, f"端口未在 {timeout}s 内 LISTEN"
            except Exception as e:
                return False, f"{type(e).__name__}: {e}"
            finally:
                try:
                    await worker.stop()
                except Exception:
                    pass

    try:
        return asyncio.run(_run())
    except Exception as e:
        return False, f"验证异常: {type(e).__name__}: {e}"


def verify_and_filter_proxies(proxies, workers, budget_seconds, mihomo_bin, timeout):
    """并发验证；返回 (verified, failed)。

    failed 是 [(name, reason), ...]，逐条可审计。
    预算用尽时保留剩余节点，不阻塞后续流程。
    """
    import concurrent.futures
    import time

    if not isinstance(proxies, list) or not proxies:
        return [], []

    verified, failed = [], []
    dict_proxies = [p for p in proxies if isinstance(p, dict)]
    # 保留非 dict（正常输入不会有，但保持与 clean_invalid_nodes 一致的容错）
    verified.extend(p for p in proxies if not isinstance(p, dict))

    if not dict_proxies:
        return verified, failed

    start = time.monotonic()
    budget_exhausted = False

    pool = concurrent.futures.ThreadPoolExecutor(max_workers=workers)
    fut_map = {pool.submit(_verify_one, p, mihomo_bin, timeout): p for p in dict_proxies}
    not_done = set(fut_map.keys())

    try:
        while not_done:
            elapsed = time.monotonic() - start
            if elapsed >= budget_seconds:
                budget_exhausted = True
                break
            remaining = budget_seconds - elapsed
            done, not_done = concurrent.futures.wait(
                not_done,
                timeout=remaining,
                return_when=concurrent.futures.FIRST_COMPLETED,
            )
            for fut in done:
                p = fut_map[fut]
                try:
                    ok, msg = fut.result()
                except Exception as e:
                    ok, msg = False, f"线程异常: {type(e).__name__}: {e}"
                if ok:
                    verified.append(p)
                else:
                    failed.append((p.get("name", "<unknown>"), msg))
    finally:
        if budget_exhausted:
            # 不阻塞：取消未开始的 future；已开始的允许在进程退出时被 join
            pool.shutdown(wait=False, cancel_futures=True)
        else:
            pool.shutdown(wait=True)

    if budget_exhausted:
        # 保留未完成节点，避免预算不足导致的误删
        for fut in not_done:
            verified.append(fut_map[fut])
        print(f"⏱️ 验证预算 {budget_seconds:.0f}s 用尽："
              f"已验证 {len(fut_map) - len(not_done)}，"
              f"保留剩余 {len(not_done)} 个节点")

    return verified, failed


# ============================================================================
# 5. proxy-groups 引用清洗
# ============================================================================
def cleanup_groups(config, valid_names):
    """过滤 proxy-groups 里的无效引用；空组填 DIRECT。"""
    valid = set(valid_names)
    nested = {g.get("name") for g in config.get("proxy-groups", []) if isinstance(g, dict)}
    special = {"DIRECT", "REJECT", "PASS", "GLOBAL"}
    for group in config.get("proxy-groups", []) or []:
        if not isinstance(group, dict):
            continue
        members = group.get("proxies")
        if not isinstance(members, list):
            continue
        filtered = [
            m for m in members
            if not isinstance(m, str) or m in valid or m in nested or m in special
        ]
        group["proxies"] = filtered or ["DIRECT"]
    return config


# ============================================================================
# 6. 主流程
# ============================================================================
def main():
    parser = argparse.ArgumentParser(
        prog="dupconfig",
        description="Clash Verge YAML 节点去重清洗（桥接 OpenRay identity）",
    )
    parser.add_argument("source", type=Path, help="源 Clash Verge YAML")
    parser.add_argument("output", type=Path, help="输出去重后的 YAML")
    parser.add_argument("--keep", choices=("first", "best"), default="first",
                        help="保留策略")
    parser.add_argument("--sort", action="store_true", help="按 identity 排序")
    parser.add_argument("--dry-run", action="store_true", help="只统计不写文件")
    parser.add_argument("--no-clean-groups", dest="clean_groups", action="store_false",
                        help="不清洗 proxy-groups 引用")
    parser.add_argument("--clean", action="store_true",
                        help="剔除不可用节点（grpc 空值 / UUID 默认值 / 残缺节点）")
    # ---- 诊断参数 ----
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="打印每个被改名节点的详情")
    parser.add_argument("--debug-name", action="append", default=[],
                        help="只打印指定 name 的处理详情（可重复指定）")
    parser.add_argument("--diagnose", action="store_true",
                        help="在关键步骤打印重名统计")
    # ---- 协议检查与 mihomo 本地验证（默认值集中定义在模块头部） ----
    parser.add_argument("--protocol-check", action="store_true",
                        default=PROTOCOL_CHECK_ENABLED,
                        help="用 OpenRay supported_params 检查协议兼容性并剔除不兼容节点")
    parser.add_argument("--verify-nodes", action="store_true",
                        default=VERIFY_NODES_ENABLED,
                        help="逐个启动 mihomo 验证节点加载有效性，剔除失败节点（零出站）")
    parser.add_argument("--verify-workers", type=int, default=VERIFY_WORKERS,
                        help=f"mihomo 验证并发数（默认 {VERIFY_WORKERS}）")
    parser.add_argument("--verify-budget", type=float, default=VERIFY_BUDGET_SECONDS,
                        help=f"mihomo 验证总预算秒数（默认 {VERIFY_BUDGET_SECONDS}）")
    parser.add_argument("--mihomo-bin", default=VERIFY_MIHOMO_BIN,
                        help=f"mihomo 二进制路径（默认 {VERIFY_MIHOMO_BIN}）")
    parser.add_argument("--strict-verify", action="store_true",
                        default=VERIFY_STRICT,
                        help="有节点被 --verify-nodes 剔除时返回非零码")
    args = parser.parse_args()

    # ---- 参数校验 ----
    if args.verify_workers < 1 or args.verify_workers > 64:
        print("❌ --verify-workers 必须在 1..64", file=sys.stderr)
        return 1
    if args.verify_budget <= 0:
        print("❌ --verify-budget 必须 > 0", file=sys.stderr)
        return 1

    debug_names = set(args.debug_name)
    strict_verify_triggered = False

    # ---------- 读文件 ----------
    if not args.source.is_file():
        print(f"❌ 源文件不存在: {args.source}", file=sys.stderr)
        return 1

    try:
        with args.source.open("r", encoding="utf-8") as f:
            config = yaml.safe_load(f)
    except yaml.YAMLError as e:
        print(f"❌ YAML 解析失败: {e}", file=sys.stderr)
        return 1

    if not isinstance(config, dict):
        print("❌ 顶层不是 YAML 映射", file=sys.stderr)
        return 1

    proxies = config.get("proxies") or []
    if not isinstance(proxies, list):
        print("❌ proxies 字段不是列表", file=sys.stderr)
        return 1

    if not proxies:
        print("⚠️  无节点，直接复制", file=sys.stderr)
        if not args.dry_run:
            with args.output.open("w", encoding="utf-8") as f:
                yaml.dump(config, f, allow_unicode=True, sort_keys=False)
        return 0

    total_in = len(proxies)
    print(f"📖 读取: {args.source} ({total_in} 个节点)")

    # ---------- 0. 初始诊断 ----------
    if args.diagnose:
        diagnose_duplicates(proxies, "初始输入", debug_names)

    # ---------- 1. identity 去重 ----------
    deduped, stats = dedup_by_identity(proxies, keep=args.keep)
    print(f"📊 去重: {total_in} → {stats['unique']} "
          f"(重复 {stats['duplicates']}, 无效 {stats['invalid']})")

    if args.diagnose:
        diagnose_duplicates(deduped, "identity 去重后", debug_names)

    # ---------- 1.5 协议兼容性检查（可选，零出站） ----------
    if args.protocol_check:
        before = len(deduped)
        deduped, proto_removed, unconvertible = filter_by_protocol_compatibility(deduped)
        if proto_removed:
            print(f"🔬 协议检查: 剔除 {len(proto_removed)} 个协议不兼容节点")
            for name, reason in proto_removed[:20]:
                print(f"    ❌ {name}: {reason}")
            if len(proto_removed) > 20:
                print(f"    ... 还有 {len(proto_removed) - 20} 个")
        if unconvertible:
            print(f"⚠️  协议检查: {len(unconvertible)} 个节点无法转换为 Proxy，保留（仅警告）")
        print(f"📊 协议检查: {before} → {len(deduped)}")

    # ---------- 2. 名称归一化 + 唯一化 ----------
    renamed, name_map = normalize_names(
        deduped,
        verbose=args.verbose,
        debug_names=debug_names,
    )
    if renamed:
        print(f"🔤 改名: {renamed} 个节点")

    # ---------- 3. 同步引用 ----------
    synced = sync_group_references(config, name_map)
    if synced:
        print(f"🔗 同步引用: {synced} 处")

    # ---------- 4. 字段修复 ----------
    ws_fixed = fix_ws_path(deduped)
    if ws_fixed:
        print(f"🔧 修复: {ws_fixed} 个 ws-opts.path")

    sec_fixed = fix_security_tls_conflict(deduped)
    if sec_fixed:
        print(f"🔧 修复: {sec_fixed} 个 security/tls 矛盾")

    xudp_fixed = fix_xudp_transport(deduped)
    if xudp_fixed:
        print(f"🔧 修复: {xudp_fixed} 个 XUDP(Vision) 传输层")

    # ---------- 5. 质量清洗 ----------
    if args.clean:
        deduped, dropped = clean_invalid_nodes(deduped)
        if dropped:
            print(f"🧹 清洗: 剔除 {dropped} 个不可用节点")

    # ---------- 5.5 mihomo 本地加载验证（可选，零出站） ----------
    if args.verify_nodes:
        before = len(deduped)
        deduped, verify_failed = verify_and_filter_proxies(
            deduped,
            workers=args.verify_workers,
            budget_seconds=args.verify_budget,
            mihomo_bin=args.mihomo_bin,
            timeout=VERIFY_TIMEOUT,
        )
        if verify_failed:
            print(f"🧪 mihomo 验证: 剔除 {len(verify_failed)} 个加载失败节点")
            for name, reason in verify_failed[:20]:
                print(f"    ❌ {name}: {reason}")
            if len(verify_failed) > 20:
                print(f"    ... 还有 {len(verify_failed) - 20} 个")
            if args.strict_verify:
                strict_verify_triggered = True
        print(f"📊 mihomo 验证: {before} → {len(deduped)}")

    # ---------- 6. 排序 ----------
    if args.sort:
        deduped.sort(key=lambda p: identity_for_clash_proxy(p) or "")

    # ---------- 7. 更新 config ----------
    config["proxies"] = deduped

    # ---------- 7.5 最后一道保险：强制唯一化 ----------
    final_fixed = enforce_unique_names(config, debug_names)
    if final_fixed:
        print(f"🛡️ 最后保险: 强制唯一化 {final_fixed} 个节点")

    # ---------- 7.6 输出前诊断 ----------
    if args.diagnose:
        diagnose_duplicates(config["proxies"], "最终输出前", debug_names)

    if args.clean_groups:
        config = cleanup_groups(
            config,
            [p.get("name") for p in config["proxies"] if isinstance(p, dict)],
        )

    # ---------- 8. 输出 ----------
    final_count = len(config["proxies"])
    print(f"📊 最终: {total_in} → {final_count} "
          f"({final_count / total_in * 100:.1f}%)")

    if args.dry_run:
        print("🔍 dry-run：不写文件")
        if strict_verify_triggered:
            return 3
        return 0

    with args.output.open("w", encoding="utf-8") as f:
        yaml.dump(
            config, f,
            allow_unicode=True,
            sort_keys=False,
            default_flow_style=False,
            width=4096,
        )
    print(f"✅ 输出: {args.output}")

    # ---------- 9. 输出文件硬性检查 ----------
    names = [p.get("name") for p in config["proxies"] if isinstance(p, dict)]
    dup = {n: c for n, c in Counter(names).items() if c > 1}
    if dup:
        print(f"\n❌ 输出文件里仍有 {len(dup)} 个重名（mihomo 会拒载）:", file=sys.stderr)
        for name, count in list(dup.items())[:10]:
            print(f"    {name!r} × {count}", file=sys.stderr)
        return 2

    # ---------- 10. --strict-verify 触发非零码 ----------
    if strict_verify_triggered:
        print("\n❌ --strict-verify: 有节点在 mihomo 验证中被剔除", file=sys.stderr)
        return 3

    return 0


if __name__ == "__main__":
    sys.exit(main())

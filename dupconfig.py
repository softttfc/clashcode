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

处理流水线:
    1. 按 identity 去重（桥接 OpenRay）
    2. 名称归一化 + 唯一化（'...' 替换 / NFC / 全角→半角 / strip / 同名加 ＃N）
    3. 同步 proxy-groups 引用（字符清洗导致的原名消失）
    4. 字段修复（ws path / security-tls 矛盾 / XUDP 传输层）
    5. 质量清洗（--clean 开启，会删节点）
    6. 最后一道保险：强制唯一化
    7. 清洗 proxy-groups 引用
    8. 输出 YAML（有重名则 exit 2）
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
    from openray_bridge import dedup_by_identity, identity_for_clash_proxy
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
    args = parser.parse_args()

    debug_names = set(args.debug_name)

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

    return 0


if __name__ == "__main__":
    sys.exit(main())

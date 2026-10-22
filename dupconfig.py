#!/usr/bin/env python3
"""dupconfig.py — Clash Verge YAML 节点去重清洗（桥接 OpenRay identity）

用法:
    python dupconfig.py 源.yaml 输出.yaml
    python dupconfig.py 源.yaml 输出.yaml --keep best
    python dupconfig.py 源.yaml 输出.yaml --clean
    python dupconfig.py 源.yaml 输出.yaml --dry-run

处理流水线:
    1. 按 identity 去重（桥接 OpenRay）
    2. 名称唯一化 + 危险字符清洗（'...' 替换 / 去不可见字符 / 同名加 #N）
    3. 同步 proxy-groups 引用（字符清洗导致的原名消失）
    4. 字段修复（默认开启，不删节点）:
       - ws-opts.path: URL 解码 / 补 '/' / 空值改 '/'
       - security/tls 矛盾: 根据是否有 TLS 证据修复
       - XUDP(Vision) 配非 TCP: 强制改 tcp
    5. 质量清洗（--clean 开启，会删节点）:
       - grpc service-name 空
       - UUID 默认值 8888...
       - 残缺节点（缺 name/type/server/port）
    6. 清洗 proxy-groups 引用
    7. 输出 YAML
"""

import argparse
import sys
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


# ============================================================================
# 1. 名称唯一化 + 危险字符清洗
# ============================================================================
def normalize_names(proxies):
    """
    清洗节点名中的 YAML 危险字符，并保证每个 name 唯一。

    处理规则:
      1. '...' 是 YAML 文档结束符 → 替换为 '…'
      2. 去不可见控制字符（保留空格）
      3. 空名字 → '未命名'
      4. 同名节点 → 追加 ' #2'、' #3' 后缀（保留第一个的原名）

    返回:
        renamed_count: 实际改名的节点数
        name_map: {旧名: 新名}，仅记录"字符清洗"导致的改名。
                  用于同步 proxy-groups 引用。
                  '#N' 后缀的唯一化改名不进 name_map，
                  因为原名仍指向第一个副本。
    """
    if not isinstance(proxies, list):
        return 0, {}

    seen = set()
    renamed_count = 0
    name_map = {}

    for p in proxies:
        if not isinstance(p, dict):
            continue
        name = p.get("name")
        if not isinstance(name, str):
            name = ""
        original = name

        # ---- 字符清洗 ----
        if "..." in name:
            name = name.replace("...", "…")
        name = "".join(c for c in name if c.isprintable() or c == " ")
        if not name.strip():
            name = "未命名"

        # ---- 记录字符清洗映射（首次出现才记） ----
        if name != original and original and original not in name_map:
            name_map[original] = name

        # ---- 唯一化 ----
        base = name
        n = 1
        while name in seen:
            n += 1
            name = f"{base} #{n}"
        seen.add(name)

        if name != original:
            p["name"] = name
            renamed_count += 1

    return renamed_count, name_map


def sync_group_references(config, name_map):
    """
    把 name_map 应用到 proxy-groups 的引用。
    仅在"字符清洗导致原名消失"时才会触发。
    '#N' 后缀的唯一化不需要同步（原名仍指向第一个副本）。
    """
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
# 2. 字段修复（默认开启，不删节点）
# ============================================================================
def fix_ws_path(proxies):
    """
    修复 ws-opts.path：
      - 含 '%' → URL 解码（mihomo 不自动解码，握手必失败）
      - 空字符串 → 改成 '/'
      - 不以 '/' 开头 → 补 '/'

    幂等：已解码的 path 不会被二次修改。
    """
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
        if "%" in path:
            try:
                path = unquote(path)
            except Exception:
                pass
        if not path:
            path = "/"
        elif not path.startswith("/"):
            path = "/" + path

        if path != original:
            ws["path"] = path
            fixed += 1
    return fixed


def fix_security_tls_conflict(proxies):
    """
    修复 'security: none' 与 'tls: true' 的矛盾。

    背景:
      mihomo 中 security 优先于 tls。'security: none' + 'tls: true'
      会让 mihomo 按"无 TLS"处理，导致 WS 明文握手失败。

    判断用户本意:
      - 有 servername / sni → 本意是 TLS → 改成 'security: tls'
      - 有 ws-opts.headers.Host → 本意是 TLS → 改成 'security: tls'
      - 都没有 → 本意是明文 → 改成 'tls: false'
    """
    if not isinstance(proxies, list):
        return 0
    fixed = 0
    for p in proxies:
        if not isinstance(p, dict):
            continue
        if p.get("tls") is not True or p.get("security") != "none":
            continue

        has_tls_evidence = bool(p.get("servername") or p.get("sni"))
        if not has_tls_evidence:
            ws = p.get("ws-opts")
            if isinstance(ws, dict):
                headers = ws.get("headers")
                if isinstance(headers, dict):
                    has_tls_evidence = bool(
                        headers.get("Host") or headers.get("host")
                    )

        if has_tls_evidence:
            p["security"] = "tls"
        else:
            p["tls"] = False
        fixed += 1
    return fixed


def fix_xudp_transport(proxies):
    """
    XUDP(Vision) 配非 TCP → 强制改为 tcp。

    背景:
      VLESS 的 xtls-rprx-vision flow 只在 tcp/raw 上支持。
      配 ws / grpc / httpupgrade 时 mihomo 直接握手失败。
    """
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
# 3. 质量清洗（--clean 开启，会删节点）
# ============================================================================
def clean_invalid_nodes(proxies):
    """
    剔除 mihomo 无法使用的节点:
      - 不是 dict（残缺）
      - 缺 name / type / server / port
      - grpc service-name 为空（mihomo 无法握手）
      - UUID 是默认值 8888...（认证必然失败）

    返回 (cleaned_proxies, dropped_count)
    """
    if not isinstance(proxies, list):
        return [], 0

    cleaned = []
    dropped = 0

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
# 4. proxy-groups 引用清洗
# ============================================================================
def cleanup_groups(config, valid_names):
    """过滤 proxy-groups 里的无效引用（已被删除或清洗的节点名）；空组填 DIRECT。"""
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
# 5. 主流程
# ============================================================================
def main():
    parser = argparse.ArgumentParser(
        prog="dupconfig",
        description="Clash Verge YAML 节点去重清洗（桥接 OpenRay identity）",
    )
    parser.add_argument("source", type=Path, help="源 Clash Verge YAML")
    parser.add_argument("output", type=Path, help="输出去重后的 YAML")
    parser.add_argument("--keep", choices=("first", "best"), default="first",
                        help="保留策略：first=第一条（默认）/ best=最佳名称")
    parser.add_argument("--sort", action="store_true", help="按 identity 排序")
    parser.add_argument("--dry-run", action="store_true", help="只统计不写文件")
    parser.add_argument("--no-clean-groups", dest="clean_groups", action="store_false",
                        help="不清洗 proxy-groups 引用")
    parser.add_argument("--clean", action="store_true",
                        help="额外剔除不可用节点（grpc 空值 / UUID 默认值 / 残缺节点）")
    args = parser.parse_args()

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

    # ---------- 1. 按 identity 去重 ----------
    deduped, stats = dedup_by_identity(proxies, keep=args.keep)
    print(f"📊 去重: {total_in} → {stats['unique']} "
          f"(重复 {stats['duplicates']}, 无效 {stats['invalid']})")

    # ---------- 2. 名称唯一化 + 危险字符清洗 ----------
    renamed, name_map = normalize_names(deduped)
    if renamed:
        print(f"🔤 改名: {renamed} 个节点"
              f"（同名加 #N / '...' 替换 / 去不可见字符）")

    # ---------- 3. 同步 proxy-groups 引用（字符清洗导致原名消失） ----------
    synced = sync_group_references(config, name_map)
    if synced:
        print(f"🔗 同步引用: {synced} 处")

    # ---------- 4. 字段修复（默认开启，不删节点） ----------
    ws_fixed = fix_ws_path(deduped)
    if ws_fixed:
        print(f"🔧 修复: {ws_fixed} 个 ws-opts.path（URL 解码 / 补 /）")

    sec_fixed = fix_security_tls_conflict(deduped)
    if sec_fixed:
        print(f"🔧 修复: {sec_fixed} 个 security/tls 矛盾")

    xudp_fixed = fix_xudp_transport(deduped)
    if xudp_fixed:
        print(f"🔧 修复: {xudp_fixed} 个 XUDP(Vision) 传输层（强制 tcp）")

    # ---------- 5. 质量清洗（--clean 开启，会删节点） ----------
    if args.clean:
        deduped, dropped = clean_invalid_nodes(deduped)
        if dropped:
            print(f"🧹 清洗: 剔除 {dropped} 个不可用节点"
                  f"（grpc 空值 / UUID 默认值 / 残缺节点）")

    # ---------- 6. 排序 ----------
    if args.sort:
        deduped.sort(key=lambda p: identity_for_clash_proxy(p) or "")

    # ---------- 7. 更新 config ----------
    config["proxies"] = deduped
    if args.clean_groups:
        config = cleanup_groups(
            config,
            [p.get("name") for p in deduped if isinstance(p, dict)],
        )

    # ---------- 8. 输出 ----------
    final_count = len(deduped)
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
    return 0


if __name__ == "__main__":
    sys.exit(main())

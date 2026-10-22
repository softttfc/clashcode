#!/usr/bin/env python3
"""dupconfig.py — Clash Verge YAML 节点去重清洗（桥接 OpenRay identity）"""

import argparse
import sys
from pathlib import Path

import yaml

try:
    from openray_bridge import dedup_by_identity
except ImportError:
    print("❌ 需要 openray_bridge.py + OpenRay 包（domain.py + render.py）", file=sys.stderr)
    sys.exit(1)


def cleanup_groups(config, valid_names):
    valid = set(valid_names)
    nested = {g.get("name") for g in config.get("proxy-groups", []) if isinstance(g, dict)}
    special = {"DIRECT", "REJECT", "PASS", "GLOBAL"}
    for group in config.get("proxy-groups", []) or []:
        if not isinstance(group, dict):
            continue
        members = group.get("proxies")
        if not isinstance(members, list):
            continue
        filtered = [m for m in members if not isinstance(m, str) or m in valid or m in nested or m in special]
        group["proxies"] = filtered or ["DIRECT"]
    return config


def main():
    parser = argparse.ArgumentParser(prog="dupconfig", description="Clash Verge YAML 节点去重")
    parser.add_argument("source", type=Path, help="源 Clash Verge YAML")
    parser.add_argument("output", type=Path, help="输出去重后的 YAML")
    parser.add_argument("--keep", choices=("first", "best"), default="first", help="保留策略")
    parser.add_argument("--sort", action="store_true", help="按 identity 排序")
    parser.add_argument("--dry-run", action="store_true", help="只统计不写文件")
    parser.add_argument("--no-clean-groups", dest="clean_groups", action="store_false")
    args = parser.parse_args()

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

    print(f"📖 读取: {args.source} ({len(proxies)} 个节点)")

    deduped, stats = dedup_by_identity(proxies, keep=args.keep)

    if args.sort:
        from openray_bridge import identity_for_clash_proxy
        deduped.sort(key=lambda p: identity_for_clash_proxy(p) or "")

    config["proxies"] = deduped
    if args.clean_groups:
        config = cleanup_groups(config, [p.get("name") for p in deduped if isinstance(p, dict)])

    print(f"📊 总计: {stats['total']}  →  唯一: {stats['unique']}  重复: {stats['duplicates']}  无效: {stats['invalid']}")
    if stats["total"] > 0:
        print(f"   保留率: {stats['unique'] / stats['total'] * 100:.1f}%")

    if args.dry_run:
        print("🔍 dry-run：不写文件")
        return 0

    with args.output.open("w", encoding="utf-8") as f:
        yaml.dump(config, f, allow_unicode=True, sort_keys=False, default_flow_style=False, width=4096)
    print(f"✅ 输出: {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

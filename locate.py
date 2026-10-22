#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
locate_errors.py — 精确定位 check.py 报出的错误在 YAML 里的行号

用法:
    python locate_errors.py <节点文件.yml>

输出:
    每个问题都带：
    - proxies 索引
    - YAML 行号（可直接跳到编辑器）
    - 节点关键字段（server/port/type/uuid）
    - YAML 片段（定位 + 上下文）
    - 可直接复制粘贴的修复命令

覆盖:
    1. duplicate name（mihomo 立即拒载）
    2. 残缺节点（缺 name/type/server/port）
    3. ws-opts.path 含 # 或 ?（URL 语义冲突）
    4. ws-opts.path 含 URL 编码
    5. ws-opts.path 为空
    6. grpc-opts.grpc-service-name 为空
    7. UUID 是默认值 8888...
    8. XUDP(Vision) 配非 TCP
    9. security/tls 字段矛盾
"""
import sys
import re
import yaml


# ============================================================================
# 用 yaml.compose 拿到每个 proxy 的 name 字段行号（1-based）
# ============================================================================
def get_proxy_line_numbers(path):
    """
    返回列表，第 i 项是 proxies[i] 的 name 字段所在行号（1-based）。
    找不到 name 字段时，退化为该 proxy 的起始行号。
    无法解析时返回 []。
    """
    with open(path, encoding='utf-8') as f:
        node = yaml.compose(f)

    if not isinstance(node, yaml.MappingNode):
        return []

    result = []
    for key, value in node.value:
        if key.value != 'proxies':
            continue
        if not isinstance(value, yaml.SequenceNode):
            return []
        for item in value.value:
            if not isinstance(item, yaml.MappingNode):
                result.append(None)
                continue
            # 默认：节点起始行
            line = item.start_mark.line + 1
            # 优先：name 字段所在行（更精确）
            for k, v in item.value:
                if k.value == 'name':
                    line = k.start_mark.line + 1
                    break
            result.append(line)
    return result


# ============================================================================
# 工具
# ============================================================================
def snippet(lines, line, context=3):
    """返回 YAML 片段（带行号，目标行用 >>> 标记）"""
    if not line:
        return []
    start = max(0, line - 1 - context)
    end = min(len(lines), line + context + 1)
    out = []
    for j in range(start, end):
        marker = '>>>' if j + 1 == line else '   '
        out.append(f"      {marker} {j+1:6d}: {lines[j]}")
    return out


def desc(proxy):
    """节点的简短描述"""
    if not isinstance(proxy, dict):
        return repr(proxy)[:80]
    return (f"type={proxy.get('type')} "
            f"server={proxy.get('server')}:{proxy.get('port')} "
            f"uuid={str(proxy.get('uuid', ''))[:16]}...")


def print_header(title):
    print()
    print('=' * 70)
    print(title)
    print('=' * 70)


def print_fix_sed(path, line, old, new):
    """打印可直接复制的 sed 命令"""
    # 转义 sed 特殊字符
    old_esc = old.replace('/', r'\/').replace('&', r'\&')
    new_esc = new.replace('/', r'\/').replace('&', r'\&')
    print(f"      sed -i '{line}s/{old_esc}/{new_esc}/' {path}")


# ============================================================================
# 各类问题检测
# ============================================================================

def find_duplicate_names(proxies, lines, path):
    """1. 重复节点名"""
    print_header("1. Duplicate name（mihomo 立即拒载 —— 最高优先级）")

    groups = {}
    for i, p in enumerate(proxies):
        if isinstance(p, dict):
            n = p.get('name')
            if isinstance(n, str) and n:
                groups.setdefault(n, []).append(i)

    found = False
    for name, idxs in groups.items():
        if len(idxs) <= 1:
            continue
        found = True
        print(f"\n  节点名: {name!r}")
        print(f"  出现 {len(idxs)} 次:")

        for k, i in enumerate(idxs):
            line = LINE_NUMBERS[i] if i < len(LINE_NUMBERS) else None
            p = proxies[i]
            print(f"\n  [{k+1}] proxies[{i}] @ 第 {line} 行")
            print(f"      {desc(p)}")
            for s in snippet(lines, line):
                print(s)

        # 修复建议
        if len(idxs) > 1:
            print(f"\n  修复建议（保留第一个，后续加 #N）:")
            first = idxs[0]
            print(f"    保留: proxies[{first}]（第 {LINE_NUMBERS[first]} 行）不改")
            for k, i in enumerate(idxs[1:], start=2):
                line = LINE_NUMBERS[i] if i < len(LINE_NUMBERS) else None
                if not line:
                    continue
                new_name = f"{name} #{k}"
                print(f"\n    修改: proxies[{i}]（第 {line} 行）")
                print(f"      旧 name: {name!r}")
                print(f"      新 name: {new_name!r}")
                print(f"      执行:")
                # 用 sed 替换该行的 name 值
                # 注意：name 可能是单引号、双引号或裸写
                print_fix_sed(path, line, name, new_name)

    if not found:
        print("  ✅ 没有重复的节点名")


def find_incomplete_nodes(proxies, lines, path):
    """2. 残缺节点"""
    print_header("2. 残缺节点（缺 name/type/server/port）")

    found = False
    for i, p in enumerate(proxies):
        if not isinstance(p, dict):
            found = True
            line = LINE_NUMBERS[i] if i < len(LINE_NUMBERS) else None
            print(f"\n  proxies[{i}] @ 第 {line} 行")
            print(f"      不是字典: {type(p).__name__}")
            for s in snippet(lines, line):
                print(s)
            continue

        missing = [k for k in ('name', 'type', 'server', 'port') if not p.get(k)]
        if missing:
            found = True
            line = LINE_NUMBERS[i] if i < len(LINE_NUMBERS) else None
            print(f"\n  proxies[{i}] @ 第 {line} 行 —— 缺字段: {missing}")
            print(f"      节点内容: {dict(p)}")
            for s in snippet(lines, line):
                print(s)

    if not found:
        print("  ✅ 没有残缺节点")


def find_ws_path_issues(proxies, lines, path):
    """3~5. ws-opts.path 问题"""
    print_header("3. ws-opts.path 问题（mihomo 会握手失败或拒连）")

    found = False
    for i, p in enumerate(proxies):
        if not isinstance(p, dict):
            continue
        ws = p.get('ws-opts')
        if not isinstance(ws, dict):
            continue
        pth = ws.get('path')
        if not isinstance(pth, str):
            continue

        issues = []
        if pth == '':
            issues.append('空字符串（mihomo 要求至少 "/"）')
        elif '%' in pth:
            issues.append(f'含 URL 编码 ({pth!r})')
        elif not pth.startswith('/'):
            issues.append(f'不以 / 开头 ({pth!r})')
        elif '#' in pth or '?' in pth:
            # 注意：# 和 ? 在 path 里是合法的 URL 字符，
            # 但 mihomo 会把整个 path 写进请求行，可能导致服务器拒绝
            issues.append(f'含 # 或 ? (语义可能冲突，建议确认)')

        if not issues:
            continue

        found = True
        line = LINE_NUMBERS[i] if i < len(LINE_NUMBERS) else None
        print(f"\n  proxies[{i}] @ 第 {line} 行")
        print(f"      name: {p.get('name')!r}")
        print(f"      path: {pth!r}")
        for issue in issues:
            print(f"      问题: {issue}")

        # 给出修复值
        if pth == '':
            new_path = '/'
        elif '%' in pth:
            import urllib.parse
            new_path = urllib.parse.unquote(pth)
            print(f"      解码后: {new_path!r}")
        elif not pth.startswith('/'):
            new_path = '/' + pth
        else:
            new_path = pth  # #/? 的情况无法自动修

        if new_path != pth:
            print(f"      修复命令:")
            print_fix_sed(path, line, f'path: "{pth}"', f'path: "{new_path}"')
            print(f"      或改成:")
            print_fix_sed(path, line, f'path: {pth!r}', f'path: {new_path!r}')

    if not found:
        print("  ✅ 没有 ws-opts.path 问题")


def find_grpc_empty(proxies, lines, path):
    """6. grpc service-name 为空"""
    print_header("6. grpc-opts.grpc-service-name 为空（mihomo 无法握手）")

    found = False
    for i, p in enumerate(proxies):
        if not isinstance(p, dict):
            continue
        grpc = p.get('grpc-opts')
        if not isinstance(grpc, dict):
            continue
        svc = grpc.get('grpc-service-name')
        if not svc:
            found = True
            line = LINE_NUMBERS[i] if i < len(LINE_NUMBERS) else None
            print(f"\n  proxies[{i}] @ 第 {line} 行")
            print(f"      name: {p.get('name')!r}")
            print(f"      service-name: {svc!r}")

    if not found:
        print("  ✅ 没有空的 grpc-service-name")


def find_default_uuid(proxies, lines, path):
    """7. UUID 是默认值 8888..."""
    print_header("7. UUID 是默认值 88888888-...（认证必然失败）")

    DEFAULT_UUID = '88888888-8888-8888-8888-888888888888'
    found = False
    for i, p in enumerate(proxies):
        if not isinstance(p, dict):
            continue
        if p.get('uuid') == DEFAULT_UUID:
            found = True
            line = LINE_NUMBERS[i] if i < len(LINE_NUMBERS) else None
            print(f"  proxies[{i}] @ 第 {line} 行  name={p.get('name')!r}")

    if not found:
        print("  ✅ 没有默认 UUID 节点")


def find_xudp_conflict(proxies, lines, path):
    """8. XUDP 配非 TCP"""
    print_header("8. XUDP(Vision) 配非 TCP（mihomo 握手失败）")

    found = False
    for i, p in enumerate(proxies):
        if not isinstance(p, dict):
            continue
        flow = p.get('flow') or ''
        if 'xtls-rprx-vision' not in str(flow):
            continue
        net = str(p.get('network') or 'tcp').lower()
        if net in ('tcp', 'raw', ''):
            continue
        found = True
        line = LINE_NUMBERS[i] if i < len(LINE_NUMBERS) else None
        print(f"  proxies[{i}] @ 第 {line} 行  "
              f"name={p.get('name')!r} flow={flow!r} network={net!r}")

    if not found:
        print("  ✅ 没有 XUDP 冲突")


def find_security_tls_conflict(proxies, lines, path):
    """9. security/tls 字段矛盾"""
    print_header("9. security/tls 字段矛盾（mihomo 可能按 security 优先，导致握手失败）")

    found = False
    for i, p in enumerate(proxies):
        if not isinstance(p, dict):
            continue
        tls = p.get('tls')
        sec = p.get('security')
        if tls is True and sec == 'none':
            found = True
            line = LINE_NUMBERS[i] if i < len(LINE_NUMBERS) else None
            print(f"\n  proxies[{i}] @ 第 {line} 行")
            print(f"      name={p.get('name')!r}")
            print(f"      tls=true 但 security=none —— 矛盾")
            print(f"      修复建议：")
            print(f"        若要 TLS:   security: tls")
            print_fix_sed(path, line, 'security: none', 'security: tls')
            print(f"        若不要 TLS: tls: false")
            print_fix_sed(path, line, 'tls: true', 'tls: false')

    if not found:
        print("  ✅ 没有 security/tls 矛盾")


# ============================================================================
# 主流程
# ============================================================================
LINE_NUMBERS = []  # 全局：每个 proxy 的 name 字段行号


def main():
    global LINE_NUMBERS

    if len(sys.argv) != 2:
        print('用法: python locate_errors.py <节点文件.yml>')
        sys.exit(1)

    path = sys.argv[1]

    # 读原文
    with open(path, encoding='utf-8') as f:
        text = f.read()
    lines = text.splitlines()

    # 解析
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as e:
        print(f'❌ YAML 解析失败: {e}')
        sys.exit(2)

    proxies = data.get('proxies') or []
    print(f'文件: {path}')
    print(f'总行数: {len(lines)}')
    print(f'节点数: {len(proxies)}')

    # 行号
    LINE_NUMBERS = get_proxy_line_numbers(path)
    if len(LINE_NUMBERS) != len(proxies):
        print(f'⚠️ 行号数量 ({len(LINE_NUMBERS)}) 和节点数 ({len(proxies)}) 不一致')
        print(f'   行号可能不准，请人工核对')

    # 逐项定位
    find_duplicate_names(proxies, lines, path)
    find_incomplete_nodes(proxies, lines, path)
    find_ws_path_issues(proxies, lines, path)
    find_grpc_empty(proxies, lines, path)
    find_default_uuid(proxies, lines, path)
    find_xudp_conflict(proxies, lines, path)
    find_security_tls_conflict(proxies, lines, path)

    # 汇总
    print()
    print('=' * 70)
    print('完成。按上面的"修复建议"逐项处理，然后:')
    print(f'  python check.py {path} check-report2.txt')
    print(f'  mihomo -t -d . -f {path}')
    print('=' * 70)


if __name__ == '__main__':
    main()

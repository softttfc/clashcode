import yaml

yaml_file = 'crawclash.metarbd.yaml'
with open(yaml_file, encoding='utf-8') as f:
    cfg = yaml.safe_load(f)
proxies = cfg.get('proxies', [])
print(f'proxies 总数: {len(proxies)}\n')

# 同时打印 3203–3207，覆盖 mihomo 0-based 和 1-based 两种索引可能
for idx in range(3203, 3208):
    if idx >= len(proxies):
        print(f'=== proxies[{idx}] 越界 ===')
        continue
    p = proxies[idx]
    print(f'=== proxies[{idx}] ===')
    print(f'  name:   {p.get("name", "?")!r}')
    print(f'  type:   {p.get("type", "?")}')
    print(f'  server: {p.get("server", "?")}:{p.get("port", "?")}')
    ro = p.get('reality-opts')
    if ro:
        sid = ro.get('short-id')
        print(f'  short-id 原始值: {sid!r}')
        print(f'  short-id 类型:   {type(sid).__name__}')
        if isinstance(sid, str):
            print(f'  short-id 长度:   {len(sid)}')
            print(f'  偶数长度:       {len(sid) % 2 == 0}')
            print(f'  全 hex:         {all(c in "0123456789abcdefABCDEF" for c in sid)}')
            print(f'  逐字符 ord:     {[ord(c) for c in sid]}')
        else:
            print(f'  ⚠️ short-id 不是字符串，YAML 解析类型异常')
    else:
        print(f'  (无 reality-opts)')
    print()

#!/usr/bin/env python3
# =============================================================================
# fetch_pro3.py 说明
# =============================================================================
#
# 一、功能
# -----------------------------------------------------------------------------
# 本脚本用于从多个来源抓取、解析、去重、合并代理节点，并生成多种订阅文件：
#   - V2Ray 明文订阅：list_raw.txt
#   - V2Ray Base64 订阅：list.txt
#   - Clash 配置：list.yml
#   - Clash Meta 配置：list.meta.yml
#   - 按地区分类的节点片段：snippets/nodes_*.yml
#   - 规则片段：snippets/rules_*.yml
#   - 统计信息：list_result.csv
# 
# 支持的节点协议包括：
#   vmess、ss、ssr、trojan、vless、hysteria2、tuic、http、https、socks5 等。
#
# 主要数据来源：
#   - sources.list 中列出的订阅链接
#   - dynamic.py 中定义的动态链接生成函数
#   - 机场列表（以 * 开头）
#   - 本地代理配置 local_proxy.conf（可选）
#
# 二、整体流程
# -----------------------------------------------------------------------------
# 1. 读取 sources.list，处理动态链接、机场列表、本地模式等。
# 2. 多线程抓取各订阅源，自动识别 YAML / Base64 / 明文链接。
# 3. 解析节点为 Node 对象，按协议解析为统一数据结构。
# 4. 使用 Node.__hash__ 去重，合并到 merged 字典；解析失败的放入 unknown 集合。
# 5. 写出 V2Ray 订阅（list_raw.txt、list.txt）。
# 6. 读取 config.yml，合并 Adblock 规则，按地区分类节点。
# 7. 生成 Clash / Meta 配置、节点片段、规则片段。
# 8. 写出统计信息 list_result.csv。
#
# 三、本次修改内容（方案 A）
# -----------------------------------------------------------------------------
# 问题：
#   在写出 V2Ray 订阅时，txt 中可能含有来自 unknown 集合的孤立代理项字符
#   （U+D800 ~ U+DFFF），导致：
#       UnicodeEncodeError: 'utf-8' codec can't encode characters ...
#       surrogates not allowed
#   该错误会中断 list_raw.txt 和 list.txt 的写出，进而导致后续所有文件无法生成。
#
# 修改：
#   在写出 V2Ray 订阅之前，对 txt 执行一次 UTF-8 编码清洗：
#       txt = txt.encode('utf-8', 'replace').decode('utf-8')
#   该操作会：
#       - 移除 / 替换所有孤立代理项字符（替换为 U+FFFD，即 �）
#       - 保证后续 f.write(txt) 和 b64encodes(txt) 不再抛出 UnicodeEncodeError
#       - 对正常节点无任何副作用（合法 Unicode 字符编码后解码不变）
#
# 影响范围：
#   - 仅影响 list_raw.txt 和 list.txt 的写出。
#   - 对 Clash / Meta 配置、分类片段、规则片段、统计 CSV 无影响。
#   - 无法解析的节点仍会被写入 V2Ray 订阅，只是其中的非法字符被替换。
#
# 四、快速排错
# -----------------------------------------------------------------------------
# - 若再次出现 UnicodeEncodeError，检查 txt 清洗是否被误删。
# - 若节点数为 0，检查 sources.list、网络、local_proxy.conf。
# - 若分类节点为空，检查 config.yml 中 NoMoreWalls.categories 关键词。
# - 若代理组冲突，查看 [DEBUG] 输出的冲突组名。
# - 下载相关超时由三个旋钮控制，语义见"五"末尾的调参说明。
#
# 五、本次修改内容（方案 B：下载超时 / 读速修复）
# -----------------------------------------------------------------------------
# 问题现象：
#   日志出现  抓取 'https://gh-proxy.com/raw.githubusercontent.com/...'... 5s
#             抓取 '...'... 10s
#             超时！
#   即使把 FETCH_TIMEOUT 里的读取等待从 10 秒改为 100 秒，部分节点文件
#   仍然超时；且只有"一部分"源会超时，小文件正常、大文件必挂。
#
# 根因（三条，按影响从大到小）：
#   1) FETCH_TIMEOUT 从未传给 requests。
#      全文件只有 threads[i].join(timeout=FETCH_TIMEOUT[1]) 用到它，
#      而 session.get(..., stream=True) 没有 timeout，requests 默认无限等待。
#      于是线程卡在 socket read 上永不结束，主线程等满
#      FETCH_TIMEOUT[0] * FETCH_TIMEOUT[1]（默认 2 × 100 秒）后只打印
#      "超时！"并 continue —— 请求本身没有被中断，daemon 线程继续挂着。
#      结论：100 秒的语义是"放弃等待"，不是"让请求失败"，对已挂起的
#      连接毫无意义，只是把每个坏源的成本从 10 秒拉长到 200 秒。
#      另：日志里的 "5s" / "10s" 是 print(f"{5*t}s") 的轮次装饰标签，
#      与实际耗时无关；真实等待 = 轮数 × 每轮秒数。
#
#   2) iter_content() 未指定 chunk_size，requests 默认 1 字节/次。
#      _download 里对每个 1 字节还要做 splitlines()、content +=、类型判断，
#      纯 Python 循环实测约 50 KB/s，且受 GIL 串行化：
#          - 单个 1MB 的 clash.yaml：_download 耗时 20.3 秒；
#          - 4 路并发各 1MB：合计 75.8 秒（几乎无并行收益）。
#      按 100 秒预算算，单文件超过约 5MB 必然超时，与网速无关；
#      源越多，CPU 越堵，每个源分到的读取时间越少。
#      这就是"为什么只有一部分节点文件超时"的直接原因。
#
#   3) extract()（机场列表展开）与 merge_adblock()（ABFURLS / ABFWHITE）
#      在主线程里直接 session.get()，既没有 timeout 也没有 join 兜底。
#      这两处一旦挂起，整个进程卡死，在 CI 上表现为"作业级超时被取消"，
#      比单源 200 秒后放弃严重得多。
#
# 修改（共 6 处，全部围绕下载控制，不触碰解析 / 合并 / 分类 / 写出逻辑）：
#   1. 新增 import time。
#
#   2. 新增两个常量，并给 FETCH_TIMEOUT 补语义注释：
#          FETCH_TIMEOUT  = (2, 100)   仅用于主线程 join 兜底：(轮数, 每轮秒数)
#          HTTP_TIMEOUT   = (5, 60)    真正交给 requests：(连接超时, 单次读取超时)
#          DOWNLOAD_BUDGET = 120       单个文件总下载预算(秒)
#
#   3. Source.get()：
#          with session.get(normpath(self.url), stream=True,
#                           timeout=HTTP_TIMEOUT) as r:
#      让"挂起的连接"在 60 秒无数据时自己抛 ReadTimeout 退出线程，
#      主线程的 join 随即返回，不再空等 200 秒。
#
#   4. Source._download()：
#          for chunk in r.iter_content(chunk_size=65536):
#      并在循环内加总耗时闸门：
#          deadline = time.monotonic() + DOWNLOAD_BUDGET
#          if time.monotonic() > deadline:
#              raise requests.exceptions.Timeout(...)
#      原因：read timeout 只约束"两次收到数据的间隔"，服务端每 59 秒
#      吐 1 字节依然能绕过 60 秒读超时，必须有总时长闸门兜住。
#
#   5. extract() 与 merge_adblock()（ABFURLS、ABFWHITE 共 3 处）：
#          session.get(..., timeout=HTTP_TIMEOUT)
#      避免主线程被一个坏链接整死。
#
#   6. 主线程等待日志改为真实秒数并 flush：
#          print(f"{5*t}s")  ->  print(f"{t * FETCH_TIMEOUT[1]}s(已等待)", flush=True)
#      避免把"轮次 × 5"的标签误读成真实超时，也避免停在缓冲区里的
#      输出被日志系统同批打点、造成时间戳错乱。
#
# 影响范围：
#   - 仅影响网络请求的超时策略与读取分块；节点解析、去重、合并、
#     地区分类、各类产物（list*.txt / list*.yml / snippets / csv）格式不变。
#   - 行为变化只在"失败时机与失败信息"：慢源或挂起源会更早失败
#     （默认 60 秒无数据即 ReadTimeout，或 120 秒总预算），并在
#     exc_queue 里给出明确的 Read timed out，而不是 200 秒后静默放弃。
#
# 验证（本机 127.0.0.1 起测试服务，网络零延迟，排除带宽干扰）：
#   - 对端返回 200 头但不发数据：
#       原版 200.0 秒后才打印"超时！"，线程仍存活、socket 未释放；
#       修复版 5.0 秒退出，content=-1，错误为 "Read timed out"。
#   - 1MB clash.yaml 的 _download：20.30 秒 → 0.00 秒。
#   - 4 路并发各 1MB：75.79 秒 → 0.02 秒。
#   - 功能回归：同一份 clash.yaml，原版与修复版均解析出 2 个节点，
#     exc_queue 为空，产物内容一致。
#   - python3 -m py_compile 通过。
#
# 调参与回退：
#   - 网络较差可放宽读超时，如 HTTP_TIMEOUT = (8, 120)，或调大
#     DOWNLOAD_BUDGET；不建议再靠加大 FETCH_TIMEOUT 拉长空等。
#   - 若想完全回到原行为：去掉 timeout=HTTP_TIMEOUT，
#     iter_content(chunk_size=65536) 改回 iter_content()，
#     并删除 deadline 判断即可，其余改动彼此独立。
#   - 进一步建议（本次未改）：用 threading.Semaphore(8~10) 限制同时在跑
#     的源数；gh-proxy 一类代理最好配镜像自动切换
#     （脚本里的 raw2fastly() 目前只在 LOCAL 模式生效）。
#
# 六、本次修改内容（去重修复：commit 1 防御 + commit 2 身份收敛）
# -----------------------------------------------------------------------------
# 背景（用 18825 条真实 list.meta.yml 对照）：
#   - 285 组 / 317 个节点是"同一节点但 hash 不同"，没有被合并；
#   - 旧 hash 只拼 type/server/port/(sni|ws host,path)/alpn/password/uuid，
#     既漏掉了 Host 键名大小写的归一，也漏掉了 tls / reality-opts / network
#     等字段；1 个节点还会让 __hash__ 抛 TypeError 后退回 hash(url)。
#
# 为什么不能"只做归一化、不动字段集合"（实测教训）：
#   先只改 path 解码 + Host 大小写 + sni 兜底时，旧 hash 里缺失的字段被暴露，
#   新增合并 178 组里出现 tls 冲突 31 组、reality-opts 27 组、network 81 组、
#   skip-cert-verify 真/假 20 组 —— 会把本来不同的节点合成一条。
#   因此 commit 2 必须同时把"身份字段集合"补齐。
#
# commit 1（防御，零风险）：
#   1. __hash__ 的 except 分支：hash(self.url) 再包一层 try；彻底失败时退化为
#      id(self) 并打标记 'hash-fail'。此前 url 属性抛异常会冒泡到 main() 的
#      except，一个坏节点就能让整条订阅被丢弃。
#
# commit 2（身份收敛）：
#   2. 新增 Node._identity()：把 data 归一成一个稳定的 JSON 字符串作为身份：
#        - 忽略纯显示/运行期字段：name、group；
#        - type 别名：hy2 -> hysteria2，https -> http(+tls)；
#        - server 小写、去 IPv6 方括号；port 统一为 int；uuid 小写；
#        - sni / servername 折叠为一个字段（取 servername 优先，小写）；
#        - alpn 字符串按逗号切分并排序；
#        - vmess 的 network 缺省按 tcp；
#        - ws-opts：path 做 unquote，去掉尾部斜杠；headers 里的 Host 键名
#          大小写不敏感并小写化（实源 Host/host/HOST 三种写法）；
#        - h2-opts 的 host 列表小写并排序；空值字段统一剔除。
#      凡是会改变"连到哪 / 用什么协议、传输、证书"的字段（tls、reality-opts、
#      cipher、network、flow、obfs、plugin-opts、grpc-opts、skip-cert-verify…）
#      全部保留在身份里，宁可少合并也不误合并。
#   3. __hash__ 改为 sha256(identity) 的前 64 bit（避免内置 hash 的 64 位碰撞
#      与跨进程随机化带来的不稳定）。
#
# commit 2b（配套，必要）：
#   4. _load_vless / _load_trojan 的 path 参数做 unquote。若不做，合并后
#      update() 会把"解码版"的节点覆盖成"%2F 版"，等于用一次去重把能用的
#      节点改坏；解码本身是服务端期望的形态，风险最小。
#      影响：样本里 2406 条节点的 ws path 会从 %2F… 变成 /…（其余节点不变）。
#
# 未做（建议后续独立提交）：
#   - merged 的键改为不可变字符串（当前 update() 改 data 会让键过期）；
#   - update() 的 names.union（no-op）与"后者覆盖前者"的数据合并语义。
#
# 验证（同一份 18825 条 list.meta.yml，旧版 vs 本版，dedup_regression.py）：
#   - 唯一节点 18776 -> 18678（净 -98）；
#   - 新增合并 110 组 / 113 个节点；组内 tls / reality-opts / network /
#     cipher / skip-cert-verify 等关键字段冲突 **0 组**；
#   - 反向：旧版错误合并的 10 组在本版被拆开（tls、reality-opts、
#     ws-opts、skip-cert-verify 差异），这部分是修正，不是回退；
#   - 旧版打印 1 次 "节点 Hash 计算失败！"（某节点 Host: null），本版 0 次；
#   - 合成用例：sni/servername、Host/HOST、path %2Fa 与 /a、/a 与 /a/、
#     uuid 大小写、port 字符串、hy2 与 hysteria2、vmess network 缺省
#     全部正确合并；tls 开关、skip-cert-verify、reality-opts、cipher、
#     password、network 不同则正确分开；
#   - 18825 条节点重算 hash 耗时 0.18 秒。
#
# 仍未合并的部分（约 204 个节点）：差异集中在 skip-cert-verify / udp /
#   tfo / client-fingerprint 等"同端点、不同客户端开关"。是否合并属于策略
#   问题（合并会丢掉其中一份开关取值），留给后续单独决策，不在本次改动里。
#
# 影响范围：
#   - 只改变"哪些节点算同一条"：node 参数一个字节都不改，输出只是少了重复项；
#   - 若需回退：把 __hash__ 与 _identity 换回原实现即可（单点改动）。
#
# 七、本次修改内容（产物格式修正 + 无效节点直接剔除）
# -----------------------------------------------------------------------------
# 问题（用 18825 条真实 list.meta.yml 校验发现）：
#   1. 321 个节点的 port 在产物里是字符串，形如 port: '443'。go-yaml 无法把
#      !!str 反序列化成 int，mihomo 加载这份配置会报错；clash_data 之前没有
#      把 port 规整成 int。
#   2. clash_data 把长度不合法的 uuid 替换成常量 88888888-…，等于把坏节点
#      "伪装"成合法节点继续送验证。该常量本身又是大量订阅的默认值（本样本
#      327 个节点用的就是它且能连通），所以既不能删也不能当作坏值替换。
#   3. 假节点只在 supports_* 里被拦截，仍留在 merged 和各项统计里。
#   4. 解析失败的原始串（unknown）被原样写进 list_raw.txt / list.txt。
#   5. snippets/nodes_*.yml 漏了 '!!str ' 清理；写 txt 只捕 UnsupportedType，
#      trojan 缺 grpc-opts 时抛 KeyError 只打堆栈、不计数，节点静默丢失。
#
# 修改：
#   1. Node.invalid_reason()：能本地判死的节点直接剔除，不再"合法化"：
#        fake（无 server / 假 IP / port<20 / 假域名）
#        no-server / bad-port（非整数或不在 1..65535）
#        bad-uuid（vmess/vless/tuic 的 uuid 长度 ≠ 36）
#        no-password（ss/ssr/trojan/hysteria2/tuic/anytls 缺认证；hysteria 认
#                    auth-str/auth_str/auth/password 四种写法）
#        no-cipher（ss/ssr 缺 cipher）、no-obfs-password、no-name
#        bad-reality-key / bad-reality-short-id / bad-flow / bad-host-header
#        （mihomo 加载配置时的硬校验；这类节点会让整份配置 test failed）
#      统一计入 invalid_stats，按原因计数并打印样例；STOP 调试模式不剔除。
#   2. merge() 在 format_name 之前判定：被剔除的节点不参与命名、去重、统计。
#   3. clash_data：port 强制转 int；删除 uuid -> DEFAULT_UUID 的替换；
#      ws-opts.headers 里值为 None / 空串的键直接去掉（'Host: null' 会让
#      mihomo 报 filed ws-opts.headers[Host] invalid 并中止整份配置加载）。
#   4. unknown 不再写进 txt，只打印条数（未校验的脏数据不进产物）。
#   5. 写 txt 的异常捕获扩到 Exception 并计数；_url_trojan 的 grpc 参数改用
#      get，缺 grpc-opts 时不再 KeyError。
#   6. 统一 yaml_dumps()/dump_yaml()：主配置与 snippets 都清理 '!!str '。
#   7. 新增 dedupe_group_names()：节点名撞上策略组名时改名并同步组引用
#      （实源有 1 个节点就叫 "🇸🇬 新加坡"，mihomo 报 the duplicate name）。
#
# 注意：以下"坏节点"不删（实测均为可用节点，删了是净损失）：
#   - uuid=88888888-… 的 327 个（vless 284 / vmess 43），mihomo 验证全部通过；
#   - network=grpc 但没写 grpc-service-name 的 183 个（serviceName 可为空）。
# =============================================================================
#!/usr/bin/env python3
# ========== User Configs Begin ==========
STOP = False
NAME_SHOW_TYPE = False
NAME_NO_FLAGS  = False
NAME_SHOW_SRC  = False
ABFURLS = (
    "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/ChineseFilter/sections/adservers.txt",
    "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/ChineseFilter/sections/adservers_firstparty.txt",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_224_Chinese/filter.txt",
    "https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/AWAvenue-Ads-Rule.txt",
    "https://raw.githubusercontent.com/d3ward/toolz/master/src/d3host.adblock",
    "https://raw.githubusercontent.com/afwfv/DD-AD/main/rule/DD-AD.txt",
)
ABFWHITE = (
    "https://raw.githubusercontent.com/privacy-protection-tools/dead-horse/master/anti-ad-white-list.txt",
    "file:///./abpwhite.txt",
)
# ========== User Configs End ==========

import yaml
import json
import base64
import re
from urllib.parse import quote, unquote, urlparse
import requests
from requests_file import FileAdapter
import datetime
import traceback
import binascii
import hashlib
import threading
import sys
import os
import time
import copy
from types import FunctionType as function
from typing import Set, List, Dict, Union, Callable, Any, Optional, Iterable, TypedDict

try: PROXY = open("local_proxy.conf").read().strip()
except FileNotFoundError: LOCAL = False; PROXY = None
else:
    if not PROXY: PROXY = None
    LOCAL = not PROXY

def b64encodes(s: str):
    return base64.b64encode(s.encode('utf-8')).decode('utf-8')

def b64encodes_safe(s: str):
    return base64.urlsafe_b64encode(s.encode('utf-8')).decode('utf-8')

def b64decodes(s: str):
    ss = s + '=' * ((4-len(s)%4)%4)
    try:
        return base64.b64decode(ss.encode('utf-8')).decode('utf-8')
    except UnicodeDecodeError: raise
    except binascii.Error: raise

def b64decodes_safe(s: str):
    ss = s + '=' * ((4-len(s)%4)%4)
    try:
        return base64.urlsafe_b64decode(ss.encode('utf-8')).decode('utf-8')
    except UnicodeDecodeError: raise
    except binascii.Error: raise

def normpath(url: str):
    if url.startswith('file://'):
        basedir = os.path.dirname(os.path.abspath(__file__))
        return url.replace('/./', '/'+basedir.lstrip('/').replace(os.sep, '/')+'/')
    return url

DEFAULT_UUID = '8'*8+'-8888'*3+'-'+'8'*12

CLASH2VMESS = {'name': 'ps', 'server': 'add', 'port': 'port', 'uuid': 'id',
              'alterId': 'aid', 'cipher': 'scy', 'network': 'net', 'servername': 'sni'}
VMESS2CLASH: Dict[str, str] = {}
for k,v in CLASH2VMESS.items(): VMESS2CLASH[v] = k

VMESS_TEMPLATE = {
    "v": "2", "ps": "", "add": "0.0.0.0", "port": "0", "aid": "0", "scy": "auto",
    "net": "tcp", "type": "none", "tls": "", "id": DEFAULT_UUID
}

CLASH_CIPHER_VMESS = "auto aes-128-gcm chacha20-poly1305 none".split()
CLASH_CIPHER_SS = "aes-128-gcm aes-192-gcm aes-256-gcm aes-128-cfb aes-192-cfb \
        aes-256-cfb aes-128-ctr aes-192-ctr aes-256-ctr rc4-md5 chacha20-ietf \
        xchacha20 chacha20-ietf-poly1305 xchacha20-ietf-poly1305".split()
CLASH_SSR_OBFS = "plain http_simple http_post random_head tls1.2_ticket_auth tls1.2_ticket_fastauth".split()
CLASH_SSR_PROTOCOL = "origin auth_sha1_v4 auth_aes128_md5 auth_aes128_sha1 auth_chain_a auth_chain_b".split()

FAKE_IPS = "8.8.8.8; 8.8.4.4; 4.2.2.2; 4.2.2.1; 114.114.114.114; 127.0.0.1; 0.0.0.0".split('; ')
FAKE_DOMAINS = ".google.com .github.com".split()

FETCH_TIMEOUT = (2, 100)   # 仅用于主线程 join 兜底：(轮数, 每轮等待秒数)
HTTP_TIMEOUT = (5, 60)     # 真正交给 requests 的超时：(连接, 单次读取) 秒
DOWNLOAD_BUDGET = 120      # 单个文件总下载预算(秒)，防止对端分块慢速喂数据

BANNED_WORDS = b64decodes('5rOV6L2uIOi9ruWtkCDova4g57uDIOawlCDlip8g5L2/5YqyIOWKsiDliqrlipsg5Yqg5rK5IOWlsyDmnYMg6L+Q5YqoIG9uZ3RhaXdhbg==').split()

DEBUG_NO_NODES = os.path.exists("local_NO_NODES")
DEBUG_NO_DYNAMIC = os.path.exists("local_NO_DYNAMIC")
DEBUG_NO_ADBLOCK = os.path.exists("local_NO_ADBLOCK")

STOP_FAKE_NODES = """vmess://ew0KICAidiI6ICIyIiwNCiAgInBzIjogIlx1NjU0Rlx1NjExRlx1NjVGNlx1NjcxRlx1RkYwQ1x1NjZGNFx1NjVCMFx1NjY4Mlx1NTA1QyIsDQogICJhZGQiOiAiMC4wLjAuMCIsDQogICJwb3J0IjogIjEiLA0KICAiaWQiOiAiODg4ODg4ODgtODg4OC04ODg4LTg4ODgtODg4ODg4ODg4ODg4IiwNCiAgImFpZCI6ICIwIiwNCiAgInNjeSI6ICJhdXRvIiwNCiAgIm5ldCI6ICJ0Y3AiLA0KICAidHlwZSI6ICJub25lIiwNCiAgImhvc3QiOiAiIiwNCiAgInBhdGgiOiAiIiwNCiAgInRscyI6ICIiLA0KICAic25pIjogIndlYi41MS5sYSIsDQogICJhbHBuIjogImh0dHAvMS4xIiwNCiAgImZwIjogImNocm9tZSINCn0=
vmess://ew0KICAidiI6ICIyIiwNCiAgInBzIjogIlx1NTk4Mlx1NjcwOVx1OTcwMFx1ODk4MVx1RkYwQ1x1ODFFQVx1ODg0Q1x1NjQyRFx1NUVGQSIsDQogICJhZGQiOiAiMC4wLjAuMCIsDQogICJwb3J0IjogIjIiLA0KICAiaWQiOiAiODg4ODg4ODgtODg4OC04ODg4LTg4ODgtODg4ODg4ODg4ODg4IiwNCiAgImFpZCI6ICIwIiwNCiAgInNjeSI6ICJhdXRvIiwNCiAgIm5ldCI6ICJ0Y3AiLA0KICAidHlwZSI6ICJub25lIiwNCiAgImhvc3QiOiAiIiwNCiAgInBhdGgiOiAiIiwNCiAgInRscyI6ICIiLA0KICAic25pIjogIndlYi41MS5sYSIsDQogICJhbHBuIjogImh0dHAvMS4xIiwNCiAgImZwIjogImNocm9tZSINCn0=
vmess://ew0KICAidiI6ICIyIiwNCiAgInBzIjogIlx1NUU4Nlx1Nzk1RFx1NEUyRFx1NTZGRFx1NTE3MVx1NEVBN1x1NTE1QVx1NjIxMFx1N0FDQjEwNVx1NTQ2OFx1NUU3NFx1RkYwMSIsDQogICJhZGQiOiAiMC4wLjAuMCIsDQogICJwb3J0IjogIjMiLA0KICAiaWQiOiAiODg4ODg4ODgtODg4OC04ODg4LTg4ODgtODg4ODg4ODg4ODg4IiwNCiAgImFpZCI6ICIwIiwNCiAgInNjeSI6ICJhdXRvIiwNCiAgIm5ldCI6ICJ0Y3AiLA0KICAidHlwZSI6ICJub25lIiwNCiAgImhvc3QiOiAiIiwNCiAgInBhdGgiOiAiIiwNCiAgInRscyI6ICIiLA0KICAic25pIjogIndlYi41MS5sYSIsDQogICJhbHBuIjogImh0dHAvMS4xIiwNCiAgImZwIjogImNocm9tZSINCn0=
"""

d = datetime.datetime.now()
if STOP or ((d.month, d.day) in ((6, 4), (7, 1), (10, 1)) and not (LOCAL or PROXY)):
    DEBUG_NO_NODES = DEBUG_NO_DYNAMIC = STOP = True
    NAME_SHOW_TYPE = NAME_NO_FLAGS = NAME_SHOW_SRC = False
    BANNED_WORDS = []

session = requests.Session()
session.trust_env = False
if PROXY and not PROXY == 'NONE':
    session.proxies = {'http': PROXY, 'https': PROXY}
session.headers["User-Agent"] = 'Mozilla/5.0 (X11; Linux x86_64) Clash-verge/v2.4.2 AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36 Edg/140.0.0.0'
session.mount('file://', FileAdapter())

class UnsupportedType(Exception): pass
class NotANode(Exception): pass

class Node:
    gNames: Set[str] = set()
    class DATA_TYPE(TypedDict):
        name: str
        type: str
        server: str
        port: int

    def __init__(self, data: Union[DATA_TYPE, str]) -> None:
        if isinstance(data, dict):
            self.data: Node.DATA_TYPE = data
            self.type = data['type']
        elif isinstance(data, str):
            self.load_url(data)
        else: raise TypeError(f"Got {type(data)}")
        if not self.data['name']:
            self.data['name'] = "未命名"
        if 'password' in self.data:
            self.data['password'] = str(self.data['password'])
        self.data['type'] = self.type
        self.names: Set[str] = {self.data['name']}
        # 修法A: 内部标记集合。刻意放在实例属性而非 self.data，
        # 因为 clash_data 是 self.data 的拷贝、__hash__ 也读 self.data；
        # 标记只作记账用途, 不参与配置序列化、不参与身份哈希。
        self.flags: Set[str] = set()

    def __str__(self):
        return self.url

    _ID_IGNORE = {'name', 'group'}

    def _identity(self) -> str:
        """把 data 归一成稳定的身份字符串（去重键的材料）。

        原则：凡是会改变"连到哪、用什么协议/传输/证书"的字段全部保留，
        只忽略纯显示字段（name/group）。写法差异在此归一，语义差异在此保留。
        """
        d = {k: v for k, v in self.data.items() if k not in self._ID_IGNORE}
        t = str(d.get('type', ''))
        if t == 'hy2':
            t = 'hysteria2'
        elif t == 'https':
            t, d['tls'] = 'http', True
        d['type'] = t
        srv = str(d.get('server', '')).strip().lower()
        if srv.startswith('[') and srv.endswith(']'):
            srv = srv[1:-1]
        d['server'] = srv
        try:
            d['port'] = int(str(d.get('port')))
        except Exception:
            pass
        if isinstance(d.get('uuid'), str):
            d['uuid'] = d['uuid'].lower()
        sni = d.pop('servername', None) or d.get('sni')
        if sni:
            d['sni'] = str(sni).strip().lower()
        else:
            d.pop('sni', None)
        alpn = d.get('alpn')
        if alpn:
            d['alpn'] = sorted(str(x).strip() for x in
                               (alpn.split(',') if isinstance(alpn, str) else alpn))
        else:
            d.pop('alpn', None)
        if t == 'vmess':
            d['network'] = d.get('network') or 'tcp'
        opts = d.get('ws-opts')
        if isinstance(opts, dict):
            new = {k: v for k, v in opts.items() if k != 'headers'}
            path = new.get('path')
            if isinstance(path, str):
                path = unquote(path)
                new['path'] = '/' if path in ('', '/') else path.rstrip('/')
            host = None
            for k, v in (opts.get('headers') or {}).items():
                if isinstance(k, str) and k.lower() == 'host' and v is not None:
                    host = v
                    break
            if host is not None:
                new['headers'] = {'host': str(host).strip().lower()}
            d['ws-opts'] = new
        opts = d.get('h2-opts')
        if isinstance(opts, dict) and isinstance(opts.get('host'), list):
            opts['host'] = sorted(str(x).strip().lower() for x in opts['host'])
            d['h2-opts'] = opts
        for k in [k for k, v in d.items() if v in (None, '', [], {})]:
            del d[k]
        return json.dumps(d, sort_keys=True, ensure_ascii=False, default=str)

    def __hash__(self):
        try:
            # type 已在 _identity() 内归一（hy2 -> hysteria2 等），此处不再重复拼接
            raw = self._identity()
            # 用 sha256 前 64 bit 作键：避免内置 hash 的 64 位碰撞，
            # 也不受 PYTHONHASHSEED 的跨进程随机化影响。
            return int(hashlib.sha256(raw.encode('utf-8')).hexdigest()[:16], 16)
        except Exception:
            print("节点 Hash 计算失败！", file=sys.stderr)
            traceback.print_exc(file=sys.stderr)
            try:
                return hash(self.url)
            except Exception:
                # 绝不让单个坏节点冒泡到 main() 的 except，否则整条订阅会被丢弃
                print("节点 Hash 兜底失效，退化为对象身份", file=sys.stderr)
                traceback.print_exc(file=sys.stderr)
                self.flags.add('hash-fail')
                return id(self)

    def __eq__(self, other: Union['Node', Any]):
        if isinstance(other, self.__class__):
            return hash(self) == hash(other)
        else:
            return False

    @staticmethod
    def urlparse(url: str, scheme='', allow_fragments=True):
        if allow_fragments and '#' in url:
            segs = url.split('#')
            fragment = segs[-1]
            url = '#'.join(segs[:-1])
        else:
            fragment = None
        res = urlparse(url, scheme, allow_fragments=False)
        if fragment:
            res = res._replace(fragment=fragment)
        return res

    def load_url(self, url: str):
        try: self.type, dt = url.split("://", 1)
        except ValueError: raise NotANode(url)
        if not self.type.isascii():
            self.type = ''.join([_ for _ in self.type if _.isascii()])
            url = self.type+'://'+url.split("://")[1]
        if self.type == 'hy2': self.type = 'hysteria2'
        loader: Optional[Callable[[str, str], None]] = getattr(self, '_load_'+self.type, None)
        if loader: loader(url, dt)
        else: raise UnsupportedType(self.type)
        if ('server' in self.data and ':' in self.data['server'] and 
                not self.data['server'].startswith('[')):
            self.data['server'] = f"[{self.data['server']}]"

    def _load_vmess(self, url: str, dt: str):
        v = VMESS_TEMPLATE.copy()
        try: v.update(json.loads(b64decodes(dt)))
        except Exception:
            raise UnsupportedType('vmess', 'SP')
        self.data = {}
        for key, val in v.items():
            if key in VMESS2CLASH:
                self.data[VMESS2CLASH[key]] = val
        self.data['tls'] = (v['tls'] == 'tls')
        self.data['alterId'] = int(self.data['alterId'])
        if v['net'] == 'ws':
            opts = {}
            if 'path' in v:
                opts['path'] = v['path']
            if 'host' in v:
                opts['headers'] = {'Host': v['host']}
            self.data['ws-opts'] = opts
        elif v['net'] == 'h2':
            opts = {}
            if 'path' in v:
                opts['path'] = v['path']
            if 'host' in v:
                opts['host'] = v['host'].split(',')
            self.data['h2-opts'] = opts
        elif v['net'] == 'grpc' and 'path' in v:
            self.data['grpc-opts'] = {'grpc-service-name': v['path']}

    def _load_ss(self, url: str, dt: str):
        info = dt.split('@')
        srvname = info.pop()
        if '#' in srvname:
            srv, name = srvname.split('#')
        else:
            srv = srvname
            name = ''
        segs = srv.split(':')
        port = segs[-1]
        server = ':'.join(segs[:-1])
        try:
            port = int(port)
        except ValueError:
            raise UnsupportedType('ss', 'SP')
        info = '@'.join(info)
        if not ':' in info:
            info = b64decodes_safe(info)
        if ':' in info:
            cipher, passwd = info.split(':')
        else:
            cipher = info
            passwd = ''
        self.data = {'name': unquote(name), 'server': server,
                'port': port, 'type': 'ss', 'password': passwd, 'cipher': cipher}

    def _load_ssr(self, url: str, dt: str):
        if '?' in url:
            parts = dt.split(':')
        else:
            parts = b64decodes_safe(dt).split(':')
        try:
            passwd, info = parts[-1].split('/?')
        except: raise
        passwd = b64decodes_safe(passwd)
        self.data = {'type': 'ssr', 'server': parts[0], 'port': parts[1],
                'protocol': parts[2], 'cipher': parts[3], 'obfs': parts[4],
                'password': passwd, 'name': ''}
        for kv in info.split('&'):
            k_v = kv.split('=', 1)
            if len(k_v) != 2:
                k = k_v[0]
                v = ''
            else: k,v = k_v
            if k == 'remarks':
                self.data['name'] = v
            elif k == 'group':
                self.data['group'] = v
            elif k == 'obfsparam':
                self.data['obfs-param'] = v
            elif k == 'protoparam':
                self.data['protocol-param'] = v

    def _load_trojan(self, url: str, dt: str):
        parsed = self.urlparse(url)
        self.data = {'name': unquote(parsed.fragment), 'server': parsed.hostname,
                'port': parsed.port, 'type': 'trojan', 'password': unquote(parsed.username)}
        if not parsed.query: return
        for kv in parsed.query.split('&'):
            k,v = kv.split('=', 1)
            if k in ('allowInsecure', 'insecure'):
                self.data['skip-cert-verify'] = (v != '0')
            elif k == 'sni': self.data['sni'] = v
            elif k == 'alpn':
                self.data['alpn'] = unquote(v).split(',')
            elif k == 'type':
                self.data['network'] = v
            elif k == 'serviceName':
                if 'grpc-opts' not in self.data:
                    self.data['grpc-opts'] = {}
                self.data['grpc-opts']['grpc-service-name'] = v
            elif k == 'host':
                if 'ws-opts' not in self.data:
                    self.data['ws-opts'] = {}
                if 'headers' not in self.data['ws-opts']:
                    self.data['ws-opts']['headers'] = {}
                self.data['ws-opts']['headers']['Host'] = v
            elif k == 'path':
                if 'ws-opts' not in self.data:
                    self.data['ws-opts'] = {}
                # path 的百分号编码归一：%2Fabc 与 /abc 指同一个服务端路径。
                # 旧实现原样保存，既让同节点 hash 不同，也会把 %2F 原样写进配置。
                self.data['ws-opts']['path'] = unquote(v)

    def _load_vless(self, url: str, dt: str):
        parsed = self.urlparse(url)
        self.data = {'name': unquote(parsed.fragment), 'server': parsed.hostname,
                'port': parsed.port, 'type': 'vless', 'uuid': unquote(parsed.username)}
        self.data['tls'] = False
        if not parsed.query: return
        for kv in parsed.query.split('&'):
            k,v = kv.split('=', 1)
            if k in ('allowInsecure', 'insecure'):
                self.data['skip-cert-verify'] = (v != '0')
            elif k == 'sni': self.data['servername'] = v
            elif k == 'alpn':
                self.data['alpn'] = unquote(v).split(',')
            elif k == 'type':
                self.data['network'] = v
            elif k == 'serviceName':
                if 'grpc-opts' not in self.data:
                    self.data['grpc-opts'] = {}
                self.data['grpc-opts']['grpc-service-name'] = v
            elif k == 'host':
                if 'ws-opts' not in self.data:
                    self.data['ws-opts'] = {}
                if 'headers' not in self.data['ws-opts']:
                    self.data['ws-opts']['headers'] = {}
                self.data['ws-opts']['headers']['Host'] = v
            elif k == 'path':
                if 'ws-opts' not in self.data:
                    self.data['ws-opts'] = {}
                # path 的百分号编码归一：%2Fabc 与 /abc 指同一个服务端路径。
                # 旧实现原样保存，既让同节点 hash 不同，也会把 %2F 原样写进配置。
                self.data['ws-opts']['path'] = unquote(v)
            elif k == 'flow':
                if v.endswith('-udp443'):
                    self.data['flow'] = v
                else: self.data['flow'] = v+'!'
            elif k == 'fp': self.data['client-fingerprint'] = v
            elif k == 'security' and v == 'tls':
                self.data['tls'] = True
            elif k == 'pbk':
                if 'reality-opts' not in self.data:
                    self.data['reality-opts'] = {}
                self.data['reality-opts']['public-key'] = v
            elif k == 'sid':
                if 'reality-opts' not in self.data:
                    self.data['reality-opts'] = {}
                self.data['reality-opts']['short-id'] = v

    def _load_hysteria2(self, url: str, dt: str):
        parsed = self.urlparse(url)
        self.data = {'name': unquote(parsed.fragment), 'server': parsed.hostname,
                'type': 'hysteria2', 'password': unquote(parsed.username)}
        if ':' in parsed.netloc:
            ports = parsed.netloc.split(':')[1]
            if ',' in ports:
                _, self.data['ports'] = ports.split(',',1)
            else:
                self.data['port'] = ports
            try: self.data['port'] = int(self.data['port'])
            except ValueError: self.data['port'] = 443
        else:
            self.data['port'] = 443
        self.data['tls'] = False
        if not parsed.query: return
        k = v = ''
        for kv in parsed.query.split('&'):
            if '=' in kv:
                k,v = kv.split('=', 1)
            else:
                v += '&' + kv
            if k == 'insecure':
                self.data['skip-cert-verify'] = (v != '0')
            elif k == 'alpn':
                self.data['alpn'] = unquote(v).split(',')
            elif k in ('sni', 'obfs', 'obfs-password'):
                self.data[k] = v
            elif k == 'fp': self.data['client-fingerprint'] = v

    def _load_tuic(self, url: str, dt: str):
        parsed = self.urlparse(url)
        self.data = {
            'name': unquote(parsed.fragment), 'server': parsed.hostname,
            'type': 'tuic', 'uuid': unquote(parsed.username),
            'password': unquote(parsed.password), 'port': parsed.port or 136
        }
        if not parsed.query: return
        k = v = ''
        for kv in parsed.query.split('&'):
            if '=' in kv:
                k,v = kv.split('=', 1)
            else:
                v += '&' + kv
            if k == 'allow_insecure':
                self.data['skip-cert-verify'] = (v != '0')
            elif k == 'alpn':
                self.data['alpn'] = unquote(v).split(',')
            elif k in ('sni', 'udp_relay_mode'):
                self.data[k.replace('_','-')] = v
            elif k == 'fp': self.data['client-fingerprint'] = v
            elif k == 'congestion_control': self.data['congestion-controller'] = v

    def _load__legacy(self, url: str, dt: str):
        parsed = urlparse(url)
        self.data = {
            'name': unquote(parsed.fragment),
            'type': 'socks5' if self.type.startswith('socks') else 'http',
            'tls': parsed.scheme == 'https',
            'server': parsed.hostname,
            'port': parsed.port,
            'username': parsed.username,
            'password': parsed.password
        }
        self.data = {k:v for k,v in self.data.items() if v != None}
        if self.type.startswith('socks'):
            self.type = self.data['type']

    _load_http = _load__legacy
    _load_https = _load__legacy
    _load_socks5 = _load__legacy
    _load_socks = _load__legacy

    def update(self, node: 'Node'):
        self.data.update(node.data)
        self.names.union(node.names)
        # 修法A配套: 合并内部标记集合(与身份无关, 仅记账)
        self.flags.update(getattr(node, 'flags', set()))

    @property
    def name(self):
        def rate(name: str):
            r = 0
            if name.startswith('@'):
                r -= 5
            if any(127462<=ord(c)<=127487 for c in name):
                r += 6
            if '\N{RIGHT-TO-LEFT MARK}' in name:
                r -= 3
            if any(word in name for word in BANNED_WORDS):
                r -= 100
            return r
        return sorted(list(self.names), key=rate)[0]

    def format_name(self, max_len=30):
        name = [ord(c) for c in self.name]
        for ch in '\N{MATHEMATICAL BOLD CAPITAL A}\N{MATHEMATICAL SANS-SERIF BOLD CAPITAL A}':
            name = [
                c - ord(ch) + ord('A') if ord(ch) <= c < ord(ch)+26 else c
                for c in name
            ]
        for ch in ('\N{MATHEMATICAL BOLD SMALL A}\N{MATHEMATICAL SANS-SERIF BOLD SMALL A}'
                    +'\N{REGIONAL INDICATOR SYMBOL LETTER A}'*NAME_NO_FLAGS):
            name = [
                c - ord(ch) + ord('a') if ord(ch) <= c < ord(ch)+26 else c
                for c in name
            ]
        name = ''.join([chr(c) for c in name])
        name = name.replace(chr(10144), '->')
        for word in BANNED_WORDS:
            name = name.replace(word, '*'*len(word))
        if len(name) > max_len:
            name = name[:max_len]
            if '\N{RIGHT-TO-LEFT MARK}' in name:
                name += '\N{LEFT-TO-RIGHT MARK}'
                print(name)
            name += '...'
        if NAME_SHOW_TYPE:
            if self.type in ('ss', 'ssr', 'vless', 'tuic'):
                tp = self.type.upper()
            else:
                tp = self.type.title()
            name = f'[{tp}] ' + name
        if name in Node.gNames:
            i = 0
            new = name
            while new in Node.gNames:
                i += 1
                new = f"{name} #{i}"
            name = new
        self.data['name'] = name

    @property
    def isfake(self) -> bool:
        if STOP: return False
        try:
            if 'server' not in self.data: return True
            if self.data['server'] in FAKE_IPS: return True
            if int(str(self.data['port'])) < 20: return True
            for domain in FAKE_DOMAINS:
                if self.data['server'] == domain.lstrip('.'): return True
                if self.data['server'].endswith(domain): return True
            if 'sni' in self.data and 'google.com' in str(self.data['sni']).lower():
                # 修法A: 原代码在此把 sni 就地改成 www.bing.com。sni 是进
                # base_identity 与 Node.__hash__ 的拨号字段, 就地改写会造成
                # 节点身份漂移 -> 假增量(下轮被当新节点重测)、且 fetch 自身
                # hash 去重也会错配。改为仅打标记、节点配置原样保留,
                # 是否真替换 sni 留到导出环节决定, 连通性交由测速环节判真。
                self.flags.add('google-sni')
        except Exception:
            print("无法验证的节点！", file=sys.stderr)
            traceback.print_exc(file=sys.stderr)
        return False

    def invalid_reason(self) -> Optional[str]:
        """本地就能判死的节点：返回剔除原因，调用方直接丢弃。

        只覆盖"无论如何都连不上"的情况，宁可漏删也不误删：
          fake          无 server / 假 IP / port<20 / 假域名（与 isfake 同规则）
          no-server     server 为空
          bad-port      port 不是整数，或不在 1..65535
          bad-uuid      vmess/vless/tuic 的 uuid 长度不是 36
          no-password   ss/ssr/trojan/hysteria2/tuic/anytls 缺认证字段
                        （hysteria 的认证字段是 auth-str/auth_str/auth/password）
          no-cipher     ss/ssr 缺 cipher
          no-obfs-password  hysteria2 写了 obfs 却没有 obfs-password
          no-name       名字为空
          bad-reality-key       REALITY public-key 不是 32 字节 base64url
          bad-reality-short-id  REALITY short-id 不是 ≤16 位偶数长度十六进制
          bad-flow              vless flow 不是 xtls-rprx-vision(-udp443)
          bad-host-header       ws-opts.headers 里的 Host 不是合法主机名
        """
        if STOP:   # 调试模式（STOP_FAKE_NODES）保留全部节点
            return None
        if self.isfake:
            return 'fake'
        d = self.data
        if not str(d.get('server') or '').strip():
            return 'no-server'
        try:
            port = int(str(d.get('port')))
        except Exception:
            return 'bad-port'
        if not 1 <= port <= 65535:
            return 'bad-port'
        t = self.type
        if t in ('vmess', 'vless'):
            if len(str(d.get('uuid') or '').strip()) != len(DEFAULT_UUID):
                return 'bad-uuid'
        elif t == 'tuic':
            if len(str(d.get('uuid') or '').strip()) != len(DEFAULT_UUID):
                return 'bad-uuid'
            if not str(d.get('password') or ''):
                return 'no-password'
        elif t in ('ss', 'ssr'):
            if not str(d.get('password') or ''):
                return 'no-password'
            if not str(d.get('cipher') or ''):
                return 'no-cipher'
        elif t in ('trojan', 'hysteria2', 'anytls'):
            if not str(d.get('password') or ''):
                return 'no-password'
        elif t == 'hysteria':
            # hysteria v1 的认证字段是 auth-str / auth_str，不是 password
            if not str(d.get('auth-str') or d.get('auth_str') or d.get('auth')
                       or d.get('password') or ''):
                return 'no-password'
        if d.get('obfs') and not str(d.get('obfs-password') or ''):
            return 'no-obfs-password'
        # 以下是 mihomo 配置加载阶段的硬校验（不满足会让整份配置加载失败，
        # 而不只是这一个节点不可用）：
        ro = d.get('reality-opts')
        if isinstance(ro, dict):
            if not _valid_reality_key(ro.get('public-key')):
                return 'bad-reality-key'
            sid = ro.get('short-id')
            if sid not in (None, '') and not _valid_short_id(sid):
                return 'bad-reality-short-id'
        flow = str(d.get('flow') or '')
        if flow and flow not in ('xtls-rprx-vision', 'xtls-rprx-vision-udp443'):
            return 'bad-flow'
        headers = ((d.get('ws-opts') or {}).get('headers') or {})
        for hk, hv in headers.items():
            if str(hk).lower() == 'host' and not _valid_ws_host(hv):
                return 'bad-host-header'
        if not str(d.get('name') or '').strip():
            return 'no-name'
        return None

    @property
    def url(self) -> str:
        handler: Optional[Callable[[Node.DATA_TYPE], str]] = getattr(self, '_url_'+self.type, None)
        if handler: return handler(self.data)
        else: raise UnsupportedType(self.type)

    def _url_vmess(self, data: DATA_TYPE) -> str:
        v = VMESS_TEMPLATE.copy()
        for key, val in data.items():
            if key in CLASH2VMESS:
                v[CLASH2VMESS[key]] = val
        if v['net'] == 'ws':
            if 'ws-opts' in data:
                try:
                    v['host'] = data['ws-opts']['headers']['Host']
                except KeyError: pass
                if 'path' in data['ws-opts']:
                    v['path'] = data['ws-opts']['path']
        elif v['net'] == 'h2':
            if 'h2-opts' in data:
                if 'host' in data['h2-opts']:
                    v['host'] = ','.join(data['h2-opts']['host'])
                if 'path' in data['h2-opts']:
                    v['path'] = data['h2-opts']['path']
        elif v['net'] == 'grpc':
            if 'grpc-opts' in data:
                if 'grpc-service-name' in data['grpc-opts']:
                    v['path'] = data['grpc-opts']['grpc-service-name']
        if data.get('tls'):
            v['tls'] = 'tls'
        return 'vmess://'+b64encodes(json.dumps(v, ensure_ascii=False))

    def _url_ss(self, data: DATA_TYPE) -> str:
        passwd = b64encodes_safe(data['cipher']+':'+data['password'])
        return f"ss://{passwd}@{data['server']}:{data['port']}#{quote(data['name'])}"

    def _url_ssr(self, data: DATA_TYPE) -> str:
        ret = (':'.join([str(data[_]) for _ in ('server','port','protocol','cipher','obfs')]) +
                b64encodes_safe(data['password']) +
                f"remarks={b64encodes_safe(data['name'])}")
        for k, urlk in (('obfs-param','obfsparam'), ('protocol-param','protoparam'), ('group','group')):
            if k in data:
                ret += '&'+urlk+'='+b64encodes_safe(data[k])
        return "ssr://"+ret

    def _url_trojan(self, data: DATA_TYPE) -> str:
        passwd = quote(data['password'])
        name = quote(data['name'])
        ret = f"trojan://{passwd}@{data['server']}:{data['port']}?"
        if 'skip-cert-verify' in data:
            ret += f"allowInsecure={int(data['skip-cert-verify'])}&"
        if 'sni' in data:
            ret += f"sni={data['sni']}&"
        if 'alpn' in data:
            ret += f"alpn={quote(','.join(data['alpn']))}&"
        if 'network' in data:
            if data['network'] == 'grpc':
                svc = (data.get('grpc-opts') or {}).get('grpc-service-name') or ''
                ret += f"type=grpc&serviceName={svc}"
            elif data['network'] == 'ws':
                ret += f"type=ws&"
                if 'ws-opts' in data:
                    try:
                        ret += f"host={data['ws-opts']['headers']['Host']}&"
                    except KeyError: pass
                    if 'path' in data['ws-opts']:
                        ret += f"path={data['ws-opts']['path']}"
        ret = ret.rstrip('&')+'#'+name
        return ret

    def _url_vless(self, data: DATA_TYPE) -> str:
        passwd = quote(data['uuid'])
        name = quote(data['name'])
        ret = f"vless://{passwd}@{data['server']}:{data['port']}?"
        if 'skip-cert-verify' in data:
            ret += f"allowInsecure={int(data['skip-cert-verify'])}&"
        if 'servername' in data:
            ret += f"sni={data['servername']}&"
        if 'alpn' in data:
            ret += f"alpn={quote(','.join(data['alpn']))}&"
        if 'network' in data:
            if data['network'] == 'grpc':
                ret += f"type=grpc&"
                try:
                    ret += f"serviceName={data['grpc-opts']['grpc-service-name']}&"
                except KeyError: pass
            elif data['network'] == 'ws':
                ret += f"type=ws&"
                if 'ws-opts' in data:
                    try:
                        ret += f"host={data['ws-opts']['headers']['Host']}&"
                    except KeyError: pass
                    if 'path' in data['ws-opts']:
                        ret += f"path={data['ws-opts']['path']}"
        if 'flow' in data:
            flow: str = data['flow']
            if flow.endswith('!'):
                ret += f"flow={flow[:-1]}&"
            else: ret += f"flow={flow}-udp443&"
        if 'client-fingerprint' in data:
            ret += f"fp={data['client-fingerprint']}&"
        if data.get('tls'):
            ret += f"security=tls&"
        elif 'reality-opts' in data:
            opts: Dict[str, str] = data['reality-opts']
            ret += f"security=reality&pbk={opts.get('public-key','')}&sid={opts.get('short-id','')}&"
        ret = ret.rstrip('&')+'#'+name
        return ret

    def _url_hysteria2(self, data: DATA_TYPE) -> str:
        passwd = quote(data['password'])
        name = quote(data['name'])
        ret = f"hysteria2://{passwd}@{data['server']}:{data['port']}"
        if 'ports' in data:
            ret += ','+data['ports']
        ret += '?'
        if 'skip-cert-verify' in data:
            ret += f"insecure={int(data['skip-cert-verify'])}&"
        if 'alpn' in data:
            ret += f"alpn={quote(','.join(data['alpn']))}&"
        if 'client-fingerprint' in data:
            ret += f"fp={data['client-fingerprint']}&"
        for k in ('sni', 'obfs', 'obfs-password'):
            if k in data:
                ret += f"{k}={data[k]}&"
        ret = ret.rstrip('&')+'#'+name
        return ret

    def _url_tuic(self, data: DATA_TYPE) -> str:
        passwd = quote(data['password'])
        uuid = quote(data['uuid'])
        name = quote(data['name'])
        ret = f"tuic://{uuid}:{passwd}@{data['server']}:{data['port']}?"
        if 'skip-cert-verify' in data:
            ret += f"allow_insecure={int(data['skip-cert-verify'])}&"
        if 'alpn' in data:
            ret += f"alpn={quote(','.join(data['alpn']))}&"
        if 'client-fingerprint' in data:
            ret += f"fp={data['client-fingerprint']}&"
        if 'congestion-controller' in data:
            ret += f"congestion_control={data['congestion-controller']}&"
        for k in ('sni', 'udp-relay-mode'):
            if k in data:
                ret += f"{k.replace('-','_')}={data[k]}&"
        ret = ret.rstrip('&')+'#'+name
        return ret

    def _url__legacy(self, data: DATA_TYPE) -> str:
        tp = 'https' if self.type == 'http' and data.get('tls') else self.type
        part = ''
        if 'username' in data:
            part += data['username']
        if 'password' in data:
            part += ':' + data['password']
        if part: part += '@'
        return f"{tp}://{part}{data['server']}:{data['port']}"

    _url_http = _url__legacy
    _url_https = _url__legacy
    _url_socks5 = _url__legacy

    @property
    def clash_data(self) -> DATA_TYPE:
        ret = self.data.copy()
        if 'server' in ret and ret['server'].startswith('['):
            ret['server'] = ret['server'][1:-1]
        if 'password' in ret and ret['password'].isdigit():
            ret['password'] = '!!str '+ret['password']
        # port 必须是 int：否则落盘成 port: '443'，类型与约定不一致
        try:
            ret['port'] = int(str(ret['port']))
        except Exception:
            pass   # 非法 port 已在 invalid_reason() 剔除，这里只兜底
        # ws-opts.headers 里值为空（None / ''）的键直接去掉：mihomo 对
        # 'Host: null' 会报 'filed ws-opts.headers[Host] invalid' 并中止
        # 整份配置加载；而"不写 Host"本来就是合法的（会用 servername）。
        # 这里要深拷贝，否则改的是 self.data，会影响去重身份。
        if isinstance(ret.get('ws-opts'), dict):
            ws = copy.deepcopy(ret['ws-opts'])
            headers = ws.get('headers')
            if isinstance(headers, dict):
                for hk in list(headers):
                    hv = headers[hk]
                    if hv is None or (isinstance(hv, str) and not hv.strip()):
                        del headers[hk]
                if not headers:
                    ws.pop('headers', None)
            ret['ws-opts'] = ws
        if 'group' in ret: del ret['group']
        if 'cipher' in ret and not ret['cipher']:
            ret['cipher'] = 'auto'
        if self.type == 'vless' and 'flow' in ret:
            if ret['flow'].endswith('-udp443'):
                ret['flow'] = ret['flow'][:-7]
            elif ret['flow'].endswith('!'):
                ret['flow'] = ret['flow'][:-1]
        if 'alpn' in ret and isinstance(ret['alpn'], str):
            ret['alpn'] = ret['alpn'].replace(' ','').split(',')
        if 'reality-opts' in ret and 'short-id' in ret['reality-opts']:
            ret['reality-opts']['short-id'] = '!!str '+ret['reality-opts']['short-id']
        if 'reality-opts' in ret:
            ret['tls'] = True
        return ret

    def supports_clash(self, meta=False) -> bool:
        if self.isfake: return False
        if 'obfs' in self.data and 'obfs-password' not in self.data:
            return False
        if self.type == 'vmess':
            supported = CLASH_CIPHER_VMESS
        elif self.type == 'ss' or self.type == 'ssr':
            supported = CLASH_CIPHER_SS
        elif self.type == 'trojan': return True
        elif not meta: return False
        else: return True
        if 'network' in self.data and self.data['network'] in ('h2','grpc'):
            self.data['tls'] = True
        if 'cipher' not in self.data: return True
        if not self.data['cipher']: return True
        if self.data['cipher'] not in supported: return False
        try:
            if self.type == 'ssr':
                if 'obfs' in self.data and self.data['obfs'] not in CLASH_SSR_OBFS:
                    return False
                if 'protocol' in self.data and self.data['protocol'] not in CLASH_SSR_PROTOCOL:
                    return False
            if 'plugin-opts' in self.data and 'mode' in self.data['plugin-opts'] \
                    and not self.data['plugin-opts']['mode']: return False
        except Exception:
            print("无法验证的 Clash 节点！", file=sys.stderr)
            traceback.print_exc(file=sys.stderr)
            return False
        return True

    def supports_meta(self) -> bool:
        return self.supports_clash(meta=True)

    def supports_ray(self) -> bool:
        if self.isfake: return False
        if self.type == 'socks5' and self.data.get('tls'):
            return False
        return True

class Source():
    def __init__(self, url: Union[str, function]) -> None:
        self.url_source: Union[str, function, None]
        if isinstance(url, function):
            self.url: str = "dynamic://"+url.__name__
            self.url_source = url
        elif url.startswith('+'):
            self.url_source = url
            self.date = datetime.datetime.now()
            self.gen_url()
        else:
            self.url: str = url
            self.url_source = None
        self.content: Union[str, Iterable[str], int] = None
        self.sub: Union[List[str], List[Dict[str, str]]] = None
        self.cfg: Dict[str, Any] = {}
        self.exc_queue: List[str] = []

    def gen_url(self):
        assert isinstance(self.url_source, str)
        tags = self.url_source.split()
        url = tags.pop()
        while tags:
            tag = tags.pop(0)
            if tag[0] != '+': break
            if tag == '+date':
                url = self.date.strftime(url)
                self.date -= datetime.timedelta(days=1)
        self.url = url

    def get(self, depth=2) -> None:
        if self.content: return
        try:
            if self.url.startswith("dynamic:"):
                assert isinstance(self.url_source, function)
                self.content: Union[str, Iterable[str]] = self.url_source()
            else:
                global session
                if '#' in self.url:
                    segs = self.url.split('#')
                    self.cfg = dict([_.split('=',1) for _ in segs[-1].split('&')])
                    if 'max' in self.cfg:
                        try:
                            self.cfg['max'] = int(self.cfg['max'])
                        except ValueError:
                            self.exc_queue.append("最大节点数限制不是整数！")
                            del self.cfg['max']
                    if 'ignore' in self.cfg:
                        self.cfg['ignore'] = [_ for _ in self.cfg['ignore'].split(',') if _.strip()]
                    self.url = '#'.join(segs[:-1])
                with session.get(normpath(self.url), stream=True, timeout=HTTP_TIMEOUT) as r:
                    if r.status_code != 200:
                        if depth > 0 and isinstance(self.url_source, str):
                            exc = f"'{self.url}' 抓取时 {r.status_code}"
                            self.gen_url()
                            exc += "，重新生成链接：\n\t"+self.url
                            self.exc_queue.append(exc)
                            self.get(depth-1)
                        else:
                            self.content = r.status_code
                        return
                    self.content = self._download(r)
        except KeyboardInterrupt: raise
        except requests.exceptions.RequestException as e:
            self.content = -1
            exc = "在抓取 '"+self.url+"' 时发生网络错误：\n"+str(e)
            self.exc_queue.append(exc)
        except:
            self.content = -2
            exc = "在抓取 '"+self.url+"' 时发生错误：\n"+traceback.format_exc()
            self.exc_queue.append(exc)
        else:
            self.parse()

    def _download(self, r: requests.Response) -> str:
        content = bytes()
        tp = None
        pending = None
        early_stop = False
        deadline = time.monotonic() + DOWNLOAD_BUDGET
        # 原代码 iter_content() 用默认 chunk_size=1，一个 20MB 的 yaml 要循环两千万次，
        # 纯 Python 开销就能吃掉几十秒，等于把超时预算耗在本地循环上。
        for chunk in r.iter_content(chunk_size=65536):
            if early_stop: pending = None; break
            if time.monotonic() > deadline:
                raise requests.exceptions.Timeout(
                    f"下载超过 {DOWNLOAD_BUDGET}s 预算（{self.url}），已中止")
            chunk: bytes
            if tp == 'sub':
                content += chunk
                continue
            if pending != None:
                chunk = pending + chunk
                pending = None
            lines = chunk.splitlines()
            if lines and lines[-1] and chunk.endswith(lines[-1]):
                pending = lines.pop()
            while lines:
                lineb = lines.pop(0)
                line = lineb.decode().replace('\\r','').rstrip()
                if not line: continue
                if not tp:
                    if ': ' in line:
                        if line.count(': ') == 1 and line.isalpha():
                            tp = 'yaml'
                    elif line[0] == '#': pass
                    else: tp = 'sub'
                if tp == 'yaml':
                    if content:
                        if line in ("proxy-groups:", "rules:", "script:"):
                            early_stop=True; break
                        content += lineb + b'\n'
                    elif line == "proxies:":
                        content = lineb + b'\n'
                elif tp == 'sub':
                    content = chunk
                    pending = None
                    break
        if pending != None: content += pending
        try:
            ret = content.decode()
        except UnicodeDecodeError:
            exc = "在抓取 '"+self.url+"' 时发生错误：\n"+traceback.format_exc()
            self.exc_queue.append(exc)
            ret = content.decode('ignore')
        return ret

    def parse(self):
        try:
            text = self.content
            if isinstance(text, str):
                if "proxies:" in text:
                    config = yaml.full_load(text.replace("!<str>","!!str"))
                    sub = config['proxies']
                elif '://' in text:
                    sub = text.strip().splitlines()
                else:
                    sub = b64decodes(text.strip()).strip().splitlines()
            elif not isinstance(text, (list, tuple)):
                sub = list(text)
            else: sub = text
            if 'max' in self.cfg and len(sub) > self.cfg['max']:
                self.exc_queue.append(f"此订阅有 {len(sub)} 个节点，最大限制为 {self.cfg['max']} 个，忽略此订阅。")
                self.sub = []
            elif sub and 'ignore' in self.cfg:
                if isinstance(sub[0], str):
                    self.sub = [_ for _ in sub if _.split('://', 1)[0] not in self.cfg['ignore']]
                elif isinstance(sub[0], dict):
                    self.sub = [_ for _ in sub if _.get('type', '') not in self.cfg['ignore']]
                else: self.sub = sub
            else: self.sub = sub
        except KeyboardInterrupt: raise
        except: self.exc_queue.append(
                "在解析 '"+self.url+"' 时发生错误：\n"+traceback.format_exc())

class DomainTree:
    def __init__(self) -> None:
        self.children: Dict[str, __class__] = {}
        self.here: bool = False

    def insert(self, domain: str):
        segs = domain.split('.')
        segs.reverse()
        self._insert(segs)

    def _insert(self, segs: List[str]):
        if not segs:
            self.here = True
            return
        if segs[0] not in self.children:
            self.children[segs[0]] = __class__()
        child = self.children[segs[0]]
        del segs[0]
        child._insert(segs)

    def remove(self, domain: str):
        segs = domain.split('.')
        segs.reverse()
        self._remove(segs)

    def _remove(self, segs: List[str]):
        self.here = False
        if not segs:
            self.children.clear()
            return
        if segs[0] in self.children:
            child = self.children[segs[0]]
            del segs[0]
            child._remove(segs)

    def get(self) -> List[str]:
        ret: List[str] = []
        for name, child in self.children.items():
            if child.here: ret.append(name)
            else: ret.extend([_+'.'+name for _ in child.get()])
        return ret

def extract(url: str) -> Union[Set[str], int]:
    global session
    res = session.get(url, timeout=HTTP_TIMEOUT)
    if res.status_code != 200: return res.status_code
    urls: Set[str] = set()
    mark = '#'+url.split('#', 1)[1] if '#' in url else ''
    for line in res.text.strip().splitlines():
        line = line.strip()
        if line.startswith("http"):
            urls.add(line+mark)
    return urls

def yaml_dumps(obj) -> str:
    """统一 YAML 序列化：清掉 '!!str ' 前缀。

    '!!str ' 是本脚本给"看起来像数字的字符串"（password / reality short-id）
    打的强制字符串标记，落盘前必须去掉，否则客户端读到的就是字面量
    '!!str xxx'。
    """
    return yaml.dump(obj, allow_unicode=True).replace('!!str ', '')


def dump_yaml(path: str, obj) -> None:
    with open(path, 'w', encoding='utf-8') as f:
        f.write(yaml_dumps(obj))


def _valid_reality_key(v) -> bool:
    """REALITY public-key 必须是 32 字节 x25519 公钥的 base64url（43 字符）。"""
    if not isinstance(v, str) or len(v) < 40:
        return False
    try:
        raw = base64.urlsafe_b64decode(v + '=' * (-len(v) % 4))
    except Exception:
        return False
    return len(raw) == 32


def _valid_short_id(v) -> bool:
    """REALITY short-id 必须是偶数长度、≤16 位的十六进制串（可为空）。"""
    if not isinstance(v, str):
        return False
    return len(v) <= 16 and len(v) % 2 == 0 and bool(re.fullmatch(r'[0-9a-fA-F]*', v))


def dedupe_group_names(conf) -> int:
    """节点名与策略组名撞车时给节点改名。

    mihomo 要求 proxies 与 proxy-groups 的名称全局唯一，命中时直接报
    'proxy group X: the duplicate name' 并拒绝加载整份配置。实源里就有
    节点恰好叫 "🇸🇬 新加坡"（与地区组同名）。改名后同步更新所有组里对该
    节点的引用（rules 引用的是组名，不动）。
    """
    groups = conf.get('proxy-groups') or []
    gnames = {g.get('name') for g in groups}
    proxies = conf.get('proxies') or []
    allnames = {p.get('name') for p in proxies} | gnames
    renamed = 0
    for p in proxies:
        nm = p.get('name')
        if nm in gnames:
            base = f"{nm} ·节点"
            new, i = base, 2
            while new in allnames:
                new = f"{base}{i}"
                i += 1
            allnames.add(new)
            p['name'] = new
            for g in groups:
                if isinstance(g.get('proxies'), list):
                    g['proxies'] = [new if x == nm else x for x in g['proxies']]
            renamed += 1
    return renamed


def _valid_ws_host(v) -> bool:
    """ws-opts.headers 的 Host 必须是合法主机名（可带端口）。

    空值不算错（mihomo 会当没写，落到 server/servername）；写成
    '/?Telegram---xxx' 这类 URL 路径的就是脏数据，会让 mihomo 报
    'filed ws-opts.headers[Host] invalid' 并让整份配置加载失败。
    """
    if not isinstance(v, str) or not v.strip():
        return True
    return bool(re.fullmatch(r'[A-Za-z0-9._\-\[\]?:]+', v.strip()))


merged: Dict[int, Node] = {}
unknown: Set[str] = set()
invalid_stats: Dict[str, int] = {}
invalid_samples: List[str] = []
used: Dict[int, Dict[int, str]] = {}
def merge(source_obj: Source, sourceId=-1):
    global merged, unknown
    sub = source_obj.sub
    if not sub: print("空订阅，跳过！", end='', flush=True); return
    for p in sub:
        if isinstance(p, str) and '://' not in p: continue
        try: n = Node(p)
        except KeyboardInterrupt: raise
        except UnsupportedType as e:
            if len(e.args) == 1:
                print(f"不支持的类型：{e}")
            unknown.add(p)
        except: traceback.print_exc()
        else:
            reason = n.invalid_reason()
            if reason:
                invalid_stats[reason] = invalid_stats.get(reason, 0) + 1
                if len(invalid_samples) < 5:
                    invalid_samples.append(f"{reason}: {str(n.data.get('name', '?'))[:40]}")
                continue
            n.format_name()
            Node.gNames.add(n.data['name'])
            hashn = hash(n)
            if hashn not in merged:
                merged[hashn] = n
            else:
                merged[hashn].update(n)
            if hashn not in used:
                used[hashn] = {}
            used[hashn][sourceId] = n.name

def raw2fastly(url: str) -> str:
    if not LOCAL: return url
    url: Union[str, List[str]]
    if url.startswith("https://raw.githubusercontent.com/"):
        url = url[34:].split('/')
        url[1] += '@'+url[2]
        del url[2]
        url = "https://fastly.jsdelivr.net/gh/"+('/'.join(url))
        return url
    return url

def merge_adblock(adblock_name: str, rules: Dict[str, str]):
    print("正在解析 Adblock 列表... ", end='', flush=True)
    blocked: Set[str] = set()
    unblock: Set[str] = set()
    for url in ABFURLS:
        url = raw2fastly(url)
        try:
            res = session.get(normpath(url), timeout=HTTP_TIMEOUT)
        except requests.exceptions.RequestException as e:
            try:
                print(f"{url} 下载失败：{e.args[0].reason}")
            except Exception:
                print(f"{url} 下载失败：无法解析的错误！")
                traceback.print_exc()
            continue
        if res.status_code != 200:
            print(url, res.status_code)
            continue
        for line in res.text.strip().splitlines():
            line = line.strip()
            if not line or line[0] in '!#': continue
            elif line[:2] == '@@':
                unblock.add(line.split('^')[0].strip('@|^'))
            elif line[:2] == '||' and ('/' not in line) and ('?' not in line) and \
                            (line[-1] == '^' or line.endswith("$all")):
                blocked.add(line.strip('al').strip('|^$'))

    for url in ABFWHITE:
        url = raw2fastly(url)
        try:
            res = session.get(normpath(url), timeout=HTTP_TIMEOUT)
        except requests.exceptions.RequestException as e:
            try:
                print(f"{url} 下载失败：{e.args[0].reason}")
            except Exception:
                print(f"{url} 下载失败：无法解析的错误！")
                traceback.print_exc()
            continue
        if res.status_code != 200:
            print(url, res.status_code)
            continue
        for line in res.text.strip().splitlines():
            line = line.strip()
            if not line or line[0] == '!': continue
            else: unblock.add(line.split('^')[0].strip('|^'))

    domain_root = DomainTree()
    domain_keys: Set[str] = set()
    for domain in blocked:
        if '/' in domain: continue
        if '*' in domain:
            domain = domain.strip('*')
            if '*' not in domain:
                domain_keys.add(domain)
            continue
        segs = domain.split('.')
        if len(segs) == 4 and domain.replace('.','').isdigit():
            for seg in segs:
                if not seg: break
                if seg[0] == '0' and seg != '0': break
            else:
                rules[f'IP-CIDR,{domain}/32'] = adblock_name
        else:
            domain_root.insert(domain)
    for domain in unblock:
        domain_root.remove(domain)

    for domain in domain_keys:
        rules[f'DOMAIN-KEYWORD,{domain}'] = adblock_name

    for domain in domain_root.get():
        for key in domain_keys:
            if key in domain: break
        else: rules[f'DOMAIN-SUFFIX,{domain}'] = adblock_name

    print(f"共有 {len(rules)} 条规则")

def main():
    global merged, FETCH_TIMEOUT, ABFURLS, AUTOURLS, AUTOFETCH
    sources = open("sources.list", encoding="utf-8").read().strip().splitlines()
    if DEBUG_NO_NODES:
        print("!!! 警告：您已启用无节点调试，程序产生的配置不能被直接使用 !!!")
        sources = []
    if DEBUG_NO_DYNAMIC:
        print("!!! 警告：您已选择不抓取动态节点 !!!")
        AUTOURLS = AUTOFETCH = []
    print("正在生成动态链接...")
    for auto_fun in AUTOURLS:
        print("正在生成 '"+auto_fun.__name__+"'... ", end='', flush=True)
        try: url = auto_fun()
        except requests.exceptions.RequestException: print("失败！")
        except: print("错误：");traceback.print_exc()
        else:
            if url:
                if isinstance(url, str):
                    sources.append(url)
                elif isinstance(url, (list, tuple, set)):
                    sources.extend(url)
                print("成功！")
            else: print("跳过！")
    print("正在整理链接...")
    sources_final: Union[Set[str], List[str]] = set()
    airports: Set[str] = set()
    for source in sources:
        if source == 'EOF': break
        if not source: continue
        if source[0] == '#': continue
        sub = source
        if sub[0] == '!':
            if LOCAL: continue
            sub = sub[1:]
        if sub[0] == '*':
            isairport = True
            sub = sub[1:]
        else: isairport = False
        if sub[0] == '+':
            tags = sub.split()
            sub = tags.pop()
            sub = ' '.join(tags) + ' ' +raw2fastly(sub)
        else:
            sub = raw2fastly(sub)
        if isairport: airports.add(sub)
        else: sources_final.add(sub)

    if airports:
        print("正在抓取机场列表...")
        for sub in airports:
            print("合并 '"+sub+"'... ", end='', flush=True)
            try:
                res = extract(sub)
            except KeyboardInterrupt:
                print("正在退出...")
                break
            except requests.exceptions.RequestException:
                print("合并失败！")
            except: traceback.print_exc()
            else:
                if isinstance(res, int):
                    print(res)
                else:
                    for url in res:
                        sources_final.add(url)
                    print("完成！")

    print("正在整理链接...")
    sources_final = list(sources_final)
    sources_final.sort()
    sources_obj = [Source(url) for url in (sources_final + AUTOFETCH)]

    print("开始抓取！")
    threads = [threading.Thread(target=_.get, daemon=True) for _ in sources_obj]
    for thread in threads: thread.start()
    for i in range(len(sources_obj)):
        try:
            for t in range(1, FETCH_TIMEOUT[0]+1):
                print("抓取 '"+sources_obj[i].url+"'... ", end='', flush=True)
                try: threads[i].join(timeout=FETCH_TIMEOUT[1])
                except KeyboardInterrupt:
                    print("正在退出...")
                    FETCH_TIMEOUT = (1, 0)
                    break
                if not threads[i].is_alive(): break
                print(f"{t * FETCH_TIMEOUT[1]}s(已等待)", flush=True)
            if threads[i].is_alive():
                print("超时！")
                continue
            res = sources_obj[i].content
            if isinstance(res, int):
                if res < 0: print("抓取失败！")
                else: print(res)
            else:
                print("正在合并... ", end='', flush=True)
                try:
                    merge(sources_obj[i], sourceId=i)
                except KeyboardInterrupt:
                    print("正在退出...")
                    break
                except:
                    print("失败！")
                    traceback.print_exc()
                else: print("完成！")
            for exc in sources_obj[i].exc_queue:
                print(exc)
            sources_obj[i].exc_queue = []
        except KeyboardInterrupt:
            print("正在退出...")
            break

    if STOP:
        merged = {}
        for nid, nd in enumerate(STOP_FAKE_NODES.splitlines()):
            merged[nid] = Node(nd)

    elif NAME_SHOW_SRC:
        for hashp, p in merged.items():
            if hashp in used:
                src = ','.join([str(_) for _ in sorted(list(used[hashp]))])
                p.data['name'] = src+'|'+p.data['name']

    print("\n正在写出 V2Ray 订阅...")
    txt = ""
    unsupports = 0
    url_unsupported = 0
    url_failed = 0
    for hashp, p in merged.items():
        try:
            if p.supports_ray():
                try:
                    txt += p.url + '\n'
                except UnsupportedType:
                    url_unsupported += 1
                except Exception:
                    url_failed += 1
                else:
                    None
            else:
                unsupports += 1
        except Exception:
            url_failed += 1
            traceback.print_exc()
    # unknown（解析失败的原始串）不再写进订阅：未校验的脏数据不落盘
    total_invalid = sum(invalid_stats.values())
    print(f"共有 {len(merged)-unsupports} 个正常节点，{len(unknown)} 个无法解析的节点，共",
            len(merged)+len(unknown),f"个。{unsupports} 个节点不被 V2Ray 支持。")
    if total_invalid:
        detail = "、".join(f"{k} {v}" for k, v in sorted(invalid_stats.items(), key=lambda x: -x[1]))
        print(f"已剔除无效节点 {total_invalid} 个：{detail}")
        if invalid_samples:
            print("  样例：" + "；".join(invalid_samples))
    if url_unsupported or url_failed:
        print(f"未写入 txt：无 url 生成器 {url_unsupported} 个，生成异常 {url_failed} 个")

    # 方案 A：写出前统一清洗孤立代理项，避免 UnicodeEncodeError
    txt = txt.encode('utf-8', 'replace').decode('utf-8')

    with open("list_raw.txt", 'w', encoding="utf-8") as f:
        f.write(txt)
    with open("list.txt", 'w', encoding="utf-8") as f:
        f.write(b64encodes(txt))
    print("写出完成！")

    with open("config.yml", encoding="utf-8") as f:
        conf: Dict[str, Any] = yaml.full_load(f)

    rules: Dict[str, str] = {}
    if DEBUG_NO_ADBLOCK:
        print("!!! 警告：您已关闭对 Adblock 规则的抓取 !!!")
    else:
        merge_adblock(conf['proxy-groups'][-2]['name'], rules)

    snip_conf: Dict[str, Dict[str, Any]] = {}
    ctg_nodes: Dict[str, List[Node.DATA_TYPE]] = {}
    ctg_nodes_meta: Dict[str, List[Node.DATA_TYPE]] = {}
    categories: Dict[str, List[str]] = {}
    try:
        snip_conf = conf['NoMoreWalls']
    except KeyError:
        print("未设置片段配置：", file=sys.stderr)
        traceback.print_exc()
    else:
        del conf['NoMoreWalls']
        # ----- DEBUG: 打印 categories_disp -----
        print("\n[DEBUG] categories_disp content:")
        for k, v in snip_conf.get('categories_disp', {}).items():
            print(f"  {k} -> {v}")
        # -----------------------------------------
        print("正在按地区分类节点...")
        categories = snip_conf['categories']
        for ctg in categories:
            ctg_nodes[ctg] = []
            ctg_nodes_meta[ctg] = []
        for node in merged.values():
            if node.supports_meta():
                ctgs: List[str] = []
                for ctg, keys in categories.items():
                    for key in keys:
                        if key in node.name:
                            ctgs.append(ctg)
                            break
                    if ctgs and keys[-1] == 'OVERALL':
                        break
                if len(ctgs) == 1:
                    try:
                        if node.supports_clash():
                            ctg_nodes[ctgs[0]].append(node.clash_data)
                        ctg_nodes_meta[ctgs[0]].append(node.clash_data)
                    except Exception:
                        traceback.print_exc()
        # ----- DEBUG: 打印各分类节点数 -----
        print("\n[DEBUG] ctg_nodes_meta keys and node counts:")
        for ctg, nodes in ctg_nodes_meta.items():
            print(f"  {ctg}: {len(nodes)} nodes")
        # ------------------------------------
        for ctg, proxies in ctg_nodes.items():
            dump_yaml("snippets/nodes_"+ctg+".yml", {'proxies': proxies})
        for ctg, proxies in ctg_nodes_meta.items():
            dump_yaml("snippets/nodes_"+ctg+".meta.yml", {'proxies': proxies})

    print("正在写出 Clash & Meta 订阅...")
    keywords: List[str] = []
    suffixes: List[str] = []
    match_rule = None
    for rule in conf['rules']:
        rule: str
        tmp = rule.strip().split(',')
        if len(tmp) == 2 and tmp[0] == 'MATCH':
            match_rule = rule
            break
        if len(tmp) == 3:
            rtype, rargument, rpolicy = tmp
            if rtype == 'DOMAIN-KEYWORD':
                keywords.append(rargument)
            elif rtype == 'DOMAIN-SUFFIX':
                suffixes.append(rargument)
        elif len(tmp) == 4:
            rtype, rargument, rpolicy, rresolve = tmp
            rpolicy += ','+rresolve
        else: print("规则 '"+rule+"' 无法被解析！"); continue
        for kwd in keywords:
            if kwd in rargument and kwd != rargument:
                break
        else:
            for sfx in suffixes:
                if ('.'+rargument).endswith('.'+sfx) and sfx != rargument:
                    break
            else:
                k = rtype+','+rargument
                if k not in rules:
                    rules[k] = rpolicy
    conf['rules'] = [','.join(_) for _ in rules.items()]+[match_rule]

    # Clash & Meta
    global_fp: Optional[str] = conf.get('global-client-fingerprint', None)
    proxies: List[Node.DATA_TYPE] = []
    proxies_snip: List[Node.DATA_TYPE] = []
    proxies_meta: List[Node.DATA_TYPE] = []
    proxies_meta_snip: List[Node.DATA_TYPE] = []
    ctg_base: Dict[str, Any] = conf['proxy-groups'][3].copy()
    names_clash: Union[Set[str], List[str]] = set()
    names_clash_meta: Union[Set[str], List[str]] = set()
    for p in merged.values():
        if p.supports_meta():
            clash_data = p.clash_data
            clash_data_snip = clash_data.copy()
            if ('client-fingerprint' in clash_data and
                    clash_data['client-fingerprint'] == global_fp):
                del clash_data['client-fingerprint']
            if p.supports_clash():
                proxies.append(clash_data)
                proxies_snip.append(clash_data_snip)
                names_clash.add(p.data['name'])
            proxies_meta.append(clash_data)
            proxies_meta_snip.append(clash_data_snip)
            names_clash_meta.add(p.data['name'])
    names_clash = list(names_clash)
    names_clash_meta = list(names_clash_meta)
    conf_meta = copy.deepcopy(conf)

    # Clash
    conf['proxies'] = proxies
    for group in conf['proxy-groups']:
        if not group['proxies']:
            group['proxies'] = names_clash
    if snip_conf:
        conf['proxy-groups'][-1]['proxies'] = []
        ctg_selects: List[str] = conf['proxy-groups'][-1]['proxies']
        ctg_disp: Dict[str, str] = snip_conf['categories_disp']
        # ----- DEBUG: Clash 部分添加前 -----
        print("\n[DEBUG] Before adding region groups (Clash):")
        existing_names = [g.get('name') for g in conf['proxy-groups']]
        print("  Existing group names:", existing_names)
        print("  ctg_disp keys and values:")
        for k, v in ctg_disp.items():
            print(f"    {k} -> {v}")
        # ------------------------------------
        for ctg, payload in ctg_nodes.items():
            if ctg in ctg_disp:
                disp = ctg_base.copy()
                disp['name'] = ctg_disp[ctg]
                # ----- DEBUG: 添加前检查 -----
                print(f"  [DEBUG] About to add group: {disp['name']} (from ctg={ctg})")
                if disp['name'] in existing_names:
                    print(f"    ⚠️ DUPLICATE DETECTED! '{disp['name']}' already exists in proxy-groups.")
                else:
                    print(f"    ✅ New group name.")
                # ----- DEBUG: 打印原始 proxies -----
                if not payload:
                    proxy_list = ['REJECT']
                else:
                    proxy_list = [_['name'] for _ in payload]
                print(f"    [DEBUG] original proxies list (first 5): {proxy_list[:5]}")
                # 过滤自身及已有组名
                group_names = [g.get('name') for g in conf['proxy-groups']]
                exclude = set(group_names)
                exclude.add(disp['name'])
                if payload:
                    filtered_names = [name for name in proxy_list if name not in exclude]
                    print(f"    [DEBUG] filtered proxies list (first 5): {filtered_names[:5]}")
                    if len(filtered_names) < len(proxy_list):
                        print(f"    [DEBUG] Removed {len(proxy_list)-len(filtered_names)} conflicting names.")
                    if not filtered_names:
                        filtered_names = ['REJECT']
                else:
                    filtered_names = ['REJECT']
                disp['proxies'] = filtered_names
                conf['proxy-groups'].append(disp)
                ctg_selects.append(disp['name'])
                existing_names.append(disp['name'])
    try:
        dns_mode: Optional[str] = conf['dns']['enhanced-mode']
    except:
        dns_mode: Optional[str] = None
    else:
        conf['dns']['enhanced-mode'] = 'fake-ip'

    # ----- 通用过滤：对所有 url-test 和 fallback 组，移除所有组名 -----
    print("\n[DEBUG] General filtering for url-test and fallback groups (Clash):")
    all_group_names = set(g['name'] for g in conf['proxy-groups'])
    for g in conf['proxy-groups']:
        if g.get('type') in ('url-test', 'fallback'):
            original = g.get('proxies', [])
            if isinstance(original, list):
                filtered = [p for p in original if p not in all_group_names]
                g['proxies'] = filtered
                removed = len(original) - len(filtered)
                if removed:
                    print(f"  [DEBUG] Group '{g['name']}' removed {removed} group-name elements")
    # ------------------------------------------------

    renamed = dedupe_group_names(conf)
    if renamed:
        print(f"节点名与策略组名冲突，已改名 {renamed} 个（否则 mihomo 拒绝加载）")
    with open("list.yml", 'w', encoding="utf-8") as f:
        f.write(datetime.datetime.now().strftime('# Update: %Y-%m-%d %H:%M\n'))
        f.write(yaml_dumps(conf))
    with open("snippets/nodes.yml", 'w', encoding="utf-8") as f:
        f.write(yaml_dumps({'proxies': proxies_snip} ))

    # Meta
    conf = conf_meta
    conf['proxies'] = proxies_meta
    for group in conf['proxy-groups']:
        if not group['proxies']:
            group['proxies'] = names_clash_meta
    if snip_conf:
        conf['proxy-groups'][-1]['proxies'] = []
        ctg_selects: List[str] = conf['proxy-groups'][-1]['proxies']
        ctg_disp: Dict[str, str] = snip_conf['categories_disp']
        # ----- DEBUG: Meta 部分添加前 -----
        print("\n[DEBUG] Before adding region groups (Meta):")
        existing_names = [g.get('name') for g in conf['proxy-groups']]
        print("  Existing group names:", existing_names)
        print("  ctg_disp keys and values:")
        for k, v in ctg_disp.items():
            print(f"    {k} -> {v}")
        # ------------------------------------
        for ctg, payload in ctg_nodes_meta.items():
            if ctg in ctg_disp:
                disp = ctg_base.copy()
                disp['name'] = ctg_disp[ctg]
                # ----- DEBUG: 添加前检查 -----
                print(f"  [DEBUG] About to add group: {disp['name']} (from ctg={ctg})")
                if disp['name'] in existing_names:
                    print(f"    ⚠️ DUPLICATE DETECTED! '{disp['name']}' already exists in proxy-groups.")
                else:
                    print(f"    ✅ New group name.")
                # ----- DEBUG: 打印原始 proxies -----
                if not payload:
                    proxy_list = ['REJECT']
                else:
                    proxy_list = [_['name'] for _ in payload]
                print(f"    [DEBUG] original proxies list (first 5): {proxy_list[:5]}")
                # 过滤自身及已有组名
                group_names = [g.get('name') for g in conf['proxy-groups']]
                exclude = set(group_names)
                exclude.add(disp['name'])
                if payload:
                    filtered_names = [name for name in proxy_list if name not in exclude]
                    print(f"    [DEBUG] filtered proxies list (first 5): {filtered_names[:5]}")
                    if len(filtered_names) < len(proxy_list):
                        print(f"    [DEBUG] Removed {len(proxy_list)-len(filtered_names)} conflicting names.")
                    if not filtered_names:
                        filtered_names = ['REJECT']
                else:
                    filtered_names = ['REJECT']
                disp['proxies'] = filtered_names
                conf['proxy-groups'].append(disp)
                ctg_selects.append(disp['name'])
                existing_names.append(disp['name'])
    if dns_mode:
        conf['dns']['enhanced-mode'] = dns_mode

    # ----- 通用过滤：对所有 url-test 和 fallback 组，移除所有组名 -----
    print("\n[DEBUG] General filtering for url-test and fallback groups (Meta):")
    all_group_names = set(g['name'] for g in conf['proxy-groups'])
    for g in conf['proxy-groups']:
        if g.get('type') in ('url-test', 'fallback'):
            original = g.get('proxies', [])
            if isinstance(original, list):
                filtered = [p for p in original if p not in all_group_names]
                g['proxies'] = filtered
                removed = len(original) - len(filtered)
                if removed:
                    print(f"  [DEBUG] Group '{g['name']}' removed {removed} group-name elements")
    # ------------------------------------------------

    # ----- DEBUG: 写入前打印最终 proxy-groups 摘要 -----
    print("\n[DEBUG] Final proxy-groups in Meta (names and proxies first 3):")
    for g in conf['proxy-groups']:
        proxies_show = g.get('proxies', [])
        if isinstance(proxies_show, list):
            proxies_show = proxies_show[:3]
        print(f"  {g.get('name')}: {proxies_show}")

    # ----- 打印特殊组完整列表 -----
    print("\n[DEBUG] Full proxies list for special groups:")
    for g in conf['proxy-groups']:
        if g.get('name') in ['♻ 自动选择', '🔰 延迟最低', '✅ 手动选择']:
            print(f"  {g.get('name')}: {g.get('proxies', [])}")

    # ----- 全面冲突检查 -----
    print("\n[DEBUG] Detailed check for group-name conflicts in all proxies:")
    all_group_names = set(g.get('name') for g in conf['proxy-groups'])
    for g in conf['proxy-groups']:
        gname = g.get('name')
        proxies = g.get('proxies', [])
        if isinstance(proxies, list):
            for p in proxies:
                if p in all_group_names and p != gname:
                    print(f"  ⚠️⚠️ CONFLICT: group '{gname}' has proxy '{p}' which is also a group name.")
    # ------------------------------------------------

    renamed = dedupe_group_names(conf)
    if renamed:
        print(f"[meta] 节点名与策略组名冲突，已改名 {renamed} 个")
    with open("list.meta.yml", 'w', encoding="utf-8") as f:
        f.write(datetime.datetime.now().strftime('# Update: %Y-%m-%d %H:%M\n'))
        f.write(yaml_dumps(conf))
    with open("snippets/nodes.meta.yml", 'w', encoding="utf-8") as f:
        f.write(yaml_dumps({'proxies': proxies_meta_snip}))

    if snip_conf:
        print("正在写出配置片段...")
        name_map: Dict[str, str] = snip_conf['name-map']
        snippets: Dict[str, List[str]] = {}
        for rpolicy in name_map.values(): snippets[rpolicy] = []
        for rule, rpolicy in rules.items():
            if ',' in rpolicy: rpolicy = rpolicy.split(',')[0]
            if rpolicy in name_map:
                snippets[name_map[rpolicy]].append(rule)
        for name, payload in snippets.items():
            with open("snippets/"+name+".yml", 'w', encoding="utf-8") as f:
                yaml.dump({'payload': payload}, f, allow_unicode=True)

        with open("snippets/example.yml", encoding="utf-8") as f:
            template: Dict[str, Any] = yaml.full_load(f)
        template = {
            k: v for k,v in template.items()
            if k in ('dns', 'proxy-groups', 'rule-providers', 'rules')
        }
        for group in template['proxy-groups']:
            group: Dict[str, Any]
            if 'use' in group:
                del group['use']
                group['include-all'] = True
        with open("snippets/rules_online.yml", 'w', encoding="utf-8") as f:
            yaml.dump(template, f, allow_unicode=True)

        del template['rule-providers']
        template['rules'] = conf['rules']
        with open("snippets/rules.yml", 'w', encoding="utf-8") as f:
            yaml.dump(template, f, allow_unicode=True)

    print("正在写出统计信息...")
    out = "序号,链接,节点数\n"
    for i, source in enumerate(sources_obj):
        out += f"{i},{source.url},"
        try: out += f"{len(source.sub)}"
        except: out += '0'
        out += '\n'
    out += f"\n总计,,{len(merged)}\n"
    open("list_result.csv",'w',errors='replace').write(out)

    print("写出完成！")

if __name__ == '__main__':
    from dynamic import AUTOURLS, AUTOFETCH
    main()
#（注：内容由AI生成）
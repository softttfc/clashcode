#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# =============================================================================
# crawler_pro2.py 说明
# =============================================================================
#
# 一、功能
# -----------------------------------------------------------------------------
# 网页爬虫 + 订阅解析 + 节点测通 + Clash 配置生成。
# 支持 11 种协议：vmess / vless / ss / ssr / trojan /
#               hysteria / hysteria2 / tuic / http / https / socks5
#
# 二、本次修改内容（协议扩展 + 隐患修复）
# -----------------------------------------------------------------------------
# 1. 新增解析函数：
#    parse_ssr / parse_hysteria2 / parse_hysteria / parse_tuic / parse_http_socks
# 2. 新增 QUIC 握手测试（修复 UDP 协议节点被 TCP 测通误杀）：
#    - test_quic_for_crawler / _quic_handshake_async
#    - UDP_TYPES 中的协议不做 TCP 测通，改走 QUIC 握手
#    - aioquic 未安装时保守保留节点，不误杀
# 3. 新增 clean_ipv6()：TCP / QUIC 测试前去除 IPv6 方括号
# 4. NODE_PREFIXES 全局常量：统一 Base64 解码、按行解析、raw 回退的前缀判断
# 5. node_link_regex 扩展：网页内嵌节点链接可识别新协议
# 6. 名称生成加协议前缀：避免不同协议同 server 节点重名
# 7. skip-cert-verify 字段统一：
#    - 解析时同时保留 allowInsecure（兼容）+ skip-cert-verify（标准）
#    - 输出时统一判断 skip-cert-verify
# 8. alpn 类型统一：解析存字符串，输出转列表
# 9. vless reality-opts 补全：pbk / sid / fp
# 10. hysteria2 多端口支持：443,8443 形式
#
# 三、URL 识别策略（本次新增）
# -----------------------------------------------------------------------------
# 本脚本对节点 URL 采用分级识别策略，平衡覆盖率和误判率：
#
# 【第一层】无条件识别（误判率接近 0）：
#     vmess:// / vless:// / ss:// / ssr:// / trojan://
#     hysteria:// / hysteria2:// / hy2:// / tuic://
#     socks5:// / socks5h:// / socks://
#
# 【第二层】严格识别（误判率 < 1%）：
#     http:// / https:// 满足以下任一条件时识别为代理：
#       A1: 有认证信息 user:pass@ + 无路径（或路径为 /）
#       A2: 有认证信息 user:pass@ + 有显式端口 + 无查询参数
#
# 【第三层】不识别：
#     其他 http:// / https:// URL（视为网页 URL）
#
# 实现要点：
#   - NODE_PREFIXES 用于第一层的 Base64 解码和按行解析
#   - HTTP_PREFIXES 单独处理，需经过 is_definitely_proxy_url 校验
#   - node_link_regex（网页抓取）不包含 http/https，避免网页 URL 污染
#   - parse_subscription_content（订阅解析）中 http/https 需校验
#
# 四、原有逻辑保持不变
# -----------------------------------------------------------------------------
# - Crawler 类爬取逻辑、process_sources 通配符处理、download_subscription
# - fetch_content / fetch_binary
# - nodes_to_clash_yaml / nodes_to_base64 主流程
# - 原有 4 种协议的解析、去重、导出分支
#
# =============================================================================
# 五、本次增量增强（三级降级 + 黑名单 + URL 规范化）
# -----------------------------------------------------------------------------
# 【新增 A】全局黑名单 BLACKLIST_SEGMENTS
#    - 路径段完整匹配（非子串），命中则跳过打开
#    - 订阅后缀（.yaml/.yml/.txt/.b64/.json）优先放行
#    - 函数：is_blacklisted()
#
# 【新增 B】URL 规范化 normalize_url()
#    - scheme/host 小写、去默认端口、去 fragment、query 排序、去尾斜杠
#    - 供 enqueue / _process_url 使用，避免同一 URL 不同写法重复打开
#
# 【新增 C】字段列表文本解析器 parse_field_list_text()
#    - 识别 "Type: VLESS\nServer: ...\nPort: ..." 这类纯文本节点卡片
#    - 辅助函数：_parse_field_block / _fields_to_node / 常量 _FIELD_ALIAS
#    - 适用 v2nodes.com/servers/xxx/ 这类页面
#
# 【新增 D】三级降级统一入口 Crawler._process_url()
#    - [1] 订阅解析（parse_subscription_content）→ 成功即 return
#    - [2] 字段列表解析（parse_field_list_text）→ 成功则继续 [3]
#    - [3] 网页解析（parse_page，递归找关键词/通配符链接）
#
# 【修改 E】Crawler.enqueue()：入口 URL 规范化（新增 1 行）
# 【修改 F】Crawler.parse_page()：源 1 / 源 2 命中 is_node_link 后仅入队
#              （并前置黑名单检查），由主循环统一走 _process_url
# 【修改 G】Crawler.crawl()：起点 + 主循环统一改调 _process_url
#
# 说明：download_subscription 保留为 legacy，主流程不再调用但保留供外部使用
# =============================================================================
# 六、本次新增（并行并集属性提取器）
# -----------------------------------------------------------------------------
# 【新增 H】属性提取器配置（EXTRACTOR_MODE / _URL_ATTRS / _ATTR_SKIP_TAGS 等）
#    用于抓取藏在 HTML 属性 / 文本容器 / 脚本里的 URL，例如：
#      - v2nodes.com 订阅链接：<input value="https://...">
#      - v2nodes.com 节点文本：<textarea readonly>vless://...</textarea>
#      - 结构化数据：<script type="application/ld+json">{...}</script>
#
# 【新增 I】3 个独立提取器函数：
#    - _extract_from_attrs()          属性型（input value / button data-config / meta content）
#    - _extract_from_text_containers() 文本容器型（textarea / code / pre / kbd / samp）
#    - _extract_from_scripts()          脚本型（JSON-LD / SSR state）
#    三者无条件全跑（union 模式），结果并集去重
#
# 【新增 J】Crawler._run_attribute_extractors() 调度器
#    与 parse_page 并列，独立错误隔离，走相同过滤链
#
# 【修改 K】Crawler._process_url() 的 [3] 分支加 4 行挂钩
#    调用新增的 _run_attribute_extractors
# =============================================================================
# 七、本次修复（关键修复）
# -----------------------------------------------------------------------------
# 【修复 L】补全 parse_trojan() 函数
#    - 之前 parse_node_link 调用了 parse_trojan 但函数未定义
#    - 导致所有 trojan:// 节点解析报 "name 'parse_trojan' is not defined"
#    - 修复：在 parse_ssr 之后补上函数定义
#
# 【修复 M】属性提取器协议链接分流
#    - 之前 _run_attribute_extractors 把所有 URL（含 vless:// 等协议链接）
#      都 enqueue，导致：
#        1. 浪费请求配额（fetch_binary("vless://...") 必然失败）
#        2. 与"协议链接直接解析"原则冲突
#    - 修复：命中 NODE_PREFIXES 的 URL 直接 parse_node_link 加入 all_nodes，
#      不再 enqueue；只有网页 URL 才 enqueue
#
# 【已取消】语言子域跳过（原【修复 N】）
#    - 原设想：v2nodes.com 有 it/id/jv/ko/fr/de/... 等子域，视为"语言副本"跳过
#    - 实际情况：这些子域是**不同国家的独立入口**，各自挂载不同国家的节点，
#               内容互不相同，跳过会漏掉该国节点池
#    - 结论：完全取消该逻辑，保留所有子域的抓取
#    - 去重由 normalize_node_key() 在节点级别处理，不在 URL 级别拦截
#
# 【修复 Q】订阅后缀直接处理 + 软上限
#    Q1：_run_attribute_extractors 增加"有订阅后缀立即处理"分支
#        后缀命中（.txt/.yaml/.yml/.b64/.base64/.conf）→ 直接 _process_url
#        不再占用队列槽位，不被 MAX_REQUESTS 截断
#    Q2：MAX_REQUESTS 改为"软上限"
#        - enqueue 仍然拒绝超过 400 后的新 URL（防止无限增长）
#        - 但 _process_url 不再检查上限
#        - crawl 主循环改为 while self.queue（不检查 request_count）
#        - 结果：已入队 URL 全部处理完，不再丢节点
#        - 实际请求数可能达 400-500，队列只出不进必然清空
#    Q3：enqueue 返回 bool，让调用方知道是否真正入队
#        - 解决日志误导：之前 _run_attribute_extractors 在 enqueue 被拒后
#          仍无条件打印 "[ATTR] queued"，看起来像"超 400 还在入队"
#        - 修复：enqueue 返回 True/False；只有成功才计数和 print
#        - 影响点：
#            * Crawler.enqueue 返回值改为 bool
#            * _run_attribute_extractors 调用点改为 if self.enqueue(...): 才计数
#            * parse_page 调用点忽略返回值（可选：调试时打印拒绝信息）
# =============================================================================
# 八、本次修改（订阅后缀直通 + 入队顺序调整）
# -----------------------------------------------------------------------------
# 【修改 R】parse_page() 里 is_node_link 命中后的分流：
#    - 之前：所有 is_node_link 命中的 URL 统一 enqueue
#    - 问题：request_count 达到 MAX_REQUESTS 后，enqueue 拒绝新 URL，
#            导致 <a> / 页面文本里发现的 .yaml/.txt/.b64/.conf 等订阅链接
#            连队列都进不去，被直接抛弃
#    - 修复：has_subscription_suffix 命中的订阅后缀链接 → 直接 _process_url
#            其余网页 URL → enqueue
#    - 影响点：
#        * parse_page() 里 <a href> 的 is_node_link 分支加订阅后缀判断
#        * parse_page() 里页面文本的 is_node_link 分支加订阅后缀判断
#    - 和 _run_attribute_extractors 的分流逻辑保持一致（Q1）
#
# 【修改 S】crawl() 调整入队顺序：
#    - 之前：先处理 direct_urls，再入队 plain_pages / wildcard_map
#    - 问题：direct_urls 不经过 enqueue，但会消耗 request_count，
#            数量多时把 request_count 推到 MAX_REQUESTS 以上，
#            后面的 plain_pages / wildcard_map 在 enqueue 时被闸门拦住
#    - 修复：先入队 plain_pages / wildcard_map（此时 request_count=0，
#            全部入队成功），再处理 direct_urls
#    - 结果：direct_urls 即使把 request_count 推到 400 以上，
#            已入队的普通页面仍会被主循环处理完（主循环不检查 request_count）
#    - 注：本版本已被【修改 T】的"每源独立处理"逻辑取代，
#          "普通页面优先于直接订阅"的语义在 sources 组装顺序中保留。
# =============================================================================
# 九、本次修改（每源独立配额 + 每源队列上限 + 全局硬上限）
# -----------------------------------------------------------------------------
# 【修改 T】MAX_REQUESTS 从"全局总请求数上限"改为"每源请求数上限"，并新增两参数：
#    - MAX_REQUESTS_PER_SOURCE：每源请求数上限（一次性触发）
#    - MAX_QUEUE_PER_SOURCE：每源队列占用上限（持续检查，必须 > 上一参数）
#    - MAX_REQUESTS_TOTAL：全局总请求数硬上限（所有源累计，达到后跳过剩余源）
#
# 【修改 T】crawl() 重写：从"全局一个队列"改为"每个源独立处理"：
#    - 旧逻辑：全局一个 queue + 一个 request_count，所有源混在一起。
#              direct_urls 先跑，会挤占 plain_pages / wildcard_map 的入队配额。
#    - 新逻辑：每个源独立处理，每源有自己的 queue 和 request_count。
#              处理完一个源的所有 URL（含剩余队列）后，再切换到下一个源。
#              visited_urls 跨源共享，不重复处理。
#              MAX_REQUESTS_PER_SOURCE 控制每源请求数（一次性触发）。
#              MAX_QUEUE_PER_SOURCE 控制每源队列占用（持续检查）。
#              MAX_REQUESTS_TOTAL 控制全局总量（达到后跳过剩余源）。
#    - 组装源（保持【修改 S】"普通页面优先于直接订阅"的语义）：
#              plain_pages 带 wildcard 绑定 → wildcard_map 未绑定项 →
#              direct_urls 独立源
#    - 队列里的 URL 走完整 _process_url（含 parse_page），
#      订阅后缀直通和协议链接直接解析不受上限影响，继续生效。
#    - 全局硬上限在当前源 while 循环内也会检查，避免单源超发过多。
#    - 被跳过或被全局上限中断的源都打印统计日志。
#
# 【修改 T】enqueue() 的双重检查：
#    - request_count >= MAX_REQUESTS_PER_SOURCE → 永久拒绝（一次性触发）
#    - len(queue) >= MAX_QUEUE_PER_SOURCE        → 暂时拒绝（消费到低于上限后恢复）
#
# 【修改 T】_process_url() 计数：
#    - request_count += 1（每源计数，每源重置）
#    - total_requests += 1（全局累计，永不重置）
#    - 软上限日志阈值从 > 改为 >=（request_count=400 时也显示队列残留）
#
# 【修改 T】download_subscription()（legacy）同步加 total_requests 计数，
#          日志引用 MAX_REQUESTS_PER_SOURCE。
# =============================================================================
# 十、本次修改（HTTP(S) 链接拼接说明文字的边界裁剪）
# -----------------------------------------------------------------------------
# 【修复 U】clean_url() 增加 HTTP(S) 链接的分层边界裁剪：
#    - 问题：页面正文 soup.get_text() 提取时，"https://.../xxx.txt复制Clash"
#            这类"URL + 锚文本/说明文字"拼接导致 404
#    - 只对 http:// / https:// 链接处理：
#        * 节点协议链接（vmess:// / vless:// 等）通常放在 <textarea>/<input>/
#          <script> 里，DOM 提取天然干净，不拼接
#        * vless/trojan 等协议含 ? 和 query 参数，强行裁剪容易误杀
#        * ss:// / ssr:// 结构不统一，无法通用裁剪
#    - 分层处理（按顺序）：
#        L3: RFC 非法字符边界（中文/全角/空格）→ 截断
#        L4: 订阅后缀边界（.txt/.yaml 等后跟非 ?#/）→ 截断
#    - 保护措施：
#        * 后缀后是 ? / # → 保留（合法 query/fragment）
#        * 后缀后是 / → 保留（后缀在路径中间）
#        * rfind 取最右侧后缀，避免路径中恰好含后缀字符串
#        * .json 不在裁剪列表（.json-backup / .jsonl 可能误伤）
#    - 影响点：只有 clean_url() 一个函数，函数签名不变，
#              6 处调用点全不用改。
#    - 潜在误杀（概率极低）：
#        * URL 里未编码空格：本应编码成 %20，未编码的 URL 本身就是坏的
#        * 中文路径：实际 URL 里中文已被 %XX 编码，不会到这里
#        * .json-backup / .jsonl：已从后缀列表中移除 .json，避免误伤
# =============================================================================
# 十一、本次修改（最后一层订阅直通 + URL/Last-Modified 日期过滤）
# -----------------------------------------------------------------------------
# 【修改 V】最后一层网页订阅直通（方案 B）：
#    - 之前：depth >= MAX_DEPTH 时直接打印 "stop expanding"，不再调用
#            parse_page / _run_attribute_extractors，导致最后一层页面里
#            的 .yaml/.txt/.b64 订阅链接全部丢弃
#    - 修复：给 parse_page() 和 _run_attribute_extractors() 增加 allow_expand 参数
#            - allow_expand=True（中间层）：行为完全不变
#            - allow_expand=False（最后一层）：仍然扫描页面，但只提取订阅后缀
#              和协议链接；普通网页 URL 一律不入队
#    - 影响点：
#        * _process_url() 的 [3] else 分支改为调 parse_page(allow_expand=False) /
#          _run_attribute_extractors(allow_expand=False)
#        * parse_page() 签名加 allow_expand=True；5 处入队判断加 and allow_expand
#        * _run_attribute_extractors() 签名加 allow_expand=True；1 处入队判断加条件
#    - 保护措施：
#        * 默认参数 allow_expand=True 保证向后兼容，中间层行为 100% 不变
#        * 订阅后缀直通和协议链接直接解析在 allow_expand 判断之前，
#          无论 True/False 行为一致
#        * MAX_DEPTH 解耦：判断用 depth < MAX_DEPTH 和 else，改 3/4/5 都自动适配
#
# 【新增 W】URL 日期过滤（方案 1，零成本）：
#    - 问题：早期网页里的节点大多已失效，爬取浪费请求配额
#    - 修复：在 enqueue() 前判断 URL 是否含日期，太老直接拒绝入队
#    - 日期模式（按 full > month > month-day 优先级）：
#        * full（年-月-日）：/2026/08/15/、/20260815/、?date=2026-08-15
#        * month（年月）：/2026/08/、/2026-08/
#        * month-day（月日）：/08/15/、/08-15/（拼接当年 + 未来保护）
#        * year（年）：删除（误判率高，一律放行）
#    - 判断规则：
#        * full：date < URL_DATE_MIN → 丢弃
#        * month：该月最后一天 < URL_DATE_MIN → 丢弃（整月在窗口外才丢弃）
#        * month-day：拼接当年 → 与 URL_DATE_MIN 比较；拼接结果在未来 → 放行
#        * 无日期 / 日期非法 → 放行
#    - 归档页判断：
#        * /2024/09/27/（日归档）→ full，直接比较
#        * /2024/09/（月归档）→ month，取最后一天比较
#        * /2024/（年归档）→ 无匹配（year 模式已删除），放行
#
# 【新增 X】Last-Modified 日期过滤（方案 3，fetch 后）：
#    - 问题：URL 不含日期的页面无法通过方案 1 判断
#    - 修复：fetch 后看 Last-Modified，明确太老则跳过解析
#    - 四条放行规则：
#        * URL 含日期 → 放行（方案 1 已处理）
#        * 订阅后缀 → 豁免（Last-Modified 老不代表订阅节点失效）
#        * 无 Last-Modified header → 放行
#        * Last-Modified 解析失败 → 放行
#    - 只对"明确太老"的丢弃，其他情况一律放行（保守策略）
#    - 新增 fetch_with_headers()，只 _process_url 使用；
#      fetch_binary() 保持不动，其他调用点不受影响
#
# 【新增 Y】分三阶段上线的开关：
#    - URL_DATE_FILTER_ENABLED：方案 1 总开关
#    - URL_DATE_FILTER_LAST_MOD_ENABLED：方案 3 总开关
#    - 灰度时设 False，观察后再开启
# =============================================================================
# 十二、本次修改（L1 + L2：日期过滤日志优化，零业务影响）
# -----------------------------------------------------------------------------
# 【L1】enqueue() 日期拒绝时打印原因：
#    - 原代码：is_url_too_old(url) 返回 False 时静默 return False
#    - 新代码：增加 1 行 print(f"  -> [DATE] enqueue rejected (too old): {url}")
#    - 影响：业务零影响，仅日志多一行，方便排查"为什么没入队"
#
# 【L2】parse_page() 两处 wildcard 分支：is_url_too_old 提前到 print 之前：
#    - 原代码：先 print("Found wildcard-matched ...")，再判断 depth/allow_expand
#      → 过期 URL 仍会打印，容易让人误以为"打印了 = 入队了"
#    - 新代码：先 is_url_too_old(url)，过期直接 continue/break，不打印
#    - 影响：业务零影响（过期 URL 本来就不会入队），仅日志更干净
#    - 涉及两处：
#        * <a href> wildcard 分支（+2 行）
#        * 页面文本 wildcard 分支（+2 行）
#
# 总改动：5 行新增，零业务影响。
# =============================================================================

import os
import sys
import requests
import re
import yaml
import base64
import json
import socket
import asyncio
from urllib.parse import urljoin, urlparse, parse_qs, unquote
from datetime import datetime, timedelta
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from bs4 import BeautifulSoup
import time
import hashlib

#直接订阅	以 .yaml / .yml / .txt 结尾	直接下载，不爬取	https://example.com/sub.yaml → 立即下载并解析节点
#普通页面	不含 *，且非直接订阅	作为爬取起点（深度=1），可绑定通配符	https://example.com/index → 入队，patterns 可能来自通配符绑定
#通配符项	含 *	不单独入队，而是与普通页面绑定；若无法绑定则自身作为起点	https://example.com/api/*/list → 
#             可能绑定到 https://example.com/api/v2/list（若存在），否则自身 https://example.com/api/ 作为起点
#动态日期	以 +date 开头	格式化后按上述规则继续分类	+date https://example.com/%Y%m%d → 2026-08-15 → https://example.com/20260815
# ======================== 全局配置（可调参数） ========================
# 爬虫控制
MAX_DEPTH = 4               # 爬取深度（从起始页算起）。增大可发现更多链接，但增加请求数。建议 2~5

MAX_REQUESTS_PER_SOURCE = 300    # 每个起点源的请求数上限（一次性触发）。
                                  # 达到后停止入队，消费完剩余队列后结束该源。
                                  # 建议 200~500；太大单源耗时长，太小节点覆盖不足。

MAX_QUEUE_PER_SOURCE = 450       # 每个起点源的队列占用上限（持续检查）。
                                  # 必须 > MAX_REQUESTS_PER_SOURCE，建议取 1.5~2 倍。
                                  # 队列达到上限时暂时拒绝入队，消费到低于上限后恢复。
                                  # 作用：防止单源派生过多链接时队列无限膨胀。

MAX_REQUESTS_TOTAL = 8000        # 全局总请求数硬上限（所有源累计）。
                                  # 达到后跳过 crawler.list 中剩余未处理的源。
                                  # 建议 1500~3000，按 CI 时间预算调整：
                                  #   - 源少（< 10）且时间充裕：3000~4000
                                  #   - 源中等（10~50）：2000~3000
                                  #   - 源多（> 50）或 CI 时间紧：1000~1500
                                  # 单请求平均耗时 1~3 秒，2000 请求约 30~100 分钟。

# ======================== 【本次新增】网页日期过滤（方案 1 + 方案 3） ========================
# 目的：只爬取最近 N 天内的网页，规避早期网页（节点大多已失效）
# 分三阶段上线：
#   阶段 1：URL_DATE_FILTER_ENABLED=False，观察会过滤多少 URL
#   阶段 2：URL_DATE_FILTER_ENABLED=True，LAST_MOD_ENABLED=False
#   阶段 3：LAST_MOD_ENABLED=True
URL_DATE_FILTER_ENABLED = True          # 方案 1 总开关（灰度时设 False）
URL_DATE_FILTER_LAST_MOD_ENABLED = True # 方案 3 总开关（灰度时设 False）
URL_DATE_KEEP_DAYS = 15                 # 只保留最近 N 天内的网页

# 运行时计算（模块级，import 时求值一次）
URL_DATE_MIN = datetime.now() - timedelta(days=URL_DATE_KEEP_DAYS)

    # ---- 订阅关键词（原有 + 扩展）----
KEYWORDS = [
    'subscri',          # subscribe / subscription / subscriptions / subscribing
    'subscribe',        # 显式列出，可读性
    'feed',             # RSS / feed
    # ---- 节点关键词 ----
   # 'node',             # node / nodes
    #'server',           # server / servers
    # ---- 订阅格式后缀 ----
    '.yaml', '.yml',    # Clash 配置
    '.txt',             # 通用订阅
    '.b64', '.base64',  # Base64 订阅
    '.json',            # Clash.Meta / sing-box
    '.conf',            # Clash / Surge
    # ---- 配置类型 / 客户端 ----
  #  'clash', 'mihomo',
    '订阅链接','clashnode',
   # 'singbox', 'sing-box',
   # 'v2ray', 'xray',
   # 'surfboard',
    # ---- 协议名 ----
   # 'vmess', 'vless', 'trojan', 'shadowsocks', 'hysteria', 'tuic',
    # ---- 目录 / 集合（用于递归发现下级）----
   # 'country', 'countries',
    'www.v2nodes.com/country',
    'subscriptions/country',
  #  'region', 'location',
   # 'collect', 'share', 'free',
    # ---- 更新标记 ----
  #  'latest', 'update', 'daily',
]


# 网络请求
REQUEST_TIMEOUT = 15        # HTTP 请求超时（秒）。增大可应对慢速服务器，减小可加快失败检测。建议 15~60
FETCH_RETRIES = 2           # 获取内容失败后的重试次数。建议 2~5
FETCH_DELAY = 2             # 重试间隔（秒）。建议 0.5~2

# 节点测通（TCP 握手）
CONNECT_TIMEOUT = 4         # TCP 握手超时（秒）。增大可减少网络波动误判，但延长总验证时间。建议 3~10
TEST_RETRIES = 2            # 测通失败后的重试次数。建议 1~3
TEST_WORKERS = 10           # 测通并发线程数。增大可加快验证，但可能因资源竞争导致失败率上升。建议 5~20
MAX_DELAY = 3000            # 节点最大可接受延迟（毫秒），超过则丢弃。调低可提高质量，但可能减少节点数。建议 2000~5000

# QUIC 握手测试超时（秒），用于 hysteria / hysteria2 / tuic 等 UDP 协议
# 建议范围: 2~5，过短易误判，过长拖慢 CI
QUIC_TIMEOUT = 2

# 导出文件
OUTPUT_YAML = 'crawclash.yaml'   # Clash 配置文件输出路径
OUTPUT_TXT = 'crawsub.txt'       # Base64 订阅文件输出路径
SOURCE_FILE = 'crawler.list'     # 起始源列表文件路径

# ======================== 协议常量（新增） ========================
# 第一层：无条件识别的节点链接前缀
# 用于 Base64 解码、按行解析、raw 回退判断
NODE_PREFIXES = (
    'vmess://', 'vless://', 'ss://', 'ssr://', 'trojan://',
    'hysteria://', 'hysteria2://', 'hy2://', 'tuic://',
    'socks5://', 'socks5h://', 'socks://',
)

# 第二层：需经过 is_definitely_proxy_url 校验的 http/https 前缀
HTTP_PREFIXES = ('http://', 'https://')

# UDP 协议：不做 TCP 测通，走 QUIC 握手
UDP_TYPES = {'hysteria', 'hysteria2', 'hy2', 'tuic'}

# 节点名称前缀映射（当 ps 为空时用于生成默认名称）
NAME_PREFIX_MAP = {
    'vmess': 'VMess',
    'vless': 'VLESS',
    'ss': 'SS',
    'ssr': 'SSR',
    'trojan': 'Trojan',
    'hysteria': 'HY',
    'hysteria2': 'HY2',
    'tuic': 'TUIC',
    'http': 'HTTP',
    'socks5': 'SOCKS5',
}

# ======================== 【新增 A】全局黑名单 ========================
# 路径段完整匹配（非子串），命中则跳过打开。
# 优先级：黑名单 > KEYWORDS；订阅后缀 .yaml/.yml/.txt/.b64/.json 优先放行。
BLACKLIST_SEGMENTS = {
    # ---- 认证 / 账号 ----
    'login', 'logout', 'signin', 'signup', 'register',
    'auth', 'oauth', 'sso', 'verify',
    'password', 'reset', 'recover',
    'user', 'users', 'profile', 'account', 'accounts', 'settings',
    'admin', 'dashboard', 'panel', 'console', 'manage',
    # ---- 法律 / 信息 ----
    'about', 'contact', 'help', 'faq', 'support', 'feedback',
    'privacy', 'terms', 'tos', 'legal', 'license', 'copyright',
    'disclaimer', 'policy',
    # ---- 内容 / 博客 ----
    'blog', 'news', 'article', 'articles', 'post', 'posts',
    'tag', 'tags', 'category', 'categories', 'archive',
    'comment', 'comments', 'share', 'search',
    # ---- 静态资源 ----
    'css', 'js', 'javascript', 'image', 'images', 'img',
    'static', 'assets', 'asset', 'font', 'fonts', 'icon', 'icons',
    'media', 'video', 'audio', 'upload', 'uploads',
    'favicon', 'robots', 'sitemap', 'manifest',
    # ---- 购物 / 支付 ----
    'cart', 'checkout', 'order', 'orders', 'payment', 'billing',
    'pricing',
    # ---- 其它噪声 ----
    'ads', 'ad', 'banner', 'popup', 'modal',
}

# ======================== 【新增 H】属性提取器配置 ========================
# 目的：抓取藏在 HTML 属性 / 文本容器 / 脚本里的 URL
# 典型场景：
#   - v2nodes.com 订阅链接：<input value="https://...">
#   - v2nodes.com 节点文本：<textarea readonly>vless://...</textarea>
#   - 结构化数据：<script type="application/ld+json">{...}</script>
#
# 设计原则：
#   1. 与 parse_page 的源 1-4 并列，互不影响
#   2. 提取到的 URL 走相同过滤链（visited / 黑名单 / is_node_link）
#   3. 所有提取器无条件全跑（union 模式），零漏检
# ================================================================

# 提取模式（当前只实现 union）
#   'union'  = 所有提取器全跑，结果合并（默认，零漏检）
EXTRACTOR_MODE = 'union'

# ---- 属性白名单：这些属性的值会被尝试提取 URL ----
_URL_ATTRS = (
    # v2nodes 订阅链接
    'data-config',
    # 通用数据属性
    'data-url', 'data-href', 'data-link',
    'data-subscription', 'data-sub', 'data-node',
    # 复制/剪切板按钮
    'data-clipboard-text', 'data-clipboard',
    'data-copy', 'data-copy-text',
    # 资源/嵌入
    'data-src', 'data-original', 'data-download-url', 'src',
    # 标准属性
    'value', 'content',
)

# 属性提取时跳过的标签：
#   a/link       → 避免与 parse_page 源 1 重复
#   script/style → 内容在别处处理，属性多为 src/href 噪声
_ATTR_SKIP_TAGS = {'a', 'link', 'script', 'style'}

# ---- 文本容器型标签（URL 是标签之间的可见文本） ----
_TEXT_CONTAINER_TAGS = ('textarea', 'code', 'pre', 'kbd', 'samp')

# ---- 统一 URL 匹配正则（http(s) + 全部协议链接） ----
_CONTAINER_URL_RE = re.compile(
    r'(?:vmess|vless|ssr|ss|trojan|hysteria2?|hy2|tuic|'
    r'socks5h|socks5|socks|https?)://[^\s<>"\'{}|\\^`\[\]]+',
    re.IGNORECASE,
)

# ======================== 辅助函数（解析与导出） ========================

def clean_url(url):
    """
    URL 清理 + http(s) 链接的分层边界裁剪。

    【修复 U】处理 HTTP(S) 链接后拼接说明文字的问题。
    场景：soup.get_text() 提取时，"https://.../xxx.txt复制Clash"
          链接和锚文本/说明文字之间没有空格，被连在一起。
    影响：has_subscription_suffix 判断时把中文当后缀一部分，404。

    只对 http:// / https:// 链接处理，理由：
      - 节点协议链接（vmess:// / vless:// 等）通常放在 <textarea>/<input>/
        <script> 里，DOM 提取天然干净，不拼接
      - vless/trojan 等协议含 ? 和 query 参数，强行裁剪容易误杀
      - ss:// / ssr:// 结构不统一，无法通用裁剪

    处理策略（按顺序）：
      L3: RFC 非法字符边界
          中文 / 全角 / 空格 → 截断（URL 里未编码这些字符是非法的）
          例：https://a.com/xxx.txt复制Clash → https://a.com/xxx.txt
      L4: 订阅后缀边界
          订阅后缀后跟非 ?#/ 的字符 → 截断
          例：https://a.com/xxx.txtCopy → https://a.com/xxx.txt
          保护：后缀后是 ? 或 # 时保留（合法 query/fragment）
                后缀后是 / 时保留（后缀在路径中间）
                用 rfind（最右）避免路径中恰好含后缀字符串

    不做额外裁剪的链接：
      - 无订阅后缀的 http(s)：无法可靠区分"路径"和"拼接"，保守保留
      - 非 http(s) 协议链接：不在本函数处理范围内

    潜在误杀（概率极低）：
      - URL 里未编码空格：本应编码成 %20，未编码的 URL 本身就是坏的
      - 中文路径：实际 URL 里中文已被 %XX 编码，不会到这里
      - .json-backup / .jsonl：已从后缀列表中移除 .json，避免误伤
    """
    if not url:
        return url
    url = url.strip()
    url = re.sub(r'[:,.?!;]+$', '', url)

    # ---- 【修复 U】仅对 http:// / https:// 链接处理 ----
    # 非 http(s) 协议链接（vmess:// / vless:// 等）直接返回原值，
    # 保持原有行为，避免误伤 query 参数和 Base64 结构。
    url_lower = url.lower()
    if not url_lower.startswith(('http://', 'https://')):
        return url

    # ---- L3: RFC 非法字符边界（中文 / 全角 / 空格）----
    # 中文：\u4e00-\u9fff
    # CJK 标点：\u3000-\u303f
    # 全角字符：\uff00-\uffef
    # 空白：\s（含空格、制表、换行）
    url = re.split(r'[\u4e00-\u9fff\u3000-\u303f\uff00-\uffef\s]',
                   url, maxsplit=1)[0]
    if not url:
        return url

    # ---- L4: 订阅后缀边界 ----
    # 用 rfind 取最右侧后缀作为边界，避免路径中间恰好含后缀字符串。
    # 不含 .json：.json-backup / .jsonl 等可能误截；
    #             .json 内容由 parse_subscription_content 兜底解析。
    _SUB_SUFFIXES = ('.txt', '.yaml', '.yml', '.b64', '.base64', '.conf')
    url_lower = url.lower()
    for suffix in _SUB_SUFFIXES:
        idx = url_lower.rfind(suffix)
        if idx < 0:
            continue
        after = url[idx + len(suffix):]
        if not after:
            break                    # 后缀就是结尾，合法
        if after[0] in '?#':
            break                    # query/fragment，合法
        if after[0] == '/':
            break                    # 后缀在路径中间，合法
        # 后缀后有内容 → 拼接，截断到后缀末尾
        url = url[:idx + len(suffix)]
        break

    return url

def safe_urljoin(base, url):
    if not url:
        return None
    try:
        return urljoin(base, url)
    except:
        return None

def clean_ipv6(server):
    """
    去除 IPv6 地址的方括号。
    例如: "[::1]" -> "::1"
    """
    if server and isinstance(server, str) and server.startswith("[") and server.endswith("]"):
        return server[1:-1]
    return server

def _alpn_to_list(alpn):
    """
    将 alpn 统一转为列表（Clash 输出要求）。
    输入:
        "h3" 或 "h3,h2" 或 ["h3", "h2"] 或 None
    输出:
        ["h3"] 或 ["h3", "h2"] 或 None
    """
    if not alpn:
        return None
    if isinstance(alpn, str):
        items = [x.strip() for x in alpn.split(',') if x.strip()]
        return items if items else None
    if isinstance(alpn, list):
        items = [str(x).strip() for x in alpn if str(x).strip()]
        return items if items else None
    return None

def is_definitely_proxy_url(url):
    """
    判断 http/https URL 是否"非常确定"是代理节点。

    等级 A 规则（满足任一即可）：
        A1: 有认证信息 user:pass@ + 无路径（或路径为 /）
        A2: 有认证信息 user:pass@ + 有显式端口 + 无查询参数

    误判率 < 1%。

    参数:
        url: 待判断的 URL

    返回:
        True  -> 非常确定是代理
        False -> 不确定（可能是网页）
    """
    if not url:
        return False
    try:
        parsed = urlparse(url)
    except Exception:
        return False

    scheme = parsed.scheme.lower()

    # 只处理 http/https
    if scheme not in ('http', 'https'):
        return False

    # 必须有主机名
    if not parsed.hostname:
        return False

    # 核心判据：必须有认证信息
    if not (parsed.username or parsed.password):
        return False

    path = parsed.path or ''
    no_path = (path == '' or path == '/')
    has_port = bool(parsed.port)
    no_query = not parsed.query

    # A1: 有认证 + 无路径
    if no_path:
        return True

    # A2: 有认证 + 有显式端口 + 无查询
    if has_port and no_query:
        return True

    return False

def is_direct_subscription(url):
    if not url:
        return False
    lower = url.lower()
    return lower.endswith(('.yaml', '.yml', '.txt'))

def is_node_link(url):
    if not url:
        return False
    lower = url.lower()
    if lower.endswith(('.yaml', '.yml', '.txt')):
        return True
    for kw in KEYWORDS:
        if kw.lower() in lower:
            return True
    return False

# ======================== 【新增 B】URL 规范化 + 【新增 A】黑名单 ========================

def normalize_url(url):
    """
    【新增 B】URL 规范化（用于 visited_urls 去重键）。
    规则：
      1. scheme / host 小写
      2. 去掉默认端口（:80 / :443）
      3. 去掉 fragment
      4. query 参数按 key 排序
      5. 路径去尾斜杠（保留根路径 /）
    示例：
      https://WWW.Example.com:443/a/?b=2&a=1#x  →  https://www.example.com/a?a=1&b=2
    """
    if not url:
        return url
    try:
        p = urlparse(url)
    except Exception:
        return url
    scheme = (p.scheme or '').lower()
    host = (p.hostname or '').lower()
    if not host:
        return url
    port = p.port
    if (scheme == 'http' and port == 80) or (scheme == 'https' and port == 443):
        port = None
    netloc = host if port is None else f"{host}:{port}"
    path = p.path or ''
    # ---- 修复：不再去掉末尾斜杠 ----
    # 原因：/path 和 /path/ 在服务器端可能是不同资源（404 vs 200）
    # 例如 v2nodes.com 强制要求带 '/'，去掉后返回 404
    # if len(path) > 1 and path.endswith('/'):
    #     path = path.rstrip('/')
    query = ''
    if p.query:
        parts = sorted(x for x in p.query.split('&') if x)
        query = '&'.join(parts)
    result = f"{scheme}://{netloc}{path}" if scheme else f"{netloc}{path}"
    if query:
        result += '?' + query
    return result


def is_blacklisted(url):
    """
    【新增 A】黑名单判定：按路径段完整匹配（非子串）。
    规则：
      - 后缀 .yaml/.yml/.txt/.b64/.json → 直接放行（订阅强信号）
      - 路径任一段（去扩展名后）命中 BLACKLIST_SEGMENTS → 拦
    示例：
      /about/         → 命中 'about'    → True
      /login?next=x   → 命中 'login'    → True
      /subscriptions/ → 不命中           → False
      /about-sub/     → 段为 'about-sub' → False（不是完整匹配）
    """
    if not url:
        return False
    try:
        parsed = urlparse(url)
    except Exception:
        return False
    path = (parsed.path or '').lower()
    if path.endswith(('.yaml', '.yml', '.txt', '.b64', '.json')):
        return False
    for seg in path.split('/'):
        if not seg:
            continue
        name = seg.rsplit('.', 1)[0]
        if name in BLACKLIST_SEGMENTS:
            return True
    return False


def has_subscription_suffix(url):
    """
    【新增 Q1】判断 URL 是否有明确的订阅文件后缀。
    只判断路径部分（忽略 query / fragment）。
    命中：.txt / .yaml / .yml / .b64 / .base64 / .conf
    用途：属性提取器分流 —— 有后缀的立即处理，不入队。
    示例：
      https://a.com/sub.txt           → True
      https://a.com/sub.b64?key=xxx   → True（忽略 query）
      https://a.com/subs/?key=xxx     → False（无后缀）
    """
    if not url:
        return False
    lower = url.lower()
    path = lower.split('?', 1)[0].split('#', 1)[0]
    return path.endswith(('.txt', '.yaml', '.yml', '.b64', '.base64', '.conf'))

# ======================== 【本次新增】URL 日期识别与过滤（方案 1） ========================
# 详见文件头【新增 W】说明
# 模式优先级：full > month > month-day（year 模式已删除，避免误判）
_URL_DATE_PATTERNS = [
    # full（年-月-日）
    (re.compile(r'/(\d{4})/(\d{2})/(\d{2})(?:/|$|\.)'), 'full'),
    (re.compile(r'/(\d{4})-(\d{2})-(\d{2})(?:/|$|\.)'), 'full'),
    (re.compile(r'/(\d{4})(\d{2})(\d{2})(?:/|$|\.)'), 'full'),
    (re.compile(r'[?&]date=(\d{4})-(\d{2})-(\d{2})'), 'full'),
    # month（年月）
    (re.compile(r'/(\d{4})/(\d{2})(?:/|$|\.)'), 'month'),
    (re.compile(r'/(\d{4})-(\d{2})(?:/|$|\.)'), 'month'),
    # month-day（月日）
    (re.compile(r'/(\d{2})/(\d{2})(?:/|$|\.)'), 'month-day'),
    (re.compile(r'/(\d{2})-(\d{2})(?:/|$|\.)'), 'month-day'),
]


def url_date_info(url):
    """
    从 URL 提取日期信息。

    返回:
        ('full', datetime)     完整日期（年-月-日）
        ('month', datetime)    年月（day=1）
        ('month-day', (月, 日)) 月日（无年份）
        None                   无日期 / 日期非法
    """
    if not url:
        return None
    for pat, kind in _URL_DATE_PATTERNS:
        m = pat.search(url)
        if not m:
            continue
        try:
            if kind == 'full':
                y, mo, d = int(m.group(1)), int(m.group(2)), int(m.group(3))
                dt = datetime(y, mo, d)
                return ('full', dt)
            elif kind == 'month':
                y, mo = int(m.group(1)), int(m.group(2))
                dt = datetime(y, mo, 1)
                return ('month', dt)
            elif kind == 'month-day':
                mo, d = int(m.group(1)), int(m.group(2))
                if not (1 <= mo <= 12 and 1 <= d <= 31):
                    continue
                return ('month-day', (mo, d))
        except (ValueError, TypeError):
            continue   # 非法日期，尝试下一个模式
    return None


def _last_day_of_month(dt):
    """返回 dt 所在月份的最后一天"""
    if dt.month == 12:
        return datetime(dt.year + 1, 1, 1) - timedelta(days=1)
    return datetime(dt.year, dt.month + 1, 1) - timedelta(days=1)


def _month_day_too_old(month, day):
    """
    月日模式：拼接当年 + 未来保护。

    策略：
        1. 拼接当年：datetime(now.year, month, day)
        2. 未来保护：拼接结果 > now → 放行（可能是明年的预发布内容）
        3. 非法日期（如 2 月 30 日）→ 放行
        4. 否则与 URL_DATE_MIN 比较
    """
    now = datetime.now()
    try:
        candidate = datetime(now.year, month, day)
    except ValueError:
        return False   # 非法日期 → 放行
    if candidate > now:
        return False   # 未来 → 放行（保守）
    return candidate < URL_DATE_MIN


def is_url_too_old(url):
    """
    【方案 1】URL 日期过滤（零成本）。

    判断规则：
        - full（年-月-日）：date < URL_DATE_MIN → True（丢弃）
        - month（年月）：该月最后一天 < URL_DATE_MIN → True（整月在窗口外才丢弃）
        - month-day（月日）：拼接当年 + 未来保护 → < URL_DATE_MIN → True
        - 无日期 / 日期非法 / 未来日期 → False（放行）
    """
    if not URL_DATE_FILTER_ENABLED:
        return False
    info = url_date_info(url)
    if not info:
        return False
    kind, val = info
    if kind == 'full':
        return val < URL_DATE_MIN
    if kind == 'month':
        return _last_day_of_month(val) < URL_DATE_MIN
    if kind == 'month-day':
        month, day = val
        return _month_day_too_old(month, day)
    return False

# ======================== 【新增 I】3 个独立提取器函数 ========================
# 用途：从 HTML 属性 / 文本容器 / 脚本里提取 URL
# 设计：每个提取器独立、纯函数、无副作用
# 调度：由 Crawler._run_attribute_extractors 统一调用
# ==========================================================================

def _extract_from_attrs(soup, base_url):
    """
    【提取器 1】属性型：从标签的 URL 属性中提取链接。
    覆盖：input[value]、button[data-config]、meta[content]、iframe[src] 等。
    跳过：a / link / script / style（避免与源 1 冲突 + 避免噪声）。
    返回：URL 字符串列表（已 clean_url，已去重）。
    """
    found, seen = [], set()
    for tag in soup.find_all(True):
        if tag.name in _ATTR_SKIP_TAGS:
            continue
        for attr in _URL_ATTRS:
            v = tag.get(attr)
            if not v or not isinstance(v, str):
                continue
            # 属性值里可能有多个 URL，用正则全部提取
            for m in _CONTAINER_URL_RE.finditer(v):
                u = clean_url(m.group(0))
                if u and u not in seen:
                    seen.add(u)
                    found.append(u)
    return found


def _extract_from_text_containers(soup, base_url):
    """
    【提取器 2】文本容器型：从 textarea/code/pre 等标签的可见文本里提取链接。
    返回：URL 字符串列表。
    """
    found, seen = [], set()
    for tag_name in _TEXT_CONTAINER_TAGS:
        for tag in soup.find_all(tag_name):
            text = tag.get_text() or ''
            for m in _CONTAINER_URL_RE.finditer(text):
                u = clean_url(m.group(0))
                if u and u not in seen:
                    seen.add(u)
                    found.append(u)
    return found


def _extract_from_scripts(soup, base_url):
    """
    【提取器 3】脚本型：从 JSON-LD / application/json / SSR state 里提取链接。
    只处理白名单 type 或常见 SSR id，避免把普通 JS 全抓出来产生噪声。
    返回：URL 字符串列表。
    """
    found, seen = [], set()
    for script in soup.find_all('script'):
        stype = (script.get('type') or '').lower()
        sid = (script.get('id') or '').lower()
        content = script.string or ''

        # 白名单：JSON-LD / 内嵌 JSON / SSR state
        is_json = stype in ('application/ld+json', 'application/json')
        is_ssr = ('__initial_state' in sid or '__next_data' in sid
                  or '__nuxt' in sid or '__apollo' in sid)
        # SSR 变量赋值形式：window.__XXX__ = {...}
        is_window_var = bool(re.match(
            r'\s*(?:window|self|globalThis)\.[A-Za-z_$][\w$]*\s*=',
            content[:200]
        ))

        if not (is_json or is_ssr or is_window_var):
            continue

        for m in _CONTAINER_URL_RE.finditer(content):
            u = clean_url(m.group(0))
            if u and u not in seen:
                seen.add(u)
                found.append(u)
    return found


# 提取器注册表（union 模式下顺序不影响结果）
URL_EXTRACTORS = [
    ('attrs',            _extract_from_attrs),
    ('text-containers',  _extract_from_text_containers),
    ('scripts',          _extract_from_scripts),
]

# ======================== HTTP 抓取 ========================

def fetch_content(url, retries=FETCH_RETRIES, delay=FETCH_DELAY):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
    }
    for i in range(retries):
        try:
            resp = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
            resp.raise_for_status()
            if resp.encoding is None:
                resp.encoding = 'utf-8'
            return resp.text
        except Exception as e:
            if i < retries - 1:
                time.sleep(delay)
                continue
            raise
    return None

def fetch_binary(url, retries=FETCH_RETRIES, delay=FETCH_DELAY):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    }
    for i in range(retries):
        try:
            resp = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
            resp.raise_for_status()
            return resp.content
        except Exception as e:
            if i < retries - 1:
                time.sleep(delay)
                continue
            raise
    return None

# ======================== 【本次新增】fetch_with_headers（方案 3 使用） ========================
# 与 fetch_binary 行为一致，但额外返回 headers。
# 仅 _process_url 使用；其他调用点（download_subscription、provider 下载）
# 继续用 fetch_binary，不受影响。
def fetch_with_headers(url, retries=FETCH_RETRIES, delay=FETCH_DELAY):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    }
    for i in range(retries):
        try:
            resp = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
            resp.raise_for_status()
            return resp.content, resp.headers
        except Exception as e:
            if i < retries - 1:
                time.sleep(delay)
                continue
            raise
    return None, {}


# ======================== 【本次新增】Last-Modified 日期过滤（方案 3） ========================
def is_too_old_by_last_modified(headers):
    """
    【方案 3】Last-Modified 日期过滤（fetch 后判断）。

    四条放行规则（"有且明确太老时才过滤，其他情况一律放行"）：
        1. 开关关闭 → 放行
        2. 无 headers / 无 Last-Modified → 放行
        3. Last-Modified 解析失败 → 放行
        4. Last-Modified 明确 < URL_DATE_MIN → 返回 True（丢弃）

    订阅后缀豁免（在调用方检查，不在本函数内）：
        订阅文件的 Last-Modified 可能是创建时间，但节点列表是动态更新的，
        不能按 Last-Modified 过滤。调用方需先排除 has_subscription_suffix。
    """
    if not URL_DATE_FILTER_LAST_MOD_ENABLED or not headers:
        return False
    from email.utils import parsedate_to_datetime
    lm = headers.get('Last-Modified')
    if not lm:
        return False
    try:
        dt = parsedate_to_datetime(lm)
        if dt.tzinfo is not None:
            dt = dt.replace(tzinfo=None)
        return dt < URL_DATE_MIN
    except Exception:
        return False


# ======================== 协议解析函数 ========================

def parse_vmess(vmess_url):
    """解析 VMess 链接，返回标准节点字典"""
    if not vmess_url.startswith('vmess://'):
        return None
    try:
        b64 = vmess_url[8:]
        b64 += '=' * (4 - len(b64) % 4)
        decoded = base64.b64decode(b64).decode('utf-8')
        data = json.loads(decoded)
        node = {
            'type': 'vmess',
            'add': data.get('add', ''),
            'port': int(data.get('port', 0)),
            'uuid': data.get('id', ''),
            'alterId': int(data.get('aid', 0)),
            'cipher': data.get('scy', 'auto'),
            'network': data.get('net', 'tcp'),
            'tls': data.get('tls', '') == 'tls',
            'sni': data.get('sni', ''),
            'host': data.get('host', ''),
            'path': data.get('path', ''),
            'ps': data.get('ps', ''),
            'raw': vmess_url,
        }
        if not node['add'] or not node['port'] or not node['uuid']:
            return None
        return node
    except Exception:
        return None

def parse_vless(vless_url):
    """解析 VLESS 链接（含 reality-opts 补全）"""
    if not vless_url.startswith('vless://'):
        return None
    try:
        parsed = urlparse(vless_url)
        uuid = parsed.username or ''
        host = parsed.hostname or ''
        port = parsed.port or 443
        query = parse_qs(parsed.query)
        node = {
            'type': 'vless',
            'add': host,
            'port': port,
            'uuid': uuid,
            'network': query.get('type', ['tcp'])[0],
            'tls': query.get('security', [''])[0] == 'tls',
            'sni': query.get('sni', [''])[0],
            'flow': query.get('flow', [''])[0],
            'encryption': query.get('encryption', ['none'])[0],
            'ps': query.get('remark', [''])[0] or f"VLESS-{host}",
            'raw': vless_url,
        }
        # ---- reality / client-fingerprint / alpn 补全 ----
        if query.get('fp', [''])[0]:
            node['client-fingerprint'] = query.get('fp', [''])[0]
        if query.get('alpn', [''])[0]:
            node['alpn'] = unquote(query.get('alpn', [''])[0])
        security = query.get('security', [''])[0]
        if security == 'reality':
            node['tls'] = True
            node['reality-opts'] = {}
            if query.get('pbk', [''])[0]:
                node['reality-opts']['public-key'] = query.get('pbk', [''])[0]
            if query.get('sid', [''])[0]:
                node['reality-opts']['short-id'] = query.get('sid', [''])[0]
        # -----------------------------------------------------
        if not node['uuid']:
            return None
        return node
    except Exception:
        return None

def parse_ss(ss_url):
    """解析 Shadowsocks 链接"""
    if not ss_url.startswith('ss://'):
        return None
    try:
        content = ss_url[5:]
        if '@' in content:
            prefix, suffix = content.split('@', 1)
            b64 = prefix.replace('-', '+').replace('_', '/')
            b64 += '=' * (4 - len(b64) % 4)
            decoded = base64.b64decode(b64).decode('utf-8')
            if ':' in decoded:
                method, password = decoded.split(':', 1)
            else:
                method, password = decoded.split(':', 1)
            if '?' in suffix:
                host_port, _ = suffix.split('?', 1)
            else:
                host_port = suffix
            host, port = host_port.split(':')
            port = int(port)
        else:
            b64 = content.replace('-', '+').replace('_', '/')
            b64 += '=' * (4 - len(b64) % 4)
            decoded = base64.b64decode(b64).decode('utf-8')
            if '@' not in decoded:
                return None
            method_pass, host_port = decoded.split('@', 1)
            method, password = method_pass.split(':', 1)
            if '?' in host_port:
                host_port, _ = host_port.split('?', 1)
            host, port = host_port.split(':')
            port = int(port)

        node = {
            'type': 'ss',
            'add': host,
            'port': port,
            'method': method,
            'password': password,
            'ps': f"SS-{host}",
            'raw': ss_url,
        }
        return node
    except Exception:
        return None

# ======================== 新增解析函数（5 个） ========================

def parse_ssr(ssr_url):
    """
    解析 ShadowsocksR 链接。
    格式: ssr://base64(server:port:protocol:cipher:obfs:base64(password)/?params)
    """
    if not ssr_url.startswith('ssr://'):
        return None
    try:
        content = ssr_url[6:]
        b64 = content.replace('-', '+').replace('_', '/')
        b64 += '=' * (4 - len(b64) % 4)
        decoded = base64.b64decode(b64).decode('utf-8')
        # 分割密码与参数
        if '/?' in decoded:
            head, params_str = decoded.split('/?', 1)
        else:
            head, params_str = decoded, ''
        parts = head.split(':')
        if len(parts) < 6:
            return None
        server, port, protocol, cipher, obfs = parts[:5]
        passwd_b64 = ':'.join(parts[5:])
        passwd_b64 = passwd_b64.replace('-', '+').replace('_', '/')
        passwd_b64 += '=' * (4 - len(passwd_b64) % 4)
        try:
            password = base64.b64decode(passwd_b64).decode('utf-8', errors='ignore')
        except Exception:
            password = ''

        node = {
            'type': 'ssr',
            'add': server,
            'port': int(port),
            'protocol': protocol,
            'cipher': cipher,
            'obfs': obfs,
            'password': password,
            'ps': f"SSR-{server}",
            'raw': ssr_url,
        }
        # 解析额外参数
        if params_str:
            for kv in params_str.split('&'):
                if '=' not in kv:
                    continue
                k, v = kv.split('=', 1)
                v_b64 = v.replace('-', '+').replace('_', '/')
                v_b64 += '=' * (4 - len(v_b64) % 4)
                try:
                    v_dec = base64.b64decode(v_b64).decode('utf-8', errors='ignore')
                except Exception:
                    v_dec = v
                if k == 'remarks':
                    node['ps'] = v_dec
                elif k == 'obfsparam':
                    node['obfs-param'] = v_dec
                elif k == 'protoparam':
                    node['protocol-param'] = v_dec
                elif k == 'group':
                    node['group'] = v_dec
        if not node['add'] or not node['password']:
            return None
        return node
    except Exception:
        return None


# ======================== 【修复 L】补全 parse_trojan 函数 ========================
# 之前 parse_node_link 调用了 parse_trojan 但函数未定义，导致：
#   "name 'parse_trojan' is not defined"
# 修复：在 parse_ssr 之后补上完整定义
# ==============================================================================

def parse_trojan(trojan_url):
    """
    【修复 L】解析 Trojan 链接。
    格式: trojan://password@host:port[?sni=xxx&allowInsecure=1&type=ws&path=...&host=...]
    常见参数：
      - sni          : TLS SNI
      - peer         : 老式 SNI 参数
      - allowInsecure: 是否跳过证书验证
      - insecure     : 同上（部分客户端使用）
      - type         : 传输层（tcp/ws/grpc）
      - path         : WebSocket 路径（type=ws 时）
      - host         : WebSocket Host 头
      - alpn         : ALPN 列表
      - fp           : 客户端指纹
    """
    if not trojan_url.startswith('trojan://'):
        return None
    try:
        parsed = urlparse(trojan_url)
        node = {
            'type': 'trojan',
            'add': parsed.hostname or '',
            'port': parsed.port or 443,
            'password': parsed.username or '',
            'ps': parsed.fragment or f"Trojan-{parsed.hostname}",
            'raw': trojan_url,
        }
        query = parse_qs(parsed.query)
        # SNI（sni 优先，兼容 peer）
        if query.get('sni', [''])[0]:
            node['sni'] = query.get('sni', [''])[0]
        elif query.get('peer', [''])[0]:
            node['sni'] = query.get('peer', [''])[0]
        # 跳过证书验证
        if query.get('allowInsecure', ['0'])[0] == '1':
            node['skip-cert-verify'] = True
            node['allowInsecure'] = True
        if query.get('insecure', ['0'])[0] == '1':
            node['skip-cert-verify'] = True
            node['allowInsecure'] = True
        # ALPN
        if query.get('alpn', [''])[0]:
            node['alpn'] = unquote(query.get('alpn', [''])[0])
        # 传输层（ws/grpc/tcp）
        if query.get('type', [''])[0]:
            node['network'] = query.get('type', [''])[0]
        # WS 路径
        if query.get('path', [''])[0]:
            node['path'] = unquote(query.get('path', [''])[0])
        # WS Host 头
        if query.get('host', [''])[0]:
            node['host'] = query.get('host', [''])[0]
        # 客户端指纹
        if query.get('fp', [''])[0]:
            node['client-fingerprint'] = query.get('fp', [''])[0]

        if not node['add'] or not node['password']:
            return None
        return node
    except Exception:
        return None


def parse_hysteria2(hy2_url):
    """
    解析 Hysteria2 链接。
    格式: hysteria2://password@host:port[,port2][?params]
    """
    if not hy2_url.startswith(('hysteria2://', 'hy2://')):
        return None
    try:
        parsed = urlparse(hy2_url)
        node = {
            'type': 'hysteria2',
            'add': parsed.hostname or '',
            'password': parsed.username or '',
            'ps': parsed.fragment or f"HY2-{parsed.hostname}",
            'raw': hy2_url,
        }
        # 处理多端口: 443,8443 这种
        netloc = parsed.netloc
        if '@' in netloc:
            netloc = netloc.split('@', 1)[1]
        if ':' in netloc and not netloc.startswith('['):
            port_part = netloc.rsplit(':', 1)[-1]
            if ',' in port_part:
                first_port, rest = port_part.split(',', 1)
                try:
                    node['port'] = int(first_port)
                except (ValueError, TypeError):
                    node['port'] = 443
                node['ports'] = rest
            else:
                try:
                    node['port'] = int(port_part)
                except (ValueError, TypeError):
                    node['port'] = 443
        else:
            node['port'] = 443

        query = parse_qs(parsed.query)
        if query.get('sni', [''])[0]:
            node['sni'] = query.get('sni', [''])[0]
        if query.get('insecure', ['0'])[0] == '1':
            node['skip-cert-verify'] = True
        if query.get('obfs', [''])[0]:
            node['obfs'] = query.get('obfs', [''])[0]
        if query.get('obfs-password', [''])[0]:
            node['obfs-password'] = query.get('obfs-password', [''])[0]
        if query.get('alpn', [''])[0]:
            node['alpn'] = unquote(query.get('alpn', [''])[0])
        if query.get('fp', [''])[0]:
            node['client-fingerprint'] = query.get('fp', [''])[0]

        if not node['add'] or not node['password']:
            return None
        return node
    except Exception:
        return None


def parse_hysteria(hy_url):
    """
    解析 Hysteria v1 链接。
    格式: hysteria://host:port?auth=xxx&peer=xxx&...
    """
    if not hy_url.startswith('hysteria://'):
        return None
    try:
        parsed = urlparse(hy_url)
        query = parse_qs(parsed.query)
        node = {
            'type': 'hysteria',
            'add': parsed.hostname or '',
            'port': parsed.port or 443,
            'auth': query.get('auth', [''])[0],
            'protocol': query.get('protocol', ['udp'])[0],
            'sni': query.get('peer', [''])[0] or parsed.hostname,
            'ps': parsed.fragment or f"HY-{parsed.hostname}",
            'raw': hy_url,
        }
        if query.get('insecure', ['0'])[0] == '1':
            node['skip-cert-verify'] = True
        if query.get('upmbps', [''])[0]:
            node['up'] = query.get('upmbps', [''])[0]
        if query.get('downmbps', [''])[0]:
            node['down'] = query.get('downmbps', [''])[0]
        if query.get('alpn', [''])[0]:
            node['alpn'] = unquote(query.get('alpn', [''])[0])
        if not node['add']:
            return None
        return node
    except Exception:
        return None


def parse_tuic(tuic_url):
    """
    解析 TUIC 链接。
    格式: tuic://uuid:password@host:port[?params]
    """
    if not tuic_url.startswith('tuic://'):
        return None
    try:
        parsed = urlparse(tuic_url)
        node = {
            'type': 'tuic',
            'add': parsed.hostname or '',
            'port': parsed.port or 136,
            'uuid': parsed.username or '',
            'password': parsed.password or '',
            'ps': parsed.fragment or f"TUIC-{parsed.hostname}",
            'raw': tuic_url,
        }
        query = parse_qs(parsed.query)
        if query.get('sni', [''])[0]:
            node['sni'] = query.get('sni', [''])[0]
        if query.get('allow_insecure', ['0'])[0] == '1':
            node['skip-cert-verify'] = True
        if query.get('alpn', [''])[0]:
            node['alpn'] = unquote(query.get('alpn', [''])[0])
        if query.get('congestion_control', [''])[0]:
            node['congestion_control'] = query.get('congestion_control', [''])[0]
        if query.get('udp_relay_mode', [''])[0]:
            node['udp_relay_mode'] = query.get('udp_relay_mode', [''])[0]
        if not node['add'] or not node['uuid']:
            return None
        return node
    except Exception:
        return None


def parse_http_socks(url, strict_http=True):
    """
    解析 http:// / https:// / socks5:// / socks5h:// / socks:// 节点链接。

    strict_http=True（默认）:
        - socks 系列：只要有主机名 + 端口即可（宽松）
        - http/https：必须满足 is_definitely_proxy_url（严格）
    strict_http=False:
        - http/https 只要有端口即识别（不推荐，仅供内部调用）

    注意：
        - 本函数从 URL 路径调用（parse_node_link / parse_subscription_content）
        - YAML 路径由 parse_subscription_content 的 proxies 分支处理
    """
    try:
        parsed = urlparse(url)
        scheme = parsed.scheme.lower()

        if scheme not in ('http', 'https', 'socks5', 'socks5h', 'socks'):
            return None

        if not parsed.hostname:
            return None

        # socks 系列：宽松处理，只需主机名 + 端口
        if scheme.startswith('socks'):
            if not parsed.port:
                return None
        else:
            # http/https：严格模式
            if strict_http:
                if not is_definitely_proxy_url(url):
                    return None
            else:
                if not parsed.port:
                    return None

        # 默认端口
        default_port = 443 if scheme == 'https' else 80
        port = parsed.port or default_port

        node_type = 'socks5' if scheme.startswith('socks') else 'http'
        node = {
            'type': node_type,
            'add': parsed.hostname,
            'port': port,
            'username': parsed.username or '',
            'password': parsed.password or '',
            'tls': scheme == 'https',
            'ps': parsed.fragment or f"{scheme.upper()}-{parsed.hostname}",
            'raw': url,
        }
        return node
    except Exception:
        return None

# ======================== parse_node_link（增量扩展） ========================

def parse_node_link(link):
    """
    解析节点链接为 dict。

    第一层无条件识别：vmess / vless / ss / ssr / trojan /
                    hysteria / hysteria2 / hy2 / tuic /
                    socks5 / socks5h / socks
    第二层严格识别：http / https（需通过 is_definitely_proxy_url 校验）
    """
    if link.startswith('vmess://'):
        return parse_vmess(link)
    elif link.startswith('vless://'):
        return parse_vless(link)
    elif link.startswith('ss://'):
        return parse_ss(link)
    # ---- 长前缀优先，避免 ss 误匹配 ssr ----
    elif link.startswith('ssr://'):
        return parse_ssr(link)
    elif link.startswith('trojan://'):
        return parse_trojan(link)
    elif link.startswith(('hysteria2://', 'hy2://')):
        return parse_hysteria2(link)
    elif link.startswith('hysteria://'):
        return parse_hysteria(link)
    elif link.startswith('tuic://'):
        return parse_tuic(link)
    # ---- 第一层：socks 系列（宽松） ----
    elif link.startswith(('socks5://', 'socks5h://', 'socks://')):
        return parse_http_socks(link, strict_http=False)
    # ---- 第二层：http/https（严格，仅识别"非常确定"的） ----
    elif link.startswith(('http://', 'https://')):
        if is_definitely_proxy_url(link):
            return parse_http_socks(link, strict_http=True)
        return None
    else:
        return None

def parse_subscription_content(content, url_hint=''):
    """
    解析订阅内容，返回节点列表。
    支持：
    - 标准 Clash YAML（proxies 字段）
    - Clash 配置（proxy-providers）
    - Base64 编码的节点链接
    - 每行一个节点链接的纯文本
    返回的每个节点字典包含 'raw' 字段（原始链接字符串）及 'ps'（备注名）
    """
    nodes = []
    if not content:
        return nodes

    # ---------- 第一步：尝试作为 Clash YAML 解析 ----------
    try:
        data = yaml.safe_load(content)
        if isinstance(data, dict):
            # 1. 标准 proxies 字段
            proxy_list = data.get('proxies') or data.get('Proxy') or data.get('proxy')
            if proxy_list and isinstance(proxy_list, list):
                for proxy in proxy_list:
                    if not isinstance(proxy, dict):
                        continue
                    ptype = proxy.get('type', '').lower()
                    # ---- 白名单扩展 ----
                    if ptype not in ('vmess', 'vless', 'ss', 'ssr', 'trojan',
                                     'hysteria', 'hysteria2', 'tuic',
                                     'http', 'socks5'):
                        continue
                    node = {
                        'type': ptype,
                        'add': proxy.get('server', ''),
                        'port': int(proxy.get('port', 0)),
                        'ps': proxy.get('name', ''),
                        'raw': f"{ptype}://{proxy.get('server', '')}:{proxy.get('port', 0)}"
                    }
                    if ptype in ('vmess', 'vless'):
                        uuid = proxy.get('uuid') or proxy.get('id', '')
                        node['uuid'] = uuid
                        node['alterId'] = int(proxy.get('alterId', 0)) if ptype == 'vmess' else 0
                        node['cipher'] = proxy.get('cipher', 'auto')
                        node['network'] = proxy.get('network', 'tcp')
                        node['tls'] = proxy.get('tls', False)
                        node['sni'] = proxy.get('sni', '')
                        node['host'] = proxy.get('host', '')
                        node['path'] = proxy.get('path', '')
                        if ptype == 'vless':
                            node['flow'] = proxy.get('flow', '')
                            node['encryption'] = proxy.get('encryption', 'none')
                            # ---- 新增 vless 字段 ----
                            if proxy.get('reality-opts'):
                                node['reality-opts'] = proxy['reality-opts']
                            if proxy.get('client-fingerprint'):
                                node['client-fingerprint'] = proxy['client-fingerprint']
                        if proxy.get('alpn'):
                            alpn = proxy['alpn']
                            node['alpn'] = ','.join(alpn) if isinstance(alpn, list) else alpn
                    elif ptype == 'ss':
                        node['method'] = proxy.get('cipher', '')
                        node['password'] = proxy.get('password', '')
                    elif ptype == 'ssr':
                        # ---- 新增 ssr ----
                        node['protocol'] = proxy.get('protocol', 'origin')
                        node['obfs'] = proxy.get('obfs', 'plain')
                        node['cipher'] = proxy.get('cipher', '')
                        node['password'] = proxy.get('password', '')
                        if proxy.get('obfs-param'):
                            node['obfs-param'] = proxy['obfs-param']
                        if proxy.get('protocol-param'):
                            node['protocol-param'] = proxy['protocol-param']
                    elif ptype == 'trojan':
                        node['password'] = proxy.get('password', '')
                        node['sni'] = proxy.get('sni', '')
                        # ---- 统一 skip-cert-verify ----
                        if proxy.get('skip-cert-verify'):
                            node['skip-cert-verify'] = True
                            node['allowInsecure'] = True
                        if proxy.get('alpn'):
                            alpn = proxy['alpn']
                            node['alpn'] = ','.join(alpn) if isinstance(alpn, list) else alpn
                    elif ptype == 'hysteria2':
                        # ---- 新增 hysteria2 ----
                        node['password'] = proxy.get('password', '')
                        node['sni'] = proxy.get('sni', '')
                        if proxy.get('skip-cert-verify'):
                            node['skip-cert-verify'] = True
                        if proxy.get('obfs'):
                            node['obfs'] = proxy['obfs']
                            node['obfs-password'] = proxy.get('obfs-password', '')
                        if proxy.get('ports'):
                            node['ports'] = proxy['ports']
                        if proxy.get('alpn'):
                            alpn = proxy['alpn']
                            node['alpn'] = ','.join(alpn) if isinstance(alpn, list) else alpn
                    elif ptype == 'hysteria':
                        # ---- 新增 hysteria v1 ----
                        node['auth'] = proxy.get('auth-str', '') or proxy.get('auth', '')
                        node['sni'] = proxy.get('sni', '')
                        if proxy.get('skip-cert-verify'):
                            node['skip-cert-verify'] = True
                        if proxy.get('up'):
                            node['up'] = proxy['up']
                        if proxy.get('down'):
                            node['down'] = proxy['down']
                        if proxy.get('alpn'):
                            alpn = proxy['alpn']
                            node['alpn'] = ','.join(alpn) if isinstance(alpn, list) else alpn
                    elif ptype == 'tuic':
                        # ---- 新增 tuic ----
                        node['uuid'] = proxy.get('uuid', '')
                        node['password'] = proxy.get('password', '')
                        node['sni'] = proxy.get('sni', '')
                        if proxy.get('skip-cert-verify'):
                            node['skip-cert-verify'] = True
                        if proxy.get('congestion-controller'):
                            node['congestion_control'] = proxy['congestion-controller']
                        if proxy.get('udp-relay-mode'):
                            node['udp_relay_mode'] = proxy['udp-relay-mode']
                        if proxy.get('alpn'):
                            alpn = proxy['alpn']
                            node['alpn'] = ','.join(alpn) if isinstance(alpn, list) else alpn
                    elif ptype == 'http':
                        # ---- 新增 http/https ----
                        node['username'] = proxy.get('username', '')
                        node['password'] = proxy.get('password', '')
                        node['tls'] = proxy.get('tls', False)
                        if proxy.get('sni'):
                            node['sni'] = proxy['sni']
                    elif ptype == 'socks5':
                        # ---- 新增 socks5 ----
                        node['username'] = proxy.get('username', '')
                        node['password'] = proxy.get('password', '')
                    if node['add'] and node['port']:
                        nodes.append(node)
                if nodes:
                    return nodes

            # 2. proxy-providers
            if 'proxy-providers' in data:
                providers = data['proxy-providers']
                for provider_name, provider_config in providers.items():
                    if not isinstance(provider_config, dict):
                        continue
                    if provider_config.get('type') == 'http':
                        provider_url = provider_config.get('url')
                        if provider_url:
                            print(f"  Found proxy-provider '{provider_name}', downloading: {provider_url}")
                            try:
                                provider_content = fetch_binary(provider_url)
                                if provider_content:
                                    provider_text = provider_content.decode('utf-8', errors='ignore')
                                    sub_nodes = parse_subscription_content(provider_text, provider_url)
                                    nodes.extend(sub_nodes)
                                    print(f"  -> Got {len(sub_nodes)} nodes from provider")
                            except Exception as e:
                                print(f"  -> Error downloading provider {provider_url}: {e}")
                if nodes:
                    return nodes
    except Exception:
        pass

    # ---------- 第二步：尝试 Base64 解码 ----------
    try:
        b64_clean = re.sub(r'\s+', '', content)
        if re.match(r'^[A-Za-z0-9+/=_-]+$', b64_clean):
            b64_clean += '=' * (4 - len(b64_clean) % 4)
            decoded = base64.b64decode(b64_clean, altchars='-_').decode('utf-8', errors='ignore')
            for line in decoded.splitlines():
                line = line.strip()
                if not line:
                    continue
                # 第一层：NODE_PREFIXES（无条件识别）
                if line.startswith(NODE_PREFIXES):
                    node = parse_node_link(line)
                    if node:
                        node['raw'] = line
                        nodes.append(node)
                # 第二层：http/https（严格校验）
                elif line.startswith(HTTP_PREFIXES):
                    if is_definitely_proxy_url(line):
                        node = parse_node_link(line)
                        if node:
                            node['raw'] = line
                            nodes.append(node)
            if nodes:
                return nodes
    except Exception:
        pass

    # ---------- 第三步：按行解析节点链接 ----------
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        # 第一层：NODE_PREFIXES（无条件识别）
        if line.startswith(NODE_PREFIXES):
            node = parse_node_link(line)
            if node:
                node['raw'] = line
                nodes.append(node)
        # 第二层：http/https（严格校验）
        elif line.startswith(HTTP_PREFIXES):
            if is_definitely_proxy_url(line):
                node = parse_node_link(line)
                if node:
                    node['raw'] = line
                    nodes.append(node)

    return nodes

# ======================== 【新增 C】字段列表文本解析器 ========================
# 适用场景：v2nodes.com/servers/xxx/ 这类页面渲染出的纯文本节点卡片
# 输入示例：
#     Type: VLESS
#     Server: 45.120.178.9
#     Port: 443
#     UUID: f8787b1b-502b-49dc-8949-4e24ec52b463
#     Security: none
#     Network: tcp
#     Path: /waqagrws
#     Remark: Vless-NL-11310608
# 策略：按 "Type:" / "协议:" 切块 → 每块抽 key:value → 组装节点
# --------------------------------------------------------------------------

# 网页显示字段名（小写）→ 内部字段名
_FIELD_ALIAS = {
    'type': 'type', 'protocol': 'type',
    'server': 'add', 'address': 'add', 'host': 'add', 'ip': 'add',
    'port': 'port',
    'uuid': 'uuid', 'id': 'uuid',
    'password': 'password', 'passwd': 'password',
    'method': 'method', 'cipher': 'method', 'encrypt': 'method',
    'flow': 'flow',
    'security': 'security', 'tls': 'security',
    'sni': 'sni', 'servername': 'sni', 'peer': 'sni',
    'alpn': 'alpn',
    'network': 'network', 'net': 'network',
    'fingerprint': 'fp', 'fp': 'fp',
    'reality public key': 'pbk', 'public key': 'pbk', 'pbk': 'pbk',
    'reality short id': 'sid', 'short id': 'sid', 'sid': 'sid',
    'path': 'path', 'host header': 'host', 'hostheader': 'host',
    'service name': 'service_name', 'mode': 'mode',
    'remark': 'ps', 'remarks': 'ps', 'name': 'ps',
    'auth': 'auth', 'auth-str': 'auth',
    'obfs': 'obfs', 'obfs-password': 'obfs_password',
    'congestion control': 'congestion_control',
    'udp relay mode': 'udp_relay_mode',
    'up': 'up', 'down': 'down',
    'insecure': 'insecure', 'username': 'username',
}

# 单行 "key: value" 匹配（兼容中英文冒号）
_FIELD_LINE_RE = re.compile(r'^\s*([A-Za-z][A-Za-z0-9 _\-\.]*?)\s*[:：]\s*(.*)$')
# 按 "Type:" / "Protocol:" / "类型:" / "协议:" 切块
_FIELD_BLOCK_SPLIT_RE = re.compile(r'\n(?=\s*(?:type|protocol|类型|协议)\s*[:：])', re.I)
# 门槛：至少要出现 server/port/uuid/type 行之一，避免误伤普通网页
_FIELD_GATE_RE = re.compile(r'^\s*(server|port|uuid|type)\s*[:：]', re.I | re.M)


def _parse_field_block(block):
    """【新增 C-辅助】单块文本 → 字段 dict"""
    fields = {}
    for line in block.splitlines():
        m = _FIELD_LINE_RE.match(line)
        if not m:
            continue
        key = _FIELD_ALIAS.get(m.group(1).strip().lower())
        val = m.group(2).strip()
        if key and val and val.lower() not in ('none', 'null', '-'):
            fields[key] = val
    return fields


def _fields_to_node(fields):
    """【新增 C-辅助】字段 dict → 节点 dict（沿用 parse_node_link 的字段约定）"""
    t = fields.get('type', '').lower()
    if t == 'hy2':
        t = 'hysteria2'
    if t not in ('vmess', 'vless', 'ss', 'ssr', 'trojan',
                 'hysteria', 'hysteria2', 'tuic', 'http', 'socks5'):
        return None
    server, port = fields.get('add'), fields.get('port')
    if not server or not port:
        return None
    try:
        port = int(port)
    except (ValueError, TypeError):
        return None

    node = {'type': t, 'add': server, 'port': port, 'ps': fields.get('ps', '')}
    sec = (fields.get('security') or '').lower()

    if t in ('vmess', 'vless'):
        node['uuid'] = fields.get('uuid', '')
        if not node['uuid']:
            return None
        node['network'] = fields.get('network', 'tcp')
        node['tls'] = sec in ('tls', 'reality', 'xtls')
        for src, dst in (('sni', 'sni'), ('path', 'path'), ('host', 'host'),
                         ('fp', 'client-fingerprint'), ('alpn', 'alpn')):
            if fields.get(src):
                node[dst] = fields[src]
        if sec == 'reality':
            ro = {}
            if fields.get('pbk'):
                ro['public-key'] = fields['pbk']
            if fields.get('sid'):
                ro['short-id'] = fields['sid']
            if ro:
                node['reality-opts'] = ro
        if fields.get('flow') and fields['flow'].lower() != 'none':
            node['flow'] = fields['flow']

    elif t == 'ss':
        node['method'] = fields.get('method', '')
        node['password'] = fields.get('password', '')
        if not node['method'] or not node['password']:
            return None

    elif t == 'ssr':
        node['protocol'] = fields.get('protocol', 'origin')
        node['obfs'] = fields.get('obfs', 'plain')
        node['cipher'] = fields.get('method', '')
        node['password'] = fields.get('password', '')
        if not node['password']:
            return None

    elif t == 'trojan':
        node['password'] = fields.get('password', '')
        if not node['password']:
            return None
        if fields.get('sni'):
            node['sni'] = fields['sni']
        if fields.get('alpn'):
            node['alpn'] = fields['alpn']
        if fields.get('insecure', '').lower() in ('1', 'true', 'yes'):
            node['skip-cert-verify'] = True

    elif t == 'hysteria2':
        node['password'] = fields.get('password') or fields.get('auth') or ''
        if fields.get('sni'):
            node['sni'] = fields['sni']
        if fields.get('obfs'):
            node['obfs'] = fields['obfs']
            if fields.get('obfs_password'):
                node['obfs-password'] = fields['obfs_password']
        if fields.get('insecure', '').lower() in ('1', 'true', 'yes'):
            node['skip-cert-verify'] = True

    elif t == 'hysteria':
        node['auth'] = fields.get('auth', '')
        if fields.get('sni'):
            node['sni'] = fields['sni']
        if fields.get('up'):
            node['up'] = fields['up']
        if fields.get('down'):
            node['down'] = fields['down']

    elif t == 'tuic':
        node['uuid'] = fields.get('uuid', '')
        node['password'] = fields.get('password', '')
        if not node['uuid'] or not node['password']:
            return None
        if fields.get('sni'):
            node['sni'] = fields['sni']
        if fields.get('congestion_control'):
            node['congestion_control'] = fields['congestion_control']
        if fields.get('udp_relay_mode'):
            node['udp_relay_mode'] = fields['udp_relay_mode']

    elif t == 'http':
        node['username'] = fields.get('username', '')
        node['password'] = fields.get('password', '')
        node['tls'] = (sec == 'tls')

    elif t == 'socks5':
        node['username'] = fields.get('username', '')
        node['password'] = fields.get('password', '')

    return node


def parse_field_list_text(text):
    """
    【新增 C-主函数】从"字段列表文本"里抽取节点。
    门槛：必须出现 server/port/uuid/type 行之一，避免误伤普通网页。
    用法示例：
        >>> parse_field_list_text("Type: VLESS\\nServer: 1.2.3.4\\nPort: 443\\nUUID: xxx")
        [{'type': 'vless', 'add': '1.2.3.4', 'port': 443, 'uuid': 'xxx', ...}]
    """
    if not text or len(text) < 20:
        return []
    if not _FIELD_GATE_RE.search(text):
        return []
    blocks = _FIELD_BLOCK_SPLIT_RE.split(text)
    nodes = []
    for block in blocks:
        block = block.strip()
        if not block:
            continue
        node = _fields_to_node(_parse_field_block(block))
        if node:
            nodes.append(node)
    return nodes

# ======================== 去重与测通 ========================

def normalize_node_key(node):
    """
    生成节点去重指纹。
    新增协议：ssr / hysteria / hysteria2 / tuic / http / socks5
    """
    t = node.get('type')
    if t == 'vmess':
        key = f"vmess_{node.get('add')}_{node.get('port')}_{node.get('uuid')}"
    elif t == 'vless':
        key = f"vless_{node.get('add')}_{node.get('port')}_{node.get('uuid')}"
    elif t == 'ss':
        key = f"ss_{node.get('add')}_{node.get('port')}_{node.get('method')}_{node.get('password')}"
    elif t == 'ssr':
        key = (f"ssr_{node.get('add')}_{node.get('port')}_"
               f"{node.get('protocol')}_{node.get('obfs')}_{node.get('password')}")
    elif t == 'trojan':
        key = f"trojan_{node.get('add')}_{node.get('port')}_{node.get('password')}"
    elif t == 'hysteria2':
        key = (f"hy2_{node.get('add')}_{node.get('port')}_"
               f"{node.get('password')}_{node.get('obfs-password', '')}")
    elif t == 'hysteria':
        key = f"hy_{node.get('add')}_{node.get('port')}_{node.get('auth')}"
    elif t == 'tuic':
        key = f"tuic_{node.get('add')}_{node.get('port')}_{node.get('uuid')}"
    elif t in ('http', 'socks5'):
        key = f"{t}_{node.get('add')}_{node.get('port')}_{node.get('username', '')}"
    else:
        key = f"{t}_{node.get('add')}_{node.get('port')}"
    return hashlib.md5(key.encode()).hexdigest()


# ---------- QUIC 握手测试（新增，用于 UDP 协议） ----------

async def _quic_handshake_async(server, port, timeout):
    """
    异步 QUIC 握手测试。
    使用 aioquic 高层 API 发起 QUIC 连接。
    wait_connected=False 允许 0-RTT 启动；verify_mode=0 跳过证书验证
    （代理节点常用自签证书）。
    """
    from aioquic.asyncio import connect
    from aioquic.quic.configuration import QuicConfiguration

    config = QuicConfiguration(is_client=True)
    config.verify_mode = 0
    config.alpn_protocols = ["h3"]

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


def test_quic_for_crawler(node):
    """
    UDP 协议节点的 QUIC 握手测试。
    返回 (可达, 延迟) 格式，与 test_node_connectivity 保持一致。

    - aioquic 未安装：保守返回 (True, 0)，保留节点，避免误杀
    - 握手成功：返回 (True, 0)
    - 握手失败：返回 (False, -1)
    """
    try:
        import aioquic  # noqa: F401
    except ImportError:
        # aioquic 未安装，保守保留节点
        node['delay'] = 0
        return True, 0

    server = clean_ipv6(node.get('add', ''))
    port = node.get('port', 0)
    if not server or not port:
        node['delay'] = -1
        return False, -1
    try:
        port = int(port)
    except (ValueError, TypeError):
        node['delay'] = -1
        return False, -1

    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            ok = loop.run_until_complete(
                _quic_handshake_async(server, port, QUIC_TIMEOUT)
            )
        finally:
            loop.close()
        node['delay'] = 0
        return ok, 0
    except Exception:
        node['delay'] = -1
        return False, -1


def test_node_connectivity(node, retries=TEST_RETRIES):
    """
    测试节点连通性，返回 (是否可达, 延迟毫秒)。
    并更新节点字典中的 'delay' 字段。

    新增：UDP 协议（hysteria / hysteria2 / tuic）走 QUIC 握手测试，
         不做 TCP 测通，避免误杀。
    IPv6 地址去方括号后再测试。
    """
    # ---- UDP 协议走 QUIC 测试 ----
    if node.get('type') in UDP_TYPES:
        return test_quic_for_crawler(node)

    host = clean_ipv6(node.get('add', ''))
    port = node.get('port', 0)
    if not host or not port:
        node['delay'] = -1
        return False, -1

    for attempt in range(retries):
        start = time.time()
        try:
            ip = socket.gethostbyname(host)
            with socket.create_connection((ip, port), timeout=CONNECT_TIMEOUT):
                delay = int((time.time() - start) * 1000)
                node['delay'] = delay
                return True, delay
        except Exception:
            if attempt < retries - 1:
                time.sleep(0.5)   # 重试间隔 0.5 秒
                continue
    node['delay'] = -1
    return False, -1


def node_to_vmess_link(node):
    """将节点对象还原为原始链接字符串（用于 Base64 导出）"""
    # ---- raw 回退：NODE_PREFIXES 或 HTTP 严格校验通过 ----
    if node.get('raw'):
        raw = node['raw']
        if raw.startswith(NODE_PREFIXES):
            return raw
        if raw.startswith(HTTP_PREFIXES) and is_definitely_proxy_url(raw):
            return raw

    ntype = node.get('type', '')
    if ntype == 'vmess':
        data = {
            'v': '2',
            'ps': node.get('ps', ''),
            'add': node.get('add', ''),
            'port': node.get('port', 0),
            'id': node.get('uuid', ''),
            'aid': node.get('alterId', 0),
            'net': node.get('network', 'tcp'),
            'type': 'none',
            'host': node.get('host', ''),
            'path': node.get('path', ''),
            'tls': 'tls' if node.get('tls') else '',
            'sni': node.get('sni', ''),
        }
        b64 = base64.b64encode(json.dumps(data).encode()).decode()
        return 'vmess://' + b64
    elif ntype == 'vless':
        uuid = node.get('uuid', '')
        host = node.get('add', '')
        port = node.get('port', 443)
        params = []
        if node.get('network'):
            params.append(f"type={node.get('network')}")
        if node.get('tls'):
            params.append("security=tls")
        if node.get('sni'):
            params.append(f"sni={node.get('sni')}")
        if node.get('flow'):
            params.append(f"flow={node.get('flow')}")
        if node.get('encryption') and node['encryption'] != 'none':
            params.append(f"encryption={node.get('encryption')}")
        # ---- reality-opts 输出 ----
        if node.get('reality-opts'):
            params.append("security=reality")
            if node['reality-opts'].get('public-key'):
                params.append(f"pbk={node['reality-opts']['public-key']}")
            if node['reality-opts'].get('short-id'):
                params.append(f"sid={node['reality-opts']['short-id']}")
        if node.get('client-fingerprint'):
            params.append(f"fp={node.get('client-fingerprint')}")
        query = '&'.join(params)
        return f"vless://{uuid}@{host}:{port}?{query}" if query else f"vless://{uuid}@{host}:{port}"
    elif ntype == 'ss':
        auth = f"{node.get('method','')}:{node.get('password','')}"
        auth_b64 = base64.b64encode(auth.encode()).decode()
        return f"ss://{auth_b64}@{node.get('add','')}:{node.get('port',0)}"
    elif ntype == 'ssr':
        # ---- ssr 输出 ----
        try:
            passwd_b64 = base64.urlsafe_b64encode(
                (node.get('password', '') or '').encode()
            ).decode().rstrip('=')
            head = f"{node.get('add','')}:{node.get('port',0)}:" \
                   f"{node.get('protocol','origin')}:{node.get('cipher','')}:" \
                   f"{node.get('obfs','plain')}:{passwd_b64}"
            params = []
            if node.get('ps'):
                params.append('remarks=' + base64.urlsafe_b64encode(
                    node['ps'].encode()).decode().rstrip('='))
            if node.get('obfs-param'):
                params.append('obfsparam=' + base64.urlsafe_b64encode(
                    node['obfs-param'].encode()).decode().rstrip('='))
            if node.get('protocol-param'):
                params.append('protoparam=' + base64.urlsafe_b64encode(
                    node['protocol-param'].encode()).decode().rstrip('='))
            raw_str = head
            if params:
                raw_str += '/?' + '&'.join(params)
            b64 = base64.urlsafe_b64encode(raw_str.encode()).decode().rstrip('=')
            return f"ssr://{b64}"
        except Exception:
            return node.get('raw', '')
    elif ntype == 'trojan':
        netloc = f"{node.get('password','')}@{node.get('add','')}:{node.get('port',443)}"
        params = []
        if node.get('sni'):
            params.append(f"sni={node.get('sni')}")
        if node.get('skip-cert-verify') or node.get('allowInsecure') == '1' or node.get('allowInsecure') is True:
            params.append("allowInsecure=1")
        query = '&'.join(params)
        return f"trojan://{netloc}?{query}" if query else f"trojan://{netloc}"
    elif ntype == 'hysteria2':
        # ---- hysteria2 输出 ----
        pwd = node.get('password', '')
        host = node.get('add', '')
        port = node.get('port', 443)
        url = f"hysteria2://{pwd}@{host}:{port}"
        if node.get('ports'):
            url += ',' + str(node['ports'])
        params = []
        if node.get('sni'):
            params.append(f"sni={node.get('sni')}")
        if node.get('skip-cert-verify'):
            params.append("insecure=1")
        if node.get('obfs'):
            params.append(f"obfs={node.get('obfs')}")
            if node.get('obfs-password'):
                params.append(f"obfs-password={node.get('obfs-password')}")
        if node.get('alpn'):
            params.append(f"alpn={node.get('alpn')}")
        query = '&'.join(params)
        return f"{url}?{query}" if query else url
    elif ntype == 'hysteria':
        # ---- hysteria v1 输出 ----
        host = node.get('add', '')
        port = node.get('port', 443)
        params = []
        if node.get('auth'):
            params.append(f"auth={node.get('auth')}")
        if node.get('sni'):
            params.append(f"peer={node.get('sni')}")
        if node.get('skip-cert-verify'):
            params.append("insecure=1")
        if node.get('up'):
            params.append(f"upmbps={node.get('up')}")
        if node.get('down'):
            params.append(f"downmbps={node.get('down')}")
        query = '&'.join(params)
        return f"hysteria://{host}:{port}?{query}" if query else f"hysteria://{host}:{port}"
    elif ntype == 'tuic':
        # ---- tuic 输出 ----
        uuid = node.get('uuid', '')
        pwd = node.get('password', '')
        host = node.get('add', '')
        port = node.get('port', 443)
        params = []
        if node.get('sni'):
            params.append(f"sni={node.get('sni')}")
        if node.get('skip-cert-verify'):
            params.append("allow_insecure=1")
        if node.get('alpn'):
            params.append(f"alpn={node.get('alpn')}")
        if node.get('congestion_control'):
            params.append(f"congestion_control={node.get('congestion_control')}")
        if node.get('udp_relay_mode'):
            params.append(f"udp_relay_mode={node.get('udp_relay_mode')}")
        query = '&'.join(params)
        return f"tuic://{uuid}:{pwd}@{host}:{port}?{query}" if query else f"tuic://{uuid}:{pwd}@{host}:{port}"
    elif ntype in ('http', 'socks5'):
        # ---- http/socks5 输出 ----
        scheme = 'socks5' if ntype == 'socks5' else ('https' if node.get('tls') else 'http')
        user = node.get('username', '')
        pwd = node.get('password', '')
        auth = ''
        if user:
            auth = user
            if pwd:
                auth += ':' + pwd
            auth += '@'
        return f"{scheme}://{auth}{node.get('add')}:{node.get('port')}"
    else:
        return node.get('raw', '')

def is_node_valid(node):
    """检查节点是否包含 Clash 必需字段"""
    node_type = node.get('type', '').lower()
    if not node_type:
        return False
    # ---- 白名单扩展 ----
    if node_type not in ('vmess', 'vless', 'ss', 'ssr', 'trojan',
                         'hysteria', 'hysteria2', 'tuic', 'http', 'socks5'):
        return False
    if node_type == 'vmess':
        if not node.get('uuid'):
            return False
    elif node_type == 'vless':
        if not node.get('uuid'):
            return False
    elif node_type == 'ss':
        if not node.get('method') or not node.get('password'):
            return False
    elif node_type == 'ssr':
        # ---- ssr 校验 ----
        if not node.get('protocol') or not node.get('password'):
            return False
    elif node_type == 'trojan':
        if not node.get('password'):
            return False
    elif node_type == 'hysteria2':
        # ---- hysteria2 校验 ----
        if not node.get('password'):
            return False
    elif node_type == 'hysteria':
        # ---- hysteria 校验 ----
        if not node.get('auth'):
            return False
    elif node_type == 'tuic':
        # ---- tuic 校验 ----
        if not node.get('uuid') or not node.get('password'):
            return False
    return True

# ======================== 导出函数（支持 11 种协议） ========================

def to_clash_proxy(node):
    """
    将节点转换为 Clash proxy 字典，支持：
    vmess / vless / ss / ssr / trojan / hysteria / hysteria2 / tuic / http / socks5
    """
    ntype = node.get('type')
    if ntype == 'vmess':
        proxy = {
            'name': '',
            'type': 'vmess',
            'server': node.get('add', ''),
            'port': int(node.get('port', 0)),
            'uuid': node.get('uuid', ''),
            'alterId': int(node.get('alterId', 0)),
            'cipher': node.get('cipher', 'auto'),
            'tls': bool(node.get('tls', False)),
            'network': node.get('network', 'tcp'),
        }
        if node.get('network') == 'ws':
            ws_opts = {
                'path': node.get('path') or '/',
                'headers': {
                    'Host': node.get('host') or node.get('add')
                }
            }
            proxy['ws-opts'] = ws_opts
        if node.get('sni'):
            proxy['sni'] = node.get('sni')
        # ---- alpn ----
        alpn = _alpn_to_list(node.get('alpn'))
        if alpn:
            proxy['alpn'] = alpn
        return proxy

    elif ntype == 'vless':
        proxy = {
            'name': '',
            'type': 'vless',
            'server': node.get('add', ''),
            'port': int(node.get('port', 0)),
            'uuid': node.get('uuid', ''),
            'network': node.get('network', 'tcp'),
            'tls': bool(node.get('tls', False)),
            'flow': node.get('flow', ''),
            'encryption': node.get('encryption', 'none'),
        }
        if node.get('sni'):
            proxy['sni'] = node.get('sni')
        # ---- reality-opts ----
        if node.get('reality-opts'):
            proxy['reality-opts'] = node['reality-opts']
            proxy['tls'] = True
        if node.get('client-fingerprint'):
            proxy['client-fingerprint'] = node['client-fingerprint']
        # ---- alpn ----
        alpn = _alpn_to_list(node.get('alpn'))
        if alpn:
            proxy['alpn'] = alpn
        return proxy

    elif ntype == 'ss':
        return {
            'name': '',
            'type': 'ss',
            'server': node.get('add', ''),
            'port': int(node.get('port', 0)),
            'cipher': node.get('method', ''),
            'password': node.get('password', ''),
        }

    # ---- ssr ----
    elif ntype == 'ssr':
        proxy = {
            'name': '',
            'type': 'ssr',
            'server': node.get('add', ''),
            'port': int(node.get('port', 0)),
            'cipher': node.get('cipher', ''),
            'password': node.get('password', ''),
            'protocol': node.get('protocol', 'origin'),
            'obfs': node.get('obfs', 'plain'),
        }
        if node.get('obfs-param'):
            proxy['obfs-param'] = node['obfs-param']
        if node.get('protocol-param'):
            proxy['protocol-param'] = node['protocol-param']
        return proxy

    elif ntype == 'trojan':
        proxy = {
            'name': '',
            'type': 'trojan',
            'server': node.get('add', ''),
            'port': int(node.get('port', 0)),
            'password': node.get('password', ''),
        }
        if node.get('sni'):
            proxy['sni'] = node.get('sni')
        # ---- 统一 skip-cert-verify 判断 ----
        if node.get('skip-cert-verify') or node.get('allowInsecure') == '1' or node.get('allowInsecure') is True:
            proxy['skip-cert-verify'] = True
        # ---- alpn ----
        alpn = _alpn_to_list(node.get('alpn'))
        if alpn:
            proxy['alpn'] = alpn
        # ---- ws / grpc 传输 ----
        if node.get('network') == 'ws':
            proxy['network'] = 'ws'
            proxy['ws-opts'] = {
                'path': node.get('path') or '/',
                'headers': {'Host': node.get('host') or node.get('add')}
            }
        return proxy

    # ---- hysteria2 ----
    elif ntype == 'hysteria2':
        proxy = {
            'name': '',
            'type': 'hysteria2',
            'server': node.get('add', ''),
            'port': int(node.get('port', 443)),
            'password': node.get('password', ''),
        }
        if node.get('sni'):
            proxy['sni'] = node['sni']
        if node.get('skip-cert-verify'):
            proxy['skip-cert-verify'] = True
        if node.get('obfs'):
            proxy['obfs'] = node['obfs']
            if node.get('obfs-password'):
                proxy['obfs-password'] = node['obfs-password']
        if node.get('ports'):
            proxy['ports'] = node['ports']
        alpn = _alpn_to_list(node.get('alpn'))
        if alpn:
            proxy['alpn'] = alpn
        return proxy

    # ---- hysteria v1 ----
    elif ntype == 'hysteria':
        proxy = {
            'name': '',
            'type': 'hysteria',
            'server': node.get('add', ''),
            'port': int(node.get('port', 443)),
            'auth-str': node.get('auth', ''),
            'protocol': node.get('protocol', 'udp'),
        }
        if node.get('sni'):
            proxy['sni'] = node['sni']
        if node.get('skip-cert-verify'):
            proxy['skip-cert-verify'] = True
        if node.get('up'):
            proxy['up'] = node['up']
        if node.get('down'):
            proxy['down'] = node['down']
        alpn = _alpn_to_list(node.get('alpn'))
        if alpn:
            proxy['alpn'] = alpn
        return proxy

    # ---- tuic ----
    elif ntype == 'tuic':
        proxy = {
            'name': '',
            'type': 'tuic',
            'server': node.get('add', ''),
            'port': int(node.get('port', 443)),
            'uuid': node.get('uuid', ''),
            'password': node.get('password', ''),
        }
        if node.get('sni'):
            proxy['sni'] = node['sni']
        if node.get('skip-cert-verify'):
            proxy['skip-cert-verify'] = True
        alpn = _alpn_to_list(node.get('alpn'))
        if alpn:
            proxy['alpn'] = alpn
        if node.get('congestion_control'):
            proxy['congestion-controller'] = node['congestion_control']
        if node.get('udp_relay_mode'):
            proxy['udp-relay-mode'] = node['udp_relay_mode']
        return proxy

    # ---- http/https ----
    elif ntype == 'http':
        proxy = {
            'name': '',
            'type': 'http',
            'server': node.get('add', ''),
            'port': int(node.get('port', 80)),
        }
        if node.get('username'):
            proxy['username'] = node['username']
        if node.get('password'):
            proxy['password'] = node['password']
        if node.get('tls'):
            proxy['tls'] = True
            proxy['sni'] = node.get('sni') or node.get('add', '')
        return proxy

    # ---- socks5 ----
    elif ntype == 'socks5':
        proxy = {
            'name': '',
            'type': 'socks5',
            'server': node.get('add', ''),
            'port': int(node.get('port', 1080)),
        }
        if node.get('username'):
            proxy['username'] = node['username']
        if node.get('password'):
            proxy['password'] = node['password']
        return proxy

    else:
        return None

def nodes_to_clash_yaml(nodes):
    """
    将节点列表转换为完整的 Clash 配置文件 YAML 字符串。
    支持 11 种协议，输出格式与原 JavaScript 版本一致。
    """
    if not nodes:
        return ""

    proxies = []
    used_names = {}

    for node in nodes:
        if not is_node_valid(node):
            print(f"⚠️ 跳过无效节点: {node.get('add', 'unknown')} (type: {node.get('type', '')})")
            continue

        # ---- 名称生成：新增协议前缀 ----
        base_name = node.get('ps', '').strip()
        if not base_name:
            t = node.get('type', '')
            prefix = NAME_PREFIX_MAP.get(t, t.upper())
            base_name = f"{prefix}-{node.get('add')}:{node.get('port')}"
        # ----------------------------------

        delay = node.get('delay', -1)
        if delay > 0:
            name = f"{base_name} - {delay}ms"
        else:
            name = base_name

        # 去重（与 JavaScript 一致）
        original_name = name
        counter = 1
        while name in used_names:
            name = f"{original_name}_{counter}"
            counter += 1
        used_names[name] = True

        # 构建 Clash proxy
        proxy = to_clash_proxy(node)
        if proxy is None:
            continue
        proxy['name'] = name
        proxies.append(proxy)

    if not proxies:
        print("⚠️ 没有有效节点，无法生成 Clash 配置")
        return ""

    # 构建完整配置（与 JavaScript 完全一致）
    proxy_names = [p['name'] for p in proxies]
    config = {
        'port': 7890,
        'socks-port': 7891,
        'allow-lan': True,
        'mode': 'Rule',
        'log-level': 'info',
        'external-controller': '127.0.0.1:9090',
        'proxies': proxies,
        'proxy-groups': [
            {
                'name': 'Auto Select',
                'type': 'url-test',
                'proxies': proxy_names,
                'url': 'http://www.gstatic.com/generate_204',
                'interval': 300
            },
            {
                'name': 'Proxy',
                'type': 'select',
                'proxies': ['Auto Select'] + proxy_names
            }
        ],
        'rules': [
            'MATCH,Proxy'
        ]
    }

    return yaml.dump(config, default_flow_style=False, allow_unicode=True)

def nodes_to_base64(nodes):
    """将节点列表转换为 Base64 订阅字符串"""
    links = []
    for node in nodes:
        link = node_to_vmess_link(node)
        if link:
            links.append(link)
    raw = '\n'.join(links)
    return base64.b64encode(raw.encode()).decode()

# ======================== 主爬虫类 ========================

class Crawler:
    def __init__(self):
        self.visited_urls = set()
        self.queue = deque()
        self.all_nodes = []
        # ---- 【修改 T】request_count 改为每源计数（每源重置），
        #                 total_requests 为全局累计（永不重置） ----
        self.request_count = 0          # 当前源的请求数（每源重置）
        self.total_requests = 0         # 全局总请求数（跨源累计，永不重置）

    def process_sources(self, lines):
        wildcard_items = []
        direct_urls = []
        plain_pages_set = set()

        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if line.startswith('+date'):
                parts = line.split(maxsplit=1)
                if len(parts) < 2:
                    continue
                url_template = parts[1].strip()
                try:
                    url = datetime.now().strftime(url_template)
                except:
                    url = url_template
            else:
                url = line

            if '*' in url:
                pattern = re.escape(url).replace('\\*', '.*')
                regex = re.compile('^' + pattern + '$', re.IGNORECASE)
                wildcard_items.append((url, regex))
            else:
                if is_direct_subscription(url):
                    direct_urls.append(url)
                else:
                    clean = url.rstrip('/')
                    plain_pages_set.add(clean)

        wildcard_map = {}
        for url, regex in wildcard_items:
            base_part = url.split('*', 1)[0].rstrip('/')
            matched_base = None
            if base_part in plain_pages_set:
                matched_base = base_part
            else:
                candidates = [p for p in plain_pages_set if p.startswith(base_part) and p != base_part]
                if candidates:
                    matched_base = max(candidates, key=len)
                else:
                    parsed = urlparse(base_part)
                    root_url = f"{parsed.scheme}://{parsed.netloc}".rstrip('/')
                    if root_url in plain_pages_set:
                        matched_base = root_url
            if matched_base:
                if matched_base not in wildcard_map:
                    wildcard_map[matched_base] = []
                wildcard_map[matched_base].append(regex)
            else:
                if base_part not in wildcard_map:
                    wildcard_map[base_part] = []
                wildcard_map[base_part].append(regex)

        plain_pages = list(plain_pages_set)
        return wildcard_map, direct_urls, plain_pages

    def enqueue(self, url, depth, patterns):
        """
        【修复 Q3】入队：URL 规范化 + 准入检查 + 返回 bool 表示是否成功入队
        返回:
            True  -> 成功加入队列
            False -> 未加入（已访问 或 超出配额）

        【修改 T】双重检查：
          - request_count >= MAX_REQUESTS_PER_SOURCE → 永久拒绝（一次性触发）
          - len(queue) >= MAX_QUEUE_PER_SOURCE        → 暂时拒绝（消费到低于上限后恢复）

        【L1】日期拒绝时打印原因，方便排查"为什么没入队"
        """
        # ---- 【修改 E】新增：URL 规范化 ----
        url = normalize_url(url)
        if url in self.visited_urls:
            return False
        # ---- 【新增 W】方案 1：URL 日期过滤（零成本）----
        # 命中"URL 含日期且太老"时直接拒绝入队，不消耗任何请求
        if is_url_too_old(url):
            # ---- 【L1】打印拒绝原因，方便排查 ----
            print(f"  -> [DATE] enqueue rejected (too old): {url}")
            return False
        # ---- 【修改 T】每源请求数上限：一次性触发 ----
        # 达到 MAX_REQUESTS_PER_SOURCE 后永久拒绝新 URL，
        # 但已入队 URL 会继续处理完（软上限）
        if self.request_count >= MAX_REQUESTS_PER_SOURCE:
            return False
        # ---- 【修改 T】每源队列上限：持续检查 ----
        # 队列达到 MAX_QUEUE_PER_SOURCE 时暂时拒绝入队，
        # 消费到低于上限后恢复放行（防止单源派生过多时队列无限膨胀）
        if len(self.queue) >= MAX_QUEUE_PER_SOURCE:
            return False
        self.queue.append((url, depth, patterns))
        return True

    # ---- 【新增 D】三级降级统一入口 ----
    def _process_url(self, url, depth, patterns):
        """
        【新增 D】处理单个 URL 的三级降级流程：
          [1] 当订阅解析（parse_subscription_content）→ 成功即 return
          [2] 当字段列表解析（parse_field_list_text）→ 成功则继续 [3]
          [3] 当网页解析（parse_page）→ 递归找关键词/通配符链接

        深度由全局变量 MAX_DEPTH 控制；请求数由 MAX_REQUESTS_PER_SOURCE 控制（软上限）。
        """
        # ---- URL 规范化 + visited 检查 ----
        # 【修复 Q2】软上限：不再检查 request_count
        # 达到 MAX_REQUESTS_PER_SOURCE 后 enqueue 已拒绝新 URL，队列只出不进必然清空
        # 已入队的 URL 必须处理完，不再丢节点
        url = normalize_url(url)
        if url in self.visited_urls:
            return
        self.visited_urls.add(url)
        # ---- 【修改 T】request_count 每源计数，total_requests 全局累计 ----
        self.request_count += 1
        self.total_requests += 1
        # ---- 【修改 T】软上限日志阈值 >= ：request_count 刚达上限时也显示队列残留 ----
        _over = f" [queue: {len(self.queue)}]" if self.request_count >= MAX_REQUESTS_PER_SOURCE else ""
        print(f"[{self.request_count}/{MAX_REQUESTS_PER_SOURCE}] Processing: {url} (depth={depth}){_over}")

        # ---- 【本次新增】抓取内容（改为带 headers，供方案 3 使用） ----
        try:
            content, resp_headers = fetch_with_headers(url)
        except Exception as e:
            print(f"  -> fetch error: {e}")
            return
        if not content:
            print(f"  -> empty content")
            return

        # ---- 【新增 X】方案 3：Last-Modified 日期过滤 ----
        # 只对"URL 无日期 + 非订阅后缀"的普通网页生效
        # 订阅后缀豁免：Last-Modified 老不代表订阅节点失效
        if (URL_DATE_FILTER_ENABLED
                and not url_date_info(url)
                and not has_subscription_suffix(url)
                and is_too_old_by_last_modified(resp_headers)):
            lm = resp_headers.get('Last-Modified', '?')
            print(f"  -> [DATE] skip too old (Last-Modified={lm}): {url}")
            return

        try:
            text = content.decode('utf-8', errors='ignore')
        except Exception:
            return
        if not text:
            return

        # ---- [1] 当订阅解析 ----
        nodes = parse_subscription_content(text, url)
        if nodes:
            for node in nodes:
                if not node.get('raw'):
                    node['raw'] = node_to_vmess_link(node)
            self.all_nodes.extend(nodes)
            print(f"  -> [SUB] {len(nodes)} nodes")
            return   # 订阅解析成功不再继续爬

        # ---- [2] 当字段列表解析 ----
        nodes = parse_field_list_text(text)
        if nodes:
            for node in nodes:
                if not node.get('raw'):
                    node['raw'] = node_to_vmess_link(node)
            self.all_nodes.extend(nodes)
            print(f"  -> [FIELD] {len(nodes)} nodes")
            # 不 return：字段列表页可能还有下级链接

        # ---- [3] 当网页继续爬 ----
        if depth < MAX_DEPTH:
            try:
                self.parse_page(text, url, depth, patterns, allow_expand=True)
            except Exception as e:
                print(f"  -> page scan error: {e}")

            # ---- 【修改 K】新增：属性提取器（并行并集） ----
            try:
                self._run_attribute_extractors(text, url, depth, patterns, allow_expand=True)
            except Exception as e:
                print(f"  -> attr scan error: {e}")
            # ----------------------------------------
        else:
            # ---- 【修改 V】最后一层网页订阅直通（方案 B） ----
            # 仍然扫描页面，但只提取订阅后缀链接和协议链接；
            # 普通网页 URL 一律不入队（allow_expand=False）
            print(f"  -> depth limit reached ({MAX_DEPTH}), extracting subscriptions only")
            try:
                self.parse_page(text, url, depth, patterns, allow_expand=False)
            except Exception as e:
                print(f"  -> page scan error: {e}")
            try:
                self._run_attribute_extractors(text, url, depth, patterns, allow_expand=False)
            except Exception as e:
                print(f"  -> attr scan error: {e}")

    # ======================== 【新增 J】属性提取器调度器 ========================
    def _run_attribute_extractors(self, html, base_url, depth, patterns, allow_expand=True):
        """
        【新增 J】并行并集模式：
          - 3 个提取器（属性/文本容器/脚本）无条件全跑
          - 结果按字符串去重后合并
          - 走与原代码一致的过滤链：
              visited_urls → 黑名单 → 协议链接直接解析 → 网页链接 enqueue

        【修复 M】协议链接分流：
          - 命中 NODE_PREFIXES 的 URL（如 vless://... / trojan://...）
            → 直接 parse_node_link 加入 all_nodes
            → 不再 enqueue（因为 fetch_binary("vless://...") 必然失败）

        【修复 Q1】订阅后缀分流（三分类）：
          - 1) 协议链接 → 直接解析，不入队
          - 2) 有订阅后缀（.txt/.b64/...）→ 立即 _process_url，不入队
          - 3) 无后缀网页 URL → 走关键词过滤后 enqueue

        【修复 Q3】enqueue 返回 bool 修正日志：
          - 之前 enqueue 被拒绝（超 400 或已访问）后仍无条件 queued += 1 + print
          - 现在只有 enqueue 返回 True 时才计数和打印

        【修改 V】新增 allow_expand 参数：
          - True（默认）：行为不变
          - False：只处理协议链接和订阅后缀，普通网页 URL 一律不入队

        设计细节：
          - 每个提取器独立 try/except：单个失败不影响其他
          - 汇总日志：仅在找到 URL 时输出，避免刷屏
          - 不修改 visited_urls，交给 enqueue / _process_url 统一处理
        """
        try:
            soup = BeautifulSoup(html, 'html.parser')
        except Exception as e:
            print(f"  [ATTR] soup parse error: {e}")
            return

        all_urls, seen = [], set()
        stats = {}

        # ---- 逐提取器执行（union：全部跑） ----
        for name, fn in URL_EXTRACTORS:
            try:
                urls = fn(soup, base_url)
            except Exception as e:
                print(f"  [ATTR-{name}] error: {e}")
                stats[name] = 0
                continue
            stats[name] = len(urls)
            for u in urls:
                if u not in seen:
                    seen.add(u)
                    all_urls.append(u)

        if not all_urls:
            return

        # ---- 汇总日志 ----
        summary = ", ".join(f"{k}={v}" for k, v in stats.items())
        print(f"  [ATTR] found {len(all_urls)} unique URLs ({summary})")

        # ---- 统一过滤链（与 parse_page 源 1/2/3 对齐） ----
        # 【修复 M】协议链接直接解析
        # 【修复 Q1】三分类：协议链接 / 有后缀订阅 / 无后缀网页
        parsed = 0        # 协议链接直接解析
        subscribed = 0    # 有后缀订阅立即处理
        queued = 0        # 无后缀网页 URL 入队
        for url in all_urls:
            if url in self.visited_urls:
                continue
            if is_blacklisted(url):
                continue

            # ---- 1) 协议链接：直接解析，不入队 ----
            if url.startswith(NODE_PREFIXES):
                node = parse_node_link(url)
                if node:
                    node['raw'] = url
                    self.all_nodes.append(node)
                    parsed += 1
                    print(f"  [ATTR] parsed node: {url[:60]}...")
                continue

            # ---- 2) 有订阅后缀：立即处理，不入队 ----
            # 【修复 Q1】后缀命中（.txt/.yaml/.yml/.b64/.base64/.conf）
            # 直接 _process_url，避免排队占用槽位、避免被 MAX_REQUESTS_PER_SOURCE 截断
            if has_subscription_suffix(url):
                print(f"  [ATTR] subscription (suffix), processing directly: {url[:80]}")
                try:
                    self._process_url(url, depth + 1, patterns)
                    subscribed += 1
                except Exception as e:
                    print(f"  [ATTR] direct subscription error: {e}")
                continue

            # ---- 3) 无后缀网页 URL：走关键词过滤后入队 ----
            # 【修复 Q3】只有 enqueue 返回 True 时才计数和打印
            # （enqueue 在超 MAX_REQUESTS_PER_SOURCE 或已访问时返回 False，静默拒绝）
            # 【修改 V】allow_expand=False 时跳过普通网页入队
            if is_node_link(url):
                if depth < MAX_DEPTH and allow_expand:
                    if self.enqueue(url, depth + 1, patterns):
                        queued += 1
                        print(f"  [ATTR] queued: {url[:100]}")

        if parsed:
            print(f"  [ATTR] {parsed} nodes parsed directly")
        if subscribed:
            print(f"  [ATTR] {subscribed} subscriptions processed directly")
        if queued:
            print(f"  [ATTR] {queued} URLs queued")

    # ---- 【Legacy】原有订阅下载方法（保留，不被主流程调用） ----
    def download_subscription(self, url):
        """
        【Legacy】仅解析订阅，不降级。
        新流程已由 _process_url 取代；保留此方法供外部调用或未来回退使用。
        """
        if url in self.visited_urls:
            return
        self.visited_urls.add(url)
        self.request_count += 1
        # ---- 【修改 T】legacy 同步累计全局计数，日志引用新参数名 ----
        self.total_requests += 1
        print(f"[{self.request_count}/{MAX_REQUESTS_PER_SOURCE}] Downloading subscription: {url}")
        try:
            content = fetch_binary(url)
            if content is None:
                print(f"  -> No content (fetch failed)")
                return
            try:
                text = content.decode('utf-8', errors='ignore')
            except:
                text = ''
            if not text:
                print(f"  -> Empty content")
                return
            nodes = parse_subscription_content(text, url)
            if nodes:
                for node in nodes:
                    if 'raw' not in node or not node['raw']:
                        node['raw'] = node_to_vmess_link(node)
                self.all_nodes.extend(nodes)
                print(f"  -> Found {len(nodes)} nodes")
            else:
                print(f"  -> No nodes parsed")
        except Exception as e:
            print(f"  -> Error: {e}")

    def parse_page(self, html, base_url, depth, patterns, allow_expand=True):
        """
        【修改 V】新增 allow_expand 参数：
          - True（默认）：行为不变，所有发现的 URL 都正常处理
          - False（最后一层）：仍然扫描页面，但普通网页 URL 一律不入队；
            协议链接和订阅后缀不受影响，继续正常处理

        【L2】wildcard 分支：日期过滤提前到 print 之前
          - 过期 URL 直接跳过，不打印、不入队，避免"打印了 = 入队了"的误解
        """
        if patterns and not isinstance(patterns, list):
            patterns = [patterns]

        soup = BeautifulSoup(html, 'html.parser')

        if patterns:
            text = soup.get_text()
            url_regex = re.compile(r'https?://[^\s<>"\'{}|\\^`\[\]]+', re.IGNORECASE)
            for match in url_regex.findall(text):
                url = clean_url(match)
                if url in self.visited_urls:
                    continue
                for pattern in patterns:
                    if pattern.match(url):
                        # ---- 【L2】日期过滤提前到 print 之前 ----
                        # 过期 URL 不打印、不入队
                        if is_url_too_old(url):
                            break
                        print(f"  Found wildcard-matched URL from text: {url}")
                        # 【修改 V】allow_expand=False 时通配符匹配的普通网页不入队
                        if depth < MAX_DEPTH and allow_expand:
                            self.enqueue(url, depth + 1, patterns)
                        break

        for a in soup.find_all('a', href=True):
            href = a['href']
            full_url = safe_urljoin(base_url, href)
            if not full_url:
                continue
            full_url = clean_url(full_url)
            if full_url in self.visited_urls:
                continue

            matched = False
            if patterns:
                for pattern in patterns:
                    if pattern.match(full_url):
                        matched = True
                        break

            if matched:
                # ---- 【L2】日期过滤提前到 print 之前 ----
                # 过期 URL 不打印、不入队
                if is_url_too_old(full_url):
                    continue
                print(f"  Found wildcard-matched URL from href: {full_url}")
                # 【修改 V】allow_expand=False 时通配符匹配的普通网页不入队
                if depth < MAX_DEPTH and allow_expand:
                    self.enqueue(full_url, depth + 1, patterns)
                continue

            if is_node_link(full_url):
                # ---- 【修改 F】新增：黑名单前置 ----
                if is_blacklisted(full_url):
                    continue
                # ---- 【修改 F】命中后仅入队，由主循环统一走 _process_url ----
                # 【修复 Q3】enqueue 返回 bool，此处不打印日志，直接忽略返回值
                # ---- 【修改 R】订阅后缀直通：.yaml/.txt/.b64/.conf 等直接处理，
                #      不入队，避免被 MAX_REQUESTS 入队闸门拦住（与 _run_attribute_extractors 逻辑一致）
                # 【修改 V】订阅后缀不受 allow_expand 影响（始终直通）
                if depth < MAX_DEPTH:
                    if has_subscription_suffix(full_url):
                        self._process_url(full_url, depth + 1, patterns)
                    elif allow_expand:
                        self.enqueue(full_url, depth + 1, patterns)

        text = soup.get_text()
        url_regex = re.compile(r'https?://[^\s<>"\'{}|\\^`\[\]]+', re.IGNORECASE)
        for match in url_regex.findall(text):
            url = clean_url(match)
            if url in self.visited_urls:
                continue

            already_matched = False
            if patterns:
                for pattern in patterns:
                    if pattern.match(url):
                        already_matched = True
                        break
            if already_matched:
                continue

            if is_node_link(url):
                # ---- 【修改 F】新增：黑名单前置 ----
                if is_blacklisted(url):
                    continue
                # ---- 【修改 F】命中后仅入队 ----
                # 【修复 Q3】enqueue 返回 bool，此处不打印日志，直接忽略返回值
                # ---- 【修改 R】订阅后缀直通：.yaml/.txt/.b64/.conf 等直接处理，
                #      不入队，避免被 MAX_REQUESTS 入队闸门拦住（与 _run_attribute_extractors 逻辑一致）
                # 【修改 V】订阅后缀不受 allow_expand 影响（始终直通）
                if depth < MAX_DEPTH:
                    if has_subscription_suffix(url):
                        self._process_url(url, depth + 1, patterns)
                    elif allow_expand:
                        self.enqueue(url, depth + 1, patterns)

        # ---- node_link_regex 前缀扩展 ----
        # 注意：
        #   1. 顺序：长前缀在前（ssr 在 ss 前，socks5h 在 socks5 前，socks5 在 socks 前）
        #   2. 不包含 http/https，避免网页 URL 污染
        #   3. 协议链接直接解析，不受 allow_expand 影响
        node_link_regex = re.compile(
            r'(vmess|vless|ssr|ss|trojan|hysteria2|hy2|hysteria|tuic|'
            r'socks5h|socks5|socks)://[^\s<>"\'{}|\\^`\[\]]+',
            re.IGNORECASE
        )
        for match in node_link_regex.finditer(text):
            link = match.group(0).strip()
            node = parse_node_link(link)
            if node:
                node['raw'] = link
                self.all_nodes.append(node)
                print(f"  Found direct node link: {link[:50]}...")

    def crawl(self, source_lines):
        wildcard_map, direct_urls, plain_pages = self.process_sources(source_lines)

        # ---- 【修改 T】重写 crawl：每源独立处理 ----
        # 旧逻辑：全局一个队列 + 全局一个 request_count，所有源混在一起。
        #         direct_urls 先跑，会挤占 plain_pages / wildcard_map 的入队配额。
        # 新逻辑：每个源独立处理，每源有自己的 queue 和 request_count。
        #         处理完一个源的所有 URL（含剩余队列）后，再切换到下一个源。
        #         visited_urls 跨源共享，不重复处理。
        #         MAX_REQUESTS_PER_SOURCE 控制每源请求数（一次性触发）。
        #         MAX_QUEUE_PER_SOURCE 控制每源队列占用（持续检查）。
        #         MAX_REQUESTS_TOTAL 控制全局总量（达到后跳过剩余源）。

        # 组装所有源（保持【修改 S】"普通页面优先于直接订阅"的语义）：
        #   1) plain_pages 带 wildcard 绑定
        #   2) wildcard_map 未绑定到普通页面的通配符 base_part
        #   3) direct_urls 直接订阅（每个独立源）
        sources = []
        for url in plain_pages:
            patterns = wildcard_map.pop(url, None)
            sources.append((url, patterns))
        for base_url, patterns in wildcard_map.items():
            sources.append((base_url, patterns))
        for url in direct_urls:
            sources.append((url, None))

        print(f"📋 Total sources: {len(sources)}")

        for source_url, patterns in sources:
            # ---- 【修改 T】全局硬上限检查（切换源时） ----
            if self.total_requests >= MAX_REQUESTS_TOTAL:
                print(f"⛔ Global request limit ({MAX_REQUESTS_TOTAL}) reached, "
                      f"skip remaining sources")
                break

            # ---- 重置当前源状态 ----
            self.queue.clear()
            self.request_count = 0
            source_start = time.time()
            source_start_nodes = len(self.all_nodes)

            # ---- 起点入队 ----
            # 注意：起点可能已被 visited_urls 拦截（被之前的源访问过），
            #       此时 enqueue 返回 False，队列为空，直接跳过该源。
            if not self.enqueue(source_url, 1, patterns):
                # ---- 【修改 T】跳过源也打印统计（requests=0, nodes=+0） ----
                print(f"⏭️  Skip source (visited or quota): {source_url} "
                      f"(requests=0, nodes=+0)")
                continue

            # ---- 消费当前源的全部 URL ----
            # 达到 MAX_REQUESTS_PER_SOURCE 后 enqueue 拒绝新 URL，
            # 但队列里的 URL 仍会走完整 _process_url（含 parse_page）。
            # 订阅后缀直通和协议链接直接解析不受上限影响，继续生效。
            try:
                while self.queue:
                    # ---- 【修改 T】全局硬上限检查（当前源消费过程中） ----
                    # 避免单个源把 total_requests 推得远超 MAX_REQUESTS_TOTAL
                    if self.total_requests >= MAX_REQUESTS_TOTAL:
                        print(f"⛔ Global request limit ({MAX_REQUESTS_TOTAL}) reached "
                              f"mid-source, stopping {source_url} "
                              f"(queue_left={len(self.queue)})")
                        self.queue.clear()
                        break
                    url, depth, pats = self.queue.popleft()
                    if url in self.visited_urls:
                        continue
                    self._process_url(url, depth, pats)
            except Exception as e:
                print(f"❌ Source error: {source_url}: {e}")

            # ---- 每源结束统计 ----
            duration = time.time() - source_start
            added_nodes = len(self.all_nodes) - source_start_nodes
            print(f"✅ Source done: {source_url} "
                  f"(requests={self.request_count}, nodes=+{added_nodes}, "
                  f"queue_left={len(self.queue)}, duration={duration:.1f}s)")

        print(f"🏁 Crawl finished. Total requests: {self.total_requests}, "
              f"Nodes collected: {len(self.all_nodes)}")

    def dedupe_and_test(self):
        print("🔄 Deduplicating...")
        unique = {}
        for node in self.all_nodes:
            key = normalize_node_key(node)
            if key not in unique:
                unique[key] = node
        nodes = list(unique.values())
        print(f"   After dedupe: {len(nodes)} nodes")

        # ---- 协议分布统计 ----
        from collections import Counter
        type_dist = Counter(n.get('type') for n in nodes)
        print(f"   Protocol distribution: {dict(type_dist)}")
        # ------------------------------

        print(f"🌐 Testing connectivity (timeout={CONNECT_TIMEOUT}s, retries={TEST_RETRIES}, workers={TEST_WORKERS})...")
        valid_nodes = []
        with ThreadPoolExecutor(max_workers=TEST_WORKERS) as executor:
            future_to_node = {executor.submit(test_node_connectivity, node): node for node in nodes}
            for future in as_completed(future_to_node):
                node = future_to_node[future]
                try:
                    reachable, delay = future.result()
                    if reachable and delay <= MAX_DELAY:
                        node['delay'] = delay
                        valid_nodes.append(node)
                        print(f"   ✅ {node.get('add')}:{node.get('port')} - {delay}ms")
                    elif reachable and delay > MAX_DELAY:
                        print(f"   ⏱️  Too slow: {node.get('add')}:{node.get('port')} - {delay}ms (exceeds {MAX_DELAY}ms)")
                    else:
                        print(f"   ❌ Unreachable: {node.get('add')}:{node.get('port')}")
                except Exception as e:
                    print(f"   ⚠️  Test error: {e}")
        print(f"   After connectivity test: {len(valid_nodes)} nodes (filtered by max delay {MAX_DELAY}ms)")
        return valid_nodes

    def run(self):
        if not os.path.exists(SOURCE_FILE):
            print(f"❌ Error: Source file '{SOURCE_FILE}' not found.")
            sys.exit(1)

        with open(SOURCE_FILE, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        self.crawl(lines)

        if not self.all_nodes:
            print("❌ No nodes collected. Check your sources and network.")
            return

        valid_nodes = self.dedupe_and_test()

        if not valid_nodes:
            print("❌ No valid nodes after testing. No output files generated.")
            return

        clash_yaml = nodes_to_clash_yaml(valid_nodes)
        if clash_yaml:
            with open(OUTPUT_YAML, 'w', encoding='utf-8') as f:
                f.write(clash_yaml)
            print(f"✅ Clash YAML written to {OUTPUT_YAML}")
        else:
            print("❌ No valid nodes to write to Clash YAML")

        base64_str = nodes_to_base64(valid_nodes)
        with open(OUTPUT_TXT, 'w', encoding='utf-8') as f:
            f.write(base64_str)
        print(f"✅ Base64 subscription written to {OUTPUT_TXT}")

# ======================== 主入口 ========================
if __name__ == '__main__':
    crawler = Crawler()
    crawler.run()

fetch_pro2.py 代码说明文档
1. 脚本概述
fetch_pro2.py 是一个多源代理节点抓取、解析、去重、合并与订阅生成脚本。
它从 sources.list、动态链接生成器以及机场订阅列表中抓取节点，解析为统一的 Node 对象，去重合并后生成：

V2Ray 明文订阅（list_raw.txt）

V2Ray Base64 订阅（list.txt）

Clash 配置（list.yml）

Clash Meta 配置（list.meta.yml）

按地区分类的节点片段（snippets/nodes_*.yml）

规则片段（snippets/rules_*.yml）

统计信息（list_result.csv）

脚本还集成了 Adblock 规则解析、节点名称格式化、协议支持性检查、代理组冲突过滤等功能。

2. 整体框架与流程
text
读取配置 (sources.list / local_proxy.conf / dynamic.py)
        │
        ▼
处理机场列表 (* 前缀) ──► extract() 抓取机场页面中的订阅链接
        │
        ▼
生成动态链接 (+ 前缀 / +date 占位符)
        │
        ▼
多线程抓取订阅源 (Source.get)
        │
        ▼
解析订阅内容 (YAML / Base64 / 明文链接)
        │
        ▼
节点解析与合并 (Node / merge)
        │
        ├──► 成功解析 → merged 字典（去重）
        └──► 解析失败 → unknown 集合（原始字符串）
        │
        ▼
写出 V2Ray 订阅 (list_raw.txt / list.txt)
        │
        ▼
生成 Clash / Meta 配置 (list.yml / list.meta.yml)
        │
        ├──► 按地区分类节点 (snippets/nodes_*.yml)
        ├──► 合并 Adblock 规则 (rules)
        └──► 写出规则片段 (snippets/rules_*.yml)
        │
        ▼
写出统计信息 (list_result.csv)
3. 核心数据结构与类
3.1 Node 类
表示一个代理节点，支持多种协议：vmess、ss、ssr、trojan、vless、hysteria2、tuic、http、https、socks5 等。

主要属性与方法：

成员	说明
data	节点数据字典，字段与 Clash 配置兼容
type	节点类型
names	该节点所有可能的名称集合
name	根据评分规则选出的最佳名称
url	生成分享链接（vmess://、ss:// 等）
clash_data	生成 Clash 配置用的字典
isfake	判断是否为假节点（如 0.0.0.0、端口 < 20 等）
supports_clash(meta=False)	是否被 Clash / Meta 支持
supports_meta()	是否被 Meta 支持
supports_ray()	是否被 V2Ray 支持
format_name(max_len=30)	格式化名称，去重、屏蔽词替换、截断
关键方法：

load_url(url)：根据协议前缀调用 _load_* 方法。

_load_vmess、_load_ss、_load_ssr、_load_trojan、_load_vless、_load_hysteria2、_load_tuic、_load__legacy：各协议解析。

_url_vmess、_url_ss、_url_ssr、_url_trojan、_url_vless、_url_hysteria2、_url_tuic、_url__legacy：各协议链接生成。

__hash__：根据 type、server、port、path、password/uuid 等生成哈希，用于去重。

3.2 Source 类
管理单个订阅源。

成员	说明
url	实际 URL
url_source	原始 URL 或动态函数
content	下载内容
sub	解析后的节点列表
cfg	从 URL # 后提取的配置（max、ignore）
exc_queue	异常信息队列
主要方法：

gen_url()：处理 +date 占位符，生成日期递减的 URL。

get(depth=2)：抓取内容，失败时尝试重新生成 URL 重试。

_download(r)：流式下载，自动识别 YAML、Base64 订阅、明文链接。

parse()：解析 content 为 sub，支持 YAML、Base64、明文。

3.3 DomainTree 类
用于 Adblock 域名树，支持插入、删除、获取所有域名。

4. 主要函数说明
函数	作用
main()	主流程入口
merge(source_obj, sourceId)	将 Source.sub 中的节点解析并合并到 merged
merge_adblock(adblock_name, rules)	解析 Adblock 规则，生成 rules 字典
extract(url)	从机场页面提取订阅链接
raw2fastly(url)	本地模式下将 GitHub Raw 转为 jsDelivr
b64encodes / b64decodes	Base64 编码/解码
b64encodes_safe / b64decodes_safe	URL 安全 Base64
normpath(url)	处理 file:// 路径
clean_surrogates（建议添加）	清洗孤立代理项
5. 生成的文件及作用
文件	内容	作用
list_raw.txt	明文节点链接，每行一个	人工查看、调试、作为源文件
list.txt	list_raw.txt 的 Base64 编码	标准 V2Ray 订阅格式，供客户端导入
list.yml	Clash 配置	包含 proxies、proxy-groups、rules
list.meta.yml	Clash Meta 配置	支持更多协议和特性
snippets/nodes_<分类>.yml	按地区分类的节点	Clash 片段
snippets/nodes_<分类>.meta.yml	按地区分类的 Meta 节点	Meta 片段
snippets/nodes.yml	全量节点片段	Clash 片段
snippets/nodes.meta.yml	全量 Meta 节点片段	Meta 片段
snippets/rules_online.yml	在线规则片段	供订阅使用
snippets/rules.yml	本地规则片段	供订阅使用
list_result.csv	统计信息	每个源的节点数、总计
6. 关键机制与设计
6.1 节点去重
通过 Node.__hash__ 计算哈希，考虑 type、server、port、network、path、password/uuid 等。

相同哈希的节点合并到 merged，名称合并到 names。

最终名称通过 rate() 评分选出：优先带国旗 emoji、避免 @ 开头、屏蔽词降权。

6.2 并发抓取
每个 Source 在独立线程中执行 get()。

主线程按顺序 join，带超时（默认 6×15 秒）。

超时后跳过该源。

6.3 订阅解析
Source._download 自动判断内容类型：

含 proxies: → YAML 配置；

含 :// → 明文链接列表；

否则 → Base64 解码后按行分割。

6.4 协议支持性检查
supports_clash：检查 VMess 加密、SS 加密、SSR obfs/protocol 等。

supports_meta：支持更多协议。

supports_ray：排除 socks5 + tls 等不被 V2Ray 支持的情况。

6.5 地区分类
从 config.yml 的 NoMoreWalls.categories 读取关键词。

遍历 merged 中的节点，按名称匹配分类。

生成 ctg_nodes 和 ctg_nodes_meta，写出对应片段。

6.6 代理组冲突过滤
对所有 url-test 和 fallback 组，移除其中与组名相同的代理，避免自引用。

地区组添加时，过滤自身及已有组名。

6.7 Adblock 规则合并
从 ABFURLS 下载规则，解析 ||domain^ 形式。

支持白名单 @@ 和 ABFWHITE。

生成 DOMAIN-SUFFIX、DOMAIN-KEYWORD、IP-CIDR 规则。

7. 已知问题与关注点
7.1 Unicode 代理项导致写文件失败
现象：UnicodeEncodeError: 'utf-8' codec can't encode characters ... surrogates not allowed

位置：f.write(txt) 写出 list_raw.txt 时。

来源：unknown 集合中的原始节点字符串含有孤立代理项，通常由 PyYAML 解析 \uD800 等转义产生。

影响：list_raw.txt 和 list.txt 均无法写出，程序终止。

修复：在写出前执行 txt = txt.encode('utf-8', 'replace').decode('utf-8')，或在 unknown.add() 前清洗。

7.2 YAML 解析风险
使用 yaml.full_load，可能执行非预期构造器。

建议改用 yaml.safe_load，并对解析结果做字符串清洗。

7.3 节点分类依赖名称关键词
若节点名称不含地区关键词，则不会被分类。

分类逻辑中 keys[-1] == 'OVERALL' 会提前终止匹配。

7.4 动态链接生成可能失败
AUTOURLS 中的函数若抛出异常，仅打印错误，不影响主流程。

+date 占位符依赖日期递减，可能生成无效 URL。

7.5 调试输出过多
代码中大量 [DEBUG] 打印，生产环境建议关闭或改为日志级别控制。

7.6 编码处理
Source._download 在 UnicodeDecodeError 时回退到 decode('ignore')，会丢弃非法字节。

b64decodes 严格解码，失败会抛异常。

8. 改进建议
统一清洗代理项：在 merge() 和写出前增加 clean_surrogates()。

使用 yaml.safe_load：避免反序列化风险。

规范化日志：用 logging 替代 print，支持级别控制。

增强异常处理：对 unknown 中的字符串做长度限制和去重。

配置化：将 FETCH_TIMEOUT、并发数、默认测试 URL 等提取到配置文件。

测试覆盖：为 Node 的解析/生成、Source 的下载解析编写单元测试。

文档化：为每个 _load_* 和 _url_* 方法添加 docstring。

9. 附：快速排错指南
问题	排查方向
写文件 UnicodeEncodeError	检查 unknown 集合，清洗代理项
节点数为 0	检查 sources.list、网络、local_proxy.conf
分类节点为空	检查 config.yml 中 NoMoreWalls.categories 关键词
代理组冲突	查看 [DEBUG] 输出的冲突组名
抓取超时	调整 FETCH_TIMEOUT 或检查源可用性
Base64 解码失败	检查订阅内容是否为合法 Base64
文档版本：基于 fetch_pro2.py 当前代码整理。
建议保存为：FETCH_PRO2_README.md，与脚本同目录。


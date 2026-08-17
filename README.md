# EasyScan

EasyScan 是一个本地优先的 Go 被动 Web 安全分析器。它分析已经观察到的 HTTP 流量：代理转发的明文 HTTP、EasyScan MITM 解密后的 HTTPS，或浏览器/代理扩展上报与 HAR/Burp 导入的流量。MITM 指纹识别只读取已经捕获的响应，不会为了识别产品额外请求路径、favicon 或其他资源。

## 已实现能力

- HTTP 正向代理；HTTPS `CONNECT` 默认透传，可选择对 allowlist 范围内主机进行本地 CA 解密
- HAR、Burp Suite XML 导入，以及浏览器/代理插件可用的 JSON 接入 API
- 作用域白名单/黑名单、请求/响应体大小限制和敏感值脱敏
- 内置被动检测：明文凭据、Basic Auth 明文传输、敏感密钥泄露、错误栈泄露、目录列表、服务版本暴露、API 文档暴露等
- 漏洞候选识别：SQL 错误、特殊字符反射、Java 序列化痕迹、命令执行错误痕迹与历史 Log4j2 版本；候选和已确认发现会明确区分
- HFinger MITM 指纹识别：对代理已经捕获的 HTTP/HTTPS 响应运行 [HackAllSec/hfinger](https://github.com/HackAllSec/hfinger) 内置规则
- 用户 HFinger YAML：桌面端可选择 YAML/YML 文件，完成 schema 校验、导入和热重载；单个错误文件不会影响其他规则
- 低误报约束：4xx/5xx 页面不接受正文、标题或路径反射作为产品证据，并过滤 jQuery、Bootstrap、GZIP encode、GSE 等低价值标签
- YAML 正则规则、去重、严重性与置信度、JSON / HTML / SARIF 2.1.0 报告
- SQLite 持久化：发现、资产、任务、结果与审计事件（不保存原始 HTTP 正文）
- 已授权主动扫描：端口扫描、目录扫描、HTTP Basic 认证检测、网站爬取、浏览器爬取与 XSS 检测
- MITM SQL 注入检测：对新观测的 Query、表单、JSON 和 Cookie 参数执行受速率与请求预算约束的报错、布尔差异和延时复核
- MITM XSS 检测：对新观测的 Query、表单和 JSON 参数只发送惰性特殊字符标记，复核脚本、标签、属性位置的可重复未编码反射（文本上下文以低置信候选报告），不执行任何脚本
- Windows 桌面客户端：Go + Wails + WebView2，集中查看发现、资产、任务和功能策略；默认每次启动清除上次漏洞/指纹，并自动生成同目录 HTML 扫描结果
- 运行时 API：`/api/v1/findings`、`/api/v1/assets`、`/api/v1/tasks`、`/api/v1/audit`、`/healthz`

## 快速开始

Windows 上如果 Go 没有加入 PATH，可使用 `C:\Program Files\Go\bin\go.exe`。

```powershell
go run ./cmd/easyscan serve --config easyscan.yaml --json-output reports/findings.json --html-output reports/report.html --sarif-output reports/findings.sarif
```

`serve` 会在收到 `Ctrl+C` 后优雅停止并写出指定报告；`analyze` 则在 HAR 分析完成后立即写出。

`serve` 是无界面模式，只启动代理和流量接入 API。日常使用桌面版时不需要运行它：直接启动 `easyscan-desktop.exe` 即可。桌面程序通过 Wails/WebView2 展示实时发现、资产、任务结果与功能策略，并自动启动本机代理和流量接入 API；不需要 Docker、WSL、容器端口映射或浏览器仪表盘。离线 HTML 报告仍可通过 `--html-output` 导出，不依赖服务运行。

将浏览器 HTTP 代理设为 `http://127.0.0.1:7777` 后，普通 HTTP 流量会被转发并分析。HTTPS 的 `CONNECT` 默认安全透传；请通过受控浏览器扩展或上游解密代理将 HTTPS 事务 POST 到接入 API。

```powershell
go run ./cmd/easyscan analyze --har .\capture.har --config easyscan.yaml --html-output reports\har.html

go run ./cmd/easyscan analyze --burp-xml .\burp-items.xml --config easyscan.yaml --html-output reports\burp.html
```

## Windows 桌面客户端

首次开发构建需要安装 Wails CLI，随后在项目根目录运行：

```powershell
go install github.com/wailsapp/wails/v2/cmd/wails@latest
$env:Path += ";$env:USERPROFILE\go\bin"
wails dev
```

发布构建：

```powershell
wails build -webview2 browser
```

生成的 `build\bin\easyscan-desktop.exe` 是可直接运行的 Windows 桌面程序，会自动启动本地代理和流量接入 API。它会自动查找当前目录、可执行文件目录及其上两级目录中的 `easyscan.yaml`，因此在本项目中可直接双击 `build\bin\easyscan-desktop.exe`。WebView2 Runtime 是唯一的桌面运行前提（Windows 10/11 通常已自带）。

桌面端默认会在每次启动时清除 SQLite 中上次会话的漏洞、资产和指纹，并从空白结果开始；主动任务历史不受影响。可在“功能策略 → 数据与会话”关闭“启动时清除上次漏洞和指纹”，该设置会在下一次启动生效。

默认开启自动 HTML 报告：`easyscan-scan-report.html` 会写到 `easyscan.yaml` 同目录，在结果变化及程序关闭时更新。报告分为“漏洞结果”和“指纹识别”两个分区。可在配置中调整：

```yaml
reports:
  auto_html: true
  html_path: "easyscan-scan-report.html"
```

桌面程序仍会使用 `easyscan.yaml` 中的 `proxy.listen`（默认 `127.0.0.1:7777`）和 `api.listen`（默认 `127.0.0.1:8787`），供浏览器代理、Chrome DevTools 或 mitmproxy 等本机流量适配器连接；这些只是本机监听端口，不是 Web UI。不要同时运行 `easyscan serve` 与桌面程序，否则它们会争用同一端口。

## 接入 API

默认监听 `127.0.0.1:8787`。当 `api.token` 已设置时，携带 `Authorization: Bearer <token>`。

```json
{
  "request": {"method":"GET", "url":"https://app.example.test/api", "headers":{"Authorization":"Bearer xxx"}, "body":""},
  "response": {"status":200, "headers":{"Server":"nginx"}, "body":"{\"ok\":true}"}
}
```

`POST /api/v1/traffic` 接收上面的事务，`GET /api/v1/findings` 返回检测结果，`GET /api/v1/assets` 返回按主机聚合的指纹。请求体也可使用 `body_base64`（标准 Base64）。

当上游工具已经捕获到 TLS 证书摘要或 favicon hash 时，可以在 `response` 对象增加 `certificate` 与 `icon_hash`；这些元数据会随已捕获事务交给本地分析，工具不会自行拉取证书或 favicon。

## 自定义规则

把 YAML 文件路径添加到 `rules.files`。规则只做已捕获文本的正则匹配，绝不产生网络请求。详见 [rules/example.yaml](rules/example.yaml)。

## 指纹识别准确率

EasyScan 使用 [HackAllSec/hfinger](https://github.com/HackAllSec/hfinger) 作为唯一的 MITM 产品指纹引擎。项目内嵌 HFinger core 规则，代理每捕获一条 `http-proxy` 或 `https-mitm` 响应后在本地匹配；HAR、Burp XML 与接入 API 导入不会触发这条 MITM 指纹链路。

为抑制已知误报，适配层增加以下约束：

- 404 与其他 4xx/5xx 页面中的正文、标题和请求路径不作为产品证据；错误页只接受规则自身命中的响应头、Cookie、Server、TLS 或 DNS 证据；
- `/admin/discuzfiles.md5` 出现在请求路径并被 404 页面原样回显时，不会识别为 Discuz；
- jQuery、jQuery official CDN、Bootstrap、Bootstrap CDN、GZIP/GZIP encode、GSE 等低价值标签不会进入资产指纹；
- CDN 分类受 `passive.cdn_detection` 开关控制，WAF 厂商识别已并入 `passive.hfinger`，不再单独开关；
- 单条事务最多保留 `max_matches_per_transaction` 个结果，并按 HFinger confidence 排序。

HFinger 来源、版本和 Apache-2.0 许可证记录见 [third_party/hfinger/EASYSCAN-NOTICE.md](third_party/hfinger/EASYSCAN-NOTICE.md)。误报基线与回归样例见 [docs/fingerprint-accuracy.md](docs/fingerprint-accuracy.md)。

## HFinger 自定义 YAML

默认配置：

```yaml
fingerprints:
  hfinger:
    custom_dir: "fingerprints/custom"
    max_matches_per_transaction: 40
```

在桌面端打开“设置 → MITM 与实时分析 → HFinger 指纹识别 → 高级设置”，可以查看有效规则、覆盖产品、自定义规则和失败文件数量，并执行：

1. **添加 YAML 指纹**：选择 `.yaml`/`.yml`，通过 HFinger parser 与 schema 校验后复制到自定义目录；单文件最大 8 MiB。
2. **重新加载规则**：重新读取内置规则和自定义目录；某个 YAML 失败时只跳过该文件，并在界面显示错误。
3. **覆盖内置规则**：自定义规则使用与内置规则相同的 `id` 时，以自定义版本为准。

最小示例见 [fingerprints/custom/example.yaml.disabled](fingerprints/custom/example.yaml.disabled)。将其复制或重命名为 `.yaml` 后点击“重新加载规则”即可启用。自定义 YAML 与内置规则一样只处理已捕获响应，不产生新的网络请求。

### 被动流量过滤

桌面端“功能与流量设置 → 流量过滤”支持域名、文件后缀、响应 `Content-Type`、URL 路径、Query 参数名以及 POST/JSON 参数名六类规则。命中任一规则时，代理仍会把请求和响应正常转发，但整条流量不写入日志，也不进入漏洞检测、指纹识别、结果存储或主动探测队列。设置保存后立即作用于新流量。

路径使用简单 Glob：`*` 只匹配一个路径段，`**` 可以跨越多段。例如 `/assets/**` 会排除整个静态资源目录，`*/health` 会排除单层前缀下的健康检查路径。路径和参数名匹配均不区分大小写；参数规则只填写名称，不填写值。嵌套 JSON 会检查其中每一级字段名。

```yaml
# features.yaml
excluded_paths:
  - "/assets/**"
  - "*/health"
excluded_query_parameters:
  - utm_source
  - tracking_id
excluded_post_parameters:
  - telemetry
  - token
```

留空列表表示不启用对应过滤。以上三类请求侧规则会在响应分析前生效；现有 `excluded_suffixes` 和 `excluded_content_types` 仍分别处理文件后缀与响应类型。

### 被动分析调度与去重

代理转发和被动分析已经解耦：HTTP 响应先完整写回客户端，再进入容量为 512 的单消费者分析队列。单消费者可以避免 HFinger 匹配与 SQLite 快照写入互相争用；队列积压会计入被动日志的 `undo_http`，队列满时跳过最新分析任务并输出一条聚合告警，不阻塞浏览器流量。停止代理时会关闭新任务入口并排空已经接收的分析任务。

普通被动流量还会进行短期请求形态去重。缓存最多保留 4096 条记录，采用 5 分钟滑动过期，只保存 SHA-256 形态键。形态包含方法、Origin、路径、Query/表单/JSON 参数名、响应状态、正文哈希和稳定响应头，不保存参数值；`Date`、请求 ID、Trace、计时和 Cookie 等易变响应头不会破坏去重。重复流量仍完成请求计数，但不会重复写日志、匹配指纹与漏洞、保存 SQLite 快照或触发 MITM SQL/POC 队列。清空会话结果时缓存也会一并重置。

## Webscan 兼容工作流

EasyScan 对应 EZ `webscan` 的通用能力如下：

- 已捕获流量/代理/Burp/HAR/浏览器适配器的被动分析与实时结果；
- 通用与框架指纹使用 HFinger 内置及用户 YAML 规则；CDN/WAF 分类受各自功能开关控制；
- 从 URL、表单和 JSON / URL 编码请求中抽取接口、HTTP 方法、参数名称和来源，作为资产接口目录；不保存参数值；
- `analysis.only_fingerprint: true` 仅进行资产与指纹识别；
- `analysis.disabled_checks` 可按精确 ID 或 glob 关闭内置/自定义检查，例如 `passive.candidate.*`；
- 在 allowlist 中对 MITM 新观测参数执行低影响 SQL 注入检测与 XSS 反射检测，并对手工任务执行 XSS 检测。

黑盒扫描存在误报与漏报。因此 MITM SQL 注入检测与 XSS 检测只产出 `candidate`，不提取数据、不执行脚本。SQL 注入等级含义为：`0` 关闭；`1` 对首个参数执行可重复 SQL 报错检测；`2` 检查配置数量内的参数，并增加真假条件响应差异复核；`3` 再增加固定 0.8 秒延时条件与两次慢响应确认。主动 XSS 检测只保留脚本、标签或属性位置中可重复的未编码特殊字符反射；普通文本和 HTML 注释反射不报告。MITM XSS 检测（`passive.xss_probe`）对每个新观测请求最多探测配置数量的参数，每个参数先发送一个惰性标记，命中可渲染 HTML 中的未编码反射后再用第二个标记复核，两次上下文一致且响应相似才报告；脚本、标签、属性上下文为中置信，普通文本上下文为低置信，HTML 注释不报告。Java 反序列化、Log4j2 和命令注入只从已捕获的强证据生成被动候选，不投递反序列化对象、JNDI 字符串或命令载荷。

## HTTPS 解密（可选）

在 `proxy.mitm: true` 时，EasyScan 在 `proxy.ca_dir` 创建本地 CA，并只对 `scope.allow_hosts` 明确包含的主机解密 HTTPS；其他 `CONNECT` 会继续透明转发。首次启动后，将 `data/ca/easyscan-ca.pem` 安装到**授权测试环境**的受信任根证书库，然后将客户端代理设为 EasyScan。CA 私钥只保留在本机 `data/ca`，权限为仅当前用户可读。

不要在未授权终端、共享浏览器或生产环境启用该模式。

## 主动扫描

> **⚠️ 授权提示**：主动扫描会直接向目标发起真实网络请求。请仅对你**拥有所有权或已获得明确书面授权**的目标使用；对未授权目标进行扫描可能违反法律法规，一切后果由使用者自行承担。

主动扫描开箱即用，无需额外开关或授权字段即可提交任务，但仍受 `scope.allow_hosts` 范围约束——目标必须落在允许的主机范围内。先在 `easyscan.yaml` 中设置精确范围：

```yaml
scope:
  allow_hosts: ["app.example.test"]
  # 对授权的内网 DNS 名称才开启；显式 IP 地址仍需写入 allow_hosts。
  allow_private_ips: true
active:
  # 可选：本机 Chrome 只加载同源 GET 资源以发现动态接口。
  enable_headless_crawl: true
```

然后在桌面客户端新建扫描任务；也可调用 `POST /api/v1/tasks`：

```json
{"kind":"port_scan","target":"app.example.test"}
```

可用类型：

- `port_scan`（端口扫描）：只能扫描内置的 50 个常见 TCP 端口；不支持端口范围、CIDR 或主机列表。
- `directory_enum`（目录扫描）：仅扫描 25 个常见路径，使用 GET、4 KiB 响应限制且不跟随重定向。
- `basic_auth_check`（HTTP Basic 认证检测）：固定 3 个用户名 × 4 个密码（最多 12 次尝试）；成功结果只保存用户名和 `[REDACTED]`，不保存密码。
- `web_crawl`（网站爬取）：受限同源 GET 爬取，从 HTML 的链接和资源 URL 发现页面；不提交表单、不执行 JavaScript、不访问外域或 logout/signout 路径。
- `web_crawl_headless`（浏览器爬取）：默认关闭的本机 Chrome 页面爬取。只加载一个入口页，并在浏览器请求层阻断非 GET、跨域、下载和 logout/delete/reset 等路径；不点击页面、不提交表单、不携带临时认证会话。渲染后的 DOM 与同源资源 URL 会进入被动分析和接口目录。

所有任务需要非空 `allow_hosts`，并受 `active` 下的并发、速率、超时和每任务请求数限制。结果位于 `/api/v1/tasks/{id}/results`，取消运行任务使用 `POST /api/v1/tasks/{id}/cancel`；审计日志在 `/api/v1/audit`。

如需扫描登录后的只读接口，可在创建任务时传入临时 `session_headers`（仅 `Cookie`、`Authorization`、`X-CSRF-Token`、`X-Requested-With`）。这些值只存在进程内存中，任务结束后立即清除，绝不写入任务记录、审计日志、SQLite 或报告。桌面客户端也提供一次性输入框；浏览器爬取有意不使用这些会话头。

`features.yaml` 是运行时功能策略文件。桌面客户端的“功能与流量设置”可以开关启动时清理上次结果、指纹识别、CDN/WAF、MITM SQL/POC，以及端口扫描、目录扫描、网站爬取、浏览器爬取等功能，并将结果写回该文件。MITM SQL 的报错、布尔和时间检测由 `passive_sqli_error_enabled`、`passive_sqli_boolean_enabled`、`passive_sqli_time_enabled` 三个独立开关控制，速率和预算使用 `passive_sqli_probe_qps`、`passive_sqli_max_requests` 和 `passive_sqli_max_parameters`；MITM XSS 检测的速率与预算使用 `passive_xss_probe_qps`、`passive_xss_max_requests` 和 `passive_xss_max_parameters`；每个发现会在当前会话中保留原始、探测及复测请求响应。指纹 YAML 目录与单事务命中上限位于 `easyscan.yaml` 的 `fingerprints.hfinger`。

组件版本顾问库只对响应头中的精确版本给出 `tentative` 候选，例如历史 Apache HTTP Server 2.4.49/2.4.50 与 Log4j2 版本范围。它会提示关联 CVE，但不会把发行版回补、配置条件或版本字符串本身误写为已确认漏洞。

## 流量适配器

- Burp Suite：使用 `easyscan analyze --burp-xml items.xml` 导入“Save items”XML。
- 浏览器：加载 [Chrome DevTools adapter](integrations/chrome-devtools/README.md) 后，由当前 DevTools 标签页异步上报流量。
- mitmproxy：使用 [mitmproxy addon](integrations/mitmproxy/README.md) 将已解密流量发送到本地 API。

## 范围与边界

端口扫描、目录扫描、HTTP Basic 认证检测、网站爬取、浏览器爬取和 XSS 检测均受 allowlist、授权确认、速率、并发和请求上限约束。MITM SQL 检测仅对已观测参数执行固定报错、真假条件与 0.8 秒延时复核，不执行联合查询、数据提取或写入语句。

## EZ WebScan 配置对照

`easyscan.yaml` 新增了 `webscan` 配置块，采用与 `D:\ez_scan\config.yaml` 相近的 HTTP 和爬取控制项：

- `webscan.http`：`max_qps`、`retry`、`timeout_seconds`、`max_redirect`、普通/强制请求头、连续失败熔断、禁扫路径及严格同源限制；
- `webscan.crawler`：Chrome 路径、沙箱、禁图、User-Agent、最大深度、最大页面数和后缀排除；
- `webscan` 选项只作用于手工创建的主动任务。HFinger 不读取该配置，只匹配 MITM 已捕获响应。

`headers_force` 不接受 `Host`、`Content-Length`、代理或连接控制头，临时登录会话头仍只保存在内存中。`max_failures` 达到时会停止该任务的后续 HTTP 请求；`retry` 仅重试传输错误，最大为 3。

import {useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState, type KeyboardEvent as ReactKeyboardEvent, type ReactElement} from "react";
import {
  Badge,
  Button,
  Checkbox,
  Dialog,
  DialogActions,
  DialogBody,
  DialogContent,
  DialogSurface,
  DialogTitle,
  Field,
  FluentProvider,
  Input,
  MessageBar,
  MessageBarBody,
  MessageBarTitle,
  Select,
  Spinner,
  Switch,
  Tab,
  TabList,
  Textarea,
  Toast,
  ToastBody,
  ToastTitle,
  Toaster,
  Tooltip,
  useId,
  useToastController,
  webDarkTheme,
} from "@fluentui/react-components";
import {
  Alert24Regular,
  ArrowClockwise20Regular,
  ChevronDown20Regular,
  ChevronRight20Regular,
  ClipboardTaskListLtr24Regular,
  Cube24Regular,
  DataBarVertical24Regular,
  DocumentBulletList24Regular,
  Dismiss20Regular,
  Globe24Regular,
  History24Regular,
  Play20Regular,
  PlugConnected20Regular,
  Power20Regular,
  Search20Regular,
  Settings24Regular,
  Shield24Regular,
  Sparkle24Regular,
  Stop20Regular,
} from "@fluentui/react-icons";
import {desktopApi} from "./wails";
import {
  emptySnapshot,
  normalizeAISettings,
  normalizeNucleiStatus,
  normalizeFindingEvidenceList,
  normalizeRuntimeLogs,
  normalizeSnapshot,
  normalizeTaskResults,
  type ActiveTask,
  type Asset,
  type Endpoint,
  type Feature,
  type FingerprintEvidence,
  type FingerprintRuleQuality,
  type NucleiStatus,
  type HFingerStats,
  type Finding,
  type FindingEvidence,
  type RuntimeLog,
  type Severity,
  type Snapshot,
  type TaskResult,
} from "./types";
import {
  isPassiveRuntimeLog,
  logTailTolerance,
  passiveRuntimeLogSignature,
  PassiveLogConsole,
} from "./components/PassiveLogConsole";
import "./App.css";

type View = "traffic" | "findings" | "assets" | "active" | "ai" | "settings" | "runtime-logs";
type NavigationSection = "monitor" | "control";
type NavigationItem = {id: View; label: string; icon: ReactElement; section: NavigationSection};
type FindingViewFilter = "web" | "information" | "fingerprint";
type AdvancedSettingsSection = "mitm-sqli" | "mitm-xss" | "mitm-poc" | "mitm-fastjson" | "mitm-shiro" | "mitm-oob" | "fingerprint" | "quality" | "sensitive-info" | "file-probe";

type ThemeId = "midnight" | "crimson" | "forest" | "indigo" | "solar" | "arctic";

const themeOptions: {id: ThemeId; label: string; swatch: string[]; description: string}[] = [
  {id: "midnight", label: "午夜深蓝", swatch: ["#0b1017", "#78a9e6", "#77c7a0"], description: "深蓝底色 + 冰蓝强调"},
  {id: "crimson", label: "绯红夜曲", swatch: ["#0d0a0b", "#e94560", "#ffa502"], description: "炭黑底色 + 绯红强调"},
  {id: "forest", label: "翡翠密林", swatch: ["#0a120e", "#f0c040", "#51cf66"], description: "深绿底色 + 金黄强调"},
  {id: "indigo", label: "皇家靛蓝", swatch: ["#0a0b1a", "#ffb830", "#00e676"], description: "靛蓝底色 + 琥珀强调"},
  {id: "solar", label: "烈日熔金", swatch: ["#120c08", "#ff8c00", "#ffd000"], description: "暖褐底色 + 电橙强调"},
  {id: "arctic", label: "极昼白光", swatch: ["#f0f3f8", "#2563eb", "#059669"], description: "浅色模式 + 钴蓝强调"},
];

const severityCopy: Record<Severity, string> = {
  critical: "严重",
  high: "高危",
  medium: "中危",
  low: "低危",
  info: "信息",
};

type FindingTranslation = Pick<Finding, "title" | "description" | "remediation">;

const findingTranslations: Record<string, FindingTranslation> = {
  "passive.transport.credentials-over-http": {title: "明文 HTTP 传输凭据", description: "在明文 HTTP 请求中观察到疑似凭据参数。", remediation: "将站点全部重定向至 HTTPS，并为 Cookie 设置 Secure 属性。"},
  "passive.transport.basic-auth-over-http": {title: "明文 HTTP Basic 认证", description: "在未使用 TLS 的连接中观察到 HTTP Basic 凭据。", remediation: "仅通过 HTTPS 接收 Authorization 请求头。"},
  "passive.exposure.aws-access-key": {title: "疑似 AWS 访问密钥泄露", description: "响应中包含符合 AWS 访问密钥格式的文本。", remediation: "从响应中移除密钥，立即轮换受影响凭据并检查访问日志。"},
  "passive.exposure.private-key": {title: "私钥材料泄露", description: "响应中包含私钥 PEM 文件头。", remediation: "立即移除私钥材料、轮换受影响凭据并排查泄露范围。"},
  "passive.exposure.application-secret": {title: "疑似应用密钥泄露", description: "响应中包含常见应用密钥的键值模式。", remediation: "确认该值是否敏感；从响应中移除并在必要时轮换。"},
  "passive.exposure.stack-trace": {title: "应用错误堆栈泄露", description: "响应疑似暴露框架堆栈或运行时异常信息。", remediation: "向客户端返回通用错误页，并将详细异常信息仅保留在受限日志中。"},
  "passive.directory-listing": {title: "目录浏览泄露", description: "响应内容符合 Web 服务器目录索引特征。", remediation: "关闭目录浏览功能，并检查已暴露文件。"},
  "passive.api-documentation": {title: "API 文档接口泄露", description: "已观测到状态码为 200 的 Swagger、OpenAPI 或 API Docs 接口。", remediation: "确认公开文档符合预期，且不包含仅供内部使用的接口或敏感说明。"},
  "passive.candidate.sql-error": {title: "数据库错误信息泄露", description: "响应中包含数据库错误特征；这表明错误信息泄露，不代表已确认存在 SQL 注入。", remediation: "关闭面向客户端的详细数据库报错，并使用参数化查询。"},
  "passive.candidate.java-deserialization": {title: "Java 序列化对象处理痕迹", description: "捕获流量表明存在序列化对象处理或反序列化异常；尚未证明可利用链。", remediation: "避免对不可信数据使用原生 Java 反序列化，并启用类型白名单与完整性保护。"},
  "passive.candidate.command-execution": {title: "进程执行细节泄露", description: "错误响应暴露了进程或 Shell 执行细节；这属于信息泄露，不代表已确认命令注入。", remediation: "避免在请求路径中调用 Shell；使用固定参数白名单。"},
  "passive.candidate.log4j2-version": {title: "疑似受影响的 Log4j2 版本暴露", description: "响应头暴露了与历史漏洞范围相关的 Log4j2 版本，仍需结合实际部署确认。", remediation: "升级至受支持的 Log4j2 版本，并确认已移除受影响的查找行为。"},
  "passive.candidate.reflected-input": {title: "可执行 HTML 上下文中的未编码输入", description: "带有 HTML 特殊字符的查询参数在脚本、标签或属性上下文中未编码反射；需进一步确认是否为 XSS。", remediation: "实施与输出上下文匹配的编码，并在浏览器中完成复核。"},
  "passive.candidate.apache-httpd-cve-2021-41773": {title: "Apache HTTP Server 2.4.49 版本风险提示", description: "响应头报告 Apache HTTP Server 2.4.49，该版本与 CVE-2021-41773 有关；需结合回补和配置确认。", remediation: "升级到受支持的厂商版本，并确认 CVE-2021-41773 已修复。"},
  "passive.candidate.apache-httpd-cve-2021-42013": {title: "Apache HTTP Server 2.4.50 版本风险提示", description: "响应头报告 Apache HTTP Server 2.4.50，该版本与 CVE-2021-42013 有关；需结合回补和配置确认。", remediation: "升级到受支持的厂商版本，并确认 CVE-2021-42013 已修复。"},
  "passive.ai.routes": {title: "AI 识别 前端路由提取", description: "AI 从有价值的 JS 文件中提取到前端路由与 API 接口路径，可用于梳理攻击面与越权测试。", remediation: "核对暴露的路由与接口是否都应公开访问，敏感接口应补充认证与鉴权。"},
  "passive.ai.secrets": {title: "AI 识别 敏感凭据检测", description: "AI 在 JS 文件中发现疑似敏感凭据/敏感信息，泄露的凭据可能被直接利用。", remediation: "立即轮换泄露的密钥/凭据，避免在前端代码中硬编码任何秘密。"},
};

const findingTitleByRuleId = Object.fromEntries(
  Object.entries(findingTranslations).map(([ruleId, translation]) => [ruleId, translation.title]),
);

function localizedFinding(finding: Finding): Finding {
  const translation = findingTranslations[finding.ruleId];
  return translation ? {...finding, ...translation} : finding;
}

const featureCopy: Record<string, string> = {
  "desktop.clear_previous_results_on_start": "启动时清除上次漏洞和指纹",
  "passive.cdn_detection": "CDN 检测",
  "passive.hfinger": "指纹识别",
  "passive.poc_scan": "MITM POC 检测",
  "passive.sqli_probe": "MITM SQL 注入检测",
  "passive.xss_probe": "MITM XSS 检测",
  "passive.sensitive_info": "敏感信息检测",
  "passive.sensitive_info.private_key": "敏感信息：私钥",
  "passive.sensitive_info.aws_access_key": "敏感信息：AWS 密钥",
  "passive.sensitive_info.aliyun_access_key": "敏感信息：阿里云密钥",
  "passive.sensitive_info.github_token": "敏感信息：GitHub Token",
  "passive.sensitive_info.google_api_key": "敏感信息：Google API 密钥",
  "passive.sensitive_info.slack_token": "敏感信息：Slack Token",
  "passive.sensitive_info.stripe_key": "敏感信息：Stripe 密钥",
  "passive.sensitive_info.jwt": "敏感信息：JWT 令牌",
  "passive.sensitive_info.database_dsn": "敏感信息：数据库连接串",
  "passive.sensitive_info.application_secret": "敏感信息：应用密钥",
  "passive.sensitive_info.stack_trace": "敏感信息：堆栈信息",
  "passive.sensitive_info.email": "敏感信息：邮箱地址",
  "passive.sensitive_info.phone": "敏感信息：手机号码",
  "passive.file_probe": "敏感文件探测",
  "passive.file_probe.git": "文件探测：Git 元数据",
  "passive.file_probe.svn": "文件探测：SVN 元数据",
  "passive.file_probe.idea": "文件探测：IDEA 项目",
  "passive.file_probe.ds_store": "文件探测：.DS_Store",
  "passive.file_probe.environment": "文件探测：环境变量文件",
  "passive.file_probe.backup": "文件探测：备份归档",
  "passive.file_probe.database_dump": "文件探测：数据库转储",
  "passive.file_probe.swagger": "文件探测：API 文档接口",
  "passive.file_probe.springboot": "文件探测：Spring Boot Actuator",
  "passive.file_probe.custom": "文件探测：自定义路径",
  "passive.file_probe.dedupe_responses": "文件探测：重复响应过滤",
  "passive.waf_probe": "WAF 检测",
  "passive.fastjson_probe": "MITM Fastjson 检测",
  "passive.shiro_probe": "MITM Shiro 检测",
  "passive.cmd_probe": "MITM 命令执行检测",
  "passive.ssrf_probe": "MITM SSRF 检测",
  "passive.xxe_probe": "MITM XXE 检测",
  "passive.upload_probe": "MITM 文件上传检测",
  "passive.ai_analysis": "AI 智能分析",
  "passive.ai_analysis.routes": "AI：路由提取",
  "passive.ai_analysis.secrets": "AI：敏感信息检测",
  "passive.ai_insight": "AI 漏洞解读",
  "passive.ai_fingerprint": "AI 指纹推断",
  "passive.ai_secret_context": "AI 敏感信息研判",
  "passive.ai_traffic_anomaly": "AI 流量异常检测",
  "active.port_scan": "端口扫描",
  "active.basic_auth_check": "HTTP Basic 认证检测",
  "active.web_crawl": "网站爬取",
  "active.web_crawl_headless": "浏览器爬取",
};

const featureDescriptionCopy: Record<string, string> = {
  "desktop.clear_previous_results_on_start": "下次启动时清除上次会话保存的漏洞和指纹。",
  "passive.cdn_detection": "根据响应头和域名特征识别 CDN 服务商。",
  "passive.hfinger": "对 MITM 已捕获响应运行内置规则和用户 YAML 规则；WAF 厂商识别已包含在内。",
  "passive.poc_scan": "对 MITM 新发现的站点执行本地 HTTP POC 规则，并限制速率与并发。",
  "passive.sqli_probe": "新参数请求进入 MITM 后，按配置速率做受控 SQL 注入探测。",
  "passive.sensitive_info": "在 MITM 捕获响应中检测私钥、云密钥、JWT、应用密钥、堆栈、邮箱、手机号等敏感信息；每类检测可在高级设置中单独关闭。",
  "passive.sensitive_info.private_key": "检测响应正文中的 PEM 私钥材料。",
  "passive.sensitive_info.aws_access_key": "检测响应正文中的 AWS Access Key ID。",
  "passive.sensitive_info.aliyun_access_key": "检测响应正文中的阿里云 AccessKey ID。",
  "passive.sensitive_info.github_token": "检测响应正文中的 GitHub Token 格式。",
  "passive.sensitive_info.google_api_key": "检测响应正文中的 Google API Key 格式。",
  "passive.sensitive_info.slack_token": "检测响应正文中的 Slack Token 格式。",
  "passive.sensitive_info.stripe_key": "检测响应正文中的 Stripe Secret/Publishable Key 格式。",
  "passive.sensitive_info.jwt": "检测响应正文中的三段式 JWT 令牌。",
  "passive.sensitive_info.database_dsn": "检测响应正文中的数据库 DSN/JDBC 连接串。",
  "passive.sensitive_info.application_secret": "检测响应正文中的敏感字段名与非占位值。",
  "passive.sensitive_info.stack_trace": "检测响应正文中的运行时堆栈信息。",
  "passive.sensitive_info.email": "检测响应正文中的邮箱地址。",
  "passive.sensitive_info.phone": "检测响应正文中的中国大陆手机号码。",
  "passive.file_probe": "MITM 观察到新站点后主动探测已知敏感文件路径；每类文件与探测速率可在高级设置中单独配置。",
  "passive.file_probe.git": "探测 .git 仓库元数据路径。",
  "passive.file_probe.svn": "探测 .svn 工作副本元数据路径。",
  "passive.file_probe.idea": "探测 .idea 项目配置 XML 文件。",
  "passive.file_probe.ds_store": "探测 macOS .DS_Store 文件。",
  "passive.file_probe.environment": "探测 .env 及 .env.* 环境变量文件。",
  "passive.file_probe.backup": "探测常见备份归档扩展名。",
  "passive.file_probe.database_dump": "探测 .sql/.dump 数据库转储文件。",
  "passive.file_probe.swagger": "在站点根目录与 MITM 捕获的路径前缀下探测 /v1/swagger.json、/openapi.json 等常见 API 文档路径，仅当响应包含 swagger/openapi 结构标记时上报。",
  "passive.file_probe.springboot": "在站点根目录与 MITM 捕获的路径前缀下探测 /actuator/env、/actuator/heapdump 等常见 Spring Boot Actuator 端点，仅当响应包含对应结构标记时上报。",
  "passive.file_probe.custom": "探测下方自定义路径列表中的路径，命中 200 且内容非空时上报；HTML 响应会标记为待人工确认。",
  "passive.file_probe.dedupe_responses": "同一站点下多个探测路径返回完全相同的响应时（大概率是统一兜底页/误报），只保留一条结果。",
  "passive.waf_probe": "对 MITM 新发现的站点发送一次 SQLi/XSS 探测包，依据响应判断是否存在 WAF 并尝试识别厂商。",
  "passive.fastjson_probe": "重放观测到的 JSON 请求（去掉一个花括号），根据解析报错特征识别阿里 Fastjson。仅做技术识别，不发送反序列化 Payload。",
  "passive.shiro_probe": "识别 Apache Shiro rememberMe 指纹，并对捕获的 rememberMe Cookie 离线比对已知密钥。不发送反序列化 Payload。",
  "passive.cmd_probe": "对 MITM 观测到的参数注入算术表达式（如 expr X+Y），仅当响应回显精确计算结果时判定命令/代码执行，误报率极低。",
  "passive.ssrf_probe": "对 URL 类参数注入内网/回环地址并与对照探针比对响应差异，识别服务端请求伪造。可在高级设置中配置 OOB 域名用于盲打确认。",
  "passive.xxe_probe": "当 MITM 观测到 XML 流量时，重放请求并注入声明外部/内部实体的 DOCTYPE，基于回显与解析报错识别 XXE。可配置 OOB 域名用于外带确认。",
  "passive.upload_probe": "对 multipart 文件上传把文件名后缀改为 .html 等可渲染类型并同步修改 Content-Type 重放，验证上传接口是否缺少后缀/类型白名单。仅重放用户自身文件字节。",
  "passive.ai_analysis": "站点 JS 加载稳定后，把全部 JS 文件名交给 AI 筛选，再对有价值的 JS 并行提取路由与敏感信息；需在 AI 设置中配置接口。",
  "passive.ai_analysis.routes": "使用 AI 从有价值的 JS 文件中提取前端路由与 API 接口路径。",
  "passive.ai_analysis.secrets": "使用 AI 从有价值的 JS 文件中提取敏感凭据、密钥与内网地址等信息。",
  "passive.ai_insight": "对检测到的漏洞，异步调用 AI 生成影响分析、利用方式与修复建议，追加到 finding 描述中。需在 AI 设置中配置接口。",
  "passive.ai_fingerprint": "当指纹规则库未识别出技术栈时，异步调用 AI 从响应头和 HTML 推断框架、语言、CMS 与版本。需在 AI 设置中配置接口。",
  "passive.ai_secret_context": "对检测到的敏感信息（密钥、Token、连接串等），异步调用 AI 判断是真实凭据还是示例/占位符，追加研判结果到 finding 描述。需在 AI 设置中配置接口。",
  "passive.ai_traffic_anomaly": "站点流量稳定后，异步调用 AI 分析流量摘要，识别调试端点暴露、异常状态码、版本混用等潜在风险。需在 AI 设置中配置接口。",
  "active.port_scan": "扫描常见 TCP 服务端口。",
  "active.basic_auth_check": "检测 HTTP Basic 认证服务的常见登录问题。",
  "active.web_crawl": "扫描同一网站内的页面和链接。",
  "active.web_crawl_headless": "使用浏览器扫描同一网站的动态页面。",
};

function featureTitle(feature: Feature): string {
  return featureCopy[feature.id] || feature.label || "功能开关";
}

function featureDescription(feature: Feature): string {
  return featureDescriptionCopy[feature.id] || feature.description || "控制该项扫描能力是否在后续任务中启用。";
}

const passiveSQLiProbeQPSRange = {min: 1, max: 20} as const;
const passiveSQLiMaxRequestsRange = {min: 3, max: 200} as const;
const passiveSQLiMaxParametersRange = {min: 1, max: 20} as const;
const passiveXSSProbeQPSRange = {min: 1, max: 20} as const;
const passiveXSSMaxRequestsRange = {min: 2, max: 100} as const;
const passiveXSSMaxParametersRange = {min: 1, max: 20} as const;
const passivePOCQPSRange = {min: 1, max: 20} as const;
const passivePOCConcurrencyRange = {min: 1, max: 8} as const;
const passiveFileProbeQPSRange = {min: 1, max: 20} as const;
const passiveFastjsonProbeQPSRange = {min: 1, max: 20} as const;
const passiveShiroProbeQPSRange = {min: 1, max: 20} as const;

const taskOptions = [
  {value: "port_scan", label: "端口扫描"},
  {value: "web_crawl", label: "网站爬取"},
  {value: "web_crawl_headless", label: "浏览器爬取"},
  {value: "basic_auth_check", label: "HTTP Basic 认证检测"},
];

const navigation: NavigationItem[] = [
  {id: "traffic", label: "被动日志", icon: <DocumentBulletList24Regular />, section: "monitor"},
  {id: "findings", label: "风险发现", icon: <Alert24Regular />, section: "monitor"},
  {id: "assets", label: "资产与接口", icon: <Cube24Regular />, section: "monitor"},
  {id: "runtime-logs", label: "运行日志", icon: <History24Regular />, section: "monitor"},
  {id: "active", label: "主动扫描", icon: <ClipboardTaskListLtr24Regular />, section: "control"},
  {id: "ai", label: "AI 设置", icon: <Sparkle24Regular />, section: "control"},
  {id: "settings", label: "功能策略", icon: <Settings24Regular />, section: "control"},
];

function formatDate(value: string): string {
  if (!value) {
    return "未记录";
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }
  return new Intl.DateTimeFormat("zh-CN", {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
  }).format(date);
}

function taskLabel(kind: string): string {
  return taskOptions.find((option) => option.value === kind)?.label || kind || "未知任务";
}

function taskStateLabel(status: string): string {
  const states: Record<string, string> = {
    queued: "排队中",
    running: "执行中",
    completed: "已完成",
    cancelled: "已取消",
    failed: "失败",
  };
  return states[status.toLowerCase()] || status || "未知";
}

function serviceStateLabel(running: boolean | null): string {
  if (running === true) {
    return "服务运行中";
  }
  if (running === false) {
    return "服务已停止";
  }
  return "等待连接";
}

function parseSessionHeaders(value: string): Record<string, string> {
  const result: Record<string, string> = {};
  const invalidLine = value.split(/\r?\n/).find((line) => {
    if (!line.trim()) {
      return false;
    }
    const separator = line.indexOf(":");
    if (separator <= 0 || !line.slice(separator + 1).trim()) {
      return true;
    }
    result[line.slice(0, separator).trim()] = line.slice(separator + 1).trim();
    return false;
  });

  if (invalidLine) {
    throw new Error("会话头每行需使用“名称: 值”的格式");
  }
  return result;
}

function severityClass(severity: Severity): string {
  return `severity severity-${severity}`;
}

function taskStatusClass(status: string): string {
  const normalized = status.toLowerCase();
  return `task-status task-status-${["queued", "running", "completed", "cancelled", "failed"].includes(normalized) ? normalized : "unknown"}`;
}

function actionSuccessMessage(key: string): string {
  if (key === "start-services") return "本地服务已经启动。";
  if (key === "stop-services") return "本地服务已经停止。";
  if (key === "submit-task") return "扫描任务已加入执行队列。";
  if (key.startsWith("cancel-")) return "扫描任务已取消。";
  if (key.startsWith("feature-")) return "功能策略已写入本地配置。";
  if (key === "hfinger-import") return "\u5df2\u5bfc\u5165\u5e76\u52a0\u8f7d YAML \u6307\u7eb9\u3002";
  if (key === "hfinger-reload") return "\u6307\u7eb9\u89c4\u5219\u5df2\u70ed\u91cd\u8f7d\u3002";
  if (key === "passive-sqli-settings") return "MITM SQL 检测参数已保存。";
  if (key === "excluded-domains") return "排除域名已保存，新流量将立即停止分析。";
  if (key === "excluded-suffixes") return "过滤流量后缀已保存；命中流量将透明转发且不记录日志、不参与分析。";
  if (key === "excluded-content-types") return "过滤 Content-Type 已保存；命中流量将透明转发且不记录日志、不参与分析。";
  if (key === "excluded-paths") return "排除路径已保存；命中路径的整条流量只转发、不检测。";
  if (key === "excluded-query-parameters") return "排除 Query 参数已保存；包含这些参数的请求只转发、不检测。";
  if (key === "excluded-post-parameters") return "排除 POST/JSON 参数已保存；包含这些字段的请求只转发、不检测。";
  if (key === "ai-settings") return "AI 接口配置已保存，新的 MITM 流量将按新配置分析。";
  return "操作已完成。";
}

function SeverityPill({severity}: {severity: Severity}) {
  return <span className={severityClass(severity)}>{severityCopy[severity]}</span>;
}

function EmptyState({title, detail}: {title: string; detail: string}) {
  return (
    <div className="empty-state">
      <div className="empty-state-icon"><DataBarVertical24Regular /></div>
      <strong>{title}</strong>
      <span>{detail}</span>
    </div>
  );
}

function Metric({label, value, tone = "neutral", detail}: {label: string; value: string | number; tone?: string; detail?: string}) {
  return (
    <div className={`metric metric-${tone}`}>
      <span className="metric-label">{label}</span>
      <strong className="metric-value">{value}</strong>
      {detail && <span className="metric-detail">{detail}</span>}
    </div>
  );
}

function FindingTable({
  findings,
  selectedId,
  onSelect,
  compact = false,
}: {
  findings: Finding[];
  selectedId: string;
  onSelect: (finding: Finding) => void;
  compact?: boolean;
}) {
  if (findings.length === 0) {
    return <EmptyState title="暂无匹配发现" detail="新的被动分析结果会显示在这里。" />;
  }

  return (
    <div className="finding-table" role="table" aria-label="风险发现列表">
      <div className="finding-table-head" role="row">
        <span>级别</span>
        <span>发现</span>
        <span>{compact ? "时间" : "目标"}</span>
        <span aria-hidden="true" />
      </div>
      {findings.map((finding) => {
        const displayFinding = localizedFinding(finding);
        return <button
          className={`finding-row ${selectedId === finding.id ? "is-selected" : ""}`}
          key={finding.id || `${finding.title}-${finding.observedAt}`}
          onClick={() => onSelect(finding)}
          type="button"
        >
          <span><SeverityPill severity={finding.severity} /></span>
          <span className="finding-title-cell">
            <strong>{displayFinding.title}</strong>
            <small>{finding.ruleId || "未标记规则"}</small>
          </span>
          <span className="finding-target">{compact ? formatDate(finding.observedAt) : finding.url || "未记录目标"}</span>
          <ChevronRight20Regular className="row-chevron" />
        </button>;
      })}
    </div>
  );
}

function FindingDetail({finding}: {finding: Finding | undefined}) {
  if (!finding) {
    return <EmptyState title="选择一条发现" detail="从左侧列表查看证据、影响和处置建议。" />;
  }
  const displayFinding = localizedFinding(finding);

  return (
    <div className="finding-detail">
      <div className="detail-heading">
        <div>
          <span className="eyebrow">{displayFinding.ruleId || "规则发现"}</span>
          <h2>{displayFinding.title}</h2>
        </div>
        <SeverityPill severity={finding.severity} />
      </div>
      <dl className="detail-facts">
        <div><dt>目标</dt><dd>{finding.url || "未记录"}</dd></div>
        <div><dt>请求</dt><dd>{finding.method || "未记录"}</dd></div>
        <div><dt>置信度</dt><dd>{finding.confidence || "未记录"}</dd></div>
        <div><dt>时间</dt><dd>{formatDate(finding.observedAt)}</dd></div>
      </dl>
      <DetailBlock label="说明" value={displayFinding.description} />
      <DetailBlock label="证据" value={displayFinding.evidence} mono />
      <DetailBlock label="处置建议" value={displayFinding.remediation} />
      {finding.tags.length > 0 && (
        <div className="detail-block">
          <span className="detail-label">标签</span>
          <div className="tag-list">{finding.tags.map((tag) => <span className="tag" key={tag}>{tag}</span>)}</div>
        </div>
      )}
    </div>
  );
}

function DetailBlock({label, value, mono = false}: {label: string; value: string; mono?: boolean}) {
  if (!value) {
    return null;
  }
  return (
    <div className="detail-block">
      <span className="detail-label">{label}</span>
      <p className={mono ? "detail-copy is-mono" : "detail-copy"}>{value}</p>
    </div>
  );
}

function findingIdentity(finding: Finding): string {
  return finding.id || [finding.ruleId, finding.url, finding.observedAt, finding.title].join("|");
}

function findingEvidenceFor(finding: Finding, evidenceByFinding: Record<string, FindingEvidence[]>): FindingEvidence[] {
  return evidenceByFinding[finding.id] ?? evidenceByFinding[findingIdentity(finding)] ?? [];
}

async function copyEvidenceText(value: string): Promise<boolean> {
  if (!value) {
    return false;
  }

  try {
    await navigator.clipboard.writeText(value);
    return true;
  } catch {
    const textarea = document.createElement("textarea");
    textarea.value = value;
    textarea.setAttribute("readonly", "");
    textarea.style.position = "fixed";
    textarea.style.opacity = "0";
    document.body.appendChild(textarea);
    textarea.select();
    const copied = document.execCommand("copy");
    textarea.remove();
    return copied;
  }
}

function RawEvidencePanel({label, value}: {label: string; value: string}) {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    void copyEvidenceText(value).then((didCopy) => {
      if (!didCopy) {
        return;
      }
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1600);
    });
  };

  return (
    <section className="raw-evidence-panel" aria-label={label}>
      <div className="raw-evidence-heading">
        <span>{label}</span>
        <button className="raw-evidence-copy" disabled={!value} onClick={handleCopy} type="button">
          {copied ? "已复制" : "复制"}
        </button>
      </div>
      {value ? (
        <pre className="raw-evidence-content">{value}</pre>
      ) : (
        <p className="raw-evidence-empty">本次观察未保留该报文。</p>
      )}
    </section>
  );
}

function findingEvidenceLabel(source: string, index: number): string {
  const normalized = source.trim().toLowerCase();
  if (!normalized.startsWith("sqli-probe.")) {
    return index === 0 ? "原始流量" : `原始流量 ${index + 1}`;
  }
  if (normalized.startsWith("sqli-probe.control")) return "基线复测";
  if (normalized.startsWith("sqli-probe.error.")) return normalized.endsWith(".replay") ? "报错复测" : "报错探测";
  if (normalized.startsWith("sqli-probe.boolean.")) {
    if (normalized.endsWith(".true")) return "布尔真条件";
    if (normalized.endsWith(".false")) return "布尔假条件";
    return "布尔复测";
  }
  if (normalized.startsWith("sqli-probe.time.")) {
    if (normalized.endsWith(".fast")) return "时间快速条件";
    if (normalized.endsWith(".slow")) return "时间延时条件";
    return "时间延时复测";
  }
  if (normalized.startsWith("sqli-probe.order-by.")) {
    if (normalized.endsWith(".valid")) return "ORDER BY 有效序号";
    if (normalized.endsWith(".invalid")) return "ORDER BY 越界序号";
    return "ORDER BY 越界复测";
  }
  return `探测报文 ${index + 1}`;
}

function FindingEvidencePackets({evidence, loading}: {evidence: FindingEvidence[]; loading: boolean}) {
  const [activeIndex, setActiveIndex] = useState(0);
  const selectedIndex = Math.min(activeIndex, Math.max(0, evidence.length - 1));
  const selectedEvidence = evidence[selectedIndex];

  if (!selectedEvidence) {
    return (
      <section className="finding-packets finding-packets-empty" aria-label="请求与响应报文">
        <div className="finding-packets-heading">
          <div><span className="detail-label">请求与响应</span><strong>检测证据报文</strong></div>
          <span className="finding-evidence-status">{loading ? "正在读取…" : "未捕获"}</span>
        </div>
        <p>{loading ? "正在读取本次会话中捕获的原始、探测与复测请求响应。" : "尚未关联到可显示的请求与响应报文。"}</p>
      </section>
    );
  }

  const tabBaseId = `finding-evidence-${selectedEvidence.findingId || selectedEvidence.id || "current"}`.replace(/[^a-zA-Z0-9_-]/g, "-");
  const panelId = `${tabBaseId}-panel-${selectedIndex}`;
  const handleEvidenceTabKeyDown = (event: ReactKeyboardEvent<HTMLButtonElement>, index: number) => {
    let nextIndex: number | null = null;
    if (event.key === "ArrowRight" || event.key === "ArrowDown") {
      nextIndex = (index + 1) % evidence.length;
    } else if (event.key === "ArrowLeft" || event.key === "ArrowUp") {
      nextIndex = (index - 1 + evidence.length) % evidence.length;
    } else if (event.key === "Home") {
      nextIndex = 0;
    } else if (event.key === "End") {
      nextIndex = evidence.length - 1;
    }
    if (nextIndex === null) {
      return;
    }
    event.preventDefault();
    setActiveIndex(nextIndex);
    window.requestAnimationFrame(() => document.getElementById(`${tabBaseId}-tab-${nextIndex}`)?.focus());
  };

  return (
    <section className="finding-packets" aria-label="请求与响应报文">
      <div className="finding-packets-heading">
        <div>
          <span className="detail-label">请求与响应</span>
          <strong>{findingEvidenceLabel(selectedEvidence.source, selectedIndex)}</strong>
        </div>
        <div className="finding-evidence-meta">
          {selectedEvidence.source && <span>{selectedEvidence.source}</span>}
          {selectedEvidence.observedAt && <time dateTime={selectedEvidence.observedAt}>{formatDate(selectedEvidence.observedAt)}</time>}
        </div>
      </div>
      {evidence.length > 1 && (
        <div className="finding-evidence-tabs" role="tablist" aria-label="证据请求选择">
          {evidence.map((item, index) => {
            const tabId = `${tabBaseId}-tab-${index}`;
            const isActive = index === selectedIndex;
            return (
              <button
                aria-controls={panelId}
                aria-selected={isActive}
                className={isActive ? "is-active" : undefined}
                id={tabId}
                key={item.id || `${item.observedAt}-${index}`}
                onClick={() => setActiveIndex(index)}
                onKeyDown={(event) => handleEvidenceTabKeyDown(event, index)}
                role="tab"
                tabIndex={isActive ? 0 : -1}
                type="button"
              >
                {findingEvidenceLabel(item.source, index)}
              </button>
            );
          })}
        </div>
      )}
      <div aria-label={evidence.length === 1 ? "请求与响应报文" : undefined} aria-labelledby={evidence.length > 1 ? `${tabBaseId}-tab-${selectedIndex}` : undefined} className="raw-evidence-grid" id={panelId} role="tabpanel">
        <RawEvidencePanel label="请求包" value={selectedEvidence.request} />
        <RawEvidencePanel label="响应包" value={selectedEvidence.response} />
      </div>
    </section>
  );
}

function InlineFindingDetail({finding, evidence, loading}: {finding: Finding; evidence: FindingEvidence[]; loading: boolean}) {
  const displayFinding = localizedFinding(finding);
  return (
    <div className="inline-finding-detail">
      <div className="inline-finding-summary">
        <div className="inline-finding-url">
          <span className="detail-label">漏洞 URL</span>
          <code>{finding.url || "未记录目标"}</code>
        </div>
        <dl className="inline-finding-facts">
          <div><dt>请求方法</dt><dd>{finding.method || "未记录"}</dd></div>
          <div><dt>置信度</dt><dd>{finding.confidence || "未记录"}</dd></div>
          <div><dt>发现时间</dt><dd>{formatDate(finding.observedAt)}</dd></div>
          <div><dt>规则</dt><dd>{finding.ruleId || "未标记规则"}</dd></div>
        </dl>
      </div>
      <div className="inline-finding-copy-grid">
        <div className="inline-finding-block">
          <span className="detail-label">说明</span>
          <p>{displayFinding.description || "未提供说明。"}</p>
        </div>
        <div className="inline-finding-block">
          <span className="detail-label">证据</span>
          <pre>{finding.evidence || "未提供规则证据。"}</pre>
        </div>
        <div className="inline-finding-block inline-finding-remediation">
          <span className="detail-label">修复建议</span>
          <p>{displayFinding.remediation || "请结合业务场景确认影响并采取相应修复措施。"}</p>
        </div>
      </div>
      {finding.tags.length > 0 && (
        <div className="inline-finding-tags">
          <span className="detail-label">标签</span>
          <div className="tag-list">{finding.tags.map((tag) => <span className="tag" key={tag}>{tag}</span>)}</div>
        </div>
      )}
      <FindingEvidencePackets evidence={evidence} loading={loading} />
    </div>
  );
}

function ExpandableFindingList({
  findings,
  expandedId,
  evidenceByFinding,
  loadingId,
  onToggle,
}: {
  findings: Finding[];
  expandedId: string;
  evidenceByFinding: Record<string, FindingEvidence[]>;
  loadingId: string;
  onToggle: (finding: Finding) => void;
}) {
  if (findings.length === 0) {
    return <EmptyState title="暂无匹配发现" detail="新的被动分析结果会显示在这里。" />;
  }

  return (
    <div className="finding-table finding-disclosure-list" role="list" aria-label="风险发现列表">
      <div className="finding-table-head" role="presentation">
        <span>级别</span>
        <span>发现</span>
        <span>目标</span>
        <span aria-hidden="true" />
      </div>
      {findings.map((finding) => {
        const displayFinding = localizedFinding(finding);
        const identity = findingIdentity(finding);
        const isExpanded = identity === expandedId;
        const disclosureId = `finding-detail-${identity}`.replace(/[^a-zA-Z0-9_-]/g, "-");
        return (
          <article className={`finding-record ${isExpanded ? "is-expanded" : ""}`} key={identity} role="listitem">
            <button
              aria-controls={disclosureId}
              aria-expanded={isExpanded}
              className={`finding-row ${isExpanded ? "is-selected" : ""}`}
              onClick={() => onToggle(finding)}
              type="button"
            >
              <span><SeverityPill severity={finding.severity} /></span>
              <span className="finding-title-cell">
                <strong>{displayFinding.title}</strong>
                <small>{finding.ruleId || "未标记规则"}</small>
              </span>
              <span className="finding-target">{finding.url || "未记录目标"}</span>
              <ChevronDown20Regular className="row-chevron" />
            </button>
            {isExpanded && (
              <div className="finding-disclosure" id={disclosureId}>
                <InlineFindingDetail evidence={findingEvidenceFor(finding, evidenceByFinding)} finding={finding} loading={loadingId === identity} />
              </div>
            )}
          </article>
        );
      })}
    </div>
  );
}

type FindingCategory = "web" | "information";

function findingCategory(finding: Finding): FindingCategory {
  const ruleID = finding.ruleId.toLowerCase();
  if (finding.severity === "info" || ruleID.startsWith("tscan.info.")) {
    return "information";
  }
  return "web";
}

function FindingCategoryPanel({
  category,
  findings,
  expandedId,
  evidenceByFinding,
  loadingId,
  onToggle,
}: {
  category: FindingCategory;
  findings: Finding[];
  expandedId: string;
  evidenceByFinding: Record<string, FindingEvidence[]>;
  loadingId: string;
  onToggle: (finding: Finding) => void;
}) {
  const isWeb = category === "web";
  return (
    <section className={`work-surface finding-category-panel finding-category-${category}`}>
      <div className="finding-category-heading">
        <div>
          <span className="eyebrow">{isWeb ? "风险发现" : "被动信息发现"}</span>
          <h2>{isWeb ? "漏洞" : "信息"}</h2>
          <p>{isWeb ? "已识别的风险，展开查看证据。" : "已观测到的地址、配置与其他信息，不计入漏洞。"}</p>
        </div>
        <span className="finding-category-count">{findings.length}</span>
      </div>
      <ExpandableFindingList
        evidenceByFinding={evidenceByFinding}
        expandedId={expandedId}
        findings={findings}
        loadingId={loadingId}
        onToggle={onToggle}
      />
    </section>
  );
}

function fingerprintEvidenceFor(asset: Asset, name: string): FingerprintEvidence | undefined {
  return asset.fingerprintEvidence.find((item) => item.fingerprint.trim().toLowerCase() === name.trim().toLowerCase());
}

function fingerprintConfidenceLabel(value: string): string {
  switch (value.trim().toLowerCase()) {
    case "high": return "高";
    case "medium": return "中";
    default: return "低";
  }
}

function FingerprintTag({asset, fingerprint}: {asset: Asset; fingerprint: string}) {
  const evidence = fingerprintEvidenceFor(asset, fingerprint);
  const detail = evidence
    ? `置信度：${fingerprintConfidenceLabel(evidence.confidence)}；命中来源：${evidence.sources.length ? evidence.sources.join("、") : "响应特征"}`
    : "命中来源：历史记录";
  return (
    <Tooltip content={detail} relationship="label">
      <span className="tag tag-fingerprint" tabIndex={0}>{fingerprint}</span>
    </Tooltip>
  );
}

function PassiveFingerprintList({assets}: {assets: Asset[]}) {
  const identified = assets.filter((asset) => asset.fingerprints.length > 0);
  if (identified.length === 0) {
    return <EmptyState title="暂无指纹识别" detail="捕获到响应后，匹配到的组件指纹会显示在这里。" />;
  }

  return (
    <div className="passive-fingerprint-list" role="list" aria-label="被动指纹识别列表">
      {identified.map((asset) => {
        const routes = asset.endpoints.map((endpoint) => endpoint.path || "/").filter(Boolean);
        const uniqueRoutes = [...new Set(routes)];
        return (
          <article className="passive-fingerprint-row" key={asset.host || asset.urls[0]} role="listitem">
            <div className="passive-fingerprint-host">
              <Globe24Regular />
              <div>
                <strong>{asset.host || "未命名资产"}</strong>
                <span>{asset.urls.length} 个 URL · 最近观测 {formatDate(asset.lastSeen)}</span>
              </div>
            </div>
            <div className="passive-fingerprint-routes">
              <span className="detail-label">路由</span>
              <div className="route-list">
                {(uniqueRoutes.length > 0 ? uniqueRoutes.slice(0, 8) : ["/"]).map((route) => <code key={route}>{route}</code>)}
                {uniqueRoutes.length > 8 && <span className="route-more">+{uniqueRoutes.length - 8}</span>}
              </div>
            </div>
            <div className="passive-fingerprint-values">
              <span className="detail-label">识别指纹</span>
              <div className="tag-list">{asset.fingerprints.map((fingerprint) => <FingerprintTag asset={asset} fingerprint={fingerprint} key={fingerprint} />)}</div>
            </div>
          </article>
        );
      })}
    </div>
  );
}

function FingerprintQualityPanel({items}: {items: FingerprintRuleQuality[]}) {
  const visible = items.slice(0, 10);
  return (
    <section className="work-surface fingerprint-quality-panel">
      <div className="surface-heading">
        <div><span className="eyebrow">识别质量</span><h2>指纹命中统计</h2></div>
        <span className="surface-count">{items.length}</span>
      </div>
      {visible.length === 0 ? (
        <p className="fingerprint-quality-empty">当前会话尚未产生指纹匹配。</p>
      ) : (
        <div className="fingerprint-quality-list">
          {visible.map((item) => (
            <div className="fingerprint-quality-row" key={item.fingerprint}>
              <div><strong>{item.fingerprint}</strong><span>{item.cooccurrences.length ? `常见组合：${item.cooccurrences[0].fingerprint}` : "暂无组合关系"}</span></div>
              <div className="fingerprint-quality-meta"><span>{fingerprintConfidenceLabel(item.confidence)}置信</span><b>{item.hits}</b><small>{item.assets} 个资产</small></div>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}

function AssetList({assets}: {assets: Asset[]}) {
  if (assets.length === 0) {
    return <EmptyState title="暂无资产" detail="从已观测到的 HTTP 流量中归一化资产与端点。" />;
  }

  return (
    <div className="asset-list">
      {assets.map((asset) => (
        <article className="asset-row" key={asset.host || asset.urls[0]}>
          <div className="asset-host">
            <Globe24Regular />
            <div>
              <h3>{asset.host || "未命名资产"}</h3>
              <span>{asset.urls.length} 个 URL · 最近观测 {formatDate(asset.lastSeen)}</span>
            </div>
          </div>
          <div className="asset-fingerprint">
            {asset.fingerprints.length > 0 ? (
              <div className="tag-list">{asset.fingerprints.map((fingerprint) => <FingerprintTag asset={asset} fingerprint={fingerprint} key={fingerprint} />)}</div>
            ) : <span className="muted">尚未识别指纹</span>}
          </div>
          <div className="asset-count">
            <strong>{asset.endpoints.length}</strong>
            <span>端点</span>
          </div>
        </article>
      ))}
    </div>
  );
}

function EndpointList({assets}: {assets: Asset[]}) {
  const [selectedHost, setSelectedHost] = useState<string | null>(null);

  // 按站点分组：仅保留含端点的资产，按 host 字典序排序
  const sites = useMemo(() => {
    return assets
      .filter((asset) => asset.endpoints.length > 0)
      .map((asset) => ({
        host: asset.host || "未命名资产",
        endpoints: asset.endpoints,
        fingerprints: asset.fingerprints,
        lastSeen: asset.lastSeen,
        urls: asset.urls,
      }))
      .sort((a, b) => a.host.localeCompare(b.host));
  }, [assets]);

  const selectedSite = sites.find((site) => site.host === selectedHost) || null;

  if (sites.length === 0) {
    return <EmptyState title="暂无归一化端点" detail="端点会在发现请求方法与路径后显示。" />;
  }

  // 二级界面：端点按方法+路径分组（同一路径不同方法聚合），统计参数
  const groupedEndpoints = selectedSite ? groupEndpointsByPath(selectedSite.endpoints) : [];

  return (
    <>
      <div className="endpoint-site-list">
        {sites.map((site) => (
          <button
            type="button"
            className="endpoint-site-row"
            key={site.host}
            onClick={() => setSelectedHost(site.host)}
            aria-label={`查看 ${site.host} 的端点详情`}
          >
            <Globe24Regular />
            <div className="endpoint-site-info">
              <h3>{site.host}</h3>
              <span>{site.endpoints.length} 个端点 · {site.fingerprints.length} 个指纹 · 最近 {formatDate(site.lastSeen)}</span>
            </div>
            <ChevronRight20Regular />
          </button>
        ))}
      </div>

      <Dialog open={selectedSite !== null} onOpenChange={(_, data) => { if (!data.open) setSelectedHost(null); }}>
        <DialogSurface className="endpoint-detail-dialog">
          <DialogBody className="endpoint-detail-dialog-body">
            <DialogTitle
              action={<Button appearance="subtle" aria-label="关闭端点详情" icon={<Dismiss20Regular />} onClick={() => setSelectedHost(null)} />}
              className="endpoint-detail-dialog-title"
            >
              <span className="eyebrow">接口地图</span>
              <span>{selectedSite?.host}</span>
              <small>{selectedSite ? `${selectedSite.endpoints.length} 个已观测端点` : ""}</small>
            </DialogTitle>
            <DialogContent className="endpoint-detail-dialog-content">
              {selectedSite && selectedSite.fingerprints.length > 0 && (
                <div className="endpoint-detail-fingerprints">
                  <span className="endpoint-detail-section-label">识别指纹</span>
                  <div className="tag-list">
                    {selectedSite.fingerprints.map((fp) => <span className="fingerprint-tag" key={fp}>{fp}</span>)}
                  </div>
                </div>
              )}
              <div className="endpoint-detail-table">
                <div className="endpoint-detail-table-header">
                  <span>方法</span>
                  <span>路径</span>
                  <span>参数</span>
                  <span>来源</span>
                </div>
                <div className="endpoint-detail-table-body">
                  {groupedEndpoints.map((group) => (
                    <div className="endpoint-detail-path-group" key={group.path}>
                      <div className="endpoint-detail-path-label">{group.path || "/"}</div>
                      {group.methods.map((item) => (
                        <div className="endpoint-detail-row" key={`${item.method}-${group.path}`}>
                          <span className="endpoint-method">{item.method || "HTTP"}</span>
                          <span className="endpoint-detail-method-path">{group.path || "/"}</span>
                          <span className="endpoint-parameters">{item.parameters.length ? item.parameters.join(", ") : "无参数名"}</span>
                          <span className="endpoint-detail-sources">{item.sources.length ? item.sources.join(", ") : "—"}</span>
                        </div>
                      ))}
                    </div>
                  ))}
                </div>
              </div>
            </DialogContent>
            <DialogActions className="endpoint-detail-dialog-actions">
              <Button appearance="secondary" onClick={() => setSelectedHost(null)}>关闭</Button>
            </DialogActions>
          </DialogBody>
        </DialogSurface>
      </Dialog>
    </>
  );
}

// 按路径分组端点，同路径下不同方法聚合在一起，路径字典序排序
function groupEndpointsByPath(endpoints: Endpoint[]) {
  const pathMap = new Map<string, {method: string; parameters: string[]; sources: string[]}[]>();
  for (const endpoint of endpoints) {
    const path = endpoint.path || "/";
    if (!pathMap.has(path)) pathMap.set(path, []);
    pathMap.get(path)!.push({
      method: endpoint.method || "HTTP",
      parameters: endpoint.parameters,
      sources: endpoint.sources,
    });
  }
  // 方法排序：GET 优先
  const methodOrder = (m: string) => {
    const upper = m.toUpperCase();
    if (upper === "GET") return 0;
    if (upper === "POST") return 1;
    if (upper === "PUT") return 2;
    if (upper === "PATCH") return 3;
    if (upper === "DELETE") return 4;
    return 5;
  };
  return Array.from(pathMap.entries())
    .map(([path, methods]) => ({
      path,
      methods: methods.sort((a, b) => methodOrder(a.method) - methodOrder(b.method)),
    }))
    .sort((a, b) => a.path.localeCompare(b.path));
}

function TaskList({
  tasks,
  selectedTaskId,
  onSelect,
  onCancel,
  busyTaskId,
}: {
  tasks: ActiveTask[];
  selectedTaskId: string;
  onSelect: (id: string) => void;
  onCancel: (id: string) => void;
  busyTaskId: string;
}) {
  if (tasks.length === 0) {
    return <EmptyState title="暂无扫描任务" detail="创建任务前，请确认已获得目标范围的书面授权。" />;
  }

  return (
    <div className="task-list">
      {tasks.map((task) => {
        const cancellable = task.status === "queued" || task.status === "running";
        return (
          <article className={`task-row ${selectedTaskId === task.id ? "is-selected" : ""}`} key={task.id}>
            <button className="task-main" onClick={() => onSelect(task.id)} type="button">
              <span className={taskStatusClass(task.status)}>{taskStateLabel(task.status)}</span>
              <span className="task-main-copy">
                <strong>{taskLabel(task.kind)}</strong>
                <small>{task.target || "未记录目标"}</small>
              </span>
              <span className="task-time">{formatDate(task.createdAt)}</span>
            </button>
            {cancellable && (
              <Tooltip content="取消当前任务" relationship="label">
                <Button
                  appearance="subtle"
                  aria-label="取消当前任务"
                  className="task-cancel"
                  disabled={busyTaskId === task.id}
                  icon={<Dismiss20Regular />}
                  onClick={() => onCancel(task.id)}
                />
              </Tooltip>
            )}
          </article>
        );
      })}
    </div>
  );
}

function TaskResults({task, results, loading}: {task: ActiveTask | undefined; results: TaskResult[]; loading: boolean}) {
  if (!task) {
    return <EmptyState title="选择一个任务" detail="扫描结果会显示在这里。" />;
  }
  if (loading) {
    return <div className="results-loading"><Spinner size="tiny" label="正在读取任务结果" /></div>;
  }

  return (
    <div className="task-results">
      <div className="results-heading">
        <div>
          <span className="eyebrow">{taskLabel(task.kind)}</span>
          <h3>{task.target || "未记录目标"}</h3>
        </div>
        <span className={taskStatusClass(task.status)}>{taskStateLabel(task.status)}</span>
      </div>
      {task.error && <div className="task-error">{task.error}</div>}
      {Object.keys(task.summary).length > 0 && (
        <div className="summary-list">
          {Object.entries(task.summary).map(([key, value]) => <span key={key}><strong>{value}</strong>{key}</span>)}
        </div>
      )}
      {results.length === 0 ? (
        <EmptyState title="暂无记录结果" detail="任务完成后，满足记录条件的结果会显示在这里。" />
      ) : (
        <div className="result-list">
          {results.map((result) => (
            <article className="result-row" key={result.id || `${result.target}-${result.observedAt}`}>
              <div className="result-row-topline">
                <span className="result-status">{result.status || "记录"}</span>
                <span>{formatDate(result.observedAt)}</span>
              </div>
              <strong>{result.target || task.target}</strong>
              {result.detail && <p>{result.detail}</p>}
              {Object.keys(result.metadata).length > 0 && (
                <div className="metadata-list">
                  {Object.entries(result.metadata).map(([key, value]) => <span key={key}><b>{key}</b>{value}</span>)}
                </div>
              )}
            </article>
          ))}
        </div>
      )}
    </div>
  );
}

type FeatureGroup = {id: string; title: string; description: string; features: Feature[]};

function featureGroupFor(feature: Feature): string {
  if (feature.id === "desktop.clear_previous_results_on_start") {
    return "data";
  }
  if (feature.id.startsWith("passive.")) {
    // Sensitive-info and file-probe sub-switches are only exposed through
    // their master switch's advanced-settings dialog, never in the top-level
    // feature list.
  if (feature.id.startsWith("passive.sensitive_info.") || feature.id.startsWith("passive.file_probe.")) {
    return "hidden";
  }
  if (feature.id.startsWith("passive.ai_")) {
    return "hidden";
  }
    return "mitm";
  }
  if (feature.id.startsWith("locked.")) {
    return "locked";
  }
  if (feature.id === "active.port_scan" || feature.id === "active.basic_auth_check") {
    return "active-network";
  }
  return "active-web";
}

function FeatureGroupPanel({
  group,
  busyAction,
  onChange,
  rowActions = {},
  rowSummaries = {},
}: {
  group: FeatureGroup;
  busyAction: string;
  onChange: (feature: Feature, enabled: boolean) => void;
  rowActions?: Partial<Record<string, {label: string; onClick: () => void}>>;
  rowSummaries?: Partial<Record<string, string>>;
}) {
  const groupEyebrows: Record<string, string> = {
    mitm: "MITM 代理",
    "mitm-overview": "实时流量",
    "active-network": "网络扫描",
    "active-web": "网站检测",
    data: "本地数据与会话",
    locked: "策略限制",
    "ai-analysis": "AI 功能",
    "ai-insight": "AI 功能",
    "ai-augment": "AI 功能",
  };

  return (
    <section className={`work-surface feature-group feature-group-${group.id}`}>
      <div className="feature-group-heading">
        <div>
          <span className="eyebrow">{groupEyebrows[group.id] || "功能策略"}</span>
          <h2>{group.title}</h2>
          <p>{group.description}</p>
        </div>
        <span className="feature-group-count">{group.features.length}</span>
      </div>
      <div className="feature-list">
        {group.features.map((feature) => {
          const rowAction = rowActions[feature.id];
          const rowSummary = rowSummaries[feature.id];
          return (
            <div className={`feature-row ${busyAction === `feature-${feature.id}` ? "is-busy" : ""}`} key={feature.id}>
              <div className="feature-row-copy">
                <strong>{featureTitle(feature)}</strong>
                <span className="feature-row-description">{featureDescription(feature)}</span>
                {rowSummary && <span className="feature-row-summary">{rowSummary}</span>}
              </div>
              <div className="feature-row-controls">
                {rowAction && (
                  <Button appearance="outline" icon={<ChevronRight20Regular />} iconPosition="after" size="small" onClick={rowAction.onClick}>
                    {rowAction.label}
                  </Button>
                )}
                <Switch
                  checked={feature.enabled}
                  disabled={feature.locked || busyAction === `feature-${feature.id}`}
                  label={feature.locked ? "已锁定" : feature.enabled ? "已启用" : "已停用"}
                  onChange={(_, data) => onChange(feature, Boolean(data.checked))}
                />
              </div>
            </div>
          );
        })}
      </div>
    </section>
  );
}

function SettingsUtilityCard({
  icon,
  eyebrow,
  title,
  description,
  meta,
  actionLabel,
  onClick,
}: {
  icon: ReactElement;
  eyebrow: string;
  title: string;
  description: string;
  meta: string;
  actionLabel: string;
  onClick: () => void;
}) {
  return (
    <article className="work-surface settings-utility-card">
      <div className="settings-utility-card-icon">{icon}</div>
      <div className="settings-utility-card-copy">
        <span className="eyebrow">{eyebrow}</span>
        <h3>{title}</h3>
        <p>{description}</p>
      </div>
      <span className="settings-utility-card-meta">{meta}</span>
      <Button appearance="outline" icon={<ChevronRight20Regular />} iconPosition="after" onClick={onClick}>{actionLabel}</Button>
    </article>
  );
}

function HFingerRulePanel({
  stats,
  busyAction,
  onImport,
  onReload,
}: {
  stats: HFingerStats;
  busyAction: string;
  onImport: () => void;
  onReload: () => void;
}) {
  const importing = busyAction === "hfinger-import";
  const reloading = busyAction === "hfinger-reload";
  const busy = importing || reloading;

  return (
    <section className={`work-surface hfinger-rule-panel ${busy ? "is-busy" : ""}`}>
      <div className="surface-heading">
        <div>
          <span className="eyebrow">MITM 指纹引擎</span>
          <h2>指纹规则库</h2>
        </div>
        <Cube24Regular className="hfinger-rule-icon" />
      </div>
      <p className="hfinger-rule-description">
        仅匹配代理已经捕获的 HTTP/HTTPS 响应。内置规则与用户 YAML 在本地合并，不会额外请求路径或资源。
      </p>
      <div className="hfinger-rule-metrics">
        <div><span>有效规则</span><strong>{stats.loaded}</strong></div>
        <div><span>覆盖产品</span><strong>{stats.products}</strong></div>
        <div><span>自定义规则</span><strong>{stats.customRules}</strong></div>
        <div className={stats.failedFiles > 0 ? "has-error" : ""}><span>失败文件</span><strong>{stats.failedFiles}</strong></div>
      </div>
      <div className="hfinger-rule-directory">
        <span>自定义 YAML 目录</span>
        <code title={stats.customDir}>{stats.customDir || "未配置自定义 YAML 指纹目录"}</code>
      </div>
      <div className="hfinger-rule-actions">
        <Button appearance="primary" disabled={busy || !stats.customDir} onClick={onImport}>
          {importing ? "正在导入…" : "添加 YAML 指纹"}
        </Button>
        <Button appearance="outline" icon={<ArrowClockwise20Regular />} disabled={busy} onClick={onReload}>
          {reloading ? "正在重载…" : "重新加载规则"}
        </Button>
      </div>
      {stats.errors.length > 0 && (
        <MessageBar intent="error">
          <MessageBarBody>
            <MessageBarTitle>部分 YAML 未加载</MessageBarTitle>
            <ul className="hfinger-rule-errors">{stats.errors.map((item) => <li key={item}>{item}</li>)}</ul>
          </MessageBarBody>
        </MessageBar>
      )}
      <p className="hfinger-rule-note">同名 rule id 由自定义 YAML 覆盖内置规则；保存文件后可直接重载，无需重启 MITM。</p>
    </section>
  );
}

function PassiveSQLiProbePanel({
  feature,
  errorEnabled,
  booleanEnabled,
  timeEnabled,
  qps,
  maxRequests,
  maxParameters,
  busyAction,
  onErrorEnabledChange,
  onBooleanEnabledChange,
  onTimeEnabledChange,
  onQPSChange,
  onMaxRequestsChange,
  onMaxParametersChange,
  onQPSFocus,
  onQPSBlur,
  onMaxRequestsFocus,
  onMaxRequestsBlur,
  onMaxParametersFocus,
  onMaxParametersBlur,
  onSave,
}: {
  feature: Feature | undefined;
  errorEnabled: boolean;
  booleanEnabled: boolean;
  timeEnabled: boolean;
  qps: string;
  maxRequests: string;
  maxParameters: string;
  busyAction: string;
  onErrorEnabledChange: (value: boolean) => void;
  onBooleanEnabledChange: (value: boolean) => void;
  onTimeEnabledChange: (value: boolean) => void;
  onQPSChange: (value: string) => void;
  onMaxRequestsChange: (value: string) => void;
  onMaxParametersChange: (value: string) => void;
  onQPSFocus: () => void;
  onQPSBlur: () => void;
  onMaxRequestsFocus: () => void;
  onMaxRequestsBlur: () => void;
  onMaxParametersFocus: () => void;
  onMaxParametersBlur: () => void;
  onSave: () => void;
}) {
  const isBusy = busyAction === "passive-sqli-settings";
  const status = !feature ? "配置不可用" : feature.enabled ? "已启用" : "已停用";

  return (
    <section className={`work-surface passive-sqli-probe-panel ${isBusy ? "is-busy" : ""}`}>
      <div className="surface-heading">
        <div>
          <span className="eyebrow">MITM 参数探测</span>
          <h2>SQL 注入检测</h2>
        </div>
        <Shield24Regular className="sqli-shield" />
      </div>
      <div className="passive-sqli-probe-body">
        <div className="passive-sqli-probe-status">
          <strong>状态：{status}</strong>
          <span>{feature ? featureDescription(feature) : "当前桌面端未提供该开关。"}</span>
        </div>
        <div className="passive-sqli-techniques" aria-label="MITM SQL 检测方式">
          <label className={errorEnabled ? "is-selected" : ""}>
            <Checkbox checked={errorEnabled} onChange={(_, data) => onErrorEnabledChange(data.checked === true)} />
            <span><strong>报错检测</strong><small>覆盖单引号、双引号、转义符以及单层和双层括号上下文。</small></span>
          </label>
          <label className={booleanEnabled ? "is-selected" : ""}>
            <Checkbox checked={booleanEnabled} onChange={(_, data) => onBooleanEnabledChange(data.checked === true)} />
            <span><strong>布尔检测</strong><small>复核真/假条件差异，并检测 ORDER BY 有效序号与越界序号。</small></span>
          </label>
          <label className={timeEnabled ? "is-selected" : ""}>
            <Checkbox checked={timeEnabled} onChange={(_, data) => onTimeEnabledChange(data.checked === true)} />
            <span><strong>时间检测</strong><small>对快速条件、延时条件和延时复测进行三次成组确认。</small></span>
          </label>
        </div>
        <div className="passive-sqli-probe-fields">
          <Field label="探测速率（请求/秒）" hint={`范围 ${passiveSQLiProbeQPSRange.min}–${passiveSQLiProbeQPSRange.max}`}>
            <Input inputMode="numeric" max={passiveSQLiProbeQPSRange.max} min={passiveSQLiProbeQPSRange.min} onBlur={onQPSBlur} onChange={(_, data) => onQPSChange(data.value)} onFocus={onQPSFocus} step={1} type="number" value={qps} />
          </Field>
          <Field label="单次最大请求数" hint={`范围 ${passiveSQLiMaxRequestsRange.min}–${passiveSQLiMaxRequestsRange.max}`}>
            <Input inputMode="numeric" max={passiveSQLiMaxRequestsRange.max} min={passiveSQLiMaxRequestsRange.min} onBlur={onMaxRequestsBlur} onChange={(_, data) => onMaxRequestsChange(data.value)} onFocus={onMaxRequestsFocus} step={1} type="number" value={maxRequests} />
          </Field>
          <Field label="单次最多参数数" hint={`范围 ${passiveSQLiMaxParametersRange.min}–${passiveSQLiMaxParametersRange.max}`}>
            <Input inputMode="numeric" max={passiveSQLiMaxParametersRange.max} min={passiveSQLiMaxParametersRange.min} onBlur={onMaxParametersBlur} onChange={(_, data) => onMaxParametersChange(data.value)} onFocus={onMaxParametersFocus} step={1} type="number" value={maxParameters} />
          </Field>
        </div>
        <p className="passive-sqli-probe-note">仅在 MITM 发现新的参数请求后触发，支持 Query、表单、JSON 和 Cookie 参数；三种检测可任意组合，结果会保留原始、探测及复测请求响应。</p>
        <Button appearance="primary" disabled={!feature || isBusy} onClick={onSave}>{isBusy ? "正在保存" : "保存 SQL 检测参数"}</Button>
      </div>
    </section>
  );
}

function PassiveXSSProbePanel({
  feature,
  qps,
  maxRequests,
  maxParameters,
  busyAction,
  onQPSChange,
  onMaxRequestsChange,
  onMaxParametersChange,
  onQPSFocus,
  onQPSBlur,
  onMaxRequestsFocus,
  onMaxRequestsBlur,
  onMaxParametersFocus,
  onMaxParametersBlur,
  onSave,
}: {
  feature: Feature | undefined;
  qps: string;
  maxRequests: string;
  maxParameters: string;
  busyAction: string;
  onQPSChange: (value: string) => void;
  onMaxRequestsChange: (value: string) => void;
  onMaxParametersChange: (value: string) => void;
  onQPSFocus: () => void;
  onQPSBlur: () => void;
  onMaxRequestsFocus: () => void;
  onMaxRequestsBlur: () => void;
  onMaxParametersFocus: () => void;
  onMaxParametersBlur: () => void;
  onSave: () => void;
}) {
  const isBusy = busyAction === "passive-xss-settings";
  const status = !feature ? "配置不可用" : feature.enabled ? "已启用" : "已停用";

  return (
    <section className={`work-surface passive-sqli-probe-panel ${isBusy ? "is-busy" : ""}`}>
      <div className="surface-heading">
        <div>
          <span className="eyebrow">MITM 参数探测</span>
          <h2>XSS 检测</h2>
        </div>
        <Shield24Regular className="sqli-shield" />
      </div>
      <div className="passive-sqli-probe-body">
        <div className="passive-sqli-probe-status">
          <strong>状态：{status}</strong>
          <span>{feature ? featureDescription(feature) : "当前桌面端未提供该开关。"}</span>
        </div>
        <div className="passive-sqli-probe-fields">
          <Field label="探测速率（请求/秒）" hint={`范围 ${passiveXSSProbeQPSRange.min}–${passiveXSSProbeQPSRange.max}`}>
            <Input inputMode="numeric" max={passiveXSSProbeQPSRange.max} min={passiveXSSProbeQPSRange.min} onBlur={onQPSBlur} onChange={(_, data) => onQPSChange(data.value)} onFocus={onQPSFocus} step={1} type="number" value={qps} />
          </Field>
          <Field label="单次最大请求数" hint={`范围 ${passiveXSSMaxRequestsRange.min}–${passiveXSSMaxRequestsRange.max}`}>
            <Input inputMode="numeric" max={passiveXSSMaxRequestsRange.max} min={passiveXSSMaxRequestsRange.min} onBlur={onMaxRequestsBlur} onChange={(_, data) => onMaxRequestsChange(data.value)} onFocus={onMaxRequestsFocus} step={1} type="number" value={maxRequests} />
          </Field>
          <Field label="单次最多参数数" hint={`范围 ${passiveXSSMaxParametersRange.min}–${passiveXSSMaxParametersRange.max}`}>
            <Input inputMode="numeric" max={passiveXSSMaxParametersRange.max} min={passiveXSSMaxParametersRange.min} onBlur={onMaxParametersBlur} onChange={(_, data) => onMaxParametersChange(data.value)} onFocus={onMaxParametersFocus} step={1} type="number" value={maxParameters} />
          </Field>
        </div>
        <p className="passive-sqli-probe-note">仅在 MITM 发现新的参数请求后触发，支持 Query、表单和 JSON 参数；只发送惰性特殊字符标记并复核可重复的未编码反射，不执行任何脚本，结果会保留原始、探测及复测请求响应。</p>
        <Button appearance="primary" disabled={!feature || isBusy} onClick={onSave}>{isBusy ? "正在保存" : "保存 XSS 检测参数"}</Button>
      </div>
    </section>
  );
}

function PassivePOCProbePanel({
  feature,
  qps,
  concurrency,
  busyAction,
  onQPSChange,
  onConcurrencyChange,
  onQPSFocus,
  onQPSBlur,
  onConcurrencyFocus,
  onConcurrencyBlur,
  onSave,
  nucleiStatus,
  nucleiPath,
  onNucleiPathChange,
  onNucleiPathSave,
  onNucleiDownload,
}: {
  feature: Feature | undefined;
  qps: string;
  concurrency: string;
  busyAction: string;
  onQPSChange: (value: string) => void;
  onConcurrencyChange: (value: string) => void;
  onQPSFocus: () => void;
  onQPSBlur: () => void;
  onConcurrencyFocus: () => void;
  onConcurrencyBlur: () => void;
  onSave: () => void;
  nucleiStatus: NucleiStatus | null;
  nucleiPath: string;
  onNucleiPathChange: (value: string) => void;
  onNucleiPathSave: () => void;
  onNucleiDownload: () => void;
}) {
  const isBusy = busyAction === "passive-poc-settings";
  const status = !feature ? "配置不可用" : feature.enabled ? "已启用" : "已停用";

  return (
    <section className={`work-surface passive-sqli-probe-panel passive-poc-probe-panel ${isBusy ? "is-busy" : ""}`}>
      <div className="surface-heading">
        <div><span className="eyebrow">MITM 主动验证</span><h2>POC 检测</h2></div>
        <Shield24Regular className="sqli-shield" />
      </div>
      <div className="passive-sqli-probe-body">
        <div className="passive-sqli-probe-status">
          <strong>状态：{status}</strong>
          <span>{feature ? `${featureDescription(feature)} 开关可在设置首页调整。` : "当前桌面端未提供该开关。"}</span>
        </div>
        <div className="passive-sqli-probe-fields passive-poc-probe-fields">
          <Field label="探测速率（请求/秒）" hint={`范围 ${passivePOCQPSRange.min}–${passivePOCQPSRange.max}`}>
            <Input inputMode="numeric" max={passivePOCQPSRange.max} min={passivePOCQPSRange.min} onBlur={onQPSBlur} onChange={(_, data) => onQPSChange(data.value)} onFocus={onQPSFocus} step={1} type="number" value={qps} />
          </Field>
          <Field label="最大并发数" hint={`范围 ${passivePOCConcurrencyRange.min}–${passivePOCConcurrencyRange.max}`}>
            <Input inputMode="numeric" max={passivePOCConcurrencyRange.max} min={passivePOCConcurrencyRange.min} onBlur={onConcurrencyBlur} onChange={(_, data) => onConcurrencyChange(data.value)} onFocus={onConcurrencyFocus} step={1} type="number" value={concurrency} />
          </Field>
        </div>
        <p className="passive-sqli-probe-note">仅对 MITM 新发现的站点调度本地 HTTP POC 规则；降低速率和并发可减少实时代理的额外负载。</p>
        <Button appearance="primary" disabled={!feature || isBusy} onClick={onSave}>{isBusy ? "正在保存" : "保存 POC 检测参数"}</Button>
        <div className="passive-poc-nuclei">
          <div className="passive-sqli-probe-status">
            <strong>nuclei 引擎：{nucleiStatus?.installed ? "已就绪" : "未安装"}</strong>
            <span>
              {nucleiStatus?.installed
                ? (nucleiStatus.version ? `版本 ${nucleiStatus.version}` : "已检测到可用的 nuclei 可执行文件。")
                : (nucleiStatus?.message || "点击下载最新版 nuclei，或在下方填写本地可执行文件路径。")}
            </span>
          </div>
          <Field label="nuclei 可执行文件路径（留空则使用下载版本或 PATH）">
            <Input onChange={(_, data) => onNucleiPathChange(data.value)} placeholder="例如 C:\\tools\\nuclei.exe" type="text" value={nucleiPath} />
          </Field>
          <div className="passive-poc-nuclei-actions">
            <Button appearance="primary" disabled={busyAction === "nuclei-download"} onClick={onNucleiDownload}>
              {busyAction === "nuclei-download" ? "正在下载" : "从 GitHub 下载最新版"}
            </Button>
            <Button appearance="secondary" disabled={busyAction === "nuclei-path"} onClick={onNucleiPathSave}>
              {busyAction === "nuclei-path" ? "正在保存" : "保存路径"}
            </Button>
          </div>
          <p className="passive-sqli-probe-note">POC 检测将根据站点识别到的指纹自动挑选 nuclei tags，对每个观测源运行一次。</p>
        </div>
      </div>
    </section>
  );
}

function SensitiveInfoPanel({
  feature,
  subFeatures,
  busyAction,
  onChange,
}: {
  feature: Feature | undefined;
  subFeatures: Feature[];
  busyAction: string;
  onChange: (feature: Feature, enabled: boolean) => void;
}) {
  const status = !feature ? "配置不可用" : feature.enabled ? "已启用" : "已停用";
  const activeCount = subFeatures.filter((item) => item.enabled).length;
  return (
    <section className="work-surface sensitive-info-panel">
      <div className="surface-heading">
        <div><span className="eyebrow">敏感信息检测</span><h2>检测器明细</h2></div>
        <Shield24Regular className="sqli-shield" />
      </div>
      <div className="passive-sqli-probe-body">
        <div className="passive-sqli-probe-status">
          <strong>主开关：{status}</strong>
          <span>{feature ? "主开关关闭时所有敏感信息检测器均不会触发；主开关开启时可单独调整以下每类检测器。" : "当前桌面端未提供该开关。"}</span>
        </div>
        <div className="sub-feature-list">
          {subFeatures.map((item) => (
            <div className={`feature-row ${busyAction === `feature-${item.id}` ? "is-busy" : ""}`} key={item.id}>
              <div className="feature-row-copy">
                <strong>{featureTitle(item)}</strong>
                <span className="feature-row-description">{featureDescription(item)}</span>
              </div>
              <Switch
                checked={item.enabled}
                disabled={!feature?.enabled || busyAction === `feature-${item.id}`}
                onChange={(_, data) => onChange(item, Boolean(data.checked))}
              />
            </div>
          ))}
        </div>
        <p className="passive-sqli-probe-note">共 {subFeatures.length} 类检测器，当前已启用 {activeCount} 类。所有检测仅在 MITM 已捕获的响应正文上运行，不会发送额外请求。</p>
      </div>
    </section>
  );
}

function FileProbePanel({
  feature,
  subFeatures,
  qps,
  busyAction,
  swaggerExcludedPaths,
  customProbePaths,
  onQPSChange,
  onQPSFocus,
  onQPSBlur,
  onSave,
  onChange,
  onSwaggerPathsChange,
  onSwaggerPathsFocus,
  onSwaggerPathsBlur,
  onSwaggerPathsSave,
  onCustomPathsChange,
  onCustomPathsFocus,
  onCustomPathsBlur,
  onCustomPathsSave,
}: {
  feature: Feature | undefined;
  subFeatures: Feature[];
  qps: string;
  busyAction: string;
  swaggerExcludedPaths: string;
  customProbePaths: string;
  onQPSChange: (value: string) => void;
  onQPSFocus: () => void;
  onQPSBlur: () => void;
  onSave: () => void;
  onChange: (feature: Feature, enabled: boolean) => void;
  onSwaggerPathsChange: (value: string) => void;
  onSwaggerPathsFocus: () => void;
  onSwaggerPathsBlur: () => void;
  onSwaggerPathsSave: () => void;
  onCustomPathsChange: (value: string) => void;
  onCustomPathsFocus: () => void;
  onCustomPathsBlur: () => void;
  onCustomPathsSave: () => void;
}) {
  const isBusy = busyAction === "passive-file-probe-settings";
  const swaggerBusy = busyAction === "swagger-excluded-paths";
  const customBusy = busyAction === "custom-probe-paths";
  const status = !feature ? "配置不可用" : feature.enabled ? "已启用" : "已停用";
  const activeCount = subFeatures.filter((item) => item.enabled).length;
  return (
    <section className={`work-surface passive-sqli-probe-panel passive-poc-probe-panel file-probe-panel ${isBusy ? "is-busy" : ""}`}>
      <div className="surface-heading">
        <div><span className="eyebrow">敏感文件探测</span><h2>探测类别与速率</h2></div>
        <Shield24Regular className="sqli-shield" />
      </div>
      <div className="passive-sqli-probe-body">
        <div className="passive-sqli-probe-status">
          <strong>主开关：{status}</strong>
          <span>{feature ? "主开关关闭时不会发起任何文件探测；主开关开启时可单独调整每类文件，并配置全局探测速率。" : "当前桌面端未提供该开关。"}</span>
        </div>
        <div className="sub-feature-list">
          {subFeatures.map((item) => (
            <div className={`feature-row ${busyAction === `feature-${item.id}` ? "is-busy" : ""}`} key={item.id}>
              <div className="feature-row-copy">
                <strong>{featureTitle(item)}</strong>
                <span className="feature-row-description">{featureDescription(item)}</span>
              </div>
              <Switch
                checked={item.enabled}
                disabled={!feature?.enabled || busyAction === `feature-${item.id}`}
                onChange={(_, data) => onChange(item, Boolean(data.checked))}
              />
            </div>
          ))}
        </div>
        <div className="passive-sqli-probe-fields passive-poc-probe-fields">
          <Field label="探测速率（请求/秒）" hint={`范围 ${passiveFileProbeQPSRange.min}–${passiveFileProbeQPSRange.max}`}>
            <Input inputMode="numeric" max={passiveFileProbeQPSRange.max} min={passiveFileProbeQPSRange.min} onBlur={onQPSBlur} onChange={(_, data) => onQPSChange(data.value)} onFocus={onQPSFocus} step={1} type="number" value={qps} />
          </Field>
        </div>
        <div className="passive-sqli-probe-fields passive-poc-probe-fields">
          <Field label="文件探测排除路径" hint="按目录前缀排除，每行一条。例如 /js 将跳过 /js/.git/HEAD、/js/v1/swagger.json 等所有文件探测，站点根目录始终探测。">
            <Textarea value={swaggerExcludedPaths} placeholder="/js&#10;/assets&#10;/static/**" rows={4} resize="vertical" disabled={swaggerBusy} onChange={(_, data) => onSwaggerPathsChange(data.value)} onFocus={onSwaggerPathsFocus} onBlur={onSwaggerPathsBlur} />
          </Field>
          <Button appearance="outline" disabled={swaggerBusy} onClick={onSwaggerPathsSave}>{swaggerBusy ? "正在保存…" : "保存排除路径"}</Button>
        </div>
        <div className="passive-sqli-probe-fields passive-poc-probe-fields">
          <Field label="自定义探测文件" hint="每行一条站点根目录下的路径，例如 /WEB-INF/web.xml、/config/database.yml。命中 200 且内容非空时上报，HTML 响应标记为待人工确认。需开启“自定义路径”类别。">
            <Textarea value={customProbePaths} placeholder="/WEB-INF/web.xml&#10;/config/database.yml&#10;/.htaccess" rows={4} resize="vertical" disabled={customBusy} onChange={(_, data) => onCustomPathsChange(data.value)} onFocus={onCustomPathsFocus} onBlur={onCustomPathsBlur} />
          </Field>
          <Button appearance="outline" disabled={customBusy} onClick={onCustomPathsSave}>{customBusy ? "正在保存…" : "保存自定义路径"}</Button>
        </div>
        <p className="passive-sqli-probe-note">共 {subFeatures.length} 类文件，当前已启用 {activeCount} 类。仅对 MITM 新发现的站点发起只读 GET 请求，不会修改目标状态。API 文档与 Spring Boot Actuator 探测仅在响应包含对应结构标记时上报。</p>
        <Button appearance="primary" disabled={!feature || isBusy} onClick={onSave}>{isBusy ? "正在保存" : "保存探测速率"}</Button>
      </div>
    </section>
  );
}

function FastjsonProbePanel({
  feature,
  qps,
  busyAction,
  onQPSChange,
  onQPSFocus,
  onQPSBlur,
  onSave,
}: {
  feature: Feature | undefined;
  qps: string;
  busyAction: string;
  onQPSChange: (value: string) => void;
  onQPSFocus: () => void;
  onQPSBlur: () => void;
  onSave: () => void;
}) {
  const isBusy = busyAction === "passive-fastjson-probe-settings";
  const status = !feature ? "配置不可用" : feature.enabled ? "已启用" : "已停用";
  return (
    <section className={`work-surface passive-sqli-probe-panel passive-poc-probe-panel ${isBusy ? "is-busy" : ""}`}>
      <div className="surface-heading">
        <div><span className="eyebrow">Fastjson 探测</span><h2>MITM Fastjson 识别</h2></div>
        <Shield24Regular className="sqli-shield" />
      </div>
      <div className="passive-sqli-probe-body">
        <div className="passive-sqli-probe-status">
          <strong>主开关：{status}</strong>
          <span>{feature ? "对观察到的 JSON 请求重发一个缺少大括号的副本，依据报错响应识别 Fastjson。仅做技术识别，不发送反序列化载荷。" : "当前桌面端未提供该开关。"}</span>
        </div>
        <div className="passive-sqli-probe-fields passive-poc-probe-fields">
          <Field label="探测速率（请求/秒）" hint={`范围 ${passiveFastjsonProbeQPSRange.min}–${passiveFastjsonProbeQPSRange.max}`}>
            <Input inputMode="numeric" max={passiveFastjsonProbeQPSRange.max} min={passiveFastjsonProbeQPSRange.min} onBlur={onQPSBlur} onChange={(_, data) => onQPSChange(data.value)} onFocus={onQPSFocus} step={1} type="number" value={qps} />
          </Field>
        </div>
        <p className="passive-sqli-probe-note">命中 com.alibaba.fastjson 等解析器特征时上报“检测到 Fastjson”。仅在原始响应不含相同特征时判定，避免误报。</p>
        <Button appearance="primary" disabled={!feature || isBusy} onClick={onSave}>{isBusy ? "正在保存" : "保存探测速率"}</Button>
      </div>
    </section>
  );
}

function ShiroProbePanel({
  feature,
  qps,
  busyAction,
  shiroKeys,
  onQPSChange,
  onQPSFocus,
  onQPSBlur,
  onSave,
  onKeysChange,
  onKeysFocus,
  onKeysBlur,
  onKeysSave,
}: {
  feature: Feature | undefined;
  qps: string;
  busyAction: string;
  shiroKeys: string;
  onQPSChange: (value: string) => void;
  onQPSFocus: () => void;
  onQPSBlur: () => void;
  onSave: () => void;
  onKeysChange: (value: string) => void;
  onKeysFocus: () => void;
  onKeysBlur: () => void;
  onKeysSave: () => void;
}) {
  const isBusy = busyAction === "passive-shiro-probe-settings";
  const keysBusy = busyAction === "shiro-keys";
  const status = !feature ? "配置不可用" : feature.enabled ? "已启用" : "已停用";
  return (
    <section className={`work-surface passive-sqli-probe-panel passive-poc-probe-panel ${isBusy ? "is-busy" : ""}`}>
      <div className="surface-heading">
        <div><span className="eyebrow">Shiro 探测</span><h2>MITM Shiro 识别与密钥校验</h2></div>
        <Shield24Regular className="sqli-shield" />
      </div>
      <div className="passive-sqli-probe-body">
        <div className="passive-sqli-probe-status">
          <strong>主开关：{status}</strong>
          <span>{feature ? "识别 rememberMe 指纹，并对捕获的 rememberMe Cookie 用常见密钥做离线解密校验。不发送反序列化载荷。" : "当前桌面端未提供该开关。"}</span>
        </div>
        <div className="passive-sqli-probe-fields passive-poc-probe-fields">
          <Field label="探测速率（请求/秒）" hint={`范围 ${passiveShiroProbeQPSRange.min}–${passiveShiroProbeQPSRange.max}`}>
            <Input inputMode="numeric" max={passiveShiroProbeQPSRange.max} min={passiveShiroProbeQPSRange.min} onBlur={onQPSBlur} onChange={(_, data) => onQPSChange(data.value)} onFocus={onQPSFocus} step={1} type="number" value={qps} />
          </Field>
        </div>
        <div className="passive-sqli-probe-fields passive-poc-probe-fields">
          <Field label="自定义 Shiro 密钥字典" hint="每行一条 Base64 密钥，将与内置常见密钥合并使用。仅在捕获到真实 rememberMe Cookie 时进行离线解密校验。">
            <Textarea value={shiroKeys} placeholder="kPH+bIxk5D2deZiIxcaaaA==&#10;2AvVhdsgAws0FSA3SDFAdhg==" rows={5} resize="vertical" disabled={keysBusy} onChange={(_, data) => onKeysChange(data.value)} onFocus={onKeysFocus} onBlur={onKeysBlur} />
          </Field>
          <Button appearance="outline" disabled={keysBusy} onClick={onKeysSave}>{keysBusy ? "正在保存…" : "保存密钥字典"}</Button>
        </div>
        <p className="passive-sqli-probe-note">检测到 rememberMe=deleteMe 或请求携带 rememberMe Cookie 时识别 Shiro；若能用常见密钥解密捕获的 Cookie，则上报高危“密钥可被识别”。</p>
        <Button appearance="primary" disabled={!feature || isBusy} onClick={onSave}>{isBusy ? "正在保存" : "保存探测速率"}</Button>
      </div>
    </section>
  );
}

function parseExcludedSuffixes(value: string): string[] {
  const seen = new Set<string>();
  return value
    .split(/[\s,，；]+/u)
    .map((suffix) => suffix.trim().replace(/^\.+/u, "").toLowerCase())
    .filter((suffix) => {
      if (!suffix || seen.has(suffix)) {
        return false;
      }
      seen.add(suffix);
      return true;
    });
}

function parseExcludedContentTypes(value: string): string[] {
  const seen = new Set<string>();
  return value
    .split(/[\s,，；]+/u)
    .map((contentType) => contentType.trim().toLowerCase())
    .filter((contentType) => {
      if (!contentType || seen.has(contentType)) {
        return false;
      }
      seen.add(contentType);
      return true;
    });
}

function parseExcludedPaths(value: string): string[] {
  const seen = new Set<string>();
  return value
    .split(/[\r\n,，、;；]+/u)
    .map((pathPattern) => pathPattern.trim().replace(/\\/gu, "/").toLowerCase())
    .filter((pathPattern) => {
      if (!pathPattern || seen.has(pathPattern)) {
        return false;
      }
      seen.add(pathPattern);
      return true;
    });
}

function parseCustomProbePaths(value: string): string[] {
  const seen = new Set<string>();
  return value
    .split(/[\r\n,，、;；]+/u)
    .map((rawPath) => rawPath.trim().replace(/\\/gu, "/"))
    .filter((rawPath) => {
      if (!rawPath || seen.has(rawPath)) {
        return false;
      }
      seen.add(rawPath);
      return true;
    });
}

function parseExcludedParameterNames(value: string): string[] {
  const seen = new Set<string>();
  return value
    .split(/[\s,，、;；]+/u)
    .map((parameter) => parameter.trim().toLowerCase())
    .filter((parameter) => {
      if (!parameter || seen.has(parameter)) {
        return false;
      }
      seen.add(parameter);
      return true;
    });
}

function TrafficFilterPanel({
  domains,
  suffixes,
  contentTypes,
  paths,
  queryParameters,
  postParameters,
  busyAction,
  onDomainsChange, onDomainsSave, onDomainsFocus, onDomainsBlur,
  onSuffixesChange, onSuffixesSave, onSuffixesFocus, onSuffixesBlur,
  onContentTypesChange, onContentTypesSave, onContentTypesFocus, onContentTypesBlur,
  onPathsChange, onPathsSave, onPathsFocus, onPathsBlur,
  onQueryParametersChange, onQueryParametersSave, onQueryParametersFocus, onQueryParametersBlur,
  onPostParametersChange, onPostParametersSave, onPostParametersFocus, onPostParametersBlur,
}: {
  domains: string; suffixes: string; contentTypes: string; paths: string; queryParameters: string; postParameters: string; busyAction: string;
  onDomainsChange: (value: string) => void; onDomainsSave: () => void; onDomainsFocus: () => void; onDomainsBlur: () => void;
  onSuffixesChange: (value: string) => void; onSuffixesSave: () => void; onSuffixesFocus: () => void; onSuffixesBlur: () => void;
  onContentTypesChange: (value: string) => void; onContentTypesSave: () => void; onContentTypesFocus: () => void; onContentTypesBlur: () => void;
  onPathsChange: (value: string) => void; onPathsSave: () => void; onPathsFocus: () => void; onPathsBlur: () => void;
  onQueryParametersChange: (value: string) => void; onQueryParametersSave: () => void; onQueryParametersFocus: () => void; onQueryParametersBlur: () => void;
  onPostParametersChange: (value: string) => void; onPostParametersSave: () => void; onPostParametersFocus: () => void; onPostParametersBlur: () => void;
}) {
  const cards = [
    {key: "excluded-domains", title: "域名", description: "匹配主机名时仅转发，不记录和分析。", value: domains, placeholder: "*.example.com", change: onDomainsChange, save: onDomainsSave, focus: onDomainsFocus, blur: onDomainsBlur},
    {key: "excluded-suffixes", title: "文件后缀", description: "过滤图片、字体等低价值静态资源。", value: suffixes, placeholder: ".png\n.woff2", change: onSuffixesChange, save: onSuffixesSave, focus: onSuffixesFocus, blur: onSuffixesBlur},
    {key: "excluded-content-types", title: "Content-Type", description: "按响应媒体类型跳过整条流量。", value: contentTypes, placeholder: "image/*\napplication/pdf", change: onContentTypesChange, save: onContentTypesSave, focus: onContentTypesFocus, blur: onContentTypesBlur},
    {key: "excluded-paths", title: "URL 路径", description: "支持路径通配符，适合健康检查和静态目录。", value: paths, placeholder: "/assets/**\n*/health", change: onPathsChange, save: onPathsSave, focus: onPathsFocus, blur: onPathsBlur},
    {key: "excluded-query-parameters", title: "Query 参数", description: "请求含有指定 Query 参数名时跳过分析。", value: queryParameters, placeholder: "callback\ntracking_id", change: onQueryParametersChange, save: onQueryParametersSave, focus: onQueryParametersFocus, blur: onQueryParametersBlur},
    {key: "excluded-post-parameters", title: "POST / JSON 参数", description: "按表单字段或 JSON 属性名跳过整条请求。", value: postParameters, placeholder: "file\ntelemetry", change: onPostParametersChange, save: onPostParametersSave, focus: onPostParametersFocus, blur: onPostParametersBlur},
  ];
  return (
    <section className="work-surface traffic-filter-panel">
      <div className="surface-heading"><div><span className="eyebrow">MITM 流量</span><h2>过滤规则</h2></div><Globe24Regular className="traffic-filter-icon" /></div>
      <p className="traffic-filter-intro">任一规则命中后，代理仍正常转发，但不写入日志、指纹或漏洞分析。</p>
      <div className="traffic-filter-grid">
        {cards.map((card) => {
          const busy = busyAction === card.key;
          return (
            <article className={`traffic-filter-card ${busy ? "is-busy" : ""}`} key={card.key}>
              <div className="traffic-filter-card-heading"><DocumentBulletList24Regular /><div><h3>{card.title}</h3><p>{card.description}</p></div></div>
              <Field>
                <Textarea value={card.value} placeholder={card.placeholder} rows={5} resize="vertical" disabled={busy} onChange={(_, data) => card.change(data.value)} onFocus={card.focus} onBlur={card.blur} />
              </Field>
              <Button appearance="outline" disabled={busy} onClick={card.save}>{busy ? "正在保存…" : "保存"}</Button>
            </article>
          );
        })}
      </div>
    </section>
  );
}

function App() {
  const [snapshot, setSnapshot] = useState<Snapshot>(emptySnapshot);
  const [view, setView] = useState<View>("traffic");
  const [theme, setTheme] = useState<ThemeId>(() => {
    const stored = typeof window !== "undefined" ? window.localStorage.getItem("easyscan-theme") : "";
    return (stored as ThemeId) || "midnight";
  });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [busyAction, setBusyAction] = useState("");
  const [findingFilter, setFindingFilter] = useState<FindingViewFilter>("web");
  const [query, setQuery] = useState("");
  const [selectedFindingId, setSelectedFindingId] = useState("");
  const [findingEvidenceById, setFindingEvidenceById] = useState<Record<string, FindingEvidence[]>>({});
  const [findingEvidenceLoadingId, setFindingEvidenceLoadingId] = useState("");
  const [selectedTaskId, setSelectedTaskId] = useState("");
  const logViewportRef = useRef<HTMLDivElement>(null);
  const logScrollTopRef = useRef(0);
  const followsLogTailRef = useRef(true);
  const lastPassiveLogSignatureRef = useRef<string | null>(null);
  const previousViewRef = useRef<View>(view);
  const [isFollowingLogTail, setIsFollowingLogTail] = useState(true);
  const findingEvidenceCacheRef = useRef(new Set<string>());
  const [taskResults, setTaskResults] = useState<TaskResult[]>([]);
  const [resultsLoading, setResultsLoading] = useState(false);
  const [taskKind, setTaskKind] = useState("web_crawl");
  const [taskTarget, setTaskTarget] = useState("");
  const [sessionHeaders, setSessionHeaders] = useState("");
  const [sqliErrorEnabled, setSQLiErrorEnabled] = useState(true);
  const [sqliBooleanEnabled, setSQLiBooleanEnabled] = useState(true);
  const [sqliTimeEnabled, setSQLiTimeEnabled] = useState(false);
  const [passiveSQLiProbeQPS, setPassiveSQLiProbeQPS] = useState("1");
  const [passiveSQLiMaxRequests, setPassiveSQLiMaxRequests] = useState("36");
  const [passiveSQLiMaxParameters, setPassiveSQLiMaxParameters] = useState("3");
  const [passiveXSSProbeQPS, setPassiveXSSProbeQPS] = useState("1");
  const [passiveXSSMaxRequests, setPassiveXSSMaxRequests] = useState("24");
  const [passiveXSSMaxParameters, setPassiveXSSMaxParameters] = useState("3");
  const [passivePOCQPS, setPassivePOCQPS] = useState("2");
  const [passivePOCConcurrency, setPassivePOCConcurrency] = useState("1");
  const [nucleiStatus, setNucleiStatus] = useState<NucleiStatus | null>(null);
  const [nucleiPath, setNucleiPath] = useState("");
  const [passiveFileProbeQPS, setPassiveFileProbeQPS] = useState("2");
  const [passiveFastjsonProbeQPS, setPassiveFastjsonProbeQPS] = useState("1");
  const [passiveShiroProbeQPS, setPassiveShiroProbeQPS] = useState("1");
  const [shiroKeysText, setShiroKeysText] = useState("");
  const [oobDomainText, setOOBDomainText] = useState("");
  const [aiBaseUrl, setAIBaseUrl] = useState("");
  const [aiModel, setAIModel] = useState("");
  const [aiApiKey, setAIApiKey] = useState("");
  const [aiConfigured, setAIConfigured] = useState(false);
  const [excludedDomainsText, setExcludedDomainsText] = useState("");
  const [excludedSuffixesText, setExcludedSuffixesText] = useState("");
  const [excludedContentTypesText, setExcludedContentTypesText] = useState("");
  const [excludedPathsText, setExcludedPathsText] = useState("");
  const [excludedQueryParametersText, setExcludedQueryParametersText] = useState("");
  const [excludedPostParametersText, setExcludedPostParametersText] = useState("");
  const [swaggerExcludedPathsText, setSwaggerExcludedPathsText] = useState("");
  const [customProbePathsText, setCustomProbePathsText] = useState("");
  const [advancedSettingsOpen, setAdvancedSettingsOpen] = useState(false);
  const [advancedSettingsSection, setAdvancedSettingsSection] = useState<AdvancedSettingsSection>("mitm-sqli");
  const [trafficFilterOpen, setTrafficFilterOpen] = useState(false);
  const toasterId = useId("easyscan-notices");
  const {dispatchToast} = useToastController(toasterId);
  const passiveSQLiProbeQPSFocusedRef = useRef(false);
  const passiveSQLiMaxRequestsFocusedRef = useRef(false);
  const passiveSQLiMaxParametersFocusedRef = useRef(false);
  const passiveXSSProbeQPSFocusedRef = useRef(false);
  const passiveXSSMaxRequestsFocusedRef = useRef(false);
  const passiveXSSMaxParametersFocusedRef = useRef(false);
  const passivePOCQPSFocusedRef = useRef(false);
  const passivePOCConcurrencyFocusedRef = useRef(false);
  const passiveFileProbeQPSFocusedRef = useRef(false);
  const passiveFastjsonProbeQPSFocusedRef = useRef(false);
  const passiveShiroProbeQPSFocusedRef = useRef(false);
  const shiroKeysFocusedRef = useRef(false);
  const oobDomainFocusedRef = useRef(false);
  const excludedDomainsFocusedRef = useRef(false);
  const excludedSuffixesFocusedRef = useRef(false);
  const excludedContentTypesFocusedRef = useRef(false);
  const excludedPathsFocusedRef = useRef(false);
  const excludedQueryParametersFocusedRef = useRef(false);
  const excludedPostParametersFocusedRef = useRef(false);
  const swaggerExcludedPathsFocusedRef = useRef(false);
  const customProbePathsFocusedRef = useRef(false);
  const [runtimeLogs, setRuntimeLogs] = useState<RuntimeLog[]>([]);
  const [runtimeLogsLoading, setRuntimeLogsLoading] = useState(false);
  const [runtimeLogsFilter, setRuntimeLogsFilter] = useState("");
  const [runtimeLogsLevelFilter, setRuntimeLogsLevelFilter] = useState<string>("all");
  const [runtimeLogsComponentFilter, setRuntimeLogsComponentFilter] = useState<string>("all");
  const runtimeLogsViewportRef = useRef<HTMLDivElement>(null);
  const runtimeLogsFollowTailRef = useRef(true);

  const refreshSnapshot = useCallback(async (silent = false) => {
    if (!silent) {
      setLoading(true);
    }
    try {
      const rawSnapshot = await desktopApi.getSnapshot();
      const nextSnapshot = normalizeSnapshot(rawSnapshot);
      setSnapshot(nextSnapshot);
      if (nextSnapshot.passiveSQLiErrorEnabled !== null) setSQLiErrorEnabled(nextSnapshot.passiveSQLiErrorEnabled);
      if (nextSnapshot.passiveSQLiBooleanEnabled !== null) setSQLiBooleanEnabled(nextSnapshot.passiveSQLiBooleanEnabled);
      if (nextSnapshot.passiveSQLiTimeEnabled !== null) setSQLiTimeEnabled(nextSnapshot.passiveSQLiTimeEnabled);
      if (nextSnapshot.passiveSQLiProbeQPS !== null && !passiveSQLiProbeQPSFocusedRef.current) {
        setPassiveSQLiProbeQPS(String(nextSnapshot.passiveSQLiProbeQPS));
      }
      if (nextSnapshot.passiveSQLiMaxRequests !== null && !passiveSQLiMaxRequestsFocusedRef.current) {
        setPassiveSQLiMaxRequests(String(nextSnapshot.passiveSQLiMaxRequests));
      }
      if (nextSnapshot.passiveSQLiMaxParameters !== null && !passiveSQLiMaxParametersFocusedRef.current) {
        setPassiveSQLiMaxParameters(String(nextSnapshot.passiveSQLiMaxParameters));
      }
      if (nextSnapshot.passiveXSSProbeQPS !== null && !passiveXSSProbeQPSFocusedRef.current) {
        setPassiveXSSProbeQPS(String(nextSnapshot.passiveXSSProbeQPS));
      }
      if (nextSnapshot.passiveXSSMaxRequests !== null && !passiveXSSMaxRequestsFocusedRef.current) {
        setPassiveXSSMaxRequests(String(nextSnapshot.passiveXSSMaxRequests));
      }
      if (nextSnapshot.passiveXSSMaxParameters !== null && !passiveXSSMaxParametersFocusedRef.current) {
        setPassiveXSSMaxParameters(String(nextSnapshot.passiveXSSMaxParameters));
      }
      if (nextSnapshot.passivePOCQPS !== null && !passivePOCQPSFocusedRef.current) {
        setPassivePOCQPS(String(nextSnapshot.passivePOCQPS));
      }
      if (nextSnapshot.passivePOCConcurrency !== null && !passivePOCConcurrencyFocusedRef.current) {
        setPassivePOCConcurrency(String(nextSnapshot.passivePOCConcurrency));
      }
      if (nextSnapshot.passiveFileProbeQPS !== null && !passiveFileProbeQPSFocusedRef.current) {
        setPassiveFileProbeQPS(String(nextSnapshot.passiveFileProbeQPS));
      }
      if (nextSnapshot.passiveFastjsonProbeQPS !== null && !passiveFastjsonProbeQPSFocusedRef.current) {
        setPassiveFastjsonProbeQPS(String(nextSnapshot.passiveFastjsonProbeQPS));
      }
      if (nextSnapshot.passiveShiroProbeQPS !== null && !passiveShiroProbeQPSFocusedRef.current) {
        setPassiveShiroProbeQPS(String(nextSnapshot.passiveShiroProbeQPS));
      }
      if (!shiroKeysFocusedRef.current) {
        setShiroKeysText(nextSnapshot.shiroKeys.join("\n"));
      }
      if (!oobDomainFocusedRef.current) {
        setOOBDomainText(nextSnapshot.oobDomain);
      }
      if (!excludedDomainsFocusedRef.current) {
        setExcludedDomainsText(nextSnapshot.excludedDomains.join("\n"));
      }
      if (!excludedSuffixesFocusedRef.current) {
        setExcludedSuffixesText(nextSnapshot.excludedSuffixes.join("\n"));
      }
      if (!excludedContentTypesFocusedRef.current) {
        setExcludedContentTypesText(nextSnapshot.excludedContentTypes.join("\n"));
      }
      if (!excludedPathsFocusedRef.current) {
        setExcludedPathsText(nextSnapshot.excludedPaths.join("\n"));
      }
      if (!excludedQueryParametersFocusedRef.current) {
        setExcludedQueryParametersText(nextSnapshot.excludedQueryParameters.join("\n"));
      }
      if (!excludedPostParametersFocusedRef.current) {
        setExcludedPostParametersText(nextSnapshot.excludedPostParameters.join("\n"));
      }
      if (!swaggerExcludedPathsFocusedRef.current) {
        setSwaggerExcludedPathsText(nextSnapshot.swaggerExcludedPaths.join("\n"));
      }
      if (!customProbePathsFocusedRef.current) {
        setCustomProbePathsText(nextSnapshot.fileProbeCustomPaths.join("\n"));
      }
      setError("");
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "无法读取桌面端状态");
    } finally {
      if (!silent) {
        setLoading(false);
      }
    }
  }, []);

  useEffect(() => {
    void refreshSnapshot();
    const timer = window.setInterval(() => void refreshSnapshot(true), view === "traffic" ? 1500 : 3500);
    return () => window.clearInterval(timer);
  }, [refreshSnapshot, view]);

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
    window.localStorage.setItem("easyscan-theme", theme);
  }, [theme]);

  const setLogTailFollowing = useCallback((isFollowing: boolean) => {
    followsLogTailRef.current = isFollowing;
    setIsFollowingLogTail((current) => current === isFollowing ? current : isFollowing);
  }, []);

  const scrollRuntimeLogsToTail = useCallback(() => {
    const viewport = logViewportRef.current;
    if (!viewport) {
      return;
    }
    viewport.scrollTop = viewport.scrollHeight;
    logScrollTopRef.current = viewport.scrollTop;
  }, []);

  const handleRuntimeLogScroll = useCallback(() => {
    const viewport = logViewportRef.current;
    if (!viewport) {
      return;
    }
    logScrollTopRef.current = viewport.scrollTop;
    const distanceToTail = Math.max(0, viewport.scrollHeight - viewport.clientHeight - viewport.scrollTop);
    setLogTailFollowing(distanceToTail <= logTailTolerance);
  }, [setLogTailFollowing]);

  const resumeRuntimeLogTail = useCallback(() => {
    setLogTailFollowing(true);
    scrollRuntimeLogsToTail();
  }, [scrollRuntimeLogsToTail, setLogTailFollowing]);

  useLayoutEffect(() => {
    const previousView = previousViewRef.current;
    previousViewRef.current = view;
    if (view !== "traffic") {
      return;
    }
    const viewport = logViewportRef.current;
    if (!viewport) {
      return;
    }

    const passiveLogSignature = passiveRuntimeLogSignature(snapshot.logs);
    const hasNewPassiveLogContent = lastPassiveLogSignatureRef.current !== passiveLogSignature;
    lastPassiveLogSignatureRef.current = passiveLogSignature;
    const enteredTrafficView = previousView !== "traffic";

    if (followsLogTailRef.current) {
      if (enteredTrafficView || hasNewPassiveLogContent) {
        scrollRuntimeLogsToTail();
      }
    } else if (enteredTrafficView) {
      const maxScrollTop = Math.max(0, viewport.scrollHeight - viewport.clientHeight);
      viewport.scrollTop = Math.min(logScrollTopRef.current, maxScrollTop);
      logScrollTopRef.current = viewport.scrollTop;
    }
  }, [scrollRuntimeLogsToTail, snapshot.logs, view]);

  useEffect(() => {
    if (view !== "traffic" || typeof ResizeObserver === "undefined") {
      return;
    }
    const viewport = logViewportRef.current;
    if (!viewport) {
      return;
    }
    const observer = new ResizeObserver(() => {
      if (followsLogTailRef.current) {
        scrollRuntimeLogsToTail();
      }
    });
    observer.observe(viewport);
    return () => observer.disconnect();
  }, [scrollRuntimeLogsToTail, view]);

  useEffect(() => {
    if (!selectedTaskId && snapshot.tasks.length > 0) {
      setSelectedTaskId(snapshot.tasks[0].id);
    }
  }, [selectedTaskId, snapshot.tasks]);

  const loadTaskResults = useCallback(async (id: string) => {
    if (!id) {
      setTaskResults([]);
      return;
    }
    setResultsLoading(true);
    try {
      const rawResults = await desktopApi.getTaskResults(id);
      setTaskResults(normalizeTaskResults(rawResults));
    } catch (reason) {
      setTaskResults([]);
      setError(reason instanceof Error ? reason.message : "无法读取任务结果");
    } finally {
      setResultsLoading(false);
    }
  }, []);

  const refreshRuntimeLogs = useCallback(async () => {
    setRuntimeLogsLoading(true);
    try {
      const raw = await desktopApi.getRuntimeLogs(0);
      const logs = normalizeRuntimeLogs(raw);
      setRuntimeLogs(logs);
      if (runtimeLogsFollowTailRef.current && runtimeLogsViewportRef.current) {
        runtimeLogsViewportRef.current.scrollTop = runtimeLogsViewportRef.current.scrollHeight;
      }
    } catch (reason) {
      setRuntimeLogs([]);
      setError(reason instanceof Error ? reason.message : "无法读取运行日志");
    } finally {
      setRuntimeLogsLoading(false);
    }
  }, []);

  useEffect(() => {
    if (view === "runtime-logs") {
      void refreshRuntimeLogs();
    }
  }, [view, refreshRuntimeLogs]);

  const loadFindingEvidence = useCallback(async (finding: Finding) => {
    const identity = findingIdentity(finding);
    if (findingEvidenceCacheRef.current.has(identity)) {
      return;
    }

    findingEvidenceCacheRef.current.add(identity);
    if (!finding.id) {
      setFindingEvidenceById((current) => ({...current, [identity]: []}));
      return;
    }

    setFindingEvidenceLoadingId(identity);
    try {
      const rawEvidence = await desktopApi.getFindingEvidence(finding.id);
      const normalizedEvidence = normalizeFindingEvidenceList(rawEvidence, finding.id);
      if (normalizedEvidence.length === 0) {
        findingEvidenceCacheRef.current.delete(identity);
      }
      setFindingEvidenceById((current) => ({
        ...current,
        [identity]: normalizedEvidence,
      }));
    } catch (reason) {
      findingEvidenceCacheRef.current.delete(identity);
      setError(reason instanceof Error ? reason.message : "无法读取该发现的原始报文");
    } finally {
      setFindingEvidenceLoadingId((current) => current === identity ? "" : current);
    }
  }, []);

  useEffect(() => {
    void loadTaskResults(selectedTaskId);
  }, [loadTaskResults, selectedTaskId]);

  useEffect(() => {
    if (view !== "runtime-logs") {
      return;
    }
    void refreshRuntimeLogs();
  }, [refreshRuntimeLogs, view]);

  const runAction = useCallback(async (key: string, action: () => Promise<unknown>, refresh = true) => {
    setBusyAction(key);
    setError("");
    try {
      await action();
      if (refresh) {
        await refreshSnapshot(true);
      }
      dispatchToast(
        <Toast>
          <ToastTitle>操作已完成</ToastTitle>
          <ToastBody>{actionSuccessMessage(key)}</ToastBody>
        </Toast>,
        {intent: "success", timeout: 3600},
      );
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : typeof reason === "string" ? reason : "操作未完成");
    } finally {
      setBusyAction("");
    }
  }, [dispatchToast, refreshSnapshot]);

  const visibleFindings = useMemo(() => {
    const normalizedQuery = query.trim().toLowerCase();
    return snapshot.findings.filter((finding) => {
      const displayFinding = localizedFinding(finding);
      const haystack = [displayFinding.title, finding.url, finding.ruleId, displayFinding.description, ...finding.tags].join(" ").toLowerCase();
      return !normalizedQuery || haystack.includes(normalizedQuery);
    });
  }, [query, snapshot.findings]);

  const categorizedFindings = useMemo(() => ({
    web: visibleFindings.filter((finding) => findingCategory(finding) === "web"),
    information: visibleFindings.filter((finding) => findingCategory(finding) === "information"),
  }), [visibleFindings]);

  const visibleFingerprintAssets = useMemo(() => {
    const normalizedQuery = query.trim().toLowerCase();
    return snapshot.assets.filter((asset) => {
      if (asset.fingerprints.length === 0) {
        return false;
      }
      if (!normalizedQuery) {
        return true;
      }
      const haystack = [asset.host, ...asset.urls, ...asset.fingerprints, ...asset.endpoints.flatMap((endpoint) => [endpoint.path, ...endpoint.sources])].join(" ").toLowerCase();
      return haystack.includes(normalizedQuery);
    });
  }, [query, snapshot.assets]);

  const featureGroups = useMemo<FeatureGroup[]>(() => {
    const definitions: Array<Omit<FeatureGroup, "features">> = [
      {id: "mitm", title: "被动检测", description: "管理 MITM 流量中的指纹识别、CDN、WAF、SQL 注入、POC、敏感信息与敏感文件检测。"},
      {id: "active-network", title: "服务扫描", description: "端口、目录与 HTTP Basic 认证检测。"},
      {id: "active-web", title: "Web 扫描", description: "网站爬取检测。"},
      {id: "data", title: "数据与会话", description: "开启或关闭“启动时清除上次漏洞和指纹”后，将在下次启动时生效。"},
      {id: "locked", title: "高级选项", description: "当前不可用的高级能力集中显示。"},
    ];
    return definitions.map((definition) => ({
      ...definition,
      features: snapshot.features.filter((feature) => featureGroupFor(feature) === definition.id),
    })).filter((group) => group.features.length > 0);
  }, [snapshot.features]);

  const passiveSQLiProbeFeature = useMemo(
    () => snapshot.features.find((feature) => feature.id === "passive.sqli_probe"),
    [snapshot.features],
  );
  const passiveXSSProbeFeature = useMemo(
    () => snapshot.features.find((feature) => feature.id === "passive.xss_probe"),
    [snapshot.features],
  );
  const passivePOCProbeFeature = useMemo(
    () => snapshot.features.find((feature) => feature.id === "passive.poc_scan"),
    [snapshot.features],
  );
  const sensitiveInfoFeature = useMemo(
    () => snapshot.features.find((feature) => feature.id === "passive.sensitive_info"),
    [snapshot.features],
  );
  const sensitiveInfoSubFeatures = useMemo(
    () => snapshot.features.filter((feature) => feature.id.startsWith("passive.sensitive_info.")),
    [snapshot.features],
  );
  const sensitiveInfoActiveCount = sensitiveInfoSubFeatures.filter((feature) => feature.enabled).length;
  const sensitiveInfoTotalCount = sensitiveInfoSubFeatures.length;
  const fileProbeFeature = useMemo(
    () => snapshot.features.find((feature) => feature.id === "passive.file_probe"),
    [snapshot.features],
  );
  const fileProbeSubFeatures = useMemo(
    () => snapshot.features.filter((feature) => feature.id.startsWith("passive.file_probe.")),
    [snapshot.features],
  );
  const fileProbeCategoryFeatures = useMemo(
    () => fileProbeSubFeatures.filter((feature) => feature.id !== "passive.file_probe.dedupe_responses"),
    [fileProbeSubFeatures],
  );
  const fileProbeActiveCount = fileProbeCategoryFeatures.filter((feature) => feature.enabled).length;
  const fileProbeTotalCount = fileProbeCategoryFeatures.length;
  const fastjsonProbeFeature = useMemo(
    () => snapshot.features.find((feature) => feature.id === "passive.fastjson_probe"),
    [snapshot.features],
  );
  const shiroProbeFeature = useMemo(
    () => snapshot.features.find((feature) => feature.id === "passive.shiro_probe"),
    [snapshot.features],
  );
  const trafficFilterRuleCount = snapshot.excludedDomains.length
    + snapshot.excludedSuffixes.length
    + snapshot.excludedContentTypes.length
    + snapshot.excludedPaths.length
    + snapshot.excludedQueryParameters.length
    + snapshot.excludedPostParameters.length;

  const chronologicalLogs = useMemo(() => [...snapshot.logs].reverse(), [snapshot.logs]);
  const passiveLogs = useMemo(() => chronologicalLogs.filter(isPassiveRuntimeLog), [chronologicalLogs]);

  const selectedTask = useMemo(() => snapshot.tasks.find((task) => task.id === selectedTaskId), [selectedTaskId, snapshot.tasks]);
  const identifiedAssets = useMemo(() => snapshot.assets.filter((asset) => asset.fingerprints.length > 0).length, [snapshot.assets]);
  const toggleFinding = (finding: Finding) => {
    const identity = findingIdentity(finding);
    if (selectedFindingId !== identity) {
      void loadFindingEvidence(finding);
    }
    setSelectedFindingId((current) => current === identity ? "" : identity);
  };

  const submitTask = () => {
    if (!taskTarget.trim()) {
      setError("请填写要扫描的单个主机或 URL");
      return;
    }
    let headers: Record<string, string>;
    try {
      headers = parseSessionHeaders(sessionHeaders);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "会话头格式无效");
      return;
    }
    void runAction("submit-task", async () => {
      const created = await desktopApi.submitTask({
        kind: taskKind,
        target: taskTarget.trim(),
        session_headers: headers,
      });
      const task = created as {id?: unknown};
      if (typeof task?.id === "string") {
        setSelectedTaskId(task.id);
      }
      setTaskTarget("");
      setSessionHeaders("");
    });
  };

  const cancelTask = (id: string) => {
    void runAction(`cancel-${id}`, async () => {
      await desktopApi.cancelTask(id);
      await loadTaskResults(id);
    });
  };

  const changeFeature = (feature: Feature, enabled: boolean) => {
    void runAction(`feature-${feature.id}`, () => desktopApi.updateFeature(feature.id, enabled));
  };

  useEffect(() => {
    if (view !== "ai") {
      return;
    }
    let cancelled = false;
    (async () => {
      try {
        const settings = normalizeAISettings(await desktopApi.getAISettings());
        if (cancelled) {
          return;
        }
        setAIBaseUrl(settings.baseUrl);
        setAIModel(settings.model);
        setAIApiKey(settings.apiKey);
        setAIConfigured(settings.configured);
      } catch (reason) {
        if (!cancelled) {
          setError(reason instanceof Error ? reason.message : "无法读取 AI 配置");
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [view]);

  const saveAISettings = () => {
    void runAction("ai-settings", async () => {
      await desktopApi.saveAISettings(aiBaseUrl, aiModel, aiApiKey);
      const settings = normalizeAISettings(await desktopApi.getAISettings());
      setAIConfigured(settings.configured);
    });
  };

  const openAdvancedSettings = (section: AdvancedSettingsSection) => {
    setAdvancedSettingsSection(section);
    setAdvancedSettingsOpen(true);
  };

  const importHFingerRule = () => {
    void runAction("hfinger-import", () => desktopApi.importHFingerRule());
  };

  const reloadHFingerRules = () => {
    void runAction("hfinger-reload", () => desktopApi.reloadHFingerRules());
  };

  const savePassiveSQLiSettings = () => {
    const qps = Number(passiveSQLiProbeQPS.trim());
    const maxRequests = Number(passiveSQLiMaxRequests.trim());
    const maxParameters = Number(passiveSQLiMaxParameters.trim());
    if (!Number.isInteger(qps) || qps < passiveSQLiProbeQPSRange.min || qps > passiveSQLiProbeQPSRange.max) {
      setError(`MITM SQL 探测速率需在 ${passiveSQLiProbeQPSRange.min}–${passiveSQLiProbeQPSRange.max} 请求/秒之间`);
      return;
    }
    if (!Number.isInteger(maxRequests) || maxRequests < passiveSQLiMaxRequestsRange.min || maxRequests > passiveSQLiMaxRequestsRange.max) {
      setError(`MITM SQL 单次最大请求数需在 ${passiveSQLiMaxRequestsRange.min}–${passiveSQLiMaxRequestsRange.max} 之间`);
      return;
    }
    if (!Number.isInteger(maxParameters) || maxParameters < passiveSQLiMaxParametersRange.min || maxParameters > passiveSQLiMaxParametersRange.max) {
      setError(`MITM SQL 单次最多参数数需在 ${passiveSQLiMaxParametersRange.min}–${passiveSQLiMaxParametersRange.max} 之间`);
      return;
    }
    setPassiveSQLiProbeQPS(String(qps));
    setPassiveSQLiMaxRequests(String(maxRequests));
    setPassiveSQLiMaxParameters(String(maxParameters));
    void runAction("passive-sqli-settings", async () => {
      await desktopApi.updateSQLiTechniques(sqliErrorEnabled, sqliBooleanEnabled, sqliTimeEnabled);
      await desktopApi.updatePassiveSQLiProbeQPS(qps);
      await desktopApi.updatePassiveSQLiMaxRequests(maxRequests);
      await desktopApi.updatePassiveSQLiMaxParameters(maxParameters);
    });
  };

  const savePassiveXSSSettings = () => {
    const qps = Number(passiveXSSProbeQPS.trim());
    const maxRequests = Number(passiveXSSMaxRequests.trim());
    const maxParameters = Number(passiveXSSMaxParameters.trim());
    if (!Number.isInteger(qps) || qps < passiveXSSProbeQPSRange.min || qps > passiveXSSProbeQPSRange.max) {
      setError(`MITM XSS 探测速率需在 ${passiveXSSProbeQPSRange.min}–${passiveXSSProbeQPSRange.max} 请求/秒之间`);
      return;
    }
    if (!Number.isInteger(maxRequests) || maxRequests < passiveXSSMaxRequestsRange.min || maxRequests > passiveXSSMaxRequestsRange.max) {
      setError(`MITM XSS 单次最大请求数需在 ${passiveXSSMaxRequestsRange.min}–${passiveXSSMaxRequestsRange.max} 之间`);
      return;
    }
    if (!Number.isInteger(maxParameters) || maxParameters < passiveXSSMaxParametersRange.min || maxParameters > passiveXSSMaxParametersRange.max) {
      setError(`MITM XSS 单次最多参数数需在 ${passiveXSSMaxParametersRange.min}–${passiveXSSMaxParametersRange.max} 之间`);
      return;
    }
    setPassiveXSSProbeQPS(String(qps));
    setPassiveXSSMaxRequests(String(maxRequests));
    setPassiveXSSMaxParameters(String(maxParameters));
    void runAction("passive-xss-settings", async () => {
      await desktopApi.updatePassiveXSSProbeQPS(qps);
      await desktopApi.updatePassiveXSSMaxRequests(maxRequests);
      await desktopApi.updatePassiveXSSMaxParameters(maxParameters);
    });
  };

  const savePassivePOCSettings = () => {
    const qps = Number(passivePOCQPS.trim());
    const concurrency = Number(passivePOCConcurrency.trim());
    if (!Number.isInteger(qps) || qps < passivePOCQPSRange.min || qps > passivePOCQPSRange.max) {
      setError(`MITM POC 探测速率需在 ${passivePOCQPSRange.min}–${passivePOCQPSRange.max} 请求/秒之间`);
      return;
    }
    if (!Number.isInteger(concurrency) || concurrency < passivePOCConcurrencyRange.min || concurrency > passivePOCConcurrencyRange.max) {
      setError(`MITM POC 最大并发数需在 ${passivePOCConcurrencyRange.min}–${passivePOCConcurrencyRange.max} 之间`);
      return;
    }
    setPassivePOCQPS(String(qps));
    setPassivePOCConcurrency(String(concurrency));
    void runAction("passive-poc-settings", async () => {
      await desktopApi.updatePassivePOCQPS(qps);
      await desktopApi.updatePassivePOCConcurrency(concurrency);
    });
  };

  const loadNucleiStatus = useCallback(async () => {
    try {
      const status = normalizeNucleiStatus(await desktopApi.getNucleiStatus());
      setNucleiStatus(status);
      setNucleiPath(status.configuredPath);
    } catch {
      // Status is best-effort; the panel simply shows the未安装 fallback.
    }
  }, []);

  const saveNucleiBinaryPath = () => {
    void runAction("nuclei-path", async () => {
      const status = normalizeNucleiStatus(await desktopApi.setNucleiBinaryPath(nucleiPath.trim()));
      setNucleiStatus(status);
      setNucleiPath(status.configuredPath);
    }, false);
  };

  const downloadNuclei = () => {
    void runAction("nuclei-download", async () => {
      const status = normalizeNucleiStatus(await desktopApi.downloadNuclei());
      setNucleiStatus(status);
      setNucleiPath(status.configuredPath);
    }, false);
  };

  useEffect(() => {
    void loadNucleiStatus();
  }, [loadNucleiStatus]);

  const savePassiveFileProbeSettings = () => {
    const qps = Number(passiveFileProbeQPS.trim());
    if (!Number.isInteger(qps) || qps < passiveFileProbeQPSRange.min || qps > passiveFileProbeQPSRange.max) {
      setError(`敏感文件探测速率需在 ${passiveFileProbeQPSRange.min}–${passiveFileProbeQPSRange.max} 请求/秒之间`);
      return;
    }
    setPassiveFileProbeQPS(String(qps));
    void runAction("passive-file-probe-settings", async () => {
      await desktopApi.updatePassiveFileProbeQPS(qps);
    });
  };

  const savePassiveFastjsonProbeSettings = () => {
    const qps = Number(passiveFastjsonProbeQPS.trim());
    if (!Number.isInteger(qps) || qps < passiveFastjsonProbeQPSRange.min || qps > passiveFastjsonProbeQPSRange.max) {
      setError(`Fastjson 探测速率需在 ${passiveFastjsonProbeQPSRange.min}–${passiveFastjsonProbeQPSRange.max} 请求/秒之间`);
      return;
    }
    setPassiveFastjsonProbeQPS(String(qps));
    void runAction("passive-fastjson-probe-settings", async () => {
      await desktopApi.updatePassiveFastjsonProbeQPS(qps);
    });
  };

  const savePassiveShiroProbeSettings = () => {
    const qps = Number(passiveShiroProbeQPS.trim());
    if (!Number.isInteger(qps) || qps < passiveShiroProbeQPSRange.min || qps > passiveShiroProbeQPSRange.max) {
      setError(`Shiro 探测速率需在 ${passiveShiroProbeQPSRange.min}–${passiveShiroProbeQPSRange.max} 请求/秒之间`);
      return;
    }
    setPassiveShiroProbeQPS(String(qps));
    void runAction("passive-shiro-probe-settings", async () => {
      await desktopApi.updatePassiveShiroProbeQPS(qps);
    });
  };

  const saveShiroKeys = () => {
    const keys = shiroKeysText
      .split(/\r?\n/u)
      .map((key) => key.trim())
      .filter(Boolean);
    void runAction("shiro-keys", async () => {
      await desktopApi.updateShiroKeys(keys);
      shiroKeysFocusedRef.current = false;
      setShiroKeysText(keys.join("\n"));
    });
  };

  const saveOOBDomain = () => {
    const domain = oobDomainText.trim();
    void runAction("oob-domain", async () => {
      await desktopApi.updateOOBDomain(domain);
      oobDomainFocusedRef.current = false;
      setOOBDomainText(domain);
    });
  };

  const saveExcludedDomains = () => {
    const domains = excludedDomainsText
      .split(/\r?\n/u)
      .map((domain) => domain.trim())
      .filter(Boolean);
    void runAction("excluded-domains", async () => {
      const persistedDomains = await desktopApi.updateExcludedDomains(domains);
      excludedDomainsFocusedRef.current = false;
      setExcludedDomainsText(persistedDomains.join("\n"));
    });
  };

  const saveExcludedSuffixes = () => {
    const suffixes = parseExcludedSuffixes(excludedSuffixesText);
    void runAction("excluded-suffixes", async () => {
      const persistedSuffixes = await desktopApi.updateExcludedSuffixes(suffixes);
      excludedSuffixesFocusedRef.current = false;
      setExcludedSuffixesText(persistedSuffixes.join("\n"));
    });
  };

  const saveExcludedContentTypes = () => {
    const contentTypes = parseExcludedContentTypes(excludedContentTypesText);
    void runAction("excluded-content-types", async () => {
      const persistedContentTypes = await desktopApi.updateExcludedContentTypes(contentTypes);
      excludedContentTypesFocusedRef.current = false;
      setExcludedContentTypesText(persistedContentTypes.join("\n"));
    });
  };

  const saveExcludedPaths = () => {
    const paths = parseExcludedPaths(excludedPathsText);
    void runAction("excluded-paths", async () => {
      const persistedPaths = await desktopApi.updateExcludedPaths(paths);
      excludedPathsFocusedRef.current = false;
      setExcludedPathsText(persistedPaths.join("\n"));
    });
  };

  const saveExcludedQueryParameters = () => {
    const parameters = parseExcludedParameterNames(excludedQueryParametersText);
    void runAction("excluded-query-parameters", async () => {
      const persistedParameters = await desktopApi.updateExcludedQueryParameters(parameters);
      excludedQueryParametersFocusedRef.current = false;
      setExcludedQueryParametersText(persistedParameters.join("\n"));
    });
  };

  const saveExcludedPostParameters = () => {
    const parameters = parseExcludedParameterNames(excludedPostParametersText);
    void runAction("excluded-post-parameters", async () => {
      const persistedParameters = await desktopApi.updateExcludedPostParameters(parameters);
      excludedPostParametersFocusedRef.current = false;
      setExcludedPostParametersText(persistedParameters.join("\n"));
    });
  };

  const saveSwaggerExcludedPaths = () => {
    const paths = parseExcludedPaths(swaggerExcludedPathsText);
    void runAction("swagger-excluded-paths", async () => {
      const persistedPaths = await desktopApi.updateSwaggerExcludedPaths(paths);
      swaggerExcludedPathsFocusedRef.current = false;
      setSwaggerExcludedPathsText(persistedPaths.join("\n"));
    });
  };

  const saveCustomProbePaths = () => {
    const paths = parseCustomProbePaths(customProbePathsText);
    void runAction("custom-probe-paths", async () => {
      const persistedPaths = await desktopApi.updateCustomProbePaths(paths);
      customProbePathsFocusedRef.current = false;
      setCustomProbePathsText(persistedPaths.join("\n"));
    });
  };

  const renderTraffic = () => (
    <PassiveLogConsole
      filterRuleCount={trafficFilterRuleCount}
      isFollowingTail={isFollowingLogTail}
      logs={passiveLogs}
      onOpenFilters={() => setTrafficFilterOpen(true)}
      onResumeTail={resumeRuntimeLogTail}
      onScroll={handleRuntimeLogScroll}
      summary={snapshot.passiveLogSummary}
      titleByRuleId={findingTitleByRuleId}
      viewportRef={logViewportRef}
    />
  );

  const renderFindings = () => (
    <>
      <section className="content-intro">
        <div><span className="eyebrow">风险发现</span><h1>发现与证据</h1></div>
        <span className="updated-at">{findingFilter === "fingerprint" ? visibleFingerprintAssets.length : categorizedFindings[findingFilter].length} 条匹配结果</span>
      </section>
      <section className="finding-toolbar">
        <div className="severity-tabs finding-category-tabs" aria-label="按发现分类筛选">
          <TabList selectedValue={findingFilter} onTabSelect={(_, data) => setFindingFilter(data.value as FindingViewFilter)} size="small">
            <Tab value="web">漏洞 <span>{categorizedFindings.web.length}</span></Tab>
            <Tab value="information">信息 <span>{categorizedFindings.information.length}</span></Tab>
            <Tab value="fingerprint">指纹识别 <span>{visibleFingerprintAssets.length}</span></Tab>
          </TabList>
        </div>
        <Input contentBefore={<Search20Regular />} onChange={(_, data) => setQuery(data.value)} placeholder="搜索规则、目标或标签" value={query} />
      </section>
      <section className="finding-category-grid">
        {findingFilter === "web" && <FindingCategoryPanel category="web" evidenceByFinding={findingEvidenceById} expandedId={selectedFindingId} findings={categorizedFindings.web} loadingId={findingEvidenceLoadingId} onToggle={toggleFinding} />}
        {findingFilter === "information" && <FindingCategoryPanel category="information" evidenceByFinding={findingEvidenceById} expandedId={selectedFindingId} findings={categorizedFindings.information} loadingId={findingEvidenceLoadingId} onToggle={toggleFinding} />}
        {findingFilter === "fingerprint" && (
          <section className="work-surface finding-category-panel finding-category-fingerprint">
            <div className="finding-category-heading">
              <div>
                <span className="eyebrow">被动指纹识别</span>
                <h2>指纹识别</h2>
                <p>按资产显示已观测路由和匹配到的组件指纹。</p>
              </div>
              <span className="finding-category-count">{visibleFingerprintAssets.length}</span>
            </div>
            <PassiveFingerprintList assets={visibleFingerprintAssets} />
          </section>
        )}
      </section>
    </>
  );

  const renderRuntimeLogs = () => {
    const reversed = [...runtimeLogs].reverse();
    const componentOptions = Array.from(new Set(runtimeLogs.map((log) => log.component))).sort();
    const levelOptions = Array.from(new Set(runtimeLogs.map((log) => log.level))).sort();
    const filtered = reversed.filter((log) => {
      if (runtimeLogsLevelFilter !== "all" && log.level !== runtimeLogsLevelFilter) {
        return false;
      }
      if (runtimeLogsComponentFilter !== "all" && log.component !== runtimeLogsComponentFilter) {
        return false;
      }
      if (runtimeLogsFilter.trim()) {
        const haystack = `${log.component} ${log.message} ${log.level}`.toLowerCase();
        if (!haystack.includes(runtimeLogsFilter.trim().toLowerCase())) {
          return false;
        }
      }
      return true;
    });
    const handleScroll = () => {
      const viewport = runtimeLogsViewportRef.current;
      if (!viewport) return;
      const distanceFromBottom = viewport.scrollHeight - viewport.scrollTop - viewport.clientHeight;
      runtimeLogsFollowTailRef.current = distanceFromBottom < 32;
    };
    return (
      <>
        <section className="content-intro">
          <div><span className="eyebrow">运行日志</span><h1>详细运行日志</h1></div>
          <span className="updated-at">{runtimeLogs.length} 条记录（最新 {runtimeLogs.length > 0 ? "在前" : ""}）</span>
        </section>
        <section className="runtime-logs-toolbar">
          <div className="runtime-logs-toolbar-left">
            <Field label="搜索">
              <Input
                value={runtimeLogsFilter}
                onChange={(_, data) => setRuntimeLogsFilter(data.value)}
                placeholder="搜索组件/消息内容"
                contentBefore={<Search20Regular />}
                appearance="filled-darker"
              />
            </Field>
            <Field label="级别">
              <Select value={runtimeLogsLevelFilter} onChange={(_, data) => setRuntimeLogsLevelFilter(data.value)} appearance="filled-darker">
                <option value="all">全部级别</option>
                {levelOptions.map((level) => <option key={level} value={level}>{level}</option>)}
              </Select>
            </Field>
            <Field label="组件">
              <Select value={runtimeLogsComponentFilter} onChange={(_, data) => setRuntimeLogsComponentFilter(data.value)} appearance="filled-darker">
                <option value="all">全部组件</option>
                {componentOptions.map((comp) => <option key={comp} value={comp}>{comp}</option>)}
              </Select>
            </Field>
          </div>
          <div className="runtime-logs-toolbar-right">
            <Tooltip content="刷新日志" relationship="label">
              <Button
                appearance="subtle"
                icon={<ArrowClockwise20Regular />}
                onClick={() => void refreshRuntimeLogs()}
                disabled={runtimeLogsLoading}
              />
            </Tooltip>
          </div>
        </section>
        <section className="runtime-logs-surface" ref={runtimeLogsViewportRef} onScroll={handleScroll}>
          {runtimeLogsLoading && runtimeLogs.length === 0 ? (
            <div className="runtime-logs-empty">加载中…</div>
          ) : filtered.length === 0 ? (
            <div className="runtime-logs-empty">暂无日志记录</div>
          ) : (
            <table className="runtime-logs-table">
              <thead>
                <tr>
                  <th className="rl-time">时间</th>
                  <th className="rl-level">级别</th>
                  <th className="rl-component">组件</th>
                  <th className="rl-message">消息</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((log) => (
                  <tr key={log.id} className={`runtime-log-row runtime-log-${log.level}`}>
                    <td className="rl-time">{log.createdAt ? new Date(log.createdAt).toLocaleString("zh-CN", {hour12: false}) : ""}</td>
                    <td className="rl-level"><span className={`runtime-log-badge runtime-log-badge-${log.level}`}>{log.level}</span></td>
                    <td className="rl-component">{log.component}</td>
                    <td className="rl-message">{log.message}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </section>
      </>
    );
  };

  const renderAssets = () => (
    <>
      <section className="content-intro">
        <div><span className="eyebrow">资产指纹</span><h1>资产与接口</h1></div>
        <span className="updated-at">{snapshot.assets.length} 个归一化资产</span>
      </section>
      <section className="metric-strip asset-metric-strip">
        <Metric label="资产总数" value={snapshot.assets.length} detail="按主机归一化" />
        <Metric label="带指纹资产" value={identifiedAssets} tone="brand" detail="本地指纹匹配" />
        <Metric label="观测端点" value={snapshot.assets.reduce((count, asset) => count + asset.endpoints.length, 0)} detail="方法与路径" />
      </section>
      <div className="assets-workspace">
        <section className="work-surface"><div className="surface-heading"><div><span className="eyebrow">资产清单</span><h2>主机与识别指纹</h2></div></div><AssetList assets={snapshot.assets} /></section>
        <section className="work-surface"><div className="surface-heading"><div><span className="eyebrow">接口地图</span><h2>已观测端点</h2></div></div><EndpointList assets={snapshot.assets} /></section>
      </div>
    </>
  );

  const renderActive = () => (
    <>
      <section className="content-intro">
        <div><span className="eyebrow">主动扫描</span><h1>扫描任务</h1></div>
        <Badge appearance="tint" color="warning">仅限授权目标</Badge>
      </section>
      <section className="active-workspace">
        <aside className="work-surface task-form-panel">
          <div className="surface-heading"><div><span className="eyebrow">创建任务</span><h2>限定目标与方式</h2></div></div>
          <div className="task-form">
            <Field label="扫描类型">
              <Select onChange={(_, data) => setTaskKind(data.value)} value={taskKind}>
                {taskOptions.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}
              </Select>
            </Field>
            <Field label="单个目标" hint={taskKind === "port_scan" ? "主机名或 IP 地址" : "http 或 https URL"}>
              <Input onChange={(_, data) => setTaskTarget(data.value)} placeholder={taskKind === "port_scan" ? "app.example.test" : "https://app.example.test/path"} value={taskTarget} />
            </Field>
            <Field label="会话头（可选）" hint="仅支持 Cookie、Authorization、X-CSRF-Token 与 X-Requested-With">
              <Textarea onChange={(_, data) => setSessionHeaders(data.value)} placeholder="Cookie: session=..." resize="vertical" value={sessionHeaders} />
            </Field>
            <Button appearance="primary" disabled={busyAction === "submit-task"} icon={<Play20Regular />} onClick={submitTask}>{busyAction === "submit-task" ? "正在提交" : "提交扫描任务"}</Button>
          </div>
        </aside>
        <section className="active-result-column">
          <div className="work-surface task-list-panel">
            <div className="surface-heading"><div><span className="eyebrow">任务队列</span><h2>执行记录</h2></div><span className="surface-count">{snapshot.tasks.length}</span></div>
            <TaskList busyTaskId={busyAction.startsWith("cancel-") ? busyAction.slice("cancel-".length) : ""} onCancel={cancelTask} onSelect={setSelectedTaskId} selectedTaskId={selectedTaskId} tasks={snapshot.tasks} />
          </div>
          <div className="work-surface task-results-panel">
            <div className="surface-heading"><div><span className="eyebrow">任务结果</span><h2>扫描结果</h2></div><Tooltip content="重新读取选中任务的结果" relationship="label"><Button appearance="subtle" aria-label="重新读取任务结果" disabled={!selectedTaskId} icon={<ArrowClockwise20Regular />} onClick={() => void loadTaskResults(selectedTaskId)} /></Tooltip></div>
            <TaskResults loading={resultsLoading} results={taskResults} task={selectedTask} />
          </div>
        </section>
      </section>
    </>
  );

  const renderAI = () => {
    const analysisFeature = snapshot.features.find((feature) => feature.id === "passive.ai_analysis");
    const routesFeature = snapshot.features.find((feature) => feature.id === "passive.ai_analysis.routes");
    const secretsFeature = snapshot.features.find((feature) => feature.id === "passive.ai_analysis.secrets");
    const insightFeature = snapshot.features.find((feature) => feature.id === "passive.ai_insight");
    const fingerprintFeature = snapshot.features.find((feature) => feature.id === "passive.ai_fingerprint");
    const secretContextFeature = snapshot.features.find((feature) => feature.id === "passive.ai_secret_context");
    const trafficAnomalyFeature = snapshot.features.find((feature) => feature.id === "passive.ai_traffic_anomaly");
    const analysisGroup: FeatureGroup = {
      id: "ai-analysis",
      title: "AI 分析开关",
      description: "主开关控制整条 AI 流水线；两个子开关分别控制路由提取与敏感信息检测的结果输出。",
      features: [analysisFeature, routesFeature, secretsFeature].filter((item): item is Feature => Boolean(item)),
    };
    const insightGroup: FeatureGroup = {
      id: "ai-insight",
      title: "AI 漏洞解读",
      description: "对检测到的非信息级漏洞 finding，异步调用 AI 生成影响分析、利用方式与修复建议，追加到 finding 描述中。默认关闭以节省 API 调用。",
      features: insightFeature ? [insightFeature] : [],
    };
    const augmentGroup: FeatureGroup = {
      id: "ai-augment",
      title: "AI 辅助研判",
      description: "在指纹识别、敏感信息与流量分析的基础上，异步调用 AI 补充指纹推断、凭据研判与流量异常识别。默认关闭以节省 API 调用。",
      features: [fingerprintFeature, secretContextFeature, trafficAnomalyFeature].filter((item): item is Feature => Boolean(item)),
    };
    return (
      <>
        <section className="content-intro">
          <div><span className="eyebrow">AI 设置</span><h1>智能分析接口与开关</h1></div>
          <span className="updated-at">
            <Badge appearance="tint" color={aiConfigured ? "success" : "danger"}>{aiConfigured ? "接口已配置" : "接口未配置"}</Badge>
          </span>
        </section>
        <section className="settings-workspace">
          <section className="settings-zone settings-zone-ai">
            <div className="settings-zone-heading">
              <div><span className="eyebrow">接口配置</span><h2>AI 分析接口</h2><p>使用 OpenAI 兼容的 Chat Completions 协议；筛选、路由提取与敏感信息检测三个角色共用该接口。API Key 仅保存在本地 features.yaml。</p></div>
              <Sparkle24Regular />
            </div>
            <section className="work-surface ai-interface-panel">
              <div className="settings-field-grid">
                <Field label="Base URL" hint="例如 https://api.openai.com/v1；只填域名时会自动补充 /v1">
                  <Input value={aiBaseUrl} onChange={(_, data) => setAIBaseUrl(data.value)} placeholder="https://api.openai.com/v1" />
                </Field>
                <Field label="模型" hint="例如 gpt-4o-mini、deepseek-chat、qwen-plus">
                  <Input value={aiModel} onChange={(_, data) => setAIModel(data.value)} placeholder="gpt-4o-mini" />
                </Field>
                <Field label="API Key" hint="以 Bearer 方式随请求发送，不会上传到任何远端">
                  <Input type="password" value={aiApiKey} onChange={(_, data) => setAIApiKey(data.value)} placeholder="sk-..." />
                </Field>
              </div>
              <div className="settings-actions">
                <Button appearance="primary" onClick={saveAISettings} disabled={busyAction === "ai-settings"}>保存 AI 配置</Button>
              </div>
            </section>
          </section>

          <section className="settings-zone settings-zone-ai">
            <div className="settings-zone-heading">
              <div><span className="eyebrow">功能开关</span><h2>AI 分析与漏洞解读</h2><p>控制 AI 流水线的各个角色；漏洞解读默认关闭，开启后会对每个非信息级 finding 异步调用 AI。</p></div>
              <Shield24Regular />
            </div>
            <div className="settings-zone-grid">
              <FeatureGroupPanel
                busyAction={busyAction}
                group={analysisGroup}
                onChange={changeFeature}
                rowSummaries={{
                  "passive.ai_analysis": analysisFeature?.enabled ? "已启用" : "已停用",
                  "passive.ai_analysis.routes": routesFeature?.enabled ? "已启用" : "已停用",
                  "passive.ai_analysis.secrets": secretsFeature?.enabled ? "已启用" : "已停用",
                }}
              />
              <FeatureGroupPanel
                busyAction={busyAction}
                group={insightGroup}
                onChange={changeFeature}
                rowSummaries={{
                  "passive.ai_insight": insightFeature?.enabled ? "已启用" : "已停用",
                }}
              />
              <FeatureGroupPanel
                busyAction={busyAction}
                group={augmentGroup}
                onChange={changeFeature}
                rowSummaries={{
                  "passive.ai_fingerprint": fingerprintFeature?.enabled ? "已启用" : "已停用",
                  "passive.ai_secret_context": secretContextFeature?.enabled ? "已启用" : "已停用",
                  "passive.ai_traffic_anomaly": trafficAnomalyFeature?.enabled ? "已启用" : "已停用",
                }}
              />
            </div>
          </section>

          <section className="settings-zone settings-zone-ai">
            <div className="settings-zone-heading">
              <div><span className="eyebrow">工作原理</span><h2>分析流程说明</h2><p>了解 AI 分析的完整流水线，从 JS 收集到结果输出。</p></div>
              <DocumentBulletList24Regular />
            </div>
            <section className="work-surface ai-flow-panel">
              <ol className="ai-flow-steps">
                <li>新流量流入 MITM 后，等待站点 JS 加载稳定（10 秒内无新 JS，或最长等待 2 分钟）；</li>
                <li>将收集到的全部 JS 文件名交给 AI，由 AI 挑出可能包含路由、接口与配置的有价值 JS；</li>
                <li>把选中 JS 的内容并行转发给两个 AI 角色：一个提取全部前端路由与 API 接口，另一个提取凭据、密钥、内网地址等敏感信息；</li>
                <li>结果输出到「风险发现」：路由提取为信息级，敏感凭据为高危级。</li>
              </ol>
            </section>
          </section>
        </section>
      </>
    );
  };

  const renderSettings = () => {
    const group = (id: string) => featureGroups.find((item) => item.id === id);
    const mitmGroup = group("mitm");
    const activeNetworkGroup = group("active-network");
    const activeWebGroup = group("active-web");
    const dataGroup = group("data");
    const lockedGroup = group("locked");
    const mitmOverviewFeatures = mitmGroup?.features ?? [];
    const mitmOverviewGroup: FeatureGroup = {
      id: "mitm-overview",
      title: "MITM 功能开关",
      description: "集中控制代理流量中的指纹识别、CDN、WAF、SQL 注入、POC、敏感信息与敏感文件检测。",
      features: mitmOverviewFeatures,
    };
    const advancedDialogCopy: Record<AdvancedSettingsSection, {eyebrow: string; title: string; description: string}> = {
      "mitm-sqli": {eyebrow: "MITM SQL 注入检测", title: "SQL 注入检测设置", description: "配置检测等级、探测速率与单次请求上限。"},
      "mitm-xss": {eyebrow: "MITM XSS 检测", title: "XSS 检测设置", description: "配置反射探测速率、单次请求上限与参数上限。"},
      "mitm-poc": {eyebrow: "MITM POC 检测", title: "POC 检测设置", description: "配置本地 POC 验证速率与最大并发数。"},
      "mitm-fastjson": {eyebrow: "MITM Fastjson 探测", title: "Fastjson 探测设置", description: "配置 Fastjson 识别的探测速率。"},
      "mitm-shiro": {eyebrow: "MITM Shiro 探测", title: "Shiro 探测设置", description: "配置 Shiro 识别速率与自定义密钥字典。"},
      "mitm-oob": {eyebrow: "OOB 外带回连", title: "SSRF / XXE OOB 配置", description: "配置用于盲打 SSRF/XXE 外带确认的回调域名（如自建 dnslog 域名）。留空则仅使用本地差异判定。"},
      fingerprint: {eyebrow: "指纹识别", title: "指纹规则管理", description: "添加、校验并热重载用户 YAML 指纹规则。"},
      quality: {eyebrow: "指纹识别", title: "指纹命中质量", description: "查看当前会话中的指纹命中次数、资产数与常见组合。"},
      "sensitive-info": {eyebrow: "敏感信息检测", title: "敏感信息检测设置", description: "单独开启或关闭每类敏感信息检测器。"},
      "file-probe": {eyebrow: "敏感文件探测", title: "敏感文件探测设置", description: "单独开启或关闭每类敏感文件探测，并配置探测速率。"},
    };
    const activeAdvancedDialog = advancedDialogCopy[advancedSettingsSection];

    return <>
      <section className="content-intro">
        <div><span className="eyebrow">设置</span><h1>功能与流量设置</h1></div>
        <span className="updated-at">更改将写入本地策略文件</span>
      </section>
      <section className="settings-workspace">
        <section className="settings-zone settings-zone-mitm">
          <div className="settings-zone-heading">
            <div><span className="eyebrow">代理设置</span><h2>MITM 与实时分析</h2><p>每个功能单独调整开关；有精细参数的功能可打开自己的高级设置。</p></div>
            <PlugConnected20Regular />
          </div>
          {mitmOverviewFeatures.length > 0 && (
            <FeatureGroupPanel
              busyAction={busyAction}
              group={mitmOverviewGroup}
              onChange={changeFeature}
              rowActions={{
                "passive.poc_scan": {label: "高级设置", onClick: () => openAdvancedSettings("mitm-poc")},
                "passive.hfinger": {label: "高级设置", onClick: () => openAdvancedSettings("fingerprint")},
                "passive.sqli_probe": {label: "高级设置", onClick: () => openAdvancedSettings("mitm-sqli")},
                "passive.xss_probe": {label: "高级设置", onClick: () => openAdvancedSettings("mitm-xss")},
                "passive.sensitive_info": {label: "高级设置", onClick: () => openAdvancedSettings("sensitive-info")},
                "passive.file_probe": {label: "高级设置", onClick: () => openAdvancedSettings("file-probe")},
                "passive.fastjson_probe": {label: "高级设置", onClick: () => openAdvancedSettings("mitm-fastjson")},
                "passive.shiro_probe": {label: "高级设置", onClick: () => openAdvancedSettings("mitm-shiro")},
                "passive.ssrf_probe": {label: "OOB 配置", onClick: () => openAdvancedSettings("mitm-oob")},
                "passive.xxe_probe": {label: "OOB 配置", onClick: () => openAdvancedSettings("mitm-oob")},
              }}
              rowSummaries={{
                "passive.poc_scan": `${passivePOCQPS || "—"} QPS · 并发 ${passivePOCConcurrency || "—"}`,
                "passive.hfinger": `${snapshot.hfinger.loaded} 条规则 · 自定义 ${snapshot.hfinger.customRules}`,
                "passive.sqli_probe": `${[
                  sqliErrorEnabled ? "报错" : "",
                  sqliBooleanEnabled ? "布尔" : "",
                  sqliTimeEnabled ? "时间" : "",
                ].filter(Boolean).join(" · ") || "未选择检测"} · ${passiveSQLiProbeQPS || "—"} QPS`,
                "passive.xss_probe": `${passiveXSSProbeQPS || "—"} QPS · 单次 ≤ ${passiveXSSMaxRequests || "—"} 请求`,
                "passive.sensitive_info": `${sensitiveInfoFeature ? (sensitiveInfoFeature.enabled ? "已启用" : "已停用") : "—"} · ${sensitiveInfoActiveCount}/${sensitiveInfoTotalCount} 类检测`,
                "passive.file_probe": `${passiveFileProbeQPS || "—"} QPS · ${fileProbeActiveCount}/${fileProbeTotalCount} 类文件`,
                "passive.fastjson_probe": `${passiveFastjsonProbeQPS || "—"} QPS`,
                "passive.shiro_probe": `${passiveShiroProbeQPS || "—"} QPS · 自定义密钥 ${snapshot.shiroKeys.length}`,
                "passive.cmd_probe": `${snapshot.passiveCmdProbeQPS || "—"} QPS · 算术回显`,
                "passive.ssrf_probe": `${snapshot.passiveSSRFProbeQPS || "—"} QPS · OOB ${snapshot.oobDomain ? "已配置" : "未配置"}`,
                "passive.xxe_probe": `${snapshot.passiveXXEProbeQPS || "—"} QPS · XML 流量触发`,
                "passive.upload_probe": `${snapshot.passiveUploadProbeQPS || "—"} QPS · 后缀改 .html`,
              }}
            />
          )}
          <div className="settings-utility-grid is-single">
            <SettingsUtilityCard
              actionLabel="查看命中质量"
              description="检查指纹的命中次数、覆盖资产及常见共现关系，辅助清理低价值规则。"
              eyebrow="识别质量"
              icon={<DataBarVertical24Regular />}
              meta={`${snapshot.fingerprintQuality.length} 个指纹`}
              onClick={() => openAdvancedSettings("quality")}
              title="指纹命中统计"
            />
          </div>
        </section>

        <section className="settings-zone settings-zone-active">
          <div className="settings-zone-heading"><div><span className="eyebrow">扫描设置</span><h2>主动扫描</h2><p>选择任务可以使用的扫描能力；探测强度在高级选项中单独配置。</p></div><Play20Regular /></div>
          <div className="settings-zone-grid">
            {activeNetworkGroup && <FeatureGroupPanel busyAction={busyAction} group={activeNetworkGroup} onChange={changeFeature} />}
            {activeWebGroup && <FeatureGroupPanel busyAction={busyAction} group={activeWebGroup} onChange={changeFeature} />}
          </div>
        </section>

        <section className="settings-zone settings-zone-local">
          <div className="settings-zone-heading"><div><span className="eyebrow">本地管理</span><h2>数据与策略限制</h2><p>管理本地会话，并查看当前策略锁定的扩展能力。</p></div><Settings24Regular /></div>
          <div className="settings-zone-grid">
            {dataGroup && <FeatureGroupPanel busyAction={busyAction} group={dataGroup} onChange={changeFeature} />}
            {lockedGroup && <FeatureGroupPanel busyAction={busyAction} group={lockedGroup} onChange={changeFeature} />}
          </div>
        </section>
      </section>

      <Dialog open={advancedSettingsOpen} onOpenChange={(_, data) => setAdvancedSettingsOpen(data.open)}>
        <DialogSurface className={`advanced-settings-dialog advanced-settings-dialog-${advancedSettingsSection}`}>
          <DialogBody className="advanced-settings-dialog-body">
            <DialogTitle
              action={<Button appearance="subtle" aria-label={`关闭${activeAdvancedDialog.eyebrow}高级设置`} icon={<Dismiss20Regular />} onClick={() => setAdvancedSettingsOpen(false)} />}
              className="advanced-settings-dialog-title"
            >
              <span className="eyebrow">{activeAdvancedDialog.eyebrow}</span>
              <span>{activeAdvancedDialog.title}</span>
              <small>{activeAdvancedDialog.description}</small>
            </DialogTitle>
            <DialogContent className="advanced-settings-dialog-content">
              <section className="advanced-settings-pane" aria-label={`${activeAdvancedDialog.eyebrow}高级设置`}>
                {advancedSettingsSection === "mitm-sqli" && (
                  <PassiveSQLiProbePanel
                    busyAction={busyAction}
                    booleanEnabled={sqliBooleanEnabled}
                    errorEnabled={sqliErrorEnabled}
                    feature={passiveSQLiProbeFeature}
                    maxParameters={passiveSQLiMaxParameters}
                    maxRequests={passiveSQLiMaxRequests}
                    onBooleanEnabledChange={setSQLiBooleanEnabled}
                    onErrorEnabledChange={setSQLiErrorEnabled}
                    onMaxParametersBlur={() => { passiveSQLiMaxParametersFocusedRef.current = false; }}
                    onMaxParametersChange={setPassiveSQLiMaxParameters}
                    onMaxParametersFocus={() => { passiveSQLiMaxParametersFocusedRef.current = true; }}
                    onMaxRequestsBlur={() => { passiveSQLiMaxRequestsFocusedRef.current = false; }}
                    onMaxRequestsChange={setPassiveSQLiMaxRequests}
                    onMaxRequestsFocus={() => { passiveSQLiMaxRequestsFocusedRef.current = true; }}
                    onQPSBlur={() => { passiveSQLiProbeQPSFocusedRef.current = false; }}
                    onQPSChange={setPassiveSQLiProbeQPS}
                    onQPSFocus={() => { passiveSQLiProbeQPSFocusedRef.current = true; }}
                    onSave={savePassiveSQLiSettings}
                    qps={passiveSQLiProbeQPS}
                    timeEnabled={sqliTimeEnabled}
                    onTimeEnabledChange={setSQLiTimeEnabled}
                  />
                )}

                {advancedSettingsSection === "mitm-xss" && (
                  <PassiveXSSProbePanel
                    busyAction={busyAction}
                    feature={passiveXSSProbeFeature}
                    maxParameters={passiveXSSMaxParameters}
                    maxRequests={passiveXSSMaxRequests}
                    onMaxParametersBlur={() => { passiveXSSMaxParametersFocusedRef.current = false; }}
                    onMaxParametersChange={setPassiveXSSMaxParameters}
                    onMaxParametersFocus={() => { passiveXSSMaxParametersFocusedRef.current = true; }}
                    onMaxRequestsBlur={() => { passiveXSSMaxRequestsFocusedRef.current = false; }}
                    onMaxRequestsChange={setPassiveXSSMaxRequests}
                    onMaxRequestsFocus={() => { passiveXSSMaxRequestsFocusedRef.current = true; }}
                    onQPSBlur={() => { passiveXSSProbeQPSFocusedRef.current = false; }}
                    onQPSChange={setPassiveXSSProbeQPS}
                    onQPSFocus={() => { passiveXSSProbeQPSFocusedRef.current = true; }}
                    onSave={savePassiveXSSSettings}
                    qps={passiveXSSProbeQPS}
                  />
                )}

                {advancedSettingsSection === "mitm-poc" && (
                  <PassivePOCProbePanel
                    busyAction={busyAction}
                    concurrency={passivePOCConcurrency}
                    feature={passivePOCProbeFeature}
                    onConcurrencyBlur={() => { passivePOCConcurrencyFocusedRef.current = false; }}
                    onConcurrencyChange={setPassivePOCConcurrency}
                    onConcurrencyFocus={() => { passivePOCConcurrencyFocusedRef.current = true; }}
                    onQPSBlur={() => { passivePOCQPSFocusedRef.current = false; }}
                    onQPSChange={setPassivePOCQPS}
                    onQPSFocus={() => { passivePOCQPSFocusedRef.current = true; }}
                    onSave={savePassivePOCSettings}
                    qps={passivePOCQPS}
                    nucleiStatus={nucleiStatus}
                    nucleiPath={nucleiPath}
                    onNucleiPathChange={setNucleiPath}
                    onNucleiPathSave={saveNucleiBinaryPath}
                    onNucleiDownload={downloadNuclei}
                  />
                )}

                {advancedSettingsSection === "mitm-fastjson" && (
                  <FastjsonProbePanel
                    busyAction={busyAction}
                    feature={fastjsonProbeFeature}
                    onQPSBlur={() => { passiveFastjsonProbeQPSFocusedRef.current = false; }}
                    onQPSChange={setPassiveFastjsonProbeQPS}
                    onQPSFocus={() => { passiveFastjsonProbeQPSFocusedRef.current = true; }}
                    onSave={savePassiveFastjsonProbeSettings}
                    qps={passiveFastjsonProbeQPS}
                  />
                )}

                {advancedSettingsSection === "mitm-shiro" && (
                  <ShiroProbePanel
                    busyAction={busyAction}
                    feature={shiroProbeFeature}
                    onQPSBlur={() => { passiveShiroProbeQPSFocusedRef.current = false; }}
                    onQPSChange={setPassiveShiroProbeQPS}
                    onQPSFocus={() => { passiveShiroProbeQPSFocusedRef.current = true; }}
                    onSave={savePassiveShiroProbeSettings}
                    qps={passiveShiroProbeQPS}
                    shiroKeys={shiroKeysText}
                    onKeysBlur={() => { shiroKeysFocusedRef.current = false; }}
                    onKeysChange={setShiroKeysText}
                    onKeysFocus={() => { shiroKeysFocusedRef.current = true; }}
                    onKeysSave={saveShiroKeys}
                  />
                )}

                {advancedSettingsSection === "mitm-oob" && (
                  <section className="passive-sqli-probe">
                    <div className="surface-heading">
                      <div><span className="eyebrow">OOB 外带回连</span><h2>SSRF / XXE 盲打确认域名</h2></div>
                      <Shield24Regular className="sqli-shield" />
                    </div>
                    <div className="passive-sqli-probe-body">
                      <div className="passive-sqli-probe-status">
                        <strong>用途</strong>
                        <span>SSRF 与 XXE 探测会将该域名的子域拼入外带 Payload。当目标真的向外发起请求时，你可在自己的 dnslog/HTTP 收集器上看到回连，从而确认盲打。留空则仅依赖本地响应差异判定。</span>
                      </div>
                      <div className="passive-sqli-probe-fields passive-poc-probe-fields">
                        <Field label="OOB 回调域名" hint="填写你可控的收集域名，例如 abcd.dnslog.cn 或自建 interactsh 域名；无需带 http:// 前缀。">
                          <Input
                            placeholder="abcd.dnslog.cn"
                            value={oobDomainText}
                            onChange={(_, data) => setOOBDomainText(data.value)}
                            onFocus={() => { oobDomainFocusedRef.current = true; }}
                            onBlur={() => { oobDomainFocusedRef.current = false; }}
                          />
                        </Field>
                      </div>
                      <p className="passive-sqli-probe-note">EasyScan 不内置回连收集服务；请自备 dnslog/interactsh 等平台查看外带记录。</p>
                      <Button appearance="primary" disabled={busyAction === "oob-domain"} onClick={saveOOBDomain}>{busyAction === "oob-domain" ? "正在保存" : "保存 OOB 域名"}</Button>
                    </div>
                  </section>
                )}

                {advancedSettingsSection === "fingerprint" && (
                  <HFingerRulePanel
                    busyAction={busyAction}
                    onImport={importHFingerRule}
                    onReload={reloadHFingerRules}
                    stats={snapshot.hfinger}
                  />
                )}

                {advancedSettingsSection === "quality" && <FingerprintQualityPanel items={snapshot.fingerprintQuality} />}

                {advancedSettingsSection === "sensitive-info" && (
                  <SensitiveInfoPanel
                    busyAction={busyAction}
                    feature={sensitiveInfoFeature}
                    subFeatures={sensitiveInfoSubFeatures}
                    onChange={changeFeature}
                  />
                )}

                {advancedSettingsSection === "file-probe" && (
                  <FileProbePanel
                    busyAction={busyAction}
                    feature={fileProbeFeature}
                    subFeatures={fileProbeSubFeatures}
                    qps={passiveFileProbeQPS}
                    swaggerExcludedPaths={swaggerExcludedPathsText}
                    customProbePaths={customProbePathsText}
                    onQPSBlur={() => { passiveFileProbeQPSFocusedRef.current = false; }}
                    onQPSChange={setPassiveFileProbeQPS}
                    onQPSFocus={() => { passiveFileProbeQPSFocusedRef.current = true; }}
                    onSave={savePassiveFileProbeSettings}
                    onChange={changeFeature}
                    onSwaggerPathsBlur={() => { swaggerExcludedPathsFocusedRef.current = false; }}
                    onSwaggerPathsChange={setSwaggerExcludedPathsText}
                    onSwaggerPathsFocus={() => { swaggerExcludedPathsFocusedRef.current = true; }}
                    onSwaggerPathsSave={saveSwaggerExcludedPaths}
                    onCustomPathsBlur={() => { customProbePathsFocusedRef.current = false; }}
                    onCustomPathsChange={setCustomProbePathsText}
                    onCustomPathsFocus={() => { customProbePathsFocusedRef.current = true; }}
                    onCustomPathsSave={saveCustomProbePaths}
                  />
                )}

              </section>
            </DialogContent>
            <DialogActions className="advanced-settings-dialog-actions">
              <Button appearance="subtle" onClick={() => setAdvancedSettingsOpen(false)}>关闭</Button>
            </DialogActions>
          </DialogBody>
        </DialogSurface>
      </Dialog>
    </>;
  };

  return (
    <FluentProvider theme={webDarkTheme}>
      <div className="app-shell">
        <aside className="app-sidebar">
          <div className="brand-lockup"><span className="brand-mark"><Shield24Regular /></span><div><strong>EasyScan</strong><span>安全工作台</span></div></div>
          <nav className="sidebar-nav" aria-label="主导航">
            <div className="sidebar-nav-section">
              <span className="sidebar-nav-label">监测</span>
              {navigation.filter((item) => item.section === "monitor").map((item) => (
                <Button appearance="subtle" className={`nav-button ${view === item.id ? "is-active" : ""}`} icon={item.icon} key={item.id} onClick={() => setView(item.id)}>{item.label}</Button>
              ))}
            </div>
            <div className="sidebar-nav-section">
              <span className="sidebar-nav-label">扫描与配置</span>
              {navigation.filter((item) => item.section === "control").map((item) => (
                <Button appearance="subtle" className={`nav-button ${view === item.id ? "is-active" : ""}`} icon={item.icon} key={item.id} onClick={() => setView(item.id)}>{item.label}</Button>
              ))}
            </div>
          </nav>
          <div className="sidebar-footer">
            <div className="sidebar-service-status">
              <span className={`connection-dot ${snapshot.status.running === true ? "is-online" : snapshot.status.running === false ? "is-offline" : ""}`} />
              <span>{serviceStateLabel(snapshot.status.running)}</span>
            </div>
            <div className="sidebar-proxy-address">
              <PlugConnected20Regular />
              <div>
                <span>MITM 代理端口</span>
                <code>{snapshot.status.proxyAddress || "未启动"}</code>
              </div>
            </div>
            <div className="sidebar-service-actions">
              <Tooltip content="刷新当前状态" relationship="label"><Button appearance="subtle" aria-label="刷新当前状态" icon={<ArrowClockwise20Regular />} onClick={() => void refreshSnapshot()} /></Tooltip>
              {loading && <Spinner size="tiny" />}
              {snapshot.status.running === true ? (
                <Button appearance="secondary" className="sidebar-service-button" disabled={busyAction === "stop-services"} icon={<Stop20Regular />} onClick={() => void runAction("stop-services", () => desktopApi.stopServices())}>{busyAction === "stop-services" ? "正在停止" : "停止服务"}</Button>
              ) : (
                <Button appearance="primary" className="sidebar-service-button" disabled={busyAction === "start-services"} icon={<Power20Regular />} onClick={() => void runAction("start-services", () => desktopApi.startServices())}>{busyAction === "start-services" ? "正在启动" : "启动服务"}</Button>
              )}
            </div>
            <div className="sidebar-theme-picker" role="group" aria-label="主题配色">
              <span className="sidebar-theme-label">主题</span>
              <div className="sidebar-theme-swatches">
                {themeOptions.map((option) => (
                  <button
                    key={option.id}
                    className={`theme-swatch ${theme === option.id ? "is-active" : ""}`}
                    onClick={() => setTheme(option.id)}
                    title={`${option.label}：${option.description}`}
                    aria-label={`${option.label}：${option.description}`}
                    type="button"
                  >
                    {option.swatch.map((color, index) => (
                      <span key={index} className="theme-swatch-dot" style={{background: color}} />
                    ))}
                  </button>
                ))}
              </div>
            </div>
          </div>
        </aside>
        <main className="app-main">
          <div className={`content-frame ${view === "traffic" ? "is-traffic-frame" : ""}`}>
            {error && <MessageBar intent="error" layout="multiline"><MessageBarBody><MessageBarTitle>操作未完成</MessageBarTitle>{error}</MessageBarBody></MessageBar>}
            <div className={`view-stage ${view === "traffic" ? "is-traffic" : ""}`} key={view}>
              {view === "traffic" && renderTraffic()}
              {view === "findings" && renderFindings()}
              {view === "assets" && renderAssets()}
              {view === "active" && renderActive()}
              {view === "ai" && renderAI()}
              {view === "settings" && renderSettings()}
              {view === "runtime-logs" && renderRuntimeLogs()}
            </div>
          </div>
        </main>
        <Dialog open={trafficFilterOpen} onOpenChange={(_, data) => setTrafficFilterOpen(data.open)}>
          <DialogSurface className="advanced-settings-dialog advanced-settings-dialog-traffic">
            <DialogBody className="advanced-settings-dialog-body">
              <DialogTitle
                action={<Button appearance="subtle" aria-label="关闭 MITM 过滤规则" icon={<Dismiss20Regular />} onClick={() => setTrafficFilterOpen(false)} />}
                className="advanced-settings-dialog-title"
              >
                <span className="eyebrow">MITM 流量过滤</span>
                <span>过滤规则</span>
                <small>配置不参与日志记录、漏洞检测、指纹识别和主动探测的流量。</small>
              </DialogTitle>
              <DialogContent className="advanced-settings-dialog-content">
                <section className="advanced-settings-pane" aria-label="MITM 流量过滤规则">
                  <TrafficFilterPanel
                    busyAction={busyAction}
                    contentTypes={excludedContentTypesText}
                    domains={excludedDomainsText}
                    paths={excludedPathsText}
                    postParameters={excludedPostParametersText}
                    queryParameters={excludedQueryParametersText}
                    onContentTypesBlur={() => { excludedContentTypesFocusedRef.current = false; }}
                    onContentTypesChange={setExcludedContentTypesText}
                    onContentTypesFocus={() => { excludedContentTypesFocusedRef.current = true; }}
                    onContentTypesSave={saveExcludedContentTypes}
                    onDomainsBlur={() => { excludedDomainsFocusedRef.current = false; }}
                    onDomainsChange={setExcludedDomainsText}
                    onDomainsFocus={() => { excludedDomainsFocusedRef.current = true; }}
                    onDomainsSave={saveExcludedDomains}
                    onPathsBlur={() => { excludedPathsFocusedRef.current = false; }}
                    onPathsChange={setExcludedPathsText}
                    onPathsFocus={() => { excludedPathsFocusedRef.current = true; }}
                    onPathsSave={saveExcludedPaths}
                    onPostParametersBlur={() => { excludedPostParametersFocusedRef.current = false; }}
                    onPostParametersChange={setExcludedPostParametersText}
                    onPostParametersFocus={() => { excludedPostParametersFocusedRef.current = true; }}
                    onPostParametersSave={saveExcludedPostParameters}
                    onQueryParametersBlur={() => { excludedQueryParametersFocusedRef.current = false; }}
                    onQueryParametersChange={setExcludedQueryParametersText}
                    onQueryParametersFocus={() => { excludedQueryParametersFocusedRef.current = true; }}
                    onQueryParametersSave={saveExcludedQueryParameters}
                    onSuffixesBlur={() => { excludedSuffixesFocusedRef.current = false; }}
                    onSuffixesChange={setExcludedSuffixesText}
                    onSuffixesFocus={() => { excludedSuffixesFocusedRef.current = true; }}
                    onSuffixesSave={saveExcludedSuffixes}
                    suffixes={excludedSuffixesText}
                  />
                </section>
              </DialogContent>
              <DialogActions className="advanced-settings-dialog-actions">
                <Button appearance="subtle" onClick={() => setTrafficFilterOpen(false)}>关闭</Button>
              </DialogActions>
            </DialogBody>
          </DialogSurface>
        </Dialog>
        <Toaster className="app-toaster" position="bottom-end" toasterId={toasterId} />
      </div>
    </FluentProvider>
  );
}

export default App;

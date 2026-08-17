package report

import (
	"bytes"
	"fmt"
	"html/template"
	"sort"
	"strings"
	"time"

	"github.com/example/easyscan/internal/model"
)

type htmlReportData struct {
	GeneratedAt      string
	Findings         []model.Finding
	Fingerprints     []fingerprintRow
	FindingCount     int
	AssetCount       int
	FingerprintCount int
}

type fingerprintRow struct {
	Host      string
	Value     string
	URLs      int
	Endpoints int
	LastSeen  time.Time
}

func renderHTML(findings []model.Finding, assets []model.Asset) ([]byte, error) {
	data := htmlReportData{
		GeneratedAt:  time.Now().UTC().Format(time.RFC3339),
		Findings:     append([]model.Finding(nil), findings...),
		FindingCount: len(findings),
		AssetCount:   len(assets),
	}
	sort.SliceStable(data.Findings, func(i, j int) bool {
		if data.Findings[i].ObservedAt.Equal(data.Findings[j].ObservedAt) {
			if data.Findings[i].URL == data.Findings[j].URL {
				return data.Findings[i].RuleID < data.Findings[j].RuleID
			}
			return data.Findings[i].URL < data.Findings[j].URL
		}
		return data.Findings[i].ObservedAt.Before(data.Findings[j].ObservedAt)
	})
	for _, asset := range assets {
		for _, value := range asset.Fingerprints {
			value = displayFingerprint(value)
			if value == "" {
				continue
			}
			data.Fingerprints = append(data.Fingerprints, fingerprintRow{
				Host:      asset.Host,
				Value:     value,
				URLs:      len(asset.URLs),
				Endpoints: len(asset.Endpoints),
				LastSeen:  asset.LastSeen,
			})
		}
	}
	sort.Slice(data.Fingerprints, func(i, j int) bool {
		if data.Fingerprints[i].Host == data.Fingerprints[j].Host {
			return data.Fingerprints[i].Value < data.Fingerprints[j].Value
		}
		return data.Fingerprints[i].Host < data.Fingerprints[j].Host
	})
	data.FingerprintCount = len(data.Fingerprints)

	var output bytes.Buffer
	if err := offlineHTMLTemplate.Execute(&output, data); err != nil {
		return nil, fmt.Errorf("render HTML report: %w", err)
	}
	return output.Bytes(), nil
}

// displayFingerprint keeps report labels stable across snapshots written by
// older versions, which stored KScan results with a presentation-only prefix.
func displayFingerprint(value string) string {
	value = strings.TrimSpace(value)
	return strings.TrimSpace(strings.TrimPrefix(value, "KScan · "))
}

func formatReportTime(value time.Time) string {
	if value.IsZero() {
		return "-"
	}
	return value.Local().Format("2006-01-02 15:04:05 MST")
}

var offlineHTMLTemplate = template.Must(template.New("offline-report").Funcs(template.FuncMap{
	"formatTime": formatReportTime,
}).Parse(`<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>EasyScan 扫描报告</title>
  <style>
    :root { color-scheme: light dark; --bg:#f5f7fa; --panel:#fff; --ink:#172033; --muted:#667085; --line:#d9e0ea; --blue:#2166d1; --red:#b42318; }
    @media (prefers-color-scheme: dark) { :root { --bg:#111827; --panel:#182234; --ink:#eef3fc; --muted:#b2bfd1; --line:#34435a; --blue:#89b4ff; --red:#ffaaa1; } }
    * { box-sizing:border-box; } body { margin:0; background:var(--bg); color:var(--ink); font:14px/1.5 "Segoe UI",system-ui,sans-serif; }
    main { width:min(1180px, calc(100% - 32px)); margin:0 auto; padding:36px 0 56px; }
    header { display:flex; justify-content:space-between; gap:24px; align-items:end; margin-bottom:24px; } h1 { margin:0; font-size:30px; letter-spacing:-.03em; } h2 { margin:0; font-size:20px; } .generated { margin:5px 0 0; color:var(--muted); font-size:12px; } nav { display:flex; gap:8px; flex-wrap:wrap; } nav a { border:1px solid var(--line); border-radius:6px; color:var(--blue); padding:7px 10px; text-decoration:none; font-size:12px; }
    .summary { display:grid; grid-template-columns:repeat(3, minmax(0,1fr)); gap:12px; margin-bottom:18px; } .metric, section { border:1px solid var(--line); border-radius:9px; background:var(--panel); } .metric { padding:17px; } .metric small { color:var(--muted); display:block; } .metric strong { display:block; margin-top:4px; font-size:29px; line-height:1; }
    section { margin-top:18px; overflow:hidden; } .section-head { display:flex; justify-content:space-between; gap:12px; align-items:baseline; padding:17px 18px; border-bottom:1px solid var(--line); } .section-head p { margin:3px 0 0; color:var(--muted); font-size:12px; } .count { color:var(--muted); font-variant-numeric:tabular-nums; }
    .table-wrap { overflow:auto; } table { border-collapse:collapse; min-width:760px; width:100%; } th, td { padding:12px 16px; border-bottom:1px solid var(--line); text-align:left; vertical-align:top; } tr:last-child td { border-bottom:0; } th { background:color-mix(in srgb, var(--panel) 84%, var(--line)); color:var(--muted); font-size:11px; font-weight:650; letter-spacing:.05em; text-transform:uppercase; } code { font:12px/1.45 ui-monospace,SFMono-Regular,Consolas,monospace; overflow-wrap:anywhere; } .severity { display:inline-block; color:var(--red); font-weight:700; text-transform:uppercase; } .empty { padding:34px 18px; color:var(--muted); text-align:center; } .tags { display:flex; flex-wrap:wrap; gap:4px; margin-top:6px; } .tag { border:1px solid var(--line); border-radius:999px; color:var(--muted); font-size:11px; padding:1px 6px; }
    footer { color:var(--muted); font-size:12px; margin-top:18px; } @media(max-width:680px) { main { width:min(100% - 20px, 1180px); padding-top:22px; } header { align-items:start; flex-direction:column; } .summary { grid-template-columns:1fr; } }
  </style>
</head>
<body>
  <main>
    <header>
      <div><h1>EasyScan 扫描报告</h1><p class="generated">生成时间：{{.GeneratedAt}}</p></div>
      <nav aria-label="报告分区"><a href="#vulnerabilities">漏洞结果</a><a href="#fingerprints">指纹识别</a></nav>
    </header>
    <div class="summary" aria-label="报告概览">
      <article class="metric"><small>漏洞结果</small><strong>{{.FindingCount}}</strong></article>
      <article class="metric"><small>已观察资产</small><strong>{{.AssetCount}}</strong></article>
      <article class="metric"><small>指纹识别</small><strong>{{.FingerprintCount}}</strong></article>
    </div>
    <section id="vulnerabilities">
      <div class="section-head"><div><h2>漏洞结果</h2><p>按规则与 URL 去重后的被动发现。</p></div><span class="count">{{.FindingCount}} 条</span></div>
      {{if .Findings}}<div class="table-wrap"><table><thead><tr><th>风险</th><th>标题 / 规则</th><th>位置</th><th>说明</th><th>发现时间</th></tr></thead><tbody>{{range .Findings}}
        <tr><td><span class="severity">{{.Severity}}</span></td><td><strong>{{.Title}}</strong><br><code>{{.RuleID}}</code>{{if .Tags}}<div class="tags">{{range .Tags}}<span class="tag">{{.}}</span>{{end}}</div>{{end}}</td><td><code>{{.Method}} {{.URL}}</code></td><td>{{.Description}}</td><td>{{formatTime .ObservedAt}}</td></tr>{{end}}
      </tbody></table></div>{{else}}<div class="empty">暂无漏洞结果。</div>{{end}}
    </section>
    <section id="fingerprints">
      <div class="section-head"><div><h2>指纹识别</h2><p>基于已捕获流量的主机与产品/边缘服务指纹。</p></div><span class="count">{{.FingerprintCount}} 条</span></div>
      {{if .Fingerprints}}<div class="table-wrap"><table><thead><tr><th>主机</th><th>指纹</th><th>已观察 URL</th><th>接口</th><th>最后出现</th></tr></thead><tbody>{{range .Fingerprints}}
        <tr><td><code>{{.Host}}</code></td><td><code>{{.Value}}</code></td><td>{{.URLs}}</td><td>{{.Endpoints}}</td><td>{{formatTime .LastSeen}}</td></tr>{{end}}
      </tbody></table></div>{{else}}<div class="empty">暂无指纹识别结果。</div>{{end}}
    </section>
    <footer>EasyScan 本地离线 HTML 报告 · 不包含原始 HTTP 正文。</footer>
  </main>
</body>
</html>`))

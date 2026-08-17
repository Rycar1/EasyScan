package fingerprint

import (
	"sort"
	"strings"
	"testing"

	"github.com/example/easyscan/internal/model"
)

// fingerprintSample models one real-world system described by its publicly
// documented HTTP signals. Each sample mirrors what the engine would observe
// after passive capture plus the active favicon/root/404 probing added in the
// fingerprint probe: a set of responses (root page, a signature path, an error
// page, etc.) for the same host.
type fingerprintSample struct {
	system    string   // human label for reporting
	expect    []string // any one of these fingerprint names counts as a hit
	responses []model.Transaction
}

func resp(url string, status int, headers map[string]string, body string) model.Transaction {
	return model.Transaction{
		Request:  model.Message{Method: "GET", URL: url},
		Response: model.Message{Status: status, Headers: headers, Body: body},
	}
}

// fingerprintCorpus returns representative samples for common systems that
// EasyScan users scan: RuoYi, Shiro apps, PHP/Java CMS and other frameworks.
// Signals are drawn from public documentation and well-known fingerprints.
func fingerprintCorpus() []fingerprintSample {
	return []fingerprintSample{
		{
			system: "RuoYi (前后端分离)",
			expect: []string{"RuoYi", "若依"},
			responses: []model.Transaction{
				resp("https://t/", 200, map[string]string{"Content-Type": "text/html"},
					`<title>若依管理系统</title><div id="app"></div><script src="/static/js/app.js"></script>`),
				resp("https://t/prod-api/", 200, map[string]string{"Content-Type": "application/json"},
					`{"msg":"操作成功","code":200,"data":"RuoYi"}`),
			},
		},
		{
			system: "RuoYi (单体 Thymeleaf)",
			expect: []string{"RuoYi", "若依"},
			responses: []model.Transaction{
				resp("https://t/login", 200, map[string]string{"Content-Type": "text/html", "Set-Cookie": "JSESSIONID=abc; Path=/"},
					`<title>RuoYi若依后台管理系统</title><a href="http://ruoyi.vip">RuoYi</a><link href="/ruoyi/css/ry-ui.css"><script src="/ruoyi/js/ry-ui.js"></script>`),
			},
		},
		{
			system: "Apache Shiro",
			expect: []string{"Apache-Shiro", "Shiro"},
			responses: []model.Transaction{
				resp("https://t/", 200, map[string]string{"Content-Type": "text/html", "Set-Cookie": "rememberMe=deleteMe; Path=/; Max-Age=0"},
					`<html><body>login</body></html>`),
			},
		},
		{
			system: "WordPress",
			expect: []string{"WordPress", "wordpress"},
			responses: []model.Transaction{
				resp("https://t/", 200, map[string]string{"Content-Type": "text/html", "Link": "</wp-json/>; rel=\"https://api.w.org/\""},
					`<meta name="generator" content="WordPress 6.5.2" /><link rel="stylesheet" href="/wp-content/themes/x/style.css"><script src="/wp-includes/js/jquery.js"></script>`),
			},
		},
		{
			system: "DedeCMS",
			expect: []string{"DedeCMS", "dedecms", "Dede"},
			responses: []model.Transaction{
				resp("https://t/", 200, map[string]string{"Content-Type": "text/html"},
					`<meta name="generator" content="DedeCMS" /><script src="/include/dedeajax2.js"></script><a href="/data/">power by DedeCms</a>`),
			},
		},
		{
			system: "ThinkPHP",
			expect: []string{"ThinkPHP"},
			responses: []model.Transaction{
				resp("https://t/", 200, map[string]string{"Content-Type": "text/html", "X-Powered-By": "ThinkPHP"},
					`<html>ThinkPHP</html>`),
				resp("https://t/index.php?s=/x", 404, map[string]string{"Content-Type": "text/html"},
					`<title>系统发生错误</title><div>ThinkPHP V5</div>`),
			},
		},
		{
			system: "PHPCMS",
			expect: []string{"PHPCMS", "phpcms"},
			responses: []model.Transaction{
				resp("https://t/", 200, map[string]string{"Content-Type": "text/html", "Set-Cookie": "PHPSESSID=x; _c_userid=1"},
					`<script src="/statics/js/common.js"></script><a href="/index.php?m=content">Powered by PHPCMS</a>`),
			},
		},
		{
			system: "Drupal",
			expect: []string{"Drupal"},
			responses: []model.Transaction{
				resp("https://t/", 200, map[string]string{"Content-Type": "text/html", "X-Generator": "Drupal 10 (https://www.drupal.org)"},
					`<meta name="Generator" content="Drupal 10"><script src="/sites/default/files/x.js"></script>`),
			},
		},
		{
			system: "Joomla",
			expect: []string{"Joomla"},
			responses: []model.Transaction{
				resp("https://t/", 200, map[string]string{"Content-Type": "text/html"},
					`<meta name="generator" content="Joomla! - Open Source Content Management" /><script src="/media/jui/js/x.js"></script>`),
			},
		},
		{
			system: "Nacos",
			expect: []string{"Nacos"},
			responses: []model.Transaction{
				resp("https://t/nacos/", 200, map[string]string{"Content-Type": "text/html"},
					`<title>Nacos</title><script src="console-ui/public/js/merge.js"></script>`),
			},
		},
		{
			system: "通达 OA (Tongda)",
			expect: []string{"Tongda", "通达"},
			responses: []model.Transaction{
				resp("https://t/", 200, map[string]string{"Content-Type": "text/html"},
					`<title>Office Anywhere 网络智能办公系统</title><script src="/static/js/tongda.js"></script>`),
			},
		},
		{
			system: "泛微 e-cology",
			expect: []string{"Weaver", "e-cology", "泛微", "Ecology"},
			responses: []model.Transaction{
				resp("https://t/", 200, map[string]string{"Content-Type": "text/html", "Set-Cookie": "ecology_JSessionid=x"},
					`<script src="/wui/index.html"></script><a>weaver ecology</a>`),
			},
		},
		{
			system: "致远 Seeyon OA",
			expect: []string{"Seeyon", "致远"},
			responses: []model.Transaction{
				resp("https://t/seeyon/", 200, map[string]string{"Content-Type": "text/html"},
					`<title>致远A8协同管理软件</title><script src="/seeyon/common/js/x.js"></script>`),
			},
		},
		{
			system: "Spring Boot Actuator",
			expect: []string{"Spring", "Spring Boot", "Actuator"},
			responses: []model.Transaction{
				resp("https://t/actuator", 200, map[string]string{"Content-Type": "application/vnd.spring-boot.actuator.v3+json"},
					`{"_links":{"self":{"href":"http://t/actuator"},"health":{"href":"http://t/actuator/health"}}}`),
			},
		},
		{
			system: "Apache Tomcat",
			expect: []string{"Tomcat", "Apache Tomcat"},
			responses: []model.Transaction{
				resp("https://t/", 404, map[string]string{"Content-Type": "text/html", "Server": "Apache-Coyote/1.1"},
					`<h1>HTTP Status 404 – Not Found</h1><h3>Apache Tomcat/9.0.71</h3>`),
			},
		},
		{
			system: "Jenkins",
			expect: []string{"Jenkins"},
			responses: []model.Transaction{
				resp("https://t/", 403, map[string]string{"Content-Type": "text/html", "X-Jenkins": "2.440.1", "X-Hudson": "1.395"},
					`<title>Dashboard [Jenkins]</title><body>jenkins.model.Jenkins</body>`),
			},
		},
		{
			system: "Grafana",
			expect: []string{"Grafana"},
			responses: []model.Transaction{
				resp("https://t/", 200, map[string]string{"Content-Type": "text/html"},
					`<title>Grafana</title><div class="grafana-app"></div><script>window.grafanaBootData={}</script>`),
			},
		},
		{
			system: "GitLab",
			expect: []string{"GitLab"},
			responses: []model.Transaction{
				resp("https://t/", 200, map[string]string{"Content-Type": "text/html", "Set-Cookie": "_gitlab_session=x"},
					`<meta content="GitLab" property="og:site_name"><body data-page="sessions:new">`),
			},
		},
		{
			system: "Weaver e-cology (泛微)",
			expect: []string{"Weaver e-cology", "e-cology"},
			responses: []model.Transaction{
				resp("https://t/", 200, map[string]string{"Content-Type": "text/html", "Set-Cookie": "ecology_JSessionId=abc; Path=/"},
					`<link href="/wui/common/css/w7ovfont.css"><script src="/theme/ecology8/jquery/js/zdialog_wev8.js"></script>`),
			},
		},
		{
			system: "Landray OA (蓝凌)",
			expect: []string{"Landray"},
			responses: []model.Transaction{
				resp("https://t/", 200, map[string]string{"Content-Type": "text/html"},
					`<script src="/scripts/jquery.landray.common.js"></script><div id="lui_login_message_td">蓝凌软件</div>`),
			},
		},
		{
			system: "Yonyou NC (用友)",
			expect: []string{"Yonyou NC"},
			responses: []model.Transaction{
				resp("https://t/", 200, map[string]string{"Content-Type": "text/html"},
					`<a href="/nc/servlet/nc.ui.iufo.login.index"><img src="logo/images/ufida_nc.png"></a>`),
			},
		},
		{
			system: "Kingdee (金蝶)",
			expect: []string{"Kingdee"},
			responses: []model.Transaction{
				resp("https://t/", 200, map[string]string{"Content-Type": "text/html", "Set-Cookie": "EASSESSIONID=x"},
					`<div>金蝶国际软件集团有限公司版权所有</div><img src="logo-kingdee.png">`),
			},
		},
		{
			system: "FineReport (帆软)",
			expect: []string{"FineReport"},
			responses: []model.Transaction{
				resp("https://t/webroot/decision/login", 200, map[string]string{"Content-Type": "text/html"},
					`<meta name="generator" content="FineReport--web reporting tool"><a href="/ReportServer">rs</a>`),
			},
		},
		{
			system: "Sangfor (深信服)",
			expect: []string{"Sangfor"},
			responses: []model.Transaction{
				resp("https://t/", 200, map[string]string{"Content-Type": "text/html"},
					`<a href="/por/login_psw.csp">login</a><script src="http://sec.sangfor.com.cn/x.js"></script>`),
			},
		},
		{
			system: "Ruijie (锐捷)",
			expect: []string{"Ruijie"},
			responses: []model.Transaction{
				resp("https://t/", 200, map[string]string{"Content-Type": "text/html", "Server": "RGOS Http-Server"},
					`<span class="resource" mark="login.copyright">锐捷网络</span>`),
			},
		},
		{
			system: "Portainer",
			expect: []string{"Portainer"},
			responses: []model.Transaction{
				resp("https://t/", 200, map[string]string{"Content-Type": "text/html"},
					`<title>Portainer</title><body ng-app="portainer"></body>`),
			},
		},
		{
			system: "Kong Gateway",
			expect: []string{"Kong"},
			responses: []model.Transaction{
				resp("https://t/", 404, map[string]string{"Content-Type": "application/json", "Server": "kong/3.4.0", "X-Kong-Response-Latency": "1"},
					`{"message":"no Route matched"}`),
			},
		},
		{
			system: "Nexus Repository",
			expect: []string{"Nexus"},
			responses: []model.Transaction{
				resp("https://t/", 200, map[string]string{"Content-Type": "text/html", "Server": "Nexus/3.61.0"},
					`<title>Nexus Repository Manager</title>`),
			},
		},
		{
			system: "Ollama",
			expect: []string{"Ollama"},
			responses: []model.Transaction{
				resp("https://t/", 200, map[string]string{"Content-Type": "text/plain"},
					`Ollama is running`),
			},
		},
		{
			system: "Argo CD",
			expect: []string{"Argo CD"},
			responses: []model.Transaction{
				resp("https://t/api/version", 200, map[string]string{"Content-Type": "application/json", "grpc-metadata-content-type": "application/grpc"},
					`{"Version":"v2.9.0"}`),
			},
		},
		{
			system: "Kubernetes Dashboard",
			expect: []string{"Kubernetes Dashboard"},
			responses: []model.Transaction{
				resp("https://t/", 200, map[string]string{"Content-Type": "text/html"},
					`<title>Kubernetes Dashboard</title><img src="assets/images/kubernetes-logo.png">`),
			},
		},
		{
			system: "KubeSphere",
			expect: []string{"KubeSphere"},
			responses: []model.Transaction{
				resp("https://t/", 200, map[string]string{"Content-Type": "text/html"},
					`<title>KubeSphere</title><a href="https://kubesphere.io">docs</a>`),
			},
		},
		{
			system: "HashiCorp Vault",
			expect: []string{"HashiCorp Vault"},
			responses: []model.Transaction{
				resp("https://t/ui/vault/auth", 200, map[string]string{"Content-Type": "text/html"},
					`<meta name="vault/config/environment" content="{}">`),
			},
		},
		{
			system: "Keycloak",
			expect: []string{"Keycloak"},
			responses: []model.Transaction{
				resp("https://t/", 200, map[string]string{"Content-Type": "text/html"},
					`<div class="kc-form-buttons"><span>Keycloak</span></div>`),
			},
		},
		{
			system: "HFish Honeypot",
			expect: []string{"HFish Honeypot"},
			responses: []model.Transaction{
				resp("https://t/", 200, map[string]string{"Content-Type": "text/html"},
					`<title>HFish</title><img src="/static/images/hfish.png"><a href="https://github.com/hacklcx/hfish">gh</a>`),
			},
		},
		{
			system: "T-Pot Honeypot",
			expect: []string{"T-Pot Honeypot"},
			responses: []model.Transaction{
				resp("https://t/", 200, map[string]string{"Content-Type": "text/html"},
					`<title>T-Pot</title><a>T-Pot @ Github</a><a>T-Pot ReadMe</a>`),
			},
		},
		{
			system: "Hillstone 防火墙",
			expect: []string{"Hillstone"},
			responses: []model.Transaction{
				resp("https://t/", 200, map[string]string{"Content-Type": "text/html"},
					`<html><head><title>Login</title></head><body>Hillstone StoneOS Software Version 5.5R7<link href="resources/login-all.css"></body></html>`),
			},
		},
		{
			system: "NSFOCUS 绿盟",
			expect: []string{"NSFOCUS"},
			responses: []model.Transaction{
				resp("https://t/", 200, map[string]string{"Content-Type": "text/html"},
					`<img src="/login_logo_espc_zh_cn.png"><span>绿盟科技企业安全中心</span>`),
			},
		},
		{
			system: "天融信 Topsec",
			expect: []string{"Topsec"},
			responses: []model.Transaction{
				resp("https://t/", 200, map[string]string{"Content-Type": "text/html"},
					`<div>天融信数据防泄漏系统</div>`),
			},
		},
		{
			system: "奇安信 QiAnXin",
			expect: []string{"QiAnXin"},
			responses: []model.Transaction{
				resp("https://t/", 200, map[string]string{"Content-Type": "text/html"},
					`<div class="login">奇安信新天擎</div>`),
			},
		},
		{
			system: "启明星辰 Venustech",
			expect: []string{"Venustech"},
			responses: []model.Transaction{
				resp("https://t/", 200, map[string]string{"Content-Type": "text/html"},
					`<title>天清汉马USG防火墙</title>`),
			},
		},
		{
			system: "Hikvision iVMS",
			expect: []string{"Hikvision iVMS"},
			responses: []model.Transaction{
				resp("https://t/", 200, map[string]string{"Content-Type": "text/html"},
					`杭州海康威视系统技术有限公司 版权所有`),
			},
		},
		{
			system: "n8n",
			expect: []string{"n8n"},
			responses: []model.Transaction{
				resp("https://t/signin", 200, map[string]string{"Content-Type": "text/html"},
					`<title>n8n.io - Workflow Automation</title>`),
			},
		},
		{
			system: "Node-RED",
			expect: []string{"Node-RED"},
			responses: []model.Transaction{
				resp("https://t/", 200, map[string]string{"Content-Type": "text/html"},
					`<title>Node-RED</title>`),
			},
		},
		{
			system: "Camunda",
			expect: []string{"Camunda"},
			responses: []model.Transaction{
				resp("https://t/app/welcome/default/", 200, map[string]string{"Content-Type": "text/html"},
					`<div>Camunda Welcome</div><footer cam-widget-footer version="v7.15">`),
			},
		},
		{
			system: "Appsmith",
			expect: []string{"Appsmith"},
			responses: []model.Transaction{
				resp("https://t/user/login", 200, map[string]string{"Content-Type": "text/html"},
					`<title>Appsmith</title>`),
			},
		},
		{
			system: "ClickHouse",
			expect: []string{"ClickHouse"},
			responses: []model.Transaction{
				resp("https://t/", 200, map[string]string{"Content-Type": "text/tab-separated-values", "X-ClickHouse-Summary": `{"read_rows":"0","read_bytes":"0"}`},
					"default\nsystem\n"),
			},
		},
		{
			system: "Neo4j",
			expect: []string{"Neo4j"},
			responses: []model.Transaction{
				resp("https://t/browser/", 200, map[string]string{"Content-Type": "text/html"},
					`<title>Neo4j Browser</title>`),
			},
		},
		{
			system: "Hue",
			expect: []string{"Hue"},
			responses: []model.Transaction{
				resp("https://t/", 200, map[string]string{"Content-Type": "text/html"},
					`<script>jHueHdfsTreeGlobals={};</script>`),
			},
		},
		{
			system: "Apache Zeppelin",
			expect: []string{"Apache Zeppelin"},
			responses: []model.Transaction{
				resp("https://t/", 200, map[string]string{"Content-Type": "text/html"},
					`<title ng-bind="$root.pageTitle">Zeppelin</title>`),
			},
		},
	}
}

func TestFingerprintRecognitionRateOnCommonSystems(t *testing.T) {
	database, err := LoadHFinger(t.TempDir(), 40)
	if err != nil {
		t.Fatal(err)
	}
	corpus := fingerprintCorpus()
	hits := 0
	var missed []string
	for _, sample := range corpus {
		matches := database.MatchDetailsMulti(sample.responses, true, true)
		names := make([]string, 0, len(matches))
		for _, m := range matches {
			names = append(names, m.Name)
		}
		if anyExpectedMatched(sample.expect, names) {
			hits++
			t.Logf("[HIT ] %-28s -> %v", sample.system, names)
		} else {
			missed = append(missed, sample.system)
			t.Logf("[MISS] %-28s expected any of %v, got %v", sample.system, sample.expect, names)
		}
	}
	rate := float64(hits) / float64(len(corpus)) * 100
	sort.Strings(missed)
	t.Logf("=== 指纹识别率: %d/%d = %.1f%% ===", hits, len(corpus), rate)
	if len(missed) > 0 {
		t.Logf("=== 未命中系统 (%d): %v ===", len(missed), missed)
	}
	// Guardrail: this corpus covers systems the ruleset ships passive rules
	// for, so a large regression should fail CI. The corpus currently reaches
	// 100%; keep a conservative floor to absorb future rule churn.
	if rate < 90 {
		t.Fatalf("指纹识别率过低: %.1f%% (命中 %d/%d)，疑似规则回归", rate, hits, len(corpus))
	}
}

func anyExpectedMatched(expected, got []string) bool {
	for _, want := range expected {
		for _, name := range got {
			if strings.Contains(strings.ToLower(name), strings.ToLower(want)) {
				return true
			}
		}
	}
	return false
}

package sqlprobe

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/example/easyscan/internal/config"
	"github.com/example/easyscan/internal/engine"
	"github.com/example/easyscan/internal/model"
)

type testPolicy struct {
	error       bool
	boolean     bool
	timing      bool
	maxRequests int
	maxParams   int
	qps         int
}

func (testPolicy) Enabled(string) bool        { return true }
func (p testPolicy) SQLiErrorEnabled() bool   { return p.error }
func (p testPolicy) SQLiBooleanEnabled() bool { return p.boolean }
func (p testPolicy) SQLiTimeEnabled() bool    { return p.timing }
func (p testPolicy) PassiveSQLiProbeQPS() int {
	if p.qps > 0 {
		return p.qps
	}
	return 20
}
func (p testPolicy) PassiveSQLiMaxRequests() int {
	if p.maxRequests > 0 {
		return p.maxRequests
	}
	return 30
}
func (p testPolicy) PassiveSQLiMaxParameters() int {
	if p.maxParams > 0 {
		return p.maxParams
	}
	return 5
}

func TestObserveHTTPProxyDetectsSQLiLabStyleError(t *testing.T) {
	const normalBody = `<html><body><h1>Welcome</h1><p>Your Login name:Dumb</p><p>Your Password:Dumb</p></body></html>`
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		value := request.URL.Query().Get("id")
		writer.Header().Set("Content-Type", "text/html")
		if strings.HasSuffix(value, "'") {
			_, _ = writer.Write([]byte(normalBody + `<font>You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version near '` + value + `'</font>`))
			return
		}
		_, _ = writer.Write([]byte(normalBody))
	}))
	defer server.Close()

	cfg := config.Default()
	cfg.Scope.AllowHosts = []string{"127.0.0.1"}
	cfg.Scope.AllowPrivateIPs = true
	probeEngine, err := engine.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	worker := New(cfg, probeEngine, testPolicy{error: true})
	defer func() { _ = worker.Shutdown(context.Background()) }()

	worker.Observe(model.Transaction{
		Observed: time.Now().UTC(),
		Source:   model.SourceHTTPProxy,
		Request:  model.Message{Method: http.MethodGet, URL: server.URL + "/Less-1/?id=1"},
		Response: model.Message{Status: http.StatusOK, Headers: map[string]string{"Content-Type": "text/html"}, Body: normalBody},
	})

	findings := waitForFindings(t, probeEngine, 3*time.Second)
	if len(findings) != 1 || !strings.HasPrefix(findings[0].RuleID, "passive.sqli-probe.query.") || !strings.Contains(findings[0].Evidence, "sql-error") {
		t.Fatalf("expected one HTTP proxy SQL finding, got %#v", findings)
	}
	evidence := probeEngine.EvidenceForFinding(findings[0].ID)
	if len(evidence) < 4 {
		t.Fatalf("expected original, control, probe, and replay packets, got %#v", evidence)
	}
	if evidence[0].Source != model.SourceHTTPProxy || !strings.Contains(evidence[0].Request, "id=1") {
		t.Fatalf("original packet missing from finding evidence: %#v", evidence[0])
	}
	if !strings.Contains(evidence[2].Source, "sqli-probe.error") || !strings.Contains(evidence[2].Request, "%27") || !strings.Contains(evidence[2].Response, "SQL syntax") {
		t.Fatalf("probe request/response missing from finding evidence: %#v", evidence[2])
	}
	if !strings.HasSuffix(evidence[3].Source, ".replay") {
		t.Fatalf("replay packet missing from finding evidence: %#v", evidence[3])
	}
}

func TestBooleanValuePairsCoverQuotedNumericSQL(t *testing.T) {
	pairs := booleanValuePairs("1")
	foundQuoted := false
	foundParenthesized := false
	for _, pair := range pairs {
		if pair.context == "single-quoted" && pair.trueValue == "1' AND '1'='1' -- " && pair.falseValue == "1' AND '1'='2' -- " {
			foundQuoted = true
		}
		if pair.context == "numeric-double-parenthesized" && strings.Contains(pair.trueValue, ")) AND ((1=1))") {
			foundParenthesized = true
		}
	}
	if !foundQuoted || !foundParenthesized {
		t.Fatalf("quoted or parenthesized SQL context missing: %#v", pairs)
	}
}

func TestOrderByValuePairsCoverQuotedAndUnquotedContexts(t *testing.T) {
	pairs := orderByValuePairs("1")
	contexts := make(map[string]orderByValuePair, len(pairs))
	for _, pair := range pairs {
		contexts[pair.context] = pair
	}
	for _, contextName := range []string{"numeric", "numeric-parenthesized", "numeric-double-parenthesized", "single-quoted", "single-quoted-parenthesized", "double-quoted", "double-quoted-parenthesized"} {
		pair, exists := contexts[contextName]
		if !exists || !strings.Contains(pair.validValue, "ORDER BY 1") || !strings.Contains(pair.invalidValue, "ORDER BY 999999") {
			t.Fatalf("ORDER BY context %s missing: %#v", contextName, pairs)
		}
	}
}

func TestHasSQLErrorRecognizesMicrosoftSQLServerFingerprints(t *testing.T) {
	positives := []string{
		`System.Data.SqlClient.SqlException: Incorrect syntax near ')'`,
		`Msg 170, Level 15, State 1, Line 1: Incorrect syntax near ')'.`,
		`Microsoft SQL Server error occurred while executing the query.`,
		`Microsoft OLE DB Provider for ODBC Drivers error '80040e14'`,
		`[Microsoft][ODBC SQL Server Driver][SQL Server]Unclosed quotation mark`,
		`[SQL Server]Conversion failed when converting the varchar value 'abc' to data type int.`,
		`com.microsoft.sqlserver.jdbc.SQLServerException: Invalid column name 'foo'.`,
		`Warning: mssql_query(): SQL Server message: syntax error`,
		`Must declare the scalar variable "@id".`,
		`The multi-part identifier "users.id" could not be bound.`,
		`Arithmetic overflow error converting expression to data type int.`,
		`Divide by zero error encountered.`,
		`String or binary data would be truncated.`,
	}
	for _, body := range positives {
		if !hasSQLError(body) {
			t.Errorf("expected SQL Server fingerprint to match: %q", body)
		}
	}
	negatives := []string{
		`<html><body>Welcome to the site.</body></html>`,
		`{"status":"ok","message":"Query completed"}`,
		`Request blocked by web application firewall`,
	}
	for _, body := range negatives {
		if hasSQLError(body) {
			t.Errorf("benign body must not match SQL error pattern: %q", body)
		}
	}
}

func TestPerParameterBudgetDistributesAcrossParameters(t *testing.T) {
	for _, test := range []struct {
		name        string
		totalBudget int
		paramCount  int
		wantMin     int
		wantMax     int
	}{
		{name: "single-param-gets-full-budget", totalBudget: 36, paramCount: 1, wantMin: 36, wantMax: 36},
		{name: "multi-param-each-gets-share", totalBudget: 36, paramCount: 3, wantMin: 12, wantMax: 12},
		{name: "budget-clamped-to-minimum", totalBudget: 4, paramCount: 3, wantMin: 3, wantMax: 3},
		{name: "zero-params-returns-zero", totalBudget: 36, paramCount: 0, wantMin: 0, wantMax: 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := perParameterBudget(test.totalBudget, test.paramCount)
			if got < test.wantMin || got > test.wantMax {
				t.Fatalf("perParameterBudget(%d, %d) = %d, want [%d, %d]", test.totalBudget, test.paramCount, got, test.wantMin, test.wantMax)
			}
		})
	}
}

func TestPerParameterBudgetGuaranteesPerParamMinimum(t *testing.T) {
	got := perParameterBudget(10, 3)
	if got < 3 {
		t.Fatalf("each parameter must get at least minimumRequests (3), got %d", got)
	}
}

func TestExtractCandidatesPrioritizesNestedAndEncodedJSON(t *testing.T) {
	jsonValue := url.QueryEscape(`{"uid":1,"id":"1"}`)
	encodedValue := url.QueryEscape(base64.StdEncoding.EncodeToString([]byte(`{"uid":1,"id":"1"}`)))
	for _, test := range []struct {
		name     string
		target   string
		location string
	}{
		{name: "query-json", target: "https://app.example.test/user/id-json?id=" + jsonValue, location: "query-json"},
		{name: "query-base64-json", target: "https://app.example.test/user/id-b64-json?id=" + encodedValue, location: "query-base64-json"},
	} {
		t.Run(test.name, func(t *testing.T) {
			items := extractCandidates(model.Transaction{Request: model.Message{Method: http.MethodGet, URL: test.target}})
			if len(items) != 2 || items[0].name != "id.id" || items[0].value != "1" || items[0].location != test.location {
				t.Fatalf("nested id candidate was not prioritized: %#v", items)
			}
			request, err := buildRequest(context.Background(), model.Transaction{Request: model.Message{Method: http.MethodGet, URL: test.target}}, items[0], "1 AND 1=2")
			if err != nil {
				t.Fatal(err)
			}
			raw := request.URL.Query().Get("id")
			if test.location == "query-base64-json" {
				decoded, ok := decodeBase64(raw)
				if !ok {
					t.Fatalf("mutated parameter is not valid base64: %q", raw)
				}
				raw = string(decoded)
			}
			var document map[string]any
			if err := json.Unmarshal([]byte(raw), &document); err != nil {
				t.Fatal(err)
			}
			if document["id"] != "1 AND 1=2" || document["uid"] != float64(1) {
				t.Fatalf("nested JSON mutation damaged the container: %#v", document)
			}
		})
	}
}

func TestBuildRequestMutatesNestedJSONHeaderAndPathCandidates(t *testing.T) {
	tx := model.Transaction{Request: model.Message{
		Method: http.MethodPost,
		URL:    "https://app.example.test/user/path/admin",
		Headers: map[string]string{
			"Content-Type": "application/json",
			"Referer":      "https://source.example.test/visitor/reference",
		},
		Body: `{"filters":[{"name":"admin"}],"keep":true}`,
	}}
	items := extractCandidates(tx)
	var jsonItem candidate
	for _, item := range items {
		if item.location == "json" && item.name == "filters[0].name" {
			jsonItem = item
			break
		}
	}
	if jsonItem.name == "" {
		t.Fatalf("nested JSON body candidate missing: %#v", items)
	}
	request, err := buildRequest(context.Background(), tx, jsonItem, "admin' -- ")
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(request.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), `"name":"admin' -- "`) || !strings.Contains(string(body), `"keep":true`) {
		t.Fatalf("nested JSON request body was not preserved: %s", body)
	}

	headerRequest, err := buildRequest(context.Background(), tx, candidate{name: "Referer", location: "header", headerName: "Referer"}, "https://source.example.test/visitor/reference' -- ")
	if err != nil || !strings.HasSuffix(headerRequest.Header.Get("Referer"), "' -- ") {
		t.Fatalf("header candidate mutation failed: request=%#v err=%v", headerRequest, err)
	}
	pathRequest, err := buildRequest(context.Background(), tx, candidate{name: "path.segment", location: "path"}, "admin' -- ")
	if err != nil || !strings.Contains(pathRequest.URL.String(), "admin%27%20--%20") {
		t.Fatalf("path candidate mutation failed: request=%#v err=%v", pathRequest, err)
	}
}

func TestCandidateSpecificLikeAndOrderTemplates(t *testing.T) {
	likePairs := orderedBooleanValuePairs(candidate{value: "a", contextHint: "like"}, nil)
	if len(likePairs) == 0 || likePairs[0].context != "like-single-quoted" || !strings.Contains(likePairs[0].trueValue, "a%'") {
		t.Fatalf("LIKE-preserving template missing: %#v", likePairs)
	}
	orderPairs := orderedOrderByValuePairs(candidate{name: "order", value: "desc"}, nil)
	if len(orderPairs) == 0 || orderPairs[0].context != "order-direction" || !strings.Contains(orderPairs[0].invalidValue, "missing_column") {
		t.Fatalf("ORDER direction template missing: %#v", orderPairs)
	}
	fieldPairs := orderedOrderByValuePairs(candidate{name: "orderby", value: "username"}, nil)
	if len(fieldPairs) == 0 || fieldPairs[0].context != "orderby-field" || fieldPairs[0].validValue != "username" {
		t.Fatalf("ORDER BY field template missing: %#v", fieldPairs)
	}
}

func TestBooleanSwitchDetectsBooleanDifferential(t *testing.T) {
	const normalBody = `<html><body><h1>Welcome</h1><p>Account record is present.</p></body></html>`
	const falseBody = `<html><body><h1>Welcome</h1><p>No account matched the supplied condition.</p></body></html>`
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "text/html")
		if strings.Contains(request.URL.Query().Get("id"), "1=2") {
			_, _ = writer.Write([]byte(falseBody))
			return
		}
		_, _ = writer.Write([]byte(normalBody))
	}))
	defer server.Close()

	makeEngine := func() (*engine.Engine, config.Config) {
		cfg := config.Default()
		cfg.Scope.AllowHosts = []string{"127.0.0.1"}
		cfg.Scope.AllowPrivateIPs = true
		probeEngine, err := engine.New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		return probeEngine, cfg
	}
	transaction := model.Transaction{
		Observed: time.Now().UTC(),
		Source:   model.SourceHTTPProxy,
		Request:  model.Message{Method: http.MethodGet, URL: server.URL + "/Less-8/?id=1"},
		Response: model.Message{Status: http.StatusOK, Headers: map[string]string{"Content-Type": "text/html"}, Body: normalBody},
	}

	errorOnlyEngine, errorOnlyConfig := makeEngine()
	errorOnlyWorker := New(errorOnlyConfig, errorOnlyEngine, testPolicy{error: true, maxRequests: 12})
	errorOnlyWorker.Observe(transaction)
	time.Sleep(500 * time.Millisecond)
	if findings := errorOnlyEngine.Findings(); len(findings) != 0 {
		t.Fatalf("error-only mode must not report a boolean-only target: %#v", findings)
	}
	_ = errorOnlyWorker.Shutdown(context.Background())

	booleanEngine, booleanConfig := makeEngine()
	booleanWorker := New(booleanConfig, booleanEngine, testPolicy{boolean: true, maxRequests: 20})
	defer func() { _ = booleanWorker.Shutdown(context.Background()) }()
	booleanWorker.Observe(transaction)
	findings := waitForFindings(t, booleanEngine, 3*time.Second)
	if len(findings) != 1 || !strings.Contains(findings[0].Evidence, "boolean-differential") {
		t.Fatalf("boolean switch expected a differential finding, got %#v", findings)
	}
}

func TestBooleanSwitchDetectsOrderByDifferential(t *testing.T) {
	const normalBody = `<html><body><h1>Products</h1><p>Three rows returned.</p></body></html>`
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "text/html")
		if strings.Contains(request.URL.Query().Get("id"), "ORDER BY 999999") {
			_, _ = writer.Write([]byte(normalBody + `<p>Unknown column '999999' in 'order clause'</p>`))
			return
		}
		_, _ = writer.Write([]byte(normalBody))
	}))
	defer server.Close()

	cfg := config.Default()
	cfg.Scope.AllowHosts = []string{"127.0.0.1"}
	cfg.Scope.AllowPrivateIPs = true
	probeEngine, err := engine.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	worker := New(cfg, probeEngine, testPolicy{boolean: true, maxRequests: 36})
	defer func() { _ = worker.Shutdown(context.Background()) }()
	worker.Observe(model.Transaction{
		Observed: time.Now().UTC(),
		Source:   model.SourceHTTPProxy,
		Request:  model.Message{Method: http.MethodGet, URL: server.URL + "/products?id=1"},
		Response: model.Message{Status: http.StatusOK, Headers: map[string]string{"Content-Type": "text/html"}, Body: normalBody},
	})

	findings := waitForFindings(t, probeEngine, 4*time.Second)
	if len(findings) != 1 || !strings.Contains(findings[0].Evidence, "order-by-differential") {
		t.Fatalf("expected an ORDER BY differential finding, got %#v", findings)
	}
	evidence := probeEngine.EvidenceForFinding(findings[0].ID)
	if len(evidence) < 5 || !strings.Contains(evidence[3].Request, "ORDER+BY+999999") || !strings.Contains(evidence[3].Response, "order clause") {
		t.Fatalf("ORDER BY probe request/response missing: %#v", evidence)
	}
}

func TestTimeSwitchDetectsTimeDifferential(t *testing.T) {
	const normalBody = `<html><body><h1>Welcome</h1><p>The response body stays constant.</p></body></html>`
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		value := request.URL.Query().Get("id")
		if strings.Contains(value, "IF(1=1,SLEEP(2.0),0)") {
			time.Sleep(timeProbeDelay)
		}
		writer.Header().Set("Content-Type", "text/html")
		_, _ = writer.Write([]byte(normalBody))
	}))
	defer server.Close()

	cfg := config.Default()
	cfg.Scope.AllowHosts = []string{"127.0.0.1"}
	cfg.Scope.AllowPrivateIPs = true
	probeEngine, err := engine.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	worker := New(cfg, probeEngine, testPolicy{timing: true, maxRequests: 36, maxParams: 3, qps: 20})
	defer func() { _ = worker.Shutdown(context.Background()) }()
	worker.Observe(model.Transaction{
		Observed: time.Now().UTC(),
		Source:   model.SourceHTTPProxy,
		Request:  model.Message{Method: http.MethodGet, URL: server.URL + "/Less-9/?id=1"},
		Response: model.Message{Status: http.StatusOK, Headers: map[string]string{"Content-Type": "text/html"}, Body: normalBody},
	})

	findings := waitForFindings(t, probeEngine, 15*time.Second)
	if len(findings) != 1 || !strings.Contains(findings[0].Evidence, "time-differential") {
		t.Fatalf("time switch expected a timing differential finding, got %#v", findings)
	}
}

func TestLiveSQLiLabMITMProbe(t *testing.T) {
	rawTarget := strings.TrimSpace(os.Getenv("EASYSCAN_SQLI_LAB_URL"))
	if rawTarget == "" {
		t.Skip("set EASYSCAN_SQLI_LAB_URL to run the local SQLi-lab regression")
	}
	parsed, err := url.Parse(rawTarget)
	if err != nil || parsed.Hostname() == "" {
		t.Fatalf("invalid EASYSCAN_SQLI_LAB_URL %q", rawTarget)
	}
	response, err := http.Get(rawTarget) // #nosec G107 -- explicit opt-in local integration target
	if err != nil {
		t.Fatal(err)
	}
	body, readErr := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if readErr != nil {
		t.Fatal(readErr)
	}

	cfg := config.Default()
	cfg.Scope.AllowHosts = []string{parsed.Hostname()}
	cfg.Scope.AllowPrivateIPs = true
	probeEngine, err := engine.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	worker := New(cfg, probeEngine, testPolicy{error: true, boolean: true, timing: true})
	defer func() { _ = worker.Shutdown(context.Background()) }()
	worker.Observe(model.Transaction{
		Observed: time.Now().UTC(),
		Source:   model.SourceHTTPProxy,
		Request:  model.Message{Method: http.MethodGet, URL: rawTarget},
		Response: model.Message{Status: response.StatusCode, Headers: map[string]string{"Content-Type": response.Header.Get("Content-Type")}, Body: string(body)},
	})

	findings := waitForFindings(t, probeEngine, 4*time.Second)
	if len(findings) == 0 {
		t.Fatal("SQLi-lab target produced no MITM SQL finding")
	}
	t.Logf("detected %s: %s", findings[0].RuleID, findings[0].Evidence)
}

func TestLiveSQLiLabFirst15ByTechnique(t *testing.T) {
	baseURL := strings.TrimRight(strings.TrimSpace(os.Getenv("EASYSCAN_SQLI_LAB_BASE")), "/")
	if baseURL == "" {
		t.Skip("set EASYSCAN_SQLI_LAB_BASE to run the Less-1 through Less-15 regression")
	}
	parsedBase, err := url.Parse(baseURL)
	if err != nil || parsedBase.Hostname() == "" {
		t.Fatalf("invalid EASYSCAN_SQLI_LAB_BASE %q", baseURL)
	}

	for lesson := 1; lesson <= 15; lesson++ {
		lesson := lesson
		policy := testPolicy{error: true, maxRequests: 36, maxParams: 3, qps: 20}
		wantTechnique := "sql-error"
		if lesson == 8 || lesson == 15 {
			policy = testPolicy{boolean: true, maxRequests: 36, maxParams: 3, qps: 20}
			wantTechnique = "boolean-differential"
		}
		if lesson == 9 || lesson == 10 {
			policy = testPolicy{timing: true, maxRequests: 36, maxParams: 3, qps: 20}
			wantTechnique = "time-differential"
		}
		t.Run(fmt.Sprintf("Less-%d-%s", lesson, wantTechnique), func(t *testing.T) {
			target := fmt.Sprintf("%s/Less-%d/", baseURL, lesson)
			method := http.MethodGet
			body := ""
			headers := map[string]string{}
			if lesson <= 10 {
				parsedTarget, parseErr := url.Parse(target)
				if parseErr != nil {
					t.Fatal(parseErr)
				}
				query := parsedTarget.Query()
				query.Set("id", "1")
				parsedTarget.RawQuery = query.Encode()
				target = parsedTarget.String()
			} else {
				method = http.MethodPost
				body = url.Values{"uname": {"admin"}, "passwd": {"admin"}, "submit": {"Submit"}}.Encode()
				headers["Content-Type"] = "application/x-www-form-urlencoded"
			}

			request, requestErr := http.NewRequest(method, target, strings.NewReader(body))
			if requestErr != nil {
				t.Fatal(requestErr)
			}
			for name, value := range headers {
				request.Header.Set(name, value)
			}
			response, requestErr := http.DefaultClient.Do(request) // #nosec G107 -- explicit local integration target
			if requestErr != nil {
				t.Fatal(requestErr)
			}
			responseBody, readErr := io.ReadAll(response.Body)
			_ = response.Body.Close()
			if readErr != nil {
				t.Fatal(readErr)
			}

			cfg := config.Default()
			cfg.Scope.AllowHosts = []string{parsedBase.Hostname()}
			cfg.Scope.AllowPrivateIPs = true
			probeEngine, engineErr := engine.New(cfg)
			if engineErr != nil {
				t.Fatal(engineErr)
			}
			worker := New(cfg, probeEngine, policy)
			worker.Observe(model.Transaction{
				Observed: time.Now().UTC(),
				Source:   model.SourceHTTPProxy,
				Request:  model.Message{Method: method, URL: target, Headers: headers, Body: body},
				Response: model.Message{Status: response.StatusCode, Headers: map[string]string{"Content-Type": response.Header.Get("Content-Type")}, Body: string(responseBody)},
			})

			findings := waitForFindings(t, probeEngine, 5*time.Second)
			_ = worker.Shutdown(context.Background())
			if len(findings) == 0 {
				t.Fatalf("Less-%d produced no SQL finding with %s enabled", lesson, wantTechnique)
			}
			if !strings.Contains(findings[0].Evidence, wantTechnique) {
				t.Fatalf("Less-%d expected %s, got %s", lesson, wantTechnique, findings[0].Evidence)
			}
			t.Logf("Less-%d %s: %s", lesson, wantTechnique, findings[0].Evidence)
		})
	}
}

func TestLiveVulinboxSQLCoverage(t *testing.T) {
	baseURL := strings.TrimRight(strings.TrimSpace(os.Getenv("EASYSCAN_VULINBOX_BASE")), "/")
	if baseURL == "" {
		t.Skip("set EASYSCAN_VULINBOX_BASE to run the local Vulinbox SQL regression")
	}
	parsedBase, err := url.Parse(baseURL)
	if err != nil || parsedBase.Hostname() == "" {
		t.Fatalf("invalid EASYSCAN_VULINBOX_BASE %q", baseURL)
	}

	type liveCase struct {
		name    string
		method  string
		path    string
		body    string
		headers map[string]string
		want    bool
	}
	cases := []liveCase{
		{name: "safe-numeric", method: http.MethodGet, path: "/user/by-id-safe?id=1", want: false},
		{name: "query-numeric", method: http.MethodGet, path: "/user/id?id=1", want: true},
		{name: "query-error", method: http.MethodGet, path: "/user/id-error?id=1", want: true},
		{name: "query-json", method: http.MethodGet, path: "/user/id-json?id=" + url.QueryEscape(`{"uid":1,"id":"1"}`), want: true},
		{name: "query-base64-json", method: http.MethodGet, path: "/user/id-b64-json?id=" + url.QueryEscape(base64.StdEncoding.EncodeToString([]byte(`{"uid":1,"id":"1"}`))), want: true},
		{name: "form-numeric", method: http.MethodPost, path: "/user/post/id", body: "id=1", headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, want: true},
		{name: "form-string", method: http.MethodPost, path: "/user/post/name", body: "name=admin", headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, want: true},
		{name: "cookie", method: http.MethodGet, path: "/user/cookie-id?skip=1", headers: map[string]string{"Cookie": "ID=1"}, want: true},
		{name: "query-string", method: http.MethodGet, path: "/user/name?name=admin", want: true},
		{name: "like", method: http.MethodGet, path: "/user/name/like?name=a", want: true},
		{name: "like-parenthesized", method: http.MethodGet, path: "/user/name/like/2?name=a", want: true},
		{name: "like-base64", method: http.MethodGet, path: "/user/name/like/b64?nameb64=YQ%3D%3D", want: true},
		{name: "like-base64-json", method: http.MethodGet, path: "/user/name/like/b64j?data=" + url.QueryEscape(base64.StdEncoding.EncodeToString([]byte(`{"nameb64j":"a"}`))), want: true},
		{name: "limit", method: http.MethodGet, path: "/user/limit/int?limit=1", want: true},
		{name: "order-direction-1", method: http.MethodGet, path: "/user/limit/4/order1?order=desc", want: true},
		{name: "order-direction-2", method: http.MethodGet, path: "/user/limit/4/order2?order=desc", want: true},
		{name: "order-direction-3", method: http.MethodGet, path: "/user/order3?order=desc", want: true},
		{name: "orderby-field", method: http.MethodGet, path: "/user/limit/4/orderby?orderby=username", want: true},
		{name: "orderby-backtick", method: http.MethodGet, path: "/user/limit/4/orderby1?orderby=id", want: true},
		{name: "orderby-backtick-multi", method: http.MethodGet, path: "/user/limit/4/orderby2?orderby=id", want: true},
		{name: "time-blind", method: http.MethodGet, path: "/user/id-time-blind?id=1", want: true},
		{name: "referer-header", method: http.MethodPost, path: "/visitor/reference", headers: map[string]string{"Referer": "http://example.com/visitor/reference"}, want: true},
		{name: "forwarded-for-header", method: http.MethodPost, path: "/visitor/x-forwarded-for", headers: map[string]string{"X-Forwarded-For": "127.0.0.1, 10.0.0.1"}, want: true},
		{name: "path-segment", method: http.MethodGet, path: "/user/path/admin", want: true},
	}

	client := &http.Client{Timeout: 6 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			target := baseURL + test.path
			request, requestErr := http.NewRequest(test.method, target, strings.NewReader(test.body))
			if requestErr != nil {
				t.Fatal(requestErr)
			}
			for name, value := range test.headers {
				request.Header.Set(name, value)
			}
			response, requestErr := client.Do(request) // #nosec G107 -- explicit local integration target
			if requestErr != nil {
				t.Fatal(requestErr)
			}
			responseBody, readErr := io.ReadAll(response.Body)
			_ = response.Body.Close()
			if readErr != nil {
				t.Fatal(readErr)
			}

			cfg := config.Default()
			cfg.Scope.AllowHosts = []string{parsedBase.Hostname()}
			cfg.Scope.AllowPrivateIPs = true
			probeEngine, engineErr := engine.New(cfg)
			if engineErr != nil {
				t.Fatal(engineErr)
			}
			worker := New(cfg, probeEngine, testPolicy{error: true, boolean: true, timing: true, maxRequests: 60, maxParams: 8, qps: 20})
			requestHeaderMap := make(map[string]string, len(request.Header))
			for name, values := range request.Header {
				requestHeaderMap[name] = strings.Join(values, "\n")
			}
			responseHeaderMap := make(map[string]string, len(response.Header))
			for name, values := range response.Header {
				responseHeaderMap[name] = strings.Join(values, "\n")
			}
			worker.Observe(model.Transaction{
				Observed: time.Now().UTC(),
				Source:   model.SourceHTTPProxy,
				Request:  model.Message{Method: test.method, URL: target, Headers: requestHeaderMap, Body: test.body},
				Response: model.Message{Status: response.StatusCode, Headers: responseHeaderMap, Body: string(responseBody)},
			})

			findings := waitForFindings(t, probeEngine, 6*time.Second)
			_ = worker.Shutdown(context.Background())
			if test.want && len(findings) == 0 {
				t.Fatalf("%s produced no SQL finding", target)
			}
			if !test.want && len(findings) != 0 {
				t.Fatalf("safe route produced a SQL false positive: %#v", findings)
			}
			if len(findings) > 0 {
				t.Logf("%s: %s", findings[0].RuleID, findings[0].Evidence)
			}
		})
	}
}

func waitForFindings(t *testing.T, probeEngine *engine.Engine, timeout time.Duration) []model.Finding {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if findings := probeEngine.Findings(); len(findings) > 0 {
			return findings
		}
		time.Sleep(20 * time.Millisecond)
	}
	return probeEngine.Findings()
}

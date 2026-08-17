package proxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/example/easyscan/internal/config"
	"github.com/example/easyscan/internal/engine"
)

type domainExclusionFunc func(string) bool

func (f domainExclusionFunc) ExcludedHost(host string) bool { return f(host) }

type suffixExclusionFunc func(string) bool

func (f suffixExclusionFunc) ExcludedURLPath(urlPath string) bool { return f(urlPath) }

func TestProxyForwardsAndAnalyzes(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Powered-By", "ExampleFramework/1.2.3")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("ok"))
	}))
	defer target.Close()
	cfg := config.Default()
	cfg.Scope.DenyHosts = nil
	e, err := engine.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, target.URL+"/resource", nil)
	recorder := httptest.NewRecorder()
	New(e, 1024).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusCreated || recorder.Body.String() != "ok" {
		t.Fatalf("unexpected proxied response: %d %q", recorder.Code, recorder.Body.String())
	}
	if len(e.Findings()) != 0 {
		t.Fatalf("technology version headers must not create a finding, got %d", len(e.Findings()))
	}
}

func TestProxyForwardsExcludedHostWithoutAnalysis(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Powered-By", "ExampleFramework/1.2.3")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer target.Close()
	cfg := config.Default()
	cfg.Scope.DenyHosts = nil
	e, err := engine.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	e.SetDomainExclusionGate(domainExclusionFunc(func(host string) bool { return host == "127.0.0.1" }))

	request := httptest.NewRequest(http.MethodGet, target.URL+"/ignored", nil)
	recorder := httptest.NewRecorder()
	New(e, 1024).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("excluded host must still be forwarded, got %d", recorder.Code)
	}
	if len(e.Findings()) != 0 || len(e.Assets()) != 0 || len(e.Traffic(10)) != 0 {
		t.Fatalf("excluded host must not enter analysis state: findings=%#v assets=%#v traffic=%#v", e.Findings(), e.Assets(), e.Traffic(10))
	}
}

func TestProxyForwardsExcludedSuffixWithoutCaptureOrAnalysis(t *testing.T) {
	var requestBody string
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read proxied request: %v", err)
			return
		}
		requestBody = string(body)
		w.Header().Set("X-Powered-By", "ExampleFramework/1.2.3")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("forwarded response"))
	}))
	defer target.Close()
	cfg := config.Default()
	cfg.Scope.DenyHosts = nil
	e, err := engine.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	e.SetSuffixExclusionGate(suffixExclusionFunc(func(urlPath string) bool {
		return strings.HasSuffix(strings.ToLower(urlPath), ".css")
	}))
	logCount := len(e.Logs(0))

	request := httptest.NewRequest(http.MethodPost, target.URL+"/assets/SITE.CSS?cache=123", strings.NewReader("request payload"))
	recorder := httptest.NewRecorder()
	New(e, 1).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusCreated || recorder.Body.String() != "forwarded response" {
		t.Fatalf("excluded suffix must still be forwarded unchanged: %d %q", recorder.Code, recorder.Body.String())
	}
	if requestBody != "request payload" {
		t.Fatalf("excluded suffix request body was not forwarded intact: %q", requestBody)
	}
	if findings, assets, traffic := e.Findings(), e.Assets(), e.Traffic(10); len(findings) != 0 || len(assets) != 0 || len(traffic) != 0 {
		t.Fatalf("excluded suffix must not enter analysis state: findings=%#v assets=%#v traffic=%#v", findings, assets, traffic)
	}
	if len(e.Logs(0)) != logCount {
		t.Fatalf("excluded suffix must not create runtime logs: %#v", e.Logs(0))
	}

	// A query value ending in .css must not turn a non-CSS path into filtered
	// traffic; the Engine's URL path decision is shared with the proxy.
	request = httptest.NewRequest(http.MethodGet, target.URL+"/download?file=SITE.CSS", nil)
	recorder = httptest.NewRecorder()
	New(e, 1024).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusCreated || len(e.Assets()) != 1 || len(e.Traffic(10)) != 1 {
		t.Fatalf("non-matching URL path should be analyzed normally: status=%d assets=%#v traffic=%#v", recorder.Code, e.Assets(), e.Traffic(10))
	}
}

func TestProxyRejectsRequestsToItsOwnListenerWithoutBlockingOtherLocalPorts(t *testing.T) {
	cfg := config.Default()
	cfg.Scope.DenyHosts = nil
	e, err := engine.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	proxy := New(e, 1024)
	proxy.listenAddress = "127.0.0.1:7777"

	request := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:7777/", nil)
	recorder := httptest.NewRecorder()
	proxy.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("proxy listener recursion must return an HTTP error, got %d %q", recorder.Code, recorder.Body.String())
	}
	if len(e.Traffic(10)) != 0 {
		t.Fatalf("self-proxy request must not enter passive traffic: %#v", e.Traffic(10))
	}

	if proxy.targetsOwnListener("127.0.0.1:19080", "http", request) {
		t.Fatal("a different local service port must remain a valid proxy target")
	}
	if !proxy.targetsOwnListener("localhost:7777", "http", request) || !proxy.targetsOwnListener("[::1]:7777", "http", request) {
		t.Fatal("loopback aliases of the proxy listener must be recognized")
	}
}

func TestMITMConnectAcceptsCleartextHTTPFromAnUpstreamProxy(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Powered-By", "PlainTunnelFixture/1.0")
		_, _ = w.Write([]byte("plain-connect-ok"))
	}))
	defer target.Close()

	cfg := config.Default()
	cfg.Scope.AllowHosts = []string{"*"}
	cfg.Scope.DenyHosts = nil
	e, err := engine.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	proxy := New(e, 1024)
	if _, err := proxy.EnableMITM(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	serveDone := make(chan error, 1)
	go func() { serveDone <- proxy.Serve(ctx, listener) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-serveDone:
			if err != nil {
				t.Errorf("stop proxy: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("proxy did not stop")
		}
	})

	connection, err := net.DialTimeout("tcp", listener.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	targetAddress := strings.TrimPrefix(target.URL, "http://")
	if _, err := fmt.Fprintf(connection, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", targetAddress, targetAddress); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(connection)
	connectResponse, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	if connectResponse.StatusCode != http.StatusOK {
		t.Fatalf("unexpected CONNECT status: %s", connectResponse.Status)
	}
	if _, err := fmt.Fprintf(connection, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", targetAddress); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || string(body) != "plain-connect-ok" {
		t.Fatalf("cleartext CONNECT request was not forwarded: %s %q", response.Status, body)
	}
	if len(e.Traffic(10)) != 1 {
		t.Fatalf("cleartext CONNECT HTTP must enter passive traffic: %#v", e.Traffic(10))
	}
}

func TestClosedIdleConnectionRetryIsLimitedToReplayableRequests(t *testing.T) {
	if !closedIdleConnectionError(errors.New("conn pool: server closed idle connection")) {
		t.Fatal("closed idle connection matcher must accept the transport error")
	}
	if closedIdleConnectionError(nil) || closedIdleConnectionError(errors.New("connection reset by peer")) {
		t.Fatal("only matching transport errors should be retried")
	}

	request := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	retry, ok := replayableRetryRequest(request)
	if !ok || retry.Body != http.NoBody {
		t.Fatalf("bodyless GET must be replayable, retry=%#v ok=%t", retry, ok)
	}

	request = httptest.NewRequest(http.MethodPost, "http://example.test/", strings.NewReader("payload"))
	if _, ok := replayableRetryRequest(request); ok {
		t.Fatal("a request body without GetBody must not be automatically replayed")
	}
}

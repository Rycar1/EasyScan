package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/example/easyscan/internal/engine"
	"github.com/example/easyscan/internal/model"
)

// Server is a forward proxy for observed HTTP. CONNECT is deliberately a
// transparent tunnel: the proxy never generates a certificate or decrypts TLS.
type Server struct {
	engine        *engine.Engine
	maxBytes      int64
	transport     *http.Transport
	analysisQueue *passiveAnalysisQueue
	mitm          *CertificateAuthority
	caPath        string
	listenAddress string
}

func New(e *engine.Engine, maxBytes int64) *Server {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	return &Server{
		engine:        e,
		maxBytes:      maxBytes,
		transport:     transport,
		analysisQueue: newPassiveAnalysisQueue(e, defaultPassiveAnalysisQueueCapacity),
	}
}

// EnableMITM activates HTTPS interception only for hosts that are explicitly
// listed in scope.allow_hosts. Callers must arrange trust for the returned CA.
func (s *Server) EnableMITM(caDir string) (string, error) {
	ca, path, err := LoadOrCreateCA(caDir)
	if err != nil {
		return "", err
	}
	s.mitm, s.caPath = ca, path
	return path, nil
}

func (s *Server) ListenAndServe(ctx context.Context, address string) error {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	return s.Serve(ctx, listener)
}

// Serve runs the proxy on an already-bound listener. Keeping listener binding
// separate lets desktop callers report port conflicts before background work
// starts.
func (s *Server) Serve(ctx context.Context, listener net.Listener) error {
	s.listenAddress = listener.Addr().String()
	queueOwner := s.analysisQueue != nil && s.analysisQueue.start()
	if queueOwner {
		defer s.analysisQueue.stop()
	}
	server := &http.Server{Handler: s}
	stopShutdownWatcher := make(chan struct{})
	shutdownWatcherDone := make(chan struct{})
	go func() {
		defer close(shutdownWatcherDone)
		select {
		case <-ctx.Done():
			_ = server.Shutdown(context.Background())
		case <-stopShutdownWatcher:
		}
	}()
	err := server.Serve(listener)
	close(stopShutdownWatcher)
	<-shutdownWatcherDone
	// Serve can also return because the listener itself failed or was closed.
	// In that case, explicitly wait for ordinary in-flight handlers before the
	// deferred queue drain closes admission.
	_ = server.Shutdown(context.Background())
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		if s.targetsOwnListener(r.Host, "https", r) {
			s.rejectOwnListenerTarget(w, r.Host)
			return
		}
		s.handleConnect(w, r)
		return
	}
	if r.URL.Scheme != "http" && r.URL.Scheme != "https" {
		r.URL.Scheme = "http"
		r.URL.Host = r.Host
	}
	if s.targetsOwnListener(r.URL.Host, r.URL.Scheme, r) {
		s.rejectOwnListenerTarget(w, r.URL.Host)
		return
	}

	transaction := s.forward(w, r, model.SourceHTTPProxy)
	if transaction != nil {
		// net/http may retain a small response in its connection buffer until
		// the handler returns. Flush it before making the transaction visible
		// to the analysis worker so analysis never gets ahead of delivery.
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
	}
	s.submitAnalysis(transaction)
}

// targetsOwnListener prevents an HTTP client configured to use EasyScan from
// requesting the proxy address itself (for example 127.0.0.1:7777 through
// 127.0.0.1:7777). Forwarding that request recursively opens proxy
// connections until the client sees a reset instead of an HTTP response.
// Other local ports remain valid passive-analysis targets.
func (s *Server) targetsOwnListener(target, scheme string, request *http.Request) bool {
	targetHost, targetPort, err := net.SplitHostPort(target)
	if err != nil {
		targetHost = strings.Trim(target, "[]")
		targetPort = defaultPort(scheme)
	}
	if targetHost == "" || targetPort == "" {
		return false
	}
	listenerAddress := s.listenAddress
	if listenerAddress == "" && request != nil {
		if local, ok := request.Context().Value(http.LocalAddrContextKey).(net.Addr); ok && local != nil {
			listenerAddress = local.String()
		}
	}
	listenerHost, listenerPort, err := net.SplitHostPort(listenerAddress)
	if err != nil || listenerPort != targetPort {
		return false
	}
	targetHost = normalizeProxyHost(targetHost)
	listenerHost = normalizeProxyHost(listenerHost)
	if targetHost == listenerHost {
		return true
	}
	return isLoopbackProxyHost(targetHost) && (isLoopbackProxyHost(listenerHost) || isUnspecifiedProxyHost(listenerHost))
}

func (s *Server) rejectOwnListenerTarget(w http.ResponseWriter, target string) {
	if s.engine != nil {
		s.engine.Log("error", "proxy", fmt.Sprintf("已阻止代理回环请求：%s 是 EasyScan 代理监听地址", target))
	}
	http.Error(w, "proxy target points to the EasyScan listener; use the local service port instead", http.StatusBadRequest)
}

func defaultPort(scheme string) string {
	switch strings.ToLower(strings.TrimSpace(scheme)) {
	case "https":
		return "443"
	case "http":
		return "80"
	default:
		return ""
	}
}

func normalizeProxyHost(host string) string {
	return strings.Trim(strings.ToLower(strings.TrimSpace(host)), "[]")
}

func isLoopbackProxyHost(host string) bool {
	return host == "localhost" || (net.ParseIP(host) != nil && net.ParseIP(host).IsLoopback())
}

func isUnspecifiedProxyHost(host string) bool {
	return host == "0.0.0.0" || host == "::"
}

func (s *Server) forward(w http.ResponseWriter, r *http.Request, source string) *model.Transaction {
	// Excluded suffixes, paths, Query names, hosts, and otherwise out-of-scope URLs still
	// use the proxy as a transparent forwarder. Skip capture entirely in that
	// case: it avoids inspecting request/response bodies for traffic the user
	// has chosen not to analyze, while preserving normal browser traffic.
	analyze := s.engine.AllowsPassiveURL(r.URL.String())
	var requestBody []byte
	var capturedRequest model.Message
	if analyze {
		var replacement io.ReadCloser
		var err error
		requestBody, replacement, err = capturePrefix(r.Body, s.maxBytes)
		if err != nil {
			http.Error(w, "unable to read request body", http.StatusBadRequest)
			return nil
		}
		r.Body = replacement
		capturedRequest = model.Message{Method: r.Method, URL: r.URL.String(), Headers: flattenHeaders(r.Header), Body: string(requestBody)}
		// POST form and JSON field names are available only after capturing the
		// bounded request prefix. A match suppresses the complete transaction,
		// but the restored request body is still forwarded unchanged.
		if !s.engine.AllowsPassiveRequest(capturedRequest) {
			analyze = false
		}
	}
	outbound := r.Clone(r.Context())
	outbound.RequestURI = ""
	outbound.Header = r.Header.Clone()
	removeHopHeaders(outbound.Header)

	response, err := s.roundTrip(outbound)
	if err != nil {
		http.Error(w, "upstream request failed: "+err.Error(), http.StatusBadGateway)
		return nil
	}
	defer response.Body.Close()
	// Content-Type can only be known after the upstream response headers are
	// available. When it matches a user filter, leave the exchange completely
	// transparent: do not retain the body, write runtime traffic, or run any
	// passive fingerprint/vulnerability checks.
	if analyze && !s.engine.AllowsPassiveContentType(response.Header.Get("Content-Type")) {
		analyze = false
	}
	var transaction *model.Transaction
	if analyze {
		responseBody, responseReplacement, err := capturePrefix(response.Body, s.maxBytes)
		if err != nil {
			http.Error(w, "unable to read upstream response", http.StatusBadGateway)
			return nil
		}
		response.Body = responseReplacement

		transaction = &model.Transaction{
			Source: source, ClientIP: remoteHost(r.RemoteAddr),
			Request:  capturedRequest,
			Response: model.Message{Status: response.StatusCode, Headers: flattenHeaders(response.Header), Body: string(responseBody), Certificate: observedCertificate(response.TLS)},
		}
	}

	removeHopHeaders(response.Header)
	copyHeaders(w.Header(), response.Header)
	w.WriteHeader(response.StatusCode)
	if _, err := io.Copy(w, response.Body); err != nil {
		return nil
	}
	return transaction
}

// submitAnalysis is called only after the response body has been written to
// the client. Serve owns the asynchronous queue lifecycle; direct ServeHTTP
// use outside Serve falls back to in-line analysis after the response write,
// preserving the historical handler API without leaving an unmanaged worker.
func (s *Server) submitAnalysis(transaction *model.Transaction) {
	if transaction == nil || s.engine == nil {
		return
	}
	if result := s.analysisQueue.trySubmit(*transaction); result != analysisQueueInactive {
		return
	}
	s.engine.Analyze(*transaction)
}

// observedCertificate summarizes the TLS certificate already presented by the
// upstream connection. It never initiates a certificate request and keeps the
// raw certificate bytes out of the transaction model.
func observedCertificate(state *tls.ConnectionState) string {
	if state == nil || len(state.PeerCertificates) == 0 {
		return ""
	}
	certificate := state.PeerCertificates[0]
	parts := make([]string, 0, len(certificate.DNSNames)+3)
	if subject := strings.TrimSpace(certificate.Subject.String()); subject != "" {
		parts = append(parts, "subject="+subject)
	}
	if issuer := strings.TrimSpace(certificate.Issuer.String()); issuer != "" {
		parts = append(parts, "issuer="+issuer)
	}
	if serial := strings.TrimSpace(certificate.SerialNumber.String()); serial != "" {
		parts = append(parts, "serial="+serial)
	}
	for _, name := range certificate.DNSNames {
		if name = strings.TrimSpace(name); name != "" {
			parts = append(parts, "dns="+name)
		}
	}
	return strings.Join(parts, "; ")
}

// roundTrip retries one request when an origin closes a pooled idle
// connection between selection and write. This is common on lightweight
// services listening on non-standard HTTP ports: the first attempt races a
// stale keep-alive socket even though a fresh connection succeeds. Retrying is
// limited to requests whose body can be replayed without changing semantics.
func (s *Server) roundTrip(request *http.Request) (*http.Response, error) {
	response, err := s.transport.RoundTrip(request)
	if err == nil || !closedIdleConnectionError(err) {
		return response, err
	}
	retry, ok := replayableRetryRequest(request)
	if !ok {
		return nil, err
	}
	// Ensure the second attempt dials a new origin connection instead of
	// selecting another stale entry from the previous pool.
	s.transport.CloseIdleConnections()
	return s.transport.RoundTrip(retry)
}

func closedIdleConnectionError(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "closed idle connection")
}

func replayableRetryRequest(request *http.Request) (*http.Request, bool) {
	if request == nil {
		return nil, false
	}
	retry := request.Clone(request.Context())
	if request.GetBody != nil {
		body, err := request.GetBody()
		if err != nil {
			return nil, false
		}
		retry.Body = body
		return retry, true
	}
	// A bodyless request is always safe to retry. For an incoming proxy
	// request, GetBody is normally nil even for GET/HEAD requests.
	if request.Body == nil || request.Body == http.NoBody || (request.ContentLength == 0 && len(request.TransferEncoding) == 0) {
		retry.Body = http.NoBody
		return retry, true
	}
	return nil, false
}

func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	host, _, err := net.SplitHostPort(r.Host)
	if err != nil {
		host = r.Host
	}
	if s.mitm != nil && s.engine.AllowsActiveHost(host) {
		s.handleMITMConnect(w, r, host)
		return
	}
	target, err := net.Dial("tcp", r.Host)
	if err != nil {
		http.Error(w, "could not connect to target", http.StatusServiceUnavailable)
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		target.Close()
		http.Error(w, "hijacking unsupported", http.StatusInternalServerError)
		return
	}
	client, _, err := hijacker.Hijack()
	if err != nil {
		target.Close()
		return
	}
	_, _ = client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	go func() { _, _ = io.Copy(target, client); _ = target.Close() }()
	go func() { _, _ = io.Copy(client, target); _ = client.Close() }()
}

func (s *Server) handleMITMConnect(w http.ResponseWriter, r *http.Request, host string) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking unsupported", http.StatusInternalServerError)
		return
	}
	client, _, err := hijacker.Hijack()
	if err != nil {
		return
	}
	reader := bufio.NewReader(client)
	if _, err := client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		_ = client.Close()
		return
	}
	// An upstream proxy can use CONNECT as a generic connection pool even for
	// cleartext HTTP. TLS interception must therefore begin only after the
	// first tunneled byte confirms a TLS ClientHello; treating every CONNECT as
	// TLS closes those pooled HTTP connections before they can send a request.
	_ = client.SetReadDeadline(time.Now().Add(15 * time.Second))
	first, err := reader.Peek(1)
	if err != nil {
		_ = client.SetReadDeadline(time.Time{})
		_ = client.Close()
		return
	}
	isTLS := first[0] == 0x16 && isTLSClientHello(reader)
	_ = client.SetReadDeadline(time.Time{})
	if isTLS {
		s.handleTLSConnect(client, reader, r, host)
		return
	}
	if first[0] >= 'A' && first[0] <= 'Z' {
		s.handlePlainHTTPConnect(client, reader, r)
		return
	}
	s.handleRawConnectTunnel(client, reader, r.Host)
}

func isTLSClientHello(reader *bufio.Reader) bool {
	prefix, err := reader.Peek(3)
	return err == nil && prefix[0] == 0x16 && prefix[1] == 0x03 && prefix[2] >= 0x01 && prefix[2] <= 0x04
}

func (s *Server) handleTLSConnect(client net.Conn, reader *bufio.Reader, r *http.Request, host string) {
	defer client.Close()
	tlsConn := tls.Server(&bufferedConn{Conn: client, reader: reader}, &tls.Config{GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return s.mitm.Certificate(host) }, MinVersion: tls.VersionTLS12})
	if err := tlsConn.Handshake(); err != nil {
		return
	}
	defer tlsConn.Close()
	tlsReader := bufio.NewReader(tlsConn)
	for {
		request, err := http.ReadRequest(tlsReader)
		if err != nil {
			return
		}
		request.URL.Scheme, request.URL.Host = "https", r.Host
		request.RequestURI = ""
		request.RemoteAddr = r.RemoteAddr
		writer := &mitmResponseWriter{header: make(http.Header), conn: tlsConn}
		transaction := s.forward(writer, request, model.SourceHTTPSMITM)
		if err := writer.Finish(); err != nil {
			return
		}
		s.submitAnalysis(transaction)
		if request.Close {
			return
		}
	}
}

// handlePlainHTTPConnect accepts an upstream proxy's cleartext HTTP requests
// carried inside CONNECT. It preserves the tunnel response format while still
// sending the transactions through normal passive analysis.
func (s *Server) handlePlainHTTPConnect(client net.Conn, reader *bufio.Reader, connectRequest *http.Request) {
	defer client.Close()
	for {
		request, err := http.ReadRequest(reader)
		if err != nil {
			return
		}
		request.URL.Scheme, request.URL.Host = "http", connectRequest.Host
		request.RequestURI = ""
		request.RemoteAddr = connectRequest.RemoteAddr
		writer := &mitmResponseWriter{header: make(http.Header), conn: client}
		transaction := s.forward(writer, request, "http-proxy")
		// Cleartext CONNECT is a compatibility path used by upstream proxy
		// pools. The response is buffered in mitmResponseWriter at this point,
		// so complete its small, deterministic analysis before publishing the
		// buffered response to the upstream proxy. Ordinary HTTP and TLS MITM
		// traffic continue to use the bounded asynchronous queue.
		if transaction != nil && s.engine != nil {
			s.engine.Analyze(*transaction)
		}
		if err := writer.Finish(); err != nil {
			return
		}
		if request.Close {
			return
		}
	}
}

// handleRawConnectTunnel retains standard CONNECT behaviour for non-HTTP and
// non-TLS protocols. The buffered reader is used on the client-to-target copy
// so the byte used for protocol detection is not lost.
func (s *Server) handleRawConnectTunnel(client net.Conn, reader *bufio.Reader, targetAddress string) {
	target, err := net.DialTimeout("tcp", targetAddress, 10*time.Second)
	if err != nil {
		_ = client.Close()
		return
	}
	go func() {
		_, _ = io.Copy(target, reader)
		_ = target.Close()
	}()
	go func() {
		_, _ = io.Copy(client, target)
		_ = client.Close()
	}()
}

// bufferedConn exposes bytes already buffered by protocol detection before
// continuing reads from the hijacked TCP connection.
type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(data []byte) (int, error) { return c.reader.Read(data) }

type mitmResponseWriter struct {
	header http.Header
	conn   net.Conn
	status int
	body   bytes.Buffer
	wrote  bool
}

func (w *mitmResponseWriter) Header() http.Header { return w.header }
func (w *mitmResponseWriter) WriteHeader(status int) {
	if w.wrote {
		return
	}
	w.wrote = true
	w.status = status
}
func (w *mitmResponseWriter) Write(data []byte) (int, error) {
	if !w.wrote {
		w.WriteHeader(http.StatusOK)
	}
	return w.body.Write(data)
}
func (w *mitmResponseWriter) Finish() error {
	if !w.wrote {
		w.WriteHeader(http.StatusOK)
	}
	response := &http.Response{StatusCode: w.status, ProtoMajor: 1, ProtoMinor: 1, Header: w.header, ContentLength: int64(w.body.Len()), Body: io.NopCloser(bytes.NewReader(w.body.Bytes()))}
	return response.Write(w.conn)
}

func capturePrefix(body io.ReadCloser, max int64) ([]byte, io.ReadCloser, error) {
	if body == nil {
		return nil, http.NoBody, nil
	}
	if max <= 0 {
		return nil, body, nil
	}
	b := make([]byte, max)
	n, err := io.ReadFull(body, b)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return nil, body, err
	}
	b = b[:n]
	return b, io.NopCloser(io.MultiReader(bytes.NewReader(b), body)), nil
}

func flattenHeaders(headers http.Header) map[string]string {
	result := make(map[string]string, len(headers))
	for key, values := range headers {
		result[key] = strings.Join(values, "\n")
	}
	return result
}

func copyHeaders(to, from http.Header) {
	for key, values := range from {
		for _, value := range values {
			to.Add(key, value)
		}
	}
}
func remoteHost(address string) string {
	host, _, err := net.SplitHostPort(address)
	if err == nil {
		return host
	}
	return address
}

func removeHopHeaders(headers http.Header) {
	for _, name := range []string{"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade"} {
		headers.Del(name)
	}
}

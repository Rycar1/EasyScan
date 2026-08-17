// Package uploadprobe implements an optional file-upload check triggered by
// multipart/form-data traffic observed through the local HTTP proxy or HTTPS
// MITM. When an upload request is seen, the worker replays it with the uploaded
// file's name suffix changed to an active-content extension (e.g. .html) and a
// matching text/html Content-Type, then inspects the response for a signal that
// the renamed file was accepted. It only re-sends the user's own captured file
// bytes; it never plants a webshell or changes server state beyond re-uploading.
package uploadprobe

import (
	"bytes"
	"context"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/example/easyscan/internal/config"
	"github.com/example/easyscan/internal/engine"
	"github.com/example/easyscan/internal/model"
)

const (
	featureID      = "passive.upload_probe"
	minimumQPS     = 1
	maximumQPS     = 20
	queueCapacity  = 32
	maxBodyBytes   = 1 << 20
	defaultTimeout = 10 * time.Second
)

// suffixAttempts lists active-content extensions to try, highest interest
// first. The user specifically requested the .html attempt.
var suffixAttempts = []string{".html", ".htm", ".phtml", ".svg", ".xhtml"}

// Policy is the live configuration surface used by the worker.
type Policy interface {
	Enabled(string) bool
	PassiveUploadProbeQPS() int
}

type Worker struct {
	cfg    config.Config
	engine *engine.Engine
	policy Policy

	ctx    context.Context
	cancel context.CancelFunc
	queue  chan job

	mu          sync.Mutex
	scheduled   map[string]struct{}
	stopped     bool
	generation  uint64
	batchCtx    context.Context
	batchCancel context.CancelFunc
	workers     sync.WaitGroup
}

type job struct {
	tx         model.Transaction
	generation uint64
}

// New constructs the worker and starts its single background scheduler.
func New(cfg config.Config, e *engine.Engine, policy Policy) *Worker {
	ctx, cancel := context.WithCancel(context.Background())
	batchCtx, batchCancel := context.WithCancel(ctx)
	w := &Worker{
		cfg:         cfg,
		engine:      e,
		policy:      policy,
		ctx:         ctx,
		cancel:      cancel,
		queue:       make(chan job, queueCapacity),
		scheduled:   make(map[string]struct{}),
		batchCtx:    batchCtx,
		batchCancel: batchCancel,
	}
	w.workers.Add(1)
	go w.run()
	return w
}

// Observe only queues work. An endpoint is scheduled once when it carries a
// multipart file upload.
func (w *Worker) Observe(tx model.Transaction) {
	if w == nil || w.engine == nil || w.policy == nil || !model.IsObservedProxySource(tx.Source) || !w.enabled() {
		return
	}
	parsed, err := url.Parse(tx.Request.URL)
	if err != nil || parsed.Hostname() == "" || !w.engine.AllowsActiveHost(parsed.Hostname()) {
		return
	}
	if !isMultipartUpload(tx) {
		return
	}
	key := tx.Request.Method + " " + parsed.Host + parsed.Path
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.stopped {
		return
	}
	if _, exists := w.scheduled[key]; exists {
		return
	}
	item := job{tx: cloneTransaction(tx), generation: w.generation}
	select {
	case w.queue <- item:
		w.scheduled[key] = struct{}{}
	default:
	}
}

func (w *Worker) CancelPending() {
	if w == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.stopped {
		return
	}
	if w.batchCancel != nil {
		w.batchCancel()
	}
	w.generation++
	w.batchCtx, w.batchCancel = context.WithCancel(w.ctx)
	w.scheduled = make(map[string]struct{})
	for {
		select {
		case <-w.queue:
		default:
			return
		}
	}
}

func (w *Worker) Shutdown(ctx context.Context) error {
	if w == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	w.mu.Lock()
	if !w.stopped {
		w.stopped = true
		if w.batchCancel != nil {
			w.batchCancel()
		}
		w.cancel()
	}
	w.mu.Unlock()
	done := make(chan struct{})
	go func() {
		w.workers.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (w *Worker) run() {
	defer w.workers.Done()
	for {
		select {
		case <-w.ctx.Done():
			return
		case item := <-w.queue:
			batch := w.currentBatch(item.generation)
			if batch != nil {
				w.probeJob(batch, item)
			}
		}
	}
}

func (w *Worker) currentBatch(generation uint64) context.Context {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.stopped || generation != w.generation {
		return nil
	}
	return w.batchCtx
}

func (w *Worker) enabled() bool {
	return w.policy != nil && w.policy.Enabled(featureID)
}

func (w *Worker) qps() int {
	if w.policy == nil {
		return minimumQPS
	}
	qps := w.policy.PassiveUploadProbeQPS()
	if qps < minimumQPS {
		return minimumQPS
	}
	if qps > maximumQPS {
		return maximumQPS
	}
	return qps
}

func (w *Worker) waitForTurn(ctx context.Context) error {
	timer := time.NewTimer(time.Second / time.Duration(w.qps()))
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (w *Worker) probeJob(ctx context.Context, jb job) {
	if !w.enabled() || w.engine == nil || ctx.Err() != nil {
		return
	}
	fields, boundary, ok := parseMultipart(jb.tx)
	if !ok {
		return
	}
	original := uploadedFilename(fields)
	client := w.client()
	for _, suffix := range suffixAttempts {
		if ctx.Err() != nil {
			return
		}
		if err := w.waitForTurn(ctx); err != nil {
			return
		}
		newName := swapSuffix(original, suffix)
		if newName == original {
			continue
		}
		body, ct, err := rebuildMultipart(fields, boundary, newName)
		if err != nil {
			continue
		}
		status, respBody := w.replay(ctx, client, jb.tx, body, ct)
		if uploadAccepted(status, respBody, newName) {
			w.report(jb.tx, original, newName, suffix, status)
			return
		}
	}
}

func (w *Worker) replay(ctx context.Context, client *http.Client, tx model.Transaction, body []byte, contentType string) (int, string) {
	method := tx.Request.Method
	if method == "" {
		method = http.MethodPost
	}
	request, err := http.NewRequestWithContext(ctx, method, tx.Request.URL, bytes.NewReader(body))
	if err != nil {
		return 0, ""
	}
	for name, value := range tx.Request.Headers {
		if strings.EqualFold(name, "Content-Length") || strings.EqualFold(name, "Host") || strings.EqualFold(name, "Content-Type") {
			continue
		}
		request.Header.Set(name, value)
	}
	request.Header.Set("Content-Type", contentType)
	request.Header.Set("User-Agent", "Mozilla/5.0 (EasyScan upload probe)")
	response, err := client.Do(request)
	if err != nil {
		return 0, ""
	}
	respBody := drainLimited(response.Body)
	response.Body.Close()
	return response.StatusCode, respBody
}

// uploadAccepted reports whether the response suggests the renamed file was
// accepted rather than rejected by a suffix/type filter.
func uploadAccepted(status int, body, newName string) bool {
	if status < 200 || status >= 300 {
		return false
	}
	lower := strings.ToLower(body)
	for _, marker := range rejectMarkers {
		if strings.Contains(lower, marker) {
			return false
		}
	}
	// The clearest positive signal: the server echoes the stored path/filename.
	if strings.Contains(lower, strings.ToLower(newName)) {
		return true
	}
	for _, marker := range successMarkers {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

var rejectMarkers = []string{"not allowed", "illegal", "invalid file", "forbidden", "禁止", "不允许", "非法", "格式不", "类型不", "只能上传", "unsupported", "reject"}

var successMarkers = []string{"upload success", "上传成功", "success", "\"code\":0", "\"code\": 0", "\"status\":\"ok\"", "\"url\"", "\"path\"", "\"filename\"", "\"filepath\""}

func (w *Worker) report(tx model.Transaction, original, newName, suffix string, status int) {
	finding := model.Finding{
		RuleID:      "passive.upload-probe.suffix",
		Title:       "文件上传后缀过滤缺失（可传 " + suffix + "）",
		Severity:    "high",
		Confidence:  "medium",
		URL:         tx.Request.URL,
		Method:      tx.Request.Method,
		Description: "MITM 文件上传探测把原始上传文件名后缀改为 " + suffix + " 并同步修改 Content-Type 后重放，服务端接受了该文件，说明上传接口缺少有效的后缀/类型白名单校验，存在上传可执行/可渲染文件（如 HTML/XSS、脚本落地）的风险。",
		Evidence:    "原文件名=" + original + "；改后=" + newName + "；响应状态=" + statusText(status),
		Remediation: "服务端对上传文件强制后缀与 MIME 白名单校验，重命名存储并放置于不可执行/不可直接访问的目录。",
		Tags:        []string{"file-upload", "mitm"},
		ObservedAt:  tx.Observed,
	}
	_, _ = w.engine.ReportFindingWithEvidence(finding, []model.Transaction{cloneTransaction(tx)})
	if w.engine != nil {
		w.engine.Log("warn", "upload-probe", "上传后缀过滤缺失（"+suffix+"）："+tx.Request.URL)
	}
}

func (w *Worker) client() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	timeout := time.Duration(w.cfg.WebScan.HTTP.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = time.Duration(w.cfg.Active.TimeoutSeconds) * time.Second
	}
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

type multipartField struct {
	name        string
	filename    string
	contentType string
	value       []byte
}

func isMultipartUpload(tx model.Transaction) bool {
	contentType := strings.ToLower(headerValue(tx.Request.Headers, "Content-Type"))
	if !strings.HasPrefix(contentType, "multipart/form-data") {
		return false
	}
	return strings.Contains(strings.ToLower(tx.Request.Body), "filename=")
}

// parseMultipart decodes the captured multipart body into ordered fields and
// returns the boundary. It fails closed when the body cannot be parsed.
func parseMultipart(tx model.Transaction) ([]multipartField, string, bool) {
	_, params, err := mime.ParseMediaType(headerValue(tx.Request.Headers, "Content-Type"))
	if err != nil {
		return nil, "", false
	}
	boundary := params["boundary"]
	if boundary == "" {
		return nil, "", false
	}
	reader := multipart.NewReader(strings.NewReader(tx.Request.Body), boundary)
	fields := make([]multipartField, 0, 4)
	hasFile := false
	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, "", false
		}
		data, _ := io.ReadAll(io.LimitReader(part, maxBodyBytes))
		field := multipartField{
			name:        part.FormName(),
			filename:    part.FileName(),
			contentType: part.Header.Get("Content-Type"),
			value:       data,
		}
		if field.filename != "" {
			hasFile = true
		}
		fields = append(fields, field)
		part.Close()
	}
	if !hasFile {
		return nil, "", false
	}
	return fields, boundary, true
}

func uploadedFilename(fields []multipartField) string {
	for _, field := range fields {
		if field.filename != "" {
			return field.filename
		}
	}
	return ""
}

// rebuildMultipart re-encodes the fields, renaming the first file field to
// newName and setting its Content-Type to text/html.
func rebuildMultipart(fields []multipartField, boundary, newName string) ([]byte, string, error) {
	buffer := &bytes.Buffer{}
	writer := multipart.NewWriter(buffer)
	if err := writer.SetBoundary(boundary); err != nil {
		// A rejected boundary (rare) falls back to a generated one.
		writer = multipart.NewWriter(buffer)
	}
	renamed := false
	for _, field := range fields {
		if field.filename != "" && !renamed {
			header := textproto.MIMEHeader{}
			header.Set("Content-Disposition", `form-data; name="`+escapeQuotes(field.name)+`"; filename="`+escapeQuotes(newName)+`"`)
			header.Set("Content-Type", "text/html")
			part, err := writer.CreatePart(header)
			if err != nil {
				return nil, "", err
			}
			if _, err := part.Write(field.value); err != nil {
				return nil, "", err
			}
			renamed = true
			continue
		}
		if field.filename != "" {
			header := textproto.MIMEHeader{}
			header.Set("Content-Disposition", `form-data; name="`+escapeQuotes(field.name)+`"; filename="`+escapeQuotes(field.filename)+`"`)
			if field.contentType != "" {
				header.Set("Content-Type", field.contentType)
			}
			part, err := writer.CreatePart(header)
			if err != nil {
				return nil, "", err
			}
			if _, err := part.Write(field.value); err != nil {
				return nil, "", err
			}
			continue
		}
		if err := writer.WriteField(field.name, string(field.value)); err != nil {
			return nil, "", err
		}
	}
	if err := writer.Close(); err != nil {
		return nil, "", err
	}
	return buffer.Bytes(), writer.FormDataContentType(), nil
}

// swapSuffix replaces the extension of name with suffix, keeping the base name.
func swapSuffix(name, suffix string) string {
	if name == "" {
		return "easyscan-probe" + suffix
	}
	if idx := strings.LastIndex(name, "."); idx >= 0 {
		return name[:idx] + suffix
	}
	return name + suffix
}

func escapeQuotes(value string) string {
	value = strings.ReplaceAll(value, "\\", "\\\\")
	return strings.ReplaceAll(value, `"`, `\"`)
}

func statusText(status int) string {
	if status == 0 {
		return "无响应"
	}
	return strconv.Itoa(status)
}

func cloneTransaction(tx model.Transaction) model.Transaction {
	tx.Request.Headers = cloneHeaderMap(tx.Request.Headers)
	tx.Response.Headers = cloneHeaderMap(tx.Response.Headers)
	return tx
}

func cloneHeaderMap(source map[string]string) map[string]string {
	result := make(map[string]string, len(source))
	for name, value := range source {
		result[name] = value
	}
	return result
}

func headerValue(headers map[string]string, name string) string {
	for key, value := range headers {
		if strings.EqualFold(strings.TrimSpace(key), name) {
			return value
		}
	}
	return ""
}

func drainLimited(body io.Reader) string {
	limited := io.LimitReader(body, maxBodyBytes)
	data, _ := io.ReadAll(limited)
	return string(data)
}

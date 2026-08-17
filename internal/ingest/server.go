package ingest

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/example/easyscan/internal/active"
	"github.com/example/easyscan/internal/engine"
	"github.com/example/easyscan/internal/features"
	"github.com/example/easyscan/internal/model"
)

type messageInput struct {
	Method      string            `json:"method"`
	URL         string            `json:"url"`
	Status      int               `json:"status"`
	Headers     map[string]string `json:"headers"`
	Body        string            `json:"body"`
	BodyBase64  string            `json:"body_base64"`
	Certificate string            `json:"certificate"`
	IconHash    string            `json:"icon_hash"`
}

type transactionInput struct {
	ID         string       `json:"id"`
	ObservedAt time.Time    `json:"observed_at"`
	Source     string       `json:"source"`
	Request    messageInput `json:"request"`
	Response   messageInput `json:"response"`
}

type Server struct {
	engine   *engine.Engine
	token    string
	maxBody  int64
	runner   *active.Runner
	features *features.Policy
}

func New(e *engine.Engine, token string, maxBody int64, runners ...*active.Runner) *Server {
	s := &Server{engine: e, token: token, maxBody: maxBody}
	if len(runners) > 0 {
		s.runner = runners[0]
	}
	return s
}

func (s *Server) SetFeaturePolicy(policy *features.Policy) { s.features = policy }

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.health)
	mux.HandleFunc("/api/v1/traffic", s.traffic)
	mux.HandleFunc("/api/v1/findings", s.findings)
	mux.HandleFunc("/api/v1/assets", s.assets)
	mux.HandleFunc("/api/v1/tasks", s.tasks)
	mux.HandleFunc("/api/v1/tasks/", s.taskByID)
	mux.HandleFunc("/api/v1/features", s.featurePolicy)
	mux.HandleFunc("/api/v1/audit", s.audit)
	return mux
}

func (s *Server) featurePolicy(w http.ResponseWriter, r *http.Request) {
	if !s.prepare(w, r) {
		return
	}
	if s.features == nil {
		http.Error(w, `{"error":"feature policy unavailable"}`, http.StatusServiceUnavailable)
		return
	}
	switch r.Method {
	case http.MethodGet:
		_ = json.NewEncoder(w).Encode(s.features.List())
	case http.MethodPut:
		var update struct {
			ID             string `json:"id"`
			Enabled        bool   `json:"enabled"`
			ErrorEnabled   *bool  `json:"error_enabled,omitempty"`
			BooleanEnabled *bool  `json:"boolean_enabled,omitempty"`
			TimeEnabled    *bool  `json:"time_enabled,omitempty"`
		}
		decoder := json.NewDecoder(io.LimitReader(r.Body, 8<<10))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&update); err != nil || update.ID == "" {
			http.Error(w, `{"error":"invalid feature update"}`, http.StatusBadRequest)
			return
		}
		var err error
		if update.ID == "passive.sqli_techniques" && update.ErrorEnabled != nil && update.BooleanEnabled != nil && update.TimeEnabled != nil {
			err = s.features.SetSQLiTechniques(*update.ErrorEnabled, *update.BooleanEnabled, *update.TimeEnabled)
		} else {
			err = s.features.Set(update.ID, update.Enabled)
		}
		if err != nil {
			http.Error(w, `{"error":`+jsonQuote(err.Error())+`}`, http.StatusForbidden)
			return
		}
		_ = json.NewEncoder(w).Encode(s.features.List())
	default:
		w.Header().Set("Allow", "GET, PUT")
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
	}
}

func (s *Server) tasks(w http.ResponseWriter, r *http.Request) {
	if !s.prepare(w, r) {
		return
	}
	if s.runner == nil {
		http.Error(w, `{"error":"active task runner unavailable"}`, http.StatusServiceUnavailable)
		return
	}
	switch r.Method {
	case http.MethodGet:
		items, err := s.runner.ListTasks(100)
		if err != nil {
			http.Error(w, `{"error":"unable to read tasks"}`, http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(items)
	case http.MethodPost:
		var input active.Request
		decoder := json.NewDecoder(io.LimitReader(r.Body, 64<<10))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&input); err != nil {
			http.Error(w, `{"error":"invalid task request"}`, http.StatusBadRequest)
			return
		}
		task, err := s.runner.Submit(input)
		if err != nil {
			http.Error(w, `{"error":`+jsonQuote(err.Error())+`}`, http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(task)
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
	}
}

func (s *Server) taskByID(w http.ResponseWriter, r *http.Request) {
	if !s.prepare(w, r) {
		return
	}
	if s.runner == nil {
		http.Error(w, `{"error":"active task runner unavailable"}`, http.StatusServiceUnavailable)
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v1/tasks/"), "/")
	if len(parts) < 2 || parts[0] == "" {
		http.NotFound(w, r)
		return
	}
	id := parts[0]
	switch parts[1] {
	case "results":
		if r.Method != http.MethodGet {
			http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		items, err := s.runner.ListTaskResults(id, 500)
		if err != nil {
			http.Error(w, `{"error":"unable to read task results"}`, http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(items)
	case "cancel":
		if r.Method != http.MethodPost {
			http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		if err := s.runner.Cancel(id); err != nil {
			http.Error(w, `{"error":`+jsonQuote(err.Error())+`}`, http.StatusConflict)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]bool{"cancelled": true})
	default:
		http.NotFound(w, r)
	}
}
func (s *Server) audit(w http.ResponseWriter, r *http.Request) {
	if !s.prepare(w, r) {
		return
	}
	if s.runner == nil {
		http.Error(w, `{"error":"active task runner unavailable"}`, http.StatusServiceUnavailable)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	items, err := s.runner.ListAudit(200)
	if err != nil {
		http.Error(w, `{"error":"unable to read audit events"}`, http.StatusInternalServerError)
		return
	}
	_ = json.NewEncoder(w).Encode(items)
}
func jsonQuote(value string) string { b, _ := json.Marshal(value); return string(b) }

func (s *Server) authorized(r *http.Request) bool {
	if s.token == "" {
		return true
	}
	return r.Header.Get("Authorization") == "Bearer "+s.token
}

func (s *Server) prepare(w http.ResponseWriter, r *http.Request) bool {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return false
	}
	if !s.authorized(r) {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return false
	}
	return true
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	if !s.prepare(w, r) {
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}
func (s *Server) findings(w http.ResponseWriter, r *http.Request) {
	if !s.prepare(w, r) {
		return
	}
	_ = json.NewEncoder(w).Encode(s.engine.Findings())
}
func (s *Server) assets(w http.ResponseWriter, r *http.Request) {
	if !s.prepare(w, r) {
		return
	}
	_ = json.NewEncoder(w).Encode(s.engine.Assets())
}

func (s *Server) traffic(w http.ResponseWriter, r *http.Request) {
	if !s.prepare(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	limit := s.maxBody*2 + (64 << 10)
	if limit <= 0 {
		limit = 2 << 20
	}
	var input transactionInput
	decoder := json.NewDecoder(io.LimitReader(r.Body, limit))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		http.Error(w, `{"error":"invalid transaction"}`, http.StatusBadRequest)
		return
	}
	requestBody, err := decodeBody(input.Request)
	if err != nil {
		http.Error(w, `{"error":"invalid request body_base64"}`, http.StatusBadRequest)
		return
	}
	responseBody, err := decodeBody(input.Response)
	if err != nil {
		http.Error(w, `{"error":"invalid response body_base64"}`, http.StatusBadRequest)
		return
	}
	if int64(len(requestBody)) > s.maxBody {
		requestBody = requestBody[:s.maxBody]
	}
	if int64(len(responseBody)) > s.maxBody {
		responseBody = responseBody[:s.maxBody]
	}
	findings := s.engine.Analyze(model.Transaction{ID: input.ID, Observed: input.ObservedAt, Source: trustedIngestSource(input.Source),
		ClientIP: clientIP(r), Request: model.Message{Method: input.Request.Method, URL: input.Request.URL, Headers: input.Request.Headers, Body: requestBody, Certificate: input.Request.Certificate, IconHash: input.Request.IconHash},
		Response: model.Message{Status: input.Response.Status, Headers: input.Response.Headers, Body: responseBody, Certificate: input.Response.Certificate, IconHash: input.Response.IconHash}})
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]any{"accepted": true, "findings": findings})
}

// trustedIngestSource reserves the internal source labels that control
// runtime behavior. API/adapter payloads may retain their own descriptive
// source, but cannot masquerade as a proxy transaction and thereby enter the
// MITM-only HFinger or probe pipelines.
func trustedIngestSource(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || model.IsObservedProxySource(strings.ToLower(value)) {
		return model.SourceAPIIngest
	}
	return value
}

func decodeBody(input messageInput) (string, error) {
	if input.BodyBase64 == "" {
		return input.Body, nil
	}
	b, err := base64.StdEncoding.DecodeString(input.BodyBase64)
	return string(b), err
}
func clientIP(r *http.Request) string { return strings.Split(r.RemoteAddr, ":")[0] }

package ssrfprobe

import (
	"strings"
	"testing"

	"github.com/example/easyscan/internal/model"
)

func TestLooksLikeURLParam(t *testing.T) {
	tests := []struct {
		name  string
		pname string
		value string
		want  bool
	}{
		{"scheme http value", "q", "http://example.com", true},
		{"scheme https value", "q", "https://example.com", true},
		{"protocol relative value", "q", "//example.com/x", true},
		{"url name hint", "redirect_url", "somewhere", true},
		{"host name hint", "targetHost", "abc", true},
		{"webhook hint", "webhook", "abc", true},
		{"plain param plain value", "id", "42", false},
		{"plain param text value", "keyword", "hello world", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := looksLikeURLParam(tt.pname, tt.value); got != tt.want {
				t.Errorf("looksLikeURLParam(%q,%q) = %v, want %v", tt.pname, tt.value, got, tt.want)
			}
		})
	}
}

func TestExtractTargetsOnlyURLLike(t *testing.T) {
	tx := model.Transaction{Request: model.Message{
		Method: "GET",
		URL:    "http://target.local/fetch?url=http://a.com&id=5&next=/home",
	}}
	got := extractTargets(tx)
	names := map[string]bool{}
	for _, tg := range got {
		names[tg.name] = true
	}
	if !names["url"] {
		t.Errorf("url param should be selected")
	}
	if !names["next"] {
		t.Errorf("next param should be selected (name hint)")
	}
	if names["id"] {
		t.Errorf("id param should NOT be selected (avoids FP noise)")
	}
}

func TestSSRFSignal(t *testing.T) {
	tests := []struct {
		name     string
		control  probeResult
		loopback probeResult
		want     bool
	}{
		{
			name:     "fetch error marker in loopback body",
			control:  probeResult{status: 200, body: "ok"},
			loopback: probeResult{status: 200, body: "curl: (7) Failed to connect to host"},
			want:     true,
		},
		{
			name:     "loopback 5xx while control differs",
			control:  probeResult{status: 200, body: "ok"},
			loopback: probeResult{status: 502, body: ""},
			want:     true,
		},
		{
			name:     "loopback status 0 while control 200",
			control:  probeResult{status: 200, body: "ok"},
			loopback: probeResult{status: 0, body: ""},
			want:     true,
		},
		{
			name:     "same status large body divergence",
			control:  probeResult{status: 200, body: "small"},
			loopback: probeResult{status: 200, body: strings.Repeat("x", 400)},
			want:     true,
		},
		{
			name:     "identical benign responses",
			control:  probeResult{status: 200, body: "same body content"},
			loopback: probeResult{status: 200, body: "same body content"},
			want:     false,
		},
		{
			name:     "both 404 small diff",
			control:  probeResult{status: 404, body: "not found"},
			loopback: probeResult{status: 404, body: "not found!"},
			want:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ssrfSignal(tt.control, tt.loopback); got != tt.want {
				t.Errorf("ssrfSignal = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestOOBProbeURL(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"", ""},
		{"   ", ""},
		{"oob.example.com", "http://ssrf.oob.example.com/easyscan"},
		{"http://oob.example.com", "http://ssrf.oob.example.com/easyscan"},
		{"https://oob.example.com/", "http://ssrf.oob.example.com/easyscan"},
	}
	for _, tt := range tests {
		if got := oobProbeURL(tt.in); got != tt.want {
			t.Errorf("oobProbeURL(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestAbsDiff(t *testing.T) {
	if absDiff(10, 3) != 7 {
		t.Errorf("absDiff(10,3) != 7")
	}
	if absDiff(3, 10) != 7 {
		t.Errorf("absDiff(3,10) != 7")
	}
	if absDiff(5, 5) != 0 {
		t.Errorf("absDiff(5,5) != 0")
	}
}

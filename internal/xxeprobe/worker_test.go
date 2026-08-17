package xxeprobe

import (
	"strings"
	"testing"

	"github.com/example/easyscan/internal/config"
	"github.com/example/easyscan/internal/model"
)

type stubPolicy struct {
	enabled bool
	qps     int
	oob     string
}

func (s stubPolicy) Enabled(string) bool     { return s.enabled }
func (s stubPolicy) PassiveXXEProbeQPS() int { return s.qps }
func (s stubPolicy) OOBDomain() string       { return s.oob }

func TestIsXMLRequest(t *testing.T) {
	tests := []struct {
		name string
		tx   model.Transaction
		want bool
	}{
		{
			name: "content-type xml",
			tx: model.Transaction{Request: model.Message{
				Headers: map[string]string{"Content-Type": "application/xml"},
				Body:    "<r>1</r>",
			}},
			want: true,
		},
		{
			name: "text xml content-type",
			tx: model.Transaction{Request: model.Message{
				Headers: map[string]string{"Content-Type": "text/xml; charset=utf-8"},
				Body:    "anything",
			}},
			want: true,
		},
		{
			name: "xml declaration prolog",
			tx: model.Transaction{Request: model.Message{
				Body: `<?xml version="1.0"?><r/>`,
			}},
			want: true,
		},
		{
			name: "tag-shaped body without content-type",
			tx: model.Transaction{Request: model.Message{
				Body: "<note><to>a</to></note>",
			}},
			want: true,
		},
		{
			name: "json body",
			tx: model.Transaction{Request: model.Message{
				Headers: map[string]string{"Content-Type": "application/json"},
				Body:    `{"a":1}`,
			}},
			want: false,
		},
		{
			name: "empty body",
			tx:   model.Transaction{Request: model.Message{Body: ""}},
			want: false,
		},
		{
			name: "plain text",
			tx:   model.Transaction{Request: model.Message{Body: "hello world"}},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isXMLRequest(tt.tx); got != tt.want {
				t.Errorf("isXMLRequest = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestXXEErrorSignal(t *testing.T) {
	tests := []struct {
		name string
		body string
		want bool
	}{
		{"libxml external entity error", "warning: failed to load external entity", true},
		{"no such file", "fopen: No such file or directory", true},
		{"java sax", "org.xml.sax.SAXParseException: DOCTYPE", true},
		{"case insensitive", "UNDEFINED ENTITY xxe", true},
		{"benign body", "<r>hello</r>", false},
		{"empty", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, hit := xxeErrorSignal(tt.body)
			if hit != tt.want {
				t.Errorf("xxeErrorSignal(%q) = %v, want %v", tt.body, hit, tt.want)
			}
		})
	}
}

func TestOOBEntity(t *testing.T) {
	if oobEntity("") != "" {
		t.Errorf("empty domain should yield empty payload")
	}
	got := oobEntity("https://oob.example.com/")
	if !strings.Contains(got, "http://xxe.oob.example.com/easyscan") {
		t.Errorf("oobEntity did not build expected system URL: %q", got)
	}
	if !strings.Contains(got, "<!DOCTYPE") {
		t.Errorf("oobEntity missing DOCTYPE declaration")
	}
}

func TestPayloads(t *testing.T) {
	base := &Worker{cfg: config.Config{}, policy: stubPolicy{}}
	got := base.payloads()
	if len(got) != 2 {
		t.Fatalf("without OOB expected 2 payloads, got %d", len(got))
	}
	for _, p := range got {
		if !strings.Contains(p.body, marker) {
			t.Errorf("payload %q missing marker", p.kind)
		}
		if !strings.Contains(p.body, "<!DOCTYPE") {
			t.Errorf("payload %q missing DOCTYPE", p.kind)
		}
	}

	withOOB := &Worker{cfg: config.Config{}, policy: stubPolicy{oob: "oob.example.com"}}
	got2 := withOOB.payloads()
	if len(got2) != 3 {
		t.Fatalf("with OOB expected 3 payloads, got %d", len(got2))
	}
	if got2[2].kind != "oob-entity" {
		t.Errorf("third payload kind = %q, want oob-entity", got2[2].kind)
	}
}

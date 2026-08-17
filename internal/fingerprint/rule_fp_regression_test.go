package fingerprint

import (
	"testing"

	"github.com/example/easyscan/internal/model"
)

// TestSeeyonRuleIgnoresGenericPortalContent guards against the live false
// positive found on large news portals: a page that merely links to a URL
// containing "/seeyon/" or contains the common idiom "致远" (e.g. "宁静致远")
// must not be fingerprinted as Seeyon OA. Only high-confidence product markers
// may trigger the rule.
func TestSeeyonRuleIgnoresGenericPortalContent(t *testing.T) {
	database, err := LoadHFinger(t.TempDir(), 40)
	if err != nil {
		t.Fatal(err)
	}
	bodies := []string{
		`<html><body><a href="https://ad.portal.test/seeyon/promo">news</a>` +
			`<p>宁静致远，厚德载物</p></body></html>`,
		`<html><title>综合门户</title><div>推荐：致远教育、致远咨询</div></html>`,
	}
	for _, body := range bodies {
		tx := model.Transaction{
			Request:  model.Message{Method: "GET", URL: "https://portal.example.test/"},
			Response: model.Message{Status: 200, Headers: map[string]string{"Content-Type": "text/html"}, Body: body},
		}
		matches := database.MatchDetailsMulti([]model.Transaction{tx}, true, true)
		if containsFingerprintMatch(matches, "Seeyon 致远 OA") {
			t.Fatalf("generic portal content must not match Seeyon: body=%q matches=%#v", body, matches)
		}
	}
}

// TestSeeyonRuleStillDetectsGenuineDeployment pairs the negative above: a real
// Seeyon deployment exposing its JS context path / product id must still match.
func TestSeeyonRuleStillDetectsGenuineDeployment(t *testing.T) {
	database, err := LoadHFinger(t.TempDir(), 40)
	if err != nil {
		t.Fatal(err)
	}
	tx := model.Transaction{
		Request: model.Message{Method: "GET", URL: "https://oa.example.test/seeyon/main.do"},
		Response: model.Message{
			Status:  200,
			Headers: map[string]string{"Content-Type": "text/html"},
			Body:    `<html><script>var _ctxPath = '/seeyon';var seeyonProductID="A8-V5";</script></html>`,
		},
	}
	matches := database.MatchDetailsMulti([]model.Transaction{tx}, true, true)
	if !containsFingerprintMatch(matches, "Seeyon 致远 OA") {
		t.Fatalf("genuine Seeyon deployment must still match: %#v", matches)
	}
}

// TestRetiredRcs2000RuleNoLongerFalsePositives guards against the live false
// positive on w3.org: the retired RCS-2000 rule matched any response whose
// headers merely contained the substring "/cms". No response should now yield
// that fingerprint.
func TestRetiredRcs2000RuleNoLongerFalsePositives(t *testing.T) {
	database, err := LoadHFinger(t.TempDir(), 40)
	if err != nil {
		t.Fatal(err)
	}
	tx := model.Transaction{
		Request: model.Message{Method: "GET", URL: "https://standards.example.test/"},
		Response: model.Message{
			Status: 200,
			Headers: map[string]string{
				"Content-Type": "text/html",
				"Link":         "</cms/assets/style.css>; rel=preload",
			},
			Body: `<html><title>Standards</title></html>`,
		},
	}
	matches := database.MatchDetailsMulti([]model.Transaction{tx}, true, true)
	if containsFingerprintMatch(matches, "机器人控制系统（RCS-2000）") {
		t.Fatalf("retired RCS-2000 rule must not match generic /cms header: %#v", matches)
	}
}

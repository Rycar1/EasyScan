package importer

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func TestBurpXML(t *testing.T) {
	request := base64.StdEncoding.EncodeToString([]byte("GET /admin HTTP/1.1\r\nHost: app.example.test\r\n\r\n"))
	response := base64.StdEncoding.EncodeToString([]byte("HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n<title>Admin</title>"))
	contents := "<items><item><time>2026-07-16T00:00:00Z</time><url>https://app.example.test/admin</url><method>GET</method><status>200</status><request base64=\"true\">" + request + "</request><response base64=\"true\">" + response + "</response></item></items>"
	filename := filepath.Join(t.TempDir(), "items.xml")
	if err := os.WriteFile(filename, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	transactions, err := BurpXML(filename)
	if err != nil {
		t.Fatal(err)
	}
	if len(transactions) != 1 || transactions[0].Request.Method != "GET" || transactions[0].Response.Status != 200 || transactions[0].Response.Headers["Server"] != "nginx" {
		t.Fatalf("unexpected transactions: %#v", transactions)
	}
}

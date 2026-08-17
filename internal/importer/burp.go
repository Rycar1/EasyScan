package importer

import (
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/example/easyscan/internal/model"
)

type burpItems struct {
	Items []burpItem `xml:"item"`
}
type burpText struct {
	Value  string `xml:",chardata"`
	Base64 bool   `xml:"base64,attr"`
}
type burpItem struct {
	Time     string   `xml:"time"`
	URL      string   `xml:"url"`
	Method   string   `xml:"method"`
	Status   int      `xml:"status"`
	Request  burpText `xml:"request"`
	Response burpText `xml:"response"`
}

// BurpXML imports Burp Suite's standard "Save items" XML export. The raw
// contents are decoded locally and flow through the same passive engine path.
func BurpXML(filename string) ([]model.Transaction, error) {
	b, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("read Burp XML: %w", err)
	}
	var document burpItems
	if err := xml.Unmarshal(b, &document); err != nil {
		return nil, fmt.Errorf("parse Burp XML: %w", err)
	}
	transactions := make([]model.Transaction, 0, len(document.Items))
	for _, item := range document.Items {
		requestRaw, err := burpBody(item.Request)
		if err != nil {
			return nil, fmt.Errorf("decode Burp request: %w", err)
		}
		responseRaw, err := burpBody(item.Response)
		if err != nil {
			return nil, fmt.Errorf("decode Burp response: %w", err)
		}
		request := parseBurpRequest(requestRaw)
		response := parseBurpResponse(responseRaw)
		if request.Method == "" {
			request.Method = item.Method
		}
		request.URL = item.URL
		if response.Status == 0 {
			response.Status = item.Status
		}
		if request.URL == "" {
			continue
		}
		transactions = append(transactions, model.Transaction{Observed: parseBurpTime(item.Time), Source: "burp-xml", Request: request, Response: response})
	}
	return transactions, nil
}

func burpBody(value burpText) (string, error) {
	if !value.Base64 {
		return value.Value, nil
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value.Value))
	return string(decoded), err
}
func parseBurpRequest(raw string) model.Message {
	head, body := splitBurpRaw(raw)
	lines := rawLines(head)
	message := model.Message{Headers: map[string]string{}, Body: body}
	if len(lines) > 0 {
		parts := strings.Fields(lines[0])
		if len(parts) > 0 {
			message.Method = parts[0]
		}
	}
	message.Headers = parseBurpHeaders(lines[1:])
	return message
}
func parseBurpResponse(raw string) model.Message {
	head, body := splitBurpRaw(raw)
	lines := rawLines(head)
	message := model.Message{Headers: map[string]string{}, Body: body}
	if len(lines) > 0 {
		parts := strings.Fields(lines[0])
		if len(parts) > 1 {
			message.Status, _ = strconv.Atoi(parts[1])
		}
	}
	message.Headers = parseBurpHeaders(lines[1:])
	return message
}
func splitBurpRaw(raw string) (string, string) {
	if parts := strings.SplitN(raw, "\r\n\r\n", 2); len(parts) == 2 {
		return parts[0], parts[1]
	}
	if parts := strings.SplitN(raw, "\n\n", 2); len(parts) == 2 {
		return parts[0], parts[1]
	}
	return raw, ""
}
func rawLines(head string) []string {
	lines := strings.Split(head, "\r\n")
	if len(lines) == 1 {
		lines = strings.Split(head, "\n")
	}
	return lines
}
func parseBurpHeaders(lines []string) map[string]string {
	headers := map[string]string{}
	for _, line := range lines {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if prior, exists := headers[key]; exists {
			headers[key] = prior + "\n" + value
		} else {
			headers[key] = value
		}
	}
	return headers
}
func parseBurpTime(value string) time.Time {
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "Mon Jan 02 15:04:05 MST 2006"} {
		if parsed, err := time.Parse(layout, strings.TrimSpace(value)); err == nil {
			return parsed.UTC()
		}
	}
	return time.Time{}
}

package importer

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/example/easyscan/internal/model"
)

type harFile struct {
	Log struct {
		Entries []harEntry `json:"entries"`
	} `json:"log"`
}
type harHeader struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}
type harContent struct {
	Text     string `json:"text"`
	Encoding string `json:"encoding"`
}
type harEntry struct {
	StartedDateTime string `json:"startedDateTime"`
	Request         struct {
		Method   string      `json:"method"`
		URL      string      `json:"url"`
		Headers  []harHeader `json:"headers"`
		PostData struct {
			Text string `json:"text"`
		} `json:"postData"`
	} `json:"request"`
	Response struct {
		Status  int         `json:"status"`
		Headers []harHeader `json:"headers"`
		Content harContent  `json:"content"`
	} `json:"response"`
}

func HAR(filename string) ([]model.Transaction, error) {
	b, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("read HAR: %w", err)
	}
	var file harFile
	if err := json.Unmarshal(b, &file); err != nil {
		return nil, fmt.Errorf("parse HAR: %w", err)
	}
	transactions := make([]model.Transaction, 0, len(file.Log.Entries))
	for _, entry := range file.Log.Entries {
		observed, _ := time.Parse(time.RFC3339Nano, entry.StartedDateTime)
		body := entry.Response.Content.Text
		if strings.EqualFold(entry.Response.Content.Encoding, "base64") {
			decoded, err := base64.StdEncoding.DecodeString(body)
			if err == nil {
				body = string(decoded)
			}
		}
		transactions = append(transactions, model.Transaction{Observed: observed, Source: "har",
			Request:  model.Message{Method: entry.Request.Method, URL: entry.Request.URL, Headers: mapHeaders(entry.Request.Headers), Body: entry.Request.PostData.Text},
			Response: model.Message{Status: entry.Response.Status, Headers: mapHeaders(entry.Response.Headers), Body: body}})
	}
	return transactions, nil
}

func mapHeaders(headers []harHeader) map[string]string {
	result := make(map[string]string, len(headers))
	for _, header := range headers {
		if old, ok := result[header.Name]; ok {
			result[header.Name] = old + "\n" + header.Value
		} else {
			result[header.Name] = header.Value
		}
	}
	return result
}

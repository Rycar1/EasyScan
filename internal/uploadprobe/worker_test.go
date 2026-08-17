package uploadprobe

import (
	"bytes"
	"io"
	"mime"
	"mime/multipart"
	"testing"

	"github.com/example/easyscan/internal/model"
)

func buildMultipartBody(t *testing.T, fileField, filename, fileCT, content, textField, textVal string) (string, string) {
	t.Helper()
	buf := &bytes.Buffer{}
	writer := multipart.NewWriter(buf)
	if textField != "" {
		if err := writer.WriteField(textField, textVal); err != nil {
			t.Fatalf("write text field: %v", err)
		}
	}
	part, err := writer.CreateFormFile(fileField, filename)
	if err != nil {
		t.Fatalf("create form file: %v", err)
	}
	if _, err := part.Write([]byte(content)); err != nil {
		t.Fatalf("write file content: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}
	return buf.String(), writer.FormDataContentType()
}

func TestIsMultipartUpload(t *testing.T) {
	body, ct := buildMultipartBody(t, "file", "shell.jpg", "", "data", "", "")
	tests := []struct {
		name string
		tx   model.Transaction
		want bool
	}{
		{
			name: "genuine multipart upload",
			tx: model.Transaction{Request: model.Message{
				Headers: map[string]string{"Content-Type": ct},
				Body:    body,
			}},
			want: true,
		},
		{
			name: "multipart without filename",
			tx: model.Transaction{Request: model.Message{
				Headers: map[string]string{"Content-Type": "multipart/form-data; boundary=x"},
				Body:    "--x\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nv\r\n--x--",
			}},
			want: false,
		},
		{
			name: "urlencoded form",
			tx: model.Transaction{Request: model.Message{
				Headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
				Body:    "a=1&filename=x",
			}},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isMultipartUpload(tt.tx); got != tt.want {
				t.Errorf("isMultipartUpload = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSwapSuffix(t *testing.T) {
	tests := []struct {
		name   string
		suffix string
		want   string
	}{
		{"shell.jpg", ".html", "shell.html"},
		{"archive.tar.gz", ".html", "archive.tar.html"},
		{"noext", ".html", "noext.html"},
		{"", ".html", "easyscan-probe.html"},
	}
	for _, tt := range tests {
		if got := swapSuffix(tt.name, tt.suffix); got != tt.want {
			t.Errorf("swapSuffix(%q,%q) = %q, want %q", tt.name, tt.suffix, got, tt.want)
		}
	}
}

func TestUploadAccepted(t *testing.T) {
	tests := []struct {
		name    string
		status  int
		body    string
		newName string
		want    bool
	}{
		{"echoes new name", 200, `{"path":"/up/shell.html"}`, "shell.html", true},
		{"success marker", 200, "上传成功", "shell.html", true},
		{"rejected by marker even if 200", 200, "文件类型不允许", "shell.html", false},
		{"rejected english marker", 200, "file type not allowed", "shell.html", false},
		{"non 2xx", 403, "shell.html accepted", "shell.html", false},
		{"2xx but no signal", 204, "", "shell.html", false},
		{"reject wins over echo", 200, "shell.html illegal file", "shell.html", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := uploadAccepted(tt.status, tt.body, tt.newName); got != tt.want {
				t.Errorf("uploadAccepted = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseAndUploadedFilename(t *testing.T) {
	body, ct := buildMultipartBody(t, "upload", "photo.png", "image/png", "PNGDATA", "csrf", "token123")
	tx := model.Transaction{Request: model.Message{
		Headers: map[string]string{"Content-Type": ct},
		Body:    body,
	}}
	fields, boundary, ok := parseMultipart(tx)
	if !ok {
		t.Fatalf("parseMultipart failed on valid body")
	}
	if boundary == "" {
		t.Errorf("boundary empty")
	}
	if uploadedFilename(fields) != "photo.png" {
		t.Errorf("uploadedFilename = %q, want photo.png", uploadedFilename(fields))
	}
}

// TestRebuildMultipartRenamesAndRetypes verifies the rebuilt body renames the
// first file field, forces text/html, and preserves the other fields.
func TestRebuildMultipartRenamesAndRetypes(t *testing.T) {
	body, ct := buildMultipartBody(t, "upload", "photo.png", "image/png", "PNGDATA", "csrf", "token123")
	tx := model.Transaction{Request: model.Message{
		Headers: map[string]string{"Content-Type": ct},
		Body:    body,
	}}
	fields, boundary, ok := parseMultipart(tx)
	if !ok {
		t.Fatalf("parseMultipart failed")
	}
	rebuilt, newCT, err := rebuildMultipart(fields, boundary, "photo.html")
	if err != nil {
		t.Fatalf("rebuildMultipart error: %v", err)
	}

	_, params, _ := mime.ParseMediaType(newCT)
	reader := multipart.NewReader(bytes.NewReader(rebuilt), params["boundary"])
	sawFile := false
	sawText := false
	for {
		part, err := reader.NextPart()
		if err != nil {
			break
		}
		if part.FileName() != "" {
			sawFile = true
			if part.FileName() != "photo.html" {
				t.Errorf("filename = %q, want photo.html", part.FileName())
			}
			if part.Header.Get("Content-Type") != "text/html" {
				t.Errorf("file content-type = %q, want text/html", part.Header.Get("Content-Type"))
			}
			data, _ := io.ReadAll(part)
			if string(data) != "PNGDATA" {
				t.Errorf("file bytes altered: %q", string(data))
			}
		} else if part.FormName() == "csrf" {
			sawText = true
			data, _ := io.ReadAll(part)
			if string(data) != "token123" {
				t.Errorf("csrf value = %q, want token123", string(data))
			}
		}
		part.Close()
	}
	if !sawFile {
		t.Errorf("rebuilt body missing file part")
	}
	if !sawText {
		t.Errorf("rebuilt body dropped text field")
	}
}

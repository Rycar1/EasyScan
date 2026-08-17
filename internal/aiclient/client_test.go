package aiclient

import "testing"

func TestConfigured(t *testing.T) {
	if Configured("", "m", "k") {
		t.Fatal("empty base URL must not be configured")
	}
	if Configured("https://api.example.com", "", "k") {
		t.Fatal("empty model must not be configured")
	}
	if Configured("https://api.example.com", "m", " ") {
		t.Fatal("blank API key must not be configured")
	}
	if !Configured("https://api.example.com", "m", "k") {
		t.Fatal("complete settings must be configured")
	}
}

func TestNormalizeBaseURL(t *testing.T) {
	cases := map[string]string{
		"https://api.example.com":        "https://api.example.com/v1",
		"https://api.example.com/":       "https://api.example.com/v1",
		"https://api.example.com/v1":     "https://api.example.com/v1",
		"https://api.example.com/v1/":    "https://api.example.com/v1",
		"https://gateway.local/ai/v2":    "https://gateway.local/ai/v2",
		"":                               "",
	}
	for input, want := range cases {
		if got := NormalizeBaseURL(input); got != want {
			t.Fatalf("NormalizeBaseURL(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestChatUnconfigured(t *testing.T) {
	client := New("", "", "")
	if _, err := client.Chat(nil, "s", "u"); err == nil {
		t.Fatal("expected error for unconfigured client")
	}
}

package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Proxy struct {
		Listen       string `yaml:"listen"`
		MaxBodyBytes int64  `yaml:"max_body_bytes"`
		MITM         bool   `yaml:"mitm"`
		CADir        string `yaml:"ca_dir"`
	} `yaml:"proxy"`
	API struct {
		Listen string `yaml:"listen"`
		Token  string `yaml:"token"`
	} `yaml:"api"`
	Scope struct {
		AllowHosts      []string `yaml:"allow_hosts"`
		DenyHosts       []string `yaml:"deny_hosts"`
		AllowPrivateIPs bool     `yaml:"allow_private_ips"`
	} `yaml:"scope"`
	Privacy struct {
		RedactEvidence bool `yaml:"redact_evidence"`
	} `yaml:"privacy"`
	Rules struct {
		Files []string `yaml:"files"`
	} `yaml:"rules"`
	Fingerprints struct {
		// HFinger uses HackAllSec/hfinger's embedded core rules for responses
		// already captured by the local proxy. CustomDir is hot-reloadable from
		// the desktop settings and accepts .yaml/.yml HFinger rules.
		HFinger struct {
			CustomDir  string `yaml:"custom_dir"`
			MaxMatches int    `yaml:"max_matches_per_transaction"`
		} `yaml:"hfinger"`
	} `yaml:"fingerprints"`
	Storage struct {
		Path string `yaml:"path"`
	} `yaml:"storage"`
	Reports struct {
		AutoHTML bool   `yaml:"auto_html"`
		HTMLPath string `yaml:"html_path"`
	} `yaml:"reports"`
	Features struct {
		Path string `yaml:"path"`
	} `yaml:"features"`
	Active struct {
		Enabled               bool `yaml:"enabled"`
		MaxConcurrentTasks    int  `yaml:"max_concurrent_tasks"`
		MaxConcurrentRequests int  `yaml:"max_concurrent_requests"`
		TimeoutSeconds        int  `yaml:"timeout_seconds"`
		MinIntervalMS         int  `yaml:"min_interval_ms"`
		MaxRequestsPerTask    int  `yaml:"max_requests_per_task"`
		EnableHeadlessCrawl   bool `yaml:"enable_headless_crawl"`
	} `yaml:"active"`
	// WebScan contains the low-impact HTTP and crawler controls modelled after
	// the reference scanner's webscan settings.  They affect explicitly
	// authorised active tasks and the separately opt-in MITM SQL probe worker.
	WebScan struct {
		HTTP struct {
			MaxQPS             int               `yaml:"max_qps"`
			Retry              int               `yaml:"retry"`
			TimeoutSeconds     int               `yaml:"timeout_seconds"`
			MaxRedirects       int               `yaml:"max_redirect"`
			Headers            map[string]string `yaml:"headers"`
			HeadersForce       map[string]string `yaml:"headers_force"`
			MaxFailures        int               `yaml:"max_failures"`
			DisallowedScanPath []string          `yaml:"disallowed_scan_path"`
			StrictSameOrigin   bool              `yaml:"strict_same_origin"`
		} `yaml:"http"`
		Crawler struct {
			ChromePath       string   `yaml:"chrome_path"`
			NoSandbox        bool     `yaml:"no_sandbox"`
			DisableImages    bool     `yaml:"disable_images"`
			UserAgent        string   `yaml:"user_agent"`
			MaxDepth         int      `yaml:"max_depth"`
			MaxPages         int      `yaml:"max_pages"`
			ExcludedSuffixes []string `yaml:"excluded_suffixes"`
		} `yaml:"crawler"`
	} `yaml:"webscan"`
	Analysis struct {
		OnlyFingerprint bool     `yaml:"only_fingerprint"`
		DisabledChecks  []string `yaml:"disabled_checks"`
	} `yaml:"analysis"`
}

func Default() Config {
	var c Config
	c.Proxy.Listen = "127.0.0.1:7777"
	c.Proxy.MaxBodyBytes = 1 << 20
	c.Proxy.CADir = "data/ca"
	c.API.Listen = "127.0.0.1:8787"
	c.Privacy.RedactEvidence = true
	c.Storage.Path = "data/easyscan.db"
	c.Reports.AutoHTML = true
	c.Reports.HTMLPath = "easyscan-scan-report.html"
	c.Features.Path = "features.yaml"
	c.Fingerprints.HFinger.MaxMatches = 40
	c.Active.MaxConcurrentTasks = 2
	c.Active.MaxConcurrentRequests = 4
	c.Active.TimeoutSeconds = 3
	c.Active.MinIntervalMS = 250
	c.Active.MaxRequestsPerTask = 50
	c.WebScan.HTTP.MaxQPS = 4
	c.WebScan.HTTP.TimeoutSeconds = 3
	c.WebScan.HTTP.MaxRedirects = 0
	c.WebScan.HTTP.MaxFailures = 5
	c.WebScan.HTTP.StrictSameOrigin = true
	c.WebScan.Crawler.MaxDepth = 2
	c.WebScan.Crawler.MaxPages = 50
	return c
}

func Load(path string) (Config, error) {
	c := Default()
	if path == "" {
		return c, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return c, fmt.Errorf("read config %q: %w", path, err)
	}
	if err := yaml.Unmarshal(b, &c); err != nil {
		return c, fmt.Errorf("parse config %q: %w", path, err)
	}
	if c.Proxy.MaxBodyBytes <= 0 {
		c.Proxy.MaxBodyBytes = 1 << 20
	}
	if c.Proxy.CADir == "" {
		c.Proxy.CADir = "data/ca"
	}
	if c.Storage.Path == "" {
		c.Storage.Path = "data/easyscan.db"
	}
	if c.Reports.HTMLPath == "" {
		c.Reports.HTMLPath = "easyscan-scan-report.html"
	}
	if c.Features.Path == "" {
		c.Features.Path = "features.yaml"
	}
	if c.Active.MaxConcurrentTasks <= 0 {
		c.Active.MaxConcurrentTasks = 1
	}
	if c.Active.MaxConcurrentRequests <= 0 {
		c.Active.MaxConcurrentRequests = 1
	}
	if c.Active.TimeoutSeconds <= 0 {
		c.Active.TimeoutSeconds = 3
	}
	if c.Active.MinIntervalMS < 0 {
		c.Active.MinIntervalMS = 0
	}
	if c.Active.MaxRequestsPerTask <= 0 {
		c.Active.MaxRequestsPerTask = 50
	}
	if c.WebScan.HTTP.MaxQPS < 0 {
		return c, fmt.Errorf("webscan.http.max_qps must not be negative")
	}
	if c.WebScan.HTTP.Retry < 0 || c.WebScan.HTTP.Retry > 3 {
		return c, fmt.Errorf("webscan.http.retry must be between 0 and 3")
	}
	if c.WebScan.HTTP.TimeoutSeconds <= 0 {
		c.WebScan.HTTP.TimeoutSeconds = c.Active.TimeoutSeconds
	}
	if c.WebScan.HTTP.MaxRedirects < 0 || c.WebScan.HTTP.MaxRedirects > 5 {
		return c, fmt.Errorf("webscan.http.max_redirects must be between 0 and 5")
	}
	if c.WebScan.HTTP.MaxFailures <= 0 {
		c.WebScan.HTTP.MaxFailures = 5
	}
	if c.WebScan.Crawler.MaxDepth < 0 || c.WebScan.Crawler.MaxDepth > 10 {
		return c, fmt.Errorf("webscan.crawler.max_depth must be between 0 and 10")
	}
	if c.WebScan.Crawler.MaxPages <= 0 {
		c.WebScan.Crawler.MaxPages = c.Active.MaxRequestsPerTask
	}
	if c.WebScan.Crawler.MaxPages > c.Active.MaxRequestsPerTask {
		c.WebScan.Crawler.MaxPages = c.Active.MaxRequestsPerTask
	}
	if err := validateHeaders(c.WebScan.HTTP.Headers, "webscan.http.headers"); err != nil {
		return c, err
	}
	if err := validateHeaders(c.WebScan.HTTP.HeadersForce, "webscan.http.headers_force"); err != nil {
		return c, err
	}
	if c.Proxy.MITM && len(c.Scope.AllowHosts) == 0 {
		return c, fmt.Errorf("proxy.mitm requires a non-empty scope.allow_hosts")
	}
	base, err := filepath.Abs(filepath.Dir(path))
	if err != nil {
		return c, fmt.Errorf("resolve config directory for %q: %w", path, err)
	}
	resolveLocalPaths(&c, base)
	return c, nil
}

// resolveLocalPaths makes configuration portable when the desktop executable
// is started from a different working directory. Resource paths are relative
// to the YAML file, not to the process that happened to launch EasyScan.
func resolveLocalPaths(c *Config, base string) {
	c.Proxy.CADir = localPath(base, c.Proxy.CADir)
	c.Fingerprints.HFinger.CustomDir = localPath(base, c.Fingerprints.HFinger.CustomDir)
	c.Storage.Path = localPath(base, c.Storage.Path)
	c.Reports.HTMLPath = localPath(base, c.Reports.HTMLPath)
	c.Features.Path = localPath(base, c.Features.Path)
	for index, file := range c.Rules.Files {
		c.Rules.Files[index] = localPath(base, file)
	}
}

func localPath(base, value string) string {
	if value == "" || filepath.IsAbs(value) {
		return value
	}
	return filepath.Join(base, value)
}

func validateHeaders(headers map[string]string, field string) error {
	for name, value := range headers {
		if !validHeaderName(name) || len(name) > 80 || len(value) > 8192 || containsNewline(value) {
			return fmt.Errorf("%s contains an invalid header", field)
		}
	}
	return nil
}

func validHeaderName(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if !(r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
			return false
		}
	}
	return true
}

func containsNewline(value string) bool {
	for _, r := range value {
		if r == '\r' || r == '\n' {
			return true
		}
	}
	return false
}

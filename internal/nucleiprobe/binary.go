// Package nucleiprobe integrates the official ProjectDiscovery nuclei binary
// into EasyScan's MITM POC pipeline. When a new in-scope origin is observed,
// the worker maps the host's recognized fingerprints to nuclei -tags and runs
// the external binary once per origin, parsing its JSONL output into findings.
//
// This file owns the binary manager: locating a usable nuclei executable and
// downloading the latest release from GitHub on demand.
package nucleiprobe

import (
	"archive/zip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"
)

const (
	// managedBinaryName is the file name of the nuclei executable stored in the
	// managed download directory.
	managedBinaryDirName = "nuclei"
	// managedTemplatesDirName is the sub-directory under dataDir where an
	// optional custom nuclei template set may live. When present it is passed to
	// nuclei via -t so users can extend the POC library without replacing the
	// binary's default templates.
	managedTemplatesDirName = "nuclei-templates"
	// templatesEnv lets a user point EasyScan at an arbitrary nuclei template
	// directory, taking precedence over the managed one.
	templatesEnv     = "EASYSCAN_NUCLEI_TEMPLATES"
	latestReleaseURL = "https://api.github.com/repos/projectdiscovery/nuclei/releases/latest"
	downloadTimeout  = 5 * time.Minute
	// maxDownloadBytes caps the release archive size we are willing to write to
	// disk, guarding against an unbounded or malicious response body.
	maxDownloadBytes = 300 << 20
)

// binaryName returns the platform-specific nuclei executable file name.
func binaryName() string {
	if runtime.GOOS == "windows" {
		return "nuclei.exe"
	}
	return "nuclei"
}

// Manager locates and downloads the nuclei binary. It is safe for concurrent
// use; downloads are serialized so two settings clicks cannot race.
type Manager struct {
	// dataDir is where the managed (downloaded) binary is stored, e.g.
	// <exe>/data/nuclei.
	dataDir string
	// configuredPath returns the user-specified override path (may be empty).
	configuredPath func() string

	mu sync.Mutex
}

// NewManager builds a manager rooted at dataDir. configuredPath is consulted on
// every Resolve call so a saved settings change applies without a restart.
func NewManager(dataDir string, configuredPath func() string) *Manager {
	return &Manager{dataDir: dataDir, configuredPath: configuredPath}
}

// managedPath is the location of the downloaded binary.
func (m *Manager) managedPath() string {
	return filepath.Join(m.dataDir, managedBinaryDirName, binaryName())
}

// TemplatesDir returns an optional custom nuclei template directory to pass via
// -t, or "" to use nuclei's built-in templates. Precedence: the
// EASYSCAN_NUCLEI_TEMPLATES override, then a managed <dataDir>/nuclei-templates
// directory if it exists. A configured-but-missing directory yields "" so the
// scan silently falls back to the default templates instead of erroring.
func (m *Manager) TemplatesDir() string {
	if custom := strings.TrimSpace(os.Getenv(templatesEnv)); custom != "" {
		if isDir(custom) {
			return custom
		}
		return ""
	}
	if m == nil || strings.TrimSpace(m.dataDir) == "" {
		return ""
	}
	managed := filepath.Join(m.dataDir, managedTemplatesDirName)
	if isDir(managed) {
		return managed
	}
	return ""
}

// CalibrationTemplatesDir returns the directory whose tags should be used to
// calibrate which nuclei tags actually have templates. It prefers an explicit
// custom directory (TemplatesDir) and otherwise falls back to nuclei's default
// "$HOME/nuclei-templates" library. Returns "" when nothing is available.
func (m *Manager) CalibrationTemplatesDir() string {
	if custom := m.TemplatesDir(); custom != "" {
		return custom
	}
	home, err := os.UserHomeDir()
	if err != nil || strings.TrimSpace(home) == "" {
		return ""
	}
	def := filepath.Join(home, "nuclei-templates")
	if isDir(def) {
		return def
	}
	return ""
}

// Resolve returns a usable nuclei executable path following the precedence:
// user override -> managed download -> PATH lookup. It returns an error when no
// usable binary is found so the caller can surface a clear message.
func (m *Manager) Resolve() (string, error) {
	if m.configuredPath != nil {
		if custom := strings.TrimSpace(m.configuredPath()); custom != "" {
			if isExecutable(custom) {
				return custom, nil
			}
			return "", fmt.Errorf("配置的 nuclei 路径不可用: %s", custom)
		}
	}
	if managed := m.managedPath(); isExecutable(managed) {
		return managed, nil
	}
	if found, err := exec.LookPath("nuclei"); err == nil {
		return found, nil
	}
	return "", errors.New("未找到可用的 nuclei，请在设置中下载或指定路径")
}

// Installed reports whether Resolve would currently succeed.
func (m *Manager) Installed() bool {
	_, err := m.Resolve()
	return err == nil
}

// Version runs "nuclei -version" and returns the trimmed output. It is used by
// the desktop layer to show the active binary version.
func (m *Manager) Version(ctx context.Context) (string, error) {
	path, err := m.Resolve()
	if err != nil {
		return "", err
	}
	cmd := exec.CommandContext(ctx, path, "-version")
	hideWindow(cmd)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("执行 nuclei -version 失败: %w", err)
	}
	return cleanVersionOutput(string(out)), nil
}

// ansiEscapePattern matches ANSI SGR color escape sequences that nuclei writes
// to its log output (e.g. "\x1b[34m").
var ansiEscapePattern = regexp.MustCompile(`\x1b\[[0-9;]*m`)

// cleanVersionOutput turns the raw, colorized multi-line "nuclei -version"
// output into a single clean version string. nuclei prints its banner via the
// logger, so the payload is wrapped in ANSI color codes and "[INF]" prefixes
// and mixed with unrelated directory lines; we strip the colors and keep only
// the engine version line.
func cleanVersionOutput(raw string) string {
	clean := ansiEscapePattern.ReplaceAllString(raw, "")
	for _, line := range strings.Split(clean, "\n") {
		line = strings.TrimSpace(line)
		if idx := strings.Index(line, "Nuclei Engine Version:"); idx >= 0 {
			if v := strings.TrimSpace(line[idx+len("Nuclei Engine Version:"):]); v != "" {
				return v
			}
		}
	}
	// Fall back to the first non-empty, de-prefixed line so callers still get
	// something meaningful if nuclei changes its banner wording.
	for _, line := range strings.Split(clean, "\n") {
		line = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "[INF]"))
		if line != "" {
			return strings.TrimSpace(line)
		}
	}
	return strings.TrimSpace(clean)
}

// ghAsset is a single release artifact from the GitHub API.
type ghAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

// ghRelease is the subset of the GitHub latest-release payload we consume.
type ghRelease struct {
	TagName string    `json:"tag_name"`
	Assets  []ghAsset `json:"assets"`
}

// DownloadLatest fetches the latest nuclei release from GitHub, extracts the
// platform archive into the managed directory, and returns the resolved binary
// path. Existing binaries are overwritten so the user always gets the newest
// version. Downloads are serialized by the manager mutex.
func (m *Manager) DownloadLatest(ctx context.Context) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	release, err := fetchLatestRelease(ctx)
	if err != nil {
		return "", err
	}
	asset, err := selectAsset(release.Assets)
	if err != nil {
		return "", err
	}
	targetDir := filepath.Join(m.dataDir, managedBinaryDirName)
	if err := os.MkdirAll(targetDir, 0o700); err != nil {
		return "", fmt.Errorf("创建 nuclei 目录失败: %w", err)
	}
	archivePath := filepath.Join(targetDir, asset.Name)
	if err := downloadFile(ctx, asset.BrowserDownloadURL, archivePath); err != nil {
		return "", err
	}
	defer os.Remove(archivePath)
	if err := extractBinaryFromZip(archivePath, targetDir); err != nil {
		return "", err
	}
	resolved := m.managedPath()
	if !isExecutable(resolved) {
		return "", fmt.Errorf("解压后未找到 nuclei 可执行文件: %s", resolved)
	}
	return resolved, nil
}

func fetchLatestRelease(ctx context.Context) (*ghRelease, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, latestReleaseURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "EasyScan")
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("查询 nuclei 最新版本失败: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("查询 nuclei 最新版本返回状态 %d", resp.StatusCode)
	}
	var release ghRelease
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&release); err != nil {
		return nil, fmt.Errorf("解析 nuclei 版本信息失败: %w", err)
	}
	if len(release.Assets) == 0 {
		return nil, errors.New("nuclei 最新版本无可用下载资源")
	}
	return &release, nil
}

// selectAsset picks the release asset that matches the current OS/arch. nuclei
// names assets like nuclei_<version>_windows_amd64.zip.
func selectAsset(assets []ghAsset) (ghAsset, error) {
	return selectAssetFor(runtime.GOOS, runtime.GOARCH, assets)
}

// selectAssetFor picks the release asset matching the given os/arch. It is
// split out from selectAsset so tests can exercise arbitrary platforms.
func selectAssetFor(osToken, archToken string, assets []ghAsset) (ghAsset, error) {
	// nuclei release assets are named like "nuclei_<ver>_<os>_<arch>.zip". Match
	// on the exact "_<os>_<arch>." boundary so a 32-bit "arm" build does not
	// accidentally select an "arm64" asset (strings.Contains("arm64","arm")).
	wantOSArch := "_" + osToken + "_" + archToken + "."
	for _, asset := range assets {
		name := strings.ToLower(asset.Name)
		if !strings.HasSuffix(name, ".zip") {
			continue
		}
		if strings.Contains(name, wantOSArch) {
			return asset, nil
		}
	}
	return ghAsset{}, fmt.Errorf("未找到匹配 %s/%s 的 nuclei 下载资源", osToken, archToken)
}

func downloadFile(ctx context.Context, url, dest string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "EasyScan")
	client := &http.Client{Timeout: downloadTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("下载 nuclei 失败: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("下载 nuclei 返回状态 %d", resp.StatusCode)
	}
	tmp := dest + ".tmp"
	out, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, io.LimitReader(resp.Body, maxDownloadBytes)); err != nil {
		out.Close()
		os.Remove(tmp)
		return fmt.Errorf("写入 nuclei 下载文件失败: %w", err)
	}
	if err := out.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, dest)
}

// extractBinaryFromZip extracts only the nuclei executable from the release
// archive into targetDir, guarding against zip-slip traversal.
func extractBinaryFromZip(archivePath, targetDir string) error {
	reader, err := zip.OpenReader(archivePath)
	if err != nil {
		return fmt.Errorf("打开 nuclei 压缩包失败: %w", err)
	}
	defer reader.Close()
	want := binaryName()
	for _, file := range reader.File {
		if filepath.Base(file.Name) != want {
			continue
		}
		dest := filepath.Join(targetDir, want)
		rc, err := file.Open()
		if err != nil {
			return err
		}
		out, err := os.OpenFile(dest, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
		if err != nil {
			rc.Close()
			return err
		}
		if _, err := io.Copy(out, io.LimitReader(rc, 200<<20)); err != nil {
			rc.Close()
			out.Close()
			return fmt.Errorf("解压 nuclei 失败: %w", err)
		}
		rc.Close()
		if err := out.Close(); err != nil {
			return err
		}
		return nil
	}
	return errors.New("nuclei 压缩包内未找到可执行文件")
}

// isExecutable reports whether path points at an existing regular file.
func isExecutable(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !info.IsDir()
}

func isDir(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.IsDir()
}

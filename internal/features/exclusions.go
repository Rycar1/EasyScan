package features

import "strings"

var defaultExcludedSuffixes = []string{
	".css", ".jpg", ".jpeg", ".png", ".mp3", ".mp4", ".ico",
	".bmp", ".flv", ".aac", ".ogg", ".avi", ".svg", ".gif", ".woff",
	".woff2", ".doc", ".docx", ".pptx", ".ppt", ".pdf",
}

var defaultExcludedContentTypes = []string{
	"image/*", "audio/*", "video/*", "application/ogg", "application/pdf",
	"application/msword", "application/x-ppt", "video/avi", "application/x-ico", "*zip",
}

func (p *Policy) ExcludedDomains() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return append([]string(nil), p.excludedDomains...)
}

func (p *Policy) ExcludedHost(host string) bool {
	normalized, ok := normalizeExcludedHost(host)
	if !ok {
		return false
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	for _, pattern := range p.excludedDomains {
		if excludedDomainMatch(normalized, pattern) {
			return true
		}
	}
	return false
}

func (p *Policy) ExcludedSuffixes() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return append([]string(nil), p.excludedSuffixes...)
}

func (p *Policy) ExcludedURLPath(urlPath string) bool {
	urlPath = strings.ToLower(urlPath)
	p.mu.RLock()
	defer p.mu.RUnlock()
	for _, suffix := range p.excludedSuffixes {
		if strings.HasSuffix(urlPath, suffix) {
			return true
		}
	}
	return false
}

func (p *Policy) ExcludedContentTypes() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return append([]string(nil), p.excludedContentTypes...)
}

func (p *Policy) ExcludedContentType(contentType string) bool {
	normalized := normalizeObservedContentType(contentType)
	if normalized == "" {
		return false
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	for _, pattern := range p.excludedContentTypes {
		if excludedContentTypeMatch(normalized, pattern) {
			return true
		}
	}
	return false
}

// ExcludedPaths returns the normalized path globs that suppress an entire
// passively observed transaction. A single star stays within one path segment
// and a double star crosses path separators, for example /assets/** and
// */health.
func (p *Policy) ExcludedPaths() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return append([]string(nil), p.excludedPaths...)
}

// ExcludedPath reports whether a URL path matches one of the configured path
// globs. The caller should pass URL.Path rather than a full URL or raw query.
func (p *Policy) ExcludedPath(urlPath string) bool {
	normalized, ok := normalizeObservedExcludedPath(urlPath)
	if !ok {
		return false
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return excludedPathPatternsMatch(normalized, p.excludedPaths)
}

func (p *Policy) ExcludedQueryParameters() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return append([]string(nil), p.excludedQueryParameters...)
}

func (p *Policy) ExcludedQueryParameter(name string) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return excludedParameterMatch(name, p.excludedQueryParameters)
}

func (p *Policy) ExcludedPostParameters() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return append([]string(nil), p.excludedPostParameters...)
}

// ExcludedPostParameter applies to form fields and JSON property names.
func (p *Policy) ExcludedPostParameter(name string) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return excludedParameterMatch(name, p.excludedPostParameters)
}

// ExcludedRequest combines the three request-side filters in one lock-safe
// call. A true result means the whole transaction should be forwarded without
// logging, passive analysis, fingerprinting, findings, or active scheduling.
func (p *Policy) ExcludedRequest(urlPath string, queryParameters, postParameters []string) bool {
	normalizedPath, pathOK := normalizeObservedExcludedPath(urlPath)
	p.mu.RLock()
	defer p.mu.RUnlock()
	if pathOK && excludedPathPatternsMatch(normalizedPath, p.excludedPaths) {
		return true
	}
	for _, name := range queryParameters {
		if excludedParameterMatch(name, p.excludedQueryParameters) {
			return true
		}
	}
	for _, name := range postParameters {
		if excludedParameterMatch(name, p.excludedPostParameters) {
			return true
		}
	}
	return false
}

func (p *Policy) SetExcludedDomains(domains []string) error {
	normalized, err := NormalizeExcludedDomains(domains)
	if err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	previous := p.excludedDomains
	p.excludedDomains = normalized
	if err := p.saveLocked(); err != nil {
		p.excludedDomains = previous
		return err
	}
	return nil
}

func (p *Policy) SetExcludedSuffixes(suffixes []string) error {
	normalized, err := NormalizeExcludedSuffixes(suffixes)
	if err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	previous := p.excludedSuffixes
	p.excludedSuffixes = normalized
	if err := p.saveLocked(); err != nil {
		p.excludedSuffixes = previous
		return err
	}
	return nil
}

func (p *Policy) SetExcludedContentTypes(contentTypes []string) error {
	normalized, err := NormalizeExcludedContentTypes(contentTypes)
	if err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	previous := p.excludedContentTypes
	p.excludedContentTypes = normalized
	if err := p.saveLocked(); err != nil {
		p.excludedContentTypes = previous
		return err
	}
	return nil
}

func (p *Policy) SetExcludedPaths(paths []string) error {
	normalized, err := NormalizeExcludedPaths(paths)
	if err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	previous := p.excludedPaths
	p.excludedPaths = normalized
	if err := p.saveLocked(); err != nil {
		p.excludedPaths = previous
		return err
	}
	return nil
}

// SwaggerExcludedPaths returns the normalized path patterns that suppress
// swagger documentation probing for captured path prefixes. A plain "/js"
// excludes "/js" and everything beneath it; glob patterns follow the same
// dialect as the traffic-filter path exclusions.
func (p *Policy) SwaggerExcludedPaths() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return append([]string(nil), p.swaggerExcludedPaths...)
}

// SwaggerExcludedPath reports whether a captured path prefix should be
// skipped by the swagger probe. The root prefix ("") is never excluded so
// the site-root documentation paths are always probed once per origin.
func (p *Policy) SwaggerExcludedPath(prefix string) bool {
	normalized, ok := normalizeObservedExcludedPath(prefix)
	if !ok || normalized == "/" {
		return false
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return swaggerPrefixExcluded(normalized, p.swaggerExcludedPaths)
}

func (p *Policy) SetSwaggerExcludedPaths(paths []string) error {
	normalized, err := NormalizeExcludedPaths(paths)
	if err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	previous := p.swaggerExcludedPaths
	p.swaggerExcludedPaths = normalized
	if err := p.saveLocked(); err != nil {
		p.swaggerExcludedPaths = previous
		return err
	}
	return nil
}

func (p *Policy) CustomProbePaths() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return append([]string(nil), p.customProbePaths...)
}

func (p *Policy) SetCustomProbePaths(paths []string) error {
	normalized := NormalizeCustomProbePaths(paths)
	p.mu.Lock()
	defer p.mu.Unlock()
	previous := p.customProbePaths
	p.customProbePaths = normalized
	if err := p.saveLocked(); err != nil {
		p.customProbePaths = previous
		return err
	}
	return nil
}

// AIBaseURL returns the configured OpenAI-compatible endpoint base URL.
func (p *Policy) AIBaseURL() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.aiBaseURL
}

// AIModel returns the configured AI model name.
func (p *Policy) AIModel() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.aiModel
}

// AIAPIKey returns the configured AI API key.
func (p *Policy) AIAPIKey() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.aiAPIKey
}

// NucleiBinaryPath returns the user-configured path to the nuclei executable.
// An empty value means the runtime should fall back to the bundled/downloaded
// binary or the one discovered on PATH.
func (p *Policy) NucleiBinaryPath() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.nucleiBinaryPath
}

func (p *Policy) SetExcludedQueryParameters(parameters []string) error {
	normalized, err := NormalizeExcludedQueryParameters(parameters)
	if err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	previous := p.excludedQueryParameters
	p.excludedQueryParameters = normalized
	if err := p.saveLocked(); err != nil {
		p.excludedQueryParameters = previous
		return err
	}
	return nil
}

func (p *Policy) SetExcludedPostParameters(parameters []string) error {
	normalized, err := NormalizeExcludedPostParameters(parameters)
	if err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	previous := p.excludedPostParameters
	p.excludedPostParameters = normalized
	if err := p.saveLocked(); err != nil {
		p.excludedPostParameters = previous
		return err
	}
	return nil
}

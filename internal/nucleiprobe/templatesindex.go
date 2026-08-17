package nucleiprobe

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// TagIndex is a set of nuclei template tags known to exist in a template
// directory. It is used to drop tags that TagsFor derives from a fingerprint
// but for which no template actually exists, so nuclei is never invoked with a
// tag that can only match zero POCs.
type TagIndex struct {
	tags map[string]struct{}
}

// Has reports whether tag is present in the index.
func (t *TagIndex) Has(tag string) bool {
	if t == nil || len(t.tags) == 0 {
		return false
	}
	_, ok := t.tags[tag]
	return ok
}

// Size returns the number of distinct tags indexed.
func (t *TagIndex) Size() int {
	if t == nil {
		return 0
	}
	return len(t.tags)
}

// Filter keeps only the tags present in the index, preserving order. When the
// index is empty it returns the input unchanged so callers safely degrade to
// "no calibration" instead of dropping everything.
func (t *TagIndex) Filter(tags []string) []string {
	if t == nil || len(t.tags) == 0 {
		return tags
	}
	kept := make([]string, 0, len(tags))
	for _, tag := range tags {
		if _, ok := t.tags[tag]; ok {
			kept = append(kept, tag)
		}
	}
	return kept
}

// BuildTagIndex walks dir for nuclei template YAML files and collects every tag
// declared in their "tags:" field. It is intentionally a lightweight line scan
// rather than a full YAML parse so indexing 10k+ templates stays fast. A missing
// or unreadable directory yields an empty (nil-safe) index.
func BuildTagIndex(dir string) *TagIndex {
	idx := &TagIndex{tags: map[string]struct{}{}}
	dir = strings.TrimSpace(dir)
	if dir == "" || !isDir(dir) {
		return idx
	}
	_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}
		collectTemplateTags(path, idx.tags)
		return nil
	})
	return idx
}

// collectTemplateTags reads a single template file and adds its tags to dst. It
// recognizes both the inline form ("tags: a,b,c") and the block-list form
// ("tags:\n  - a\n  - b"). Scanning stops once the tags line is consumed for the
// inline form; block form reads the immediately following list items.
func collectTemplateTags(path string, dst map[string]struct{}) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)
	inBlock := false
	for scanner.Scan() {
		raw := scanner.Text()
		line := strings.TrimSpace(raw)
		if inBlock {
			if strings.HasPrefix(line, "- ") {
				addTag(dst, strings.TrimPrefix(line, "- "))
				continue
			}
			// Any non-list line ends the block form.
			inBlock = false
		}
		if !strings.HasPrefix(line, "tags:") {
			continue
		}
		value := strings.TrimSpace(strings.TrimPrefix(line, "tags:"))
		if value == "" {
			// Block-list form: the tags follow on subsequent "- x" lines.
			inBlock = true
			continue
		}
		for _, part := range strings.Split(value, ",") {
			addTag(dst, part)
		}
		// The info block only declares tags once; stop early to avoid picking up
		// unrelated "tags:" keys nested elsewhere.
		return
	}
}

func addTag(dst map[string]struct{}, tag string) {
	tag = strings.ToLower(strings.TrimSpace(strings.Trim(tag, `"'`)))
	if tag == "" {
		return
	}
	dst[tag] = struct{}{}
}

// tagIndexCache lazily builds and memoizes a TagIndex per directory so repeated
// scans across many origins do not re-walk the template tree. It supports
// asynchronous warm-up so the first scan is not blocked by the (potentially
// multi-second) walk of a large template library.
type tagIndexCache struct {
	mu       sync.Mutex
	dir      string
	index    *TagIndex
	building bool
}

// get returns the cached index for dir, building it synchronously on first use.
// When dir changes the cache is rebuilt. An empty dir yields an empty index.
// This blocks and is used by callers (and tests) that need the index now.
func (c *tagIndexCache) get(dir string) *TagIndex {
	c.mu.Lock()
	if c.index != nil && c.dir == dir {
		idx := c.index
		c.mu.Unlock()
		return idx
	}
	c.mu.Unlock()

	built := BuildTagIndex(dir)

	c.mu.Lock()
	defer c.mu.Unlock()
	// Honor a concurrent warm-up that may have finished for the same dir.
	if c.index == nil || c.dir != dir {
		c.dir = dir
		c.index = built
	}
	return c.index
}

// ready returns the cached index for dir without building it, or nil when the
// index is not built yet (or is being built for a different dir). Callers use
// nil to mean "skip calibration for now" so scans never block on the walk.
func (c *tagIndexCache) ready(dir string) *TagIndex {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.index != nil && c.dir == dir {
		return c.index
	}
	return nil
}

// warm builds the index for dir in the background if it is not already built or
// in progress. Safe to call multiple times; only one build runs at a time. The
// build is bounded by nothing here — callers pass an already-scoped goroutine
// lifecycle if cancellation is required.
func (c *tagIndexCache) warm(dir string) {
	c.mu.Lock()
	if c.building || (c.index != nil && c.dir == dir) {
		c.mu.Unlock()
		return
	}
	c.building = true
	c.mu.Unlock()

	built := BuildTagIndex(dir)

	c.mu.Lock()
	c.dir = dir
	c.index = built
	c.building = false
	c.mu.Unlock()
}


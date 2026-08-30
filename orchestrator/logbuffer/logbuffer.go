// Package logbuffer provides a small, thread-safe, in-memory ring buffer that
// captures output written to Go's standard logger. It is used by the TEMPORARY
// debug console (GET /api/v1/debug/logs) so operators can view and filter recent
// orchestrator logs from the UI without shelling into the container.
//
// It implements io.Writer, so it can be attached with:
//
//	buf := logbuffer.New(2000)
//	log.SetOutput(io.MultiWriter(os.Stderr, buf))
//
// This is a debugging aid and is expected to be removed (or disabled via
// DEBUG_CONSOLE=false) once module execution is confirmed healthy.
package logbuffer

import (
	"bytes"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Entry is a single parsed log line.
type Entry struct {
	ID      int64     `json:"id"`      // monotonically increasing; used as a poll cursor
	Time    time.Time `json:"time"`    // capture time (server clock)
	Level   string    `json:"level"`   // "info" | "warn" | "error"
	Source  string    `json:"source"`  // component tag, e.g. "worker", "scheduler", "callback"
	Message string    `json:"message"` // line with the leading date/time stripped
	Raw     string    `json:"raw"`     // original, unmodified line
}

// Query filters entries returned by Buffer.Query.
type Query struct {
	Level  string // "" or "all" for any
	Source string // "" or "all" for any
	Search string // case-insensitive substring match against Raw
	Since  int64  // return only entries with ID > Since (0 = from start)
	Limit  int    // max entries returned (most recent kept); 0 = no cap
}

// Buffer is a bounded FIFO store of log entries. Safe for concurrent use.
type Buffer struct {
	mu       sync.Mutex
	entries  []Entry
	capacity int
	nextID   int64
	partial  []byte // holds an incomplete trailing line between Write calls
}

// New creates a Buffer holding up to capacity entries (default 2000).
func New(capacity int) *Buffer {
	if capacity <= 0 {
		capacity = 2000
	}
	return &Buffer{
		capacity: capacity,
		entries:  make([]Entry, 0, capacity),
	}
}

// Write implements io.Writer. It splits input on newlines, parses each complete
// line into an Entry, and appends it. It never returns an error so it is safe to
// use as a logger sink.
func (b *Buffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.partial = append(b.partial, p...)
	for {
		idx := bytes.IndexByte(b.partial, '\n')
		if idx < 0 {
			break
		}
		line := string(b.partial[:idx])
		b.partial = b.partial[idx+1:]
		if strings.TrimSpace(line) == "" {
			continue
		}
		b.appendLocked(parseLine(line))
	}
	return len(p), nil
}

func (b *Buffer) appendLocked(e Entry) {
	b.nextID++
	e.ID = b.nextID
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	if len(b.entries) >= b.capacity {
		// Drop the oldest entry. O(n) but log volume is low and capacity small.
		copy(b.entries, b.entries[1:])
		b.entries = b.entries[:len(b.entries)-1]
	}
	b.entries = append(b.entries, e)
}

// Query returns entries matching q, oldest-to-newest.
func (b *Buffer) Query(q Query) []Entry {
	b.mu.Lock()
	defer b.mu.Unlock()

	search := strings.ToLower(q.Search)
	out := make([]Entry, 0, len(b.entries))
	for _, e := range b.entries {
		if q.Since > 0 && e.ID <= q.Since {
			continue
		}
		if q.Level != "" && q.Level != "all" && e.Level != q.Level {
			continue
		}
		if q.Source != "" && q.Source != "all" && e.Source != q.Source {
			continue
		}
		if search != "" && !strings.Contains(strings.ToLower(e.Raw), search) {
			continue
		}
		out = append(out, e)
	}
	if q.Limit > 0 && len(out) > q.Limit {
		out = out[len(out)-q.Limit:]
	}
	return out
}

// Sources returns the distinct component tags currently present, for populating
// a filter dropdown.
func (b *Buffer) Sources() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	seen := map[string]bool{}
	out := []string{}
	for _, e := range b.entries {
		if !seen[e.Source] {
			seen[e.Source] = true
			out = append(out, e.Source)
		}
	}
	return out
}

// Counts returns the number of buffered entries per level.
func (b *Buffer) Counts() map[string]int {
	b.mu.Lock()
	defer b.mu.Unlock()
	c := map[string]int{"info": 0, "warn": 0, "error": 0}
	for _, e := range b.entries {
		c[e.Level]++
	}
	return c
}

// ─── Parsing ──────────────────────────────────────────────────────────────────

var (
	// Matches the default Go log prefix: "2025/08/10 12:00:00 " (optional micros).
	tsRe = regexp.MustCompile(`^\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}(\.\d+)?\s+`)
	// Matches the first "[tag]" component marker used throughout the codebase.
	sourceRe = regexp.MustCompile(`\[([a-zA-Z0-9_\-]+)\]`)
)

func parseLine(line string) Entry {
	raw := line
	msg := tsRe.ReplaceAllString(line, "")

	source := "app"
	if m := sourceRe.FindStringSubmatch(msg); m != nil {
		source = m[1]
	}

	return Entry{
		Time:    time.Now(),
		Level:   classify(msg),
		Source:  source,
		Message: msg,
		Raw:     raw,
	}
}

// classify infers a severity level from the message text. It is intentionally
// conservative: anything that looks like a failure is surfaced as "error" so it
// is easy to filter for problems in the console.
func classify(s string) string {
	l := strings.ToLower(s)
	switch {
	case strings.Contains(l, "panic"),
		strings.Contains(l, "fatal"),
		strings.Contains(l, "error"),
		strings.Contains(l, "failed"),
		strings.Contains(l, "failure"),
		strings.Contains(l, "unknown module"),
		strings.Contains(l, "unable to"),
		strings.Contains(l, "could not"):
		return "error"
	case strings.Contains(l, "warn"),
		strings.Contains(l, "retry"),
		strings.Contains(l, "retrying"):
		return "warn"
	default:
		return "info"
	}
}

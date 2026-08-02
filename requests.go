package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// RequestEntry is one parsed line from an nginx proxy manager (NPM) access
// log — a single HTTP request that arrived at the VPS and was forwarded to
// one of the proxied services. This is exactly what the "Requests" tile in
// the UI renders as one table row.
type RequestEntry struct {
	Time     int64  `json:"time"`     // unix seconds, parsed from the log's [time_local]
	Domain   string `json:"domain"`   // the Host the client asked for, e.g. api.example.com
	Method   string `json:"method"`   // GET, POST, OPTIONS, ...
	Path     string `json:"path"`     // request URI incl. query, e.g. /api/v1/getStash
	Status   int    `json:"status"`   // HTTP status NPM returned, e.g. 200, 404
	ClientIP string `json:"client"`   // remote address of the caller
	Upstream string `json:"upstream"` // which backend NPM forwarded to (Sent-to)
}

// npmLogLine parses one line of NPM's DEFAULT access-log format. A real line
// looks like (wrapped here for readability):
//
//	[07/Jul/2026:20:26:09 +0000] - 200 200 - POST https api.example.com
//	  "/api/v1/orders" [Client 203.0.113.10] [Length 74] [Gzip -]
//	  [Sent-to app-backend] "<user-agent>" "<referer>"
//
// Rather than split on spaces (fragile — user-agents and URIs contain
// spaces), we anchor a regexp on the parts whose shape is fixed. Each
// capture group below is numbered so extractRequest can pull it out by index:
//
//	1 time_local   inside the leading [...]
//	2 status       first 3-digit number after the cache-status token
//	3 method       GET / POST / ... (the request verb)
//	4 scheme       http | https              (captured but unused)
//	5 host         the domain the client requested
//	6 request_uri  inside the first "..." — the path we want
//	7 client_ip    inside [Client ...]
//	8 upstream     inside [Sent-to ...]
var npmLogLine = regexp.MustCompile(
	`^\[([^\]]+)\]` + // 1: [time_local]
		`\s+\S+` + //        cache status (usually "-")
		`\s+(\d{3})` + //    2: status code
		`\s+\S+` + //        upstream status
		`\s+\S+` + //        request length / dash
		`\s+(\S+)` + //      3: method
		`\s+(\S+)` + //      4: scheme
		`\s+(\S+)` + //      5: host
		`\s+"([^"]*)"` + //  6: request uri (quoted)
		`.*?\[Client\s+([^\]]+)\]` + //  7: client ip
		`.*?\[Sent-to\s+([^\]]*)\]`) //  8: upstream name

// npmTimeLayout is Go's reference-time spelling of NPM's timestamp
// (day/Mon/year:hour:min:sec zone). time.Parse matches an input against this.
const npmTimeLayout = "02/Jan/2006:15:04:05 -0700"

// extractRequest turns a single raw log line into a RequestEntry. It returns
// ok=false when the line doesn't match (blank lines, stream logs, or the
// letsencrypt log all share the directory but not this format) so the caller
// can simply skip them.
func extractRequest(line string) (RequestEntry, bool) {
	// FindStringSubmatch returns nil when the line doesn't match the format;
	// on a match, m[0] is the whole match and m[1..8] are the capture groups.
	m := npmLogLine.FindStringSubmatch(line)
	if m == nil {
		return RequestEntry{}, false
	}

	// Parse the timestamp; if it's somehow malformed we keep the entry but
	// leave Time at 0 rather than dropping an otherwise-valid request.
	var unix int64
	if parsed, err := time.Parse(npmTimeLayout, m[1]); err == nil {
		unix = parsed.Unix()
	}

	// The status group is guaranteed to be 3 digits by the regexp, so Atoi
	// cannot realistically fail; ignore the error and use whatever it returns.
	status, _ := strconv.Atoi(m[2])

	// Assemble the entry from the captured groups (see npmLogLine for the
	// index → field mapping).
	return RequestEntry{
		Time:     unix,
		Domain:   m[5],
		Method:   m[3],
		Path:     m[6],
		Status:   status,
		ClientIP: m[7],
		Upstream: m[8],
	}, true
}

// tailLines reads roughly the last maxBytes of a file and returns its lines,
// newest content included. We seek near the end instead of reading the whole
// file because a busy proxy-host log can be many megabytes and we only ever
// show the most recent requests.
func tailLines(path string, maxBytes int64) []string {
	// Open the log read-only; a missing/again-rotated file just yields nil.
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	// Stat gives us the current size so we can compute how far from the end
	// to start reading.
	info, err := f.Stat()
	if err != nil {
		return nil
	}

	// start is the byte offset we begin reading from: the last maxBytes of
	// the file, or 0 if the file is smaller than that.
	start := info.Size() - maxBytes
	if start < 0 {
		start = 0
	}
	// Move the read cursor to that offset before reading.
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		return nil
	}

	// Read from the cursor to EOF into memory (bounded by maxBytes).
	data, err := io.ReadAll(f)
	if err != nil {
		return nil
	}

	// Split into individual lines.
	lines := splitLines(string(data))
	// When we seeked into the middle of the file, the first "line" is almost
	// certainly a partial line — drop it so we never parse a half record.
	if start > 0 && len(lines) > 0 {
		lines = lines[1:]
	}
	return lines
}

// splitLines breaks text on '\n' and discards empty trailing pieces. It
// avoids strings.Split's habit of returning a trailing "" after the final
// newline, which would just fail the parser anyway.
func splitLines(text string) []string {
	var out []string
	// start marks the beginning of the current line as we scan forward.
	start := 0
	for i := 0; i < len(text); i++ {
		if text[i] == '\n' {
			// Emit the line [start, i) if it isn't empty, then advance start
			// past the newline.
			if i > start {
				out = append(out, text[start:i])
			}
			start = i + 1
		}
	}
	// Emit whatever follows the last newline (a line with no trailing \n).
	if start < len(text) {
		out = append(out, text[start:])
	}
	return out
}

// collectRequests reads every proxy-host access log in the mounted NPM log
// directory, parses the recent lines, merges them, and returns the newest
// `limit` requests across ALL domains, sorted newest-first.
//
// It never fails hard: an unmounted directory or an unreadable file simply
// contributes nothing. The second return value is a diagnostic for the UI —
// empty when everything is fine, otherwise it names the reason the table is
// empty (not mounted / wrong directory / unrecognised log format), because
// "no requests" alone is indistinguishable from a silent misconfiguration.
func collectRequests(limit int) ([]RequestEntry, string) {
	// Where NPM's logs are mounted inside this container (see docker-compose).
	dir := envOr("NPM_LOG_DIR", "/npm-logs")

	// Nothing mounted at all: the feature is simply off.
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return nil, fmt.Sprintf("%s does not exist in the container — mount nginx proxy manager's log directory there (see docker-compose.yml) to see traffic here", dir)
	}

	// Match only the plain access logs. Rotated ".log.1.gz" files are skipped
	// (different content encoding) and so are the *_error.log files — we only
	// want request records. The glob also picks up fallback_http_access.log,
	// whose bot-probe traffic is genuinely useful to see.
	paths, err := filepath.Glob(filepath.Join(dir, "*_access.log"))
	if err != nil {
		return nil, "cannot list " + dir + ": " + err.Error()
	}
	if len(paths) == 0 {
		// The mount exists but holds no access logs: almost always the host
		// path is wrong (Docker created an empty directory) or it points at
		// something other than NPM's /data/logs.
		return nil, fmt.Sprintf("%s is mounted but contains no *_access.log files (%s) — point the mount at nginx proxy manager's /data/logs on the host: docker inspect <npm-container> --format '{{json .Mounts}}'", dir, describeDir(dir))
	}

	var all []RequestEntry
	// Walk each log file and accumulate its parsed entries.
	for _, path := range paths {
		// Read at most the last 256KB of each file — enough for a few hundred
		// recent requests on even a chatty host, cheap enough to do per poll.
		for _, line := range tailLines(path, 256*1024) {
			if entry, ok := extractRequest(line); ok {
				all = append(all, entry)
			}
		}
	}
	if len(all) == 0 {
		// Files are there but nothing parsed: either genuinely no traffic yet,
		// or NPM's log format was customised away from the default the
		// npmLogLine regexp expects.
		return nil, fmt.Sprintf("read %d access log(s) in %s but no line matched nginx proxy manager's default log format — either no traffic has arrived yet, or the format was customised", len(paths), dir)
	}

	// Sort the merged list newest-first so the UI shows the latest request at
	// the top regardless of which file it came from.
	sort.Slice(all, func(i, j int) bool { return all[i].Time > all[j].Time })

	// Trim to the requested limit (the tail of oldest entries is discarded).
	if len(all) > limit {
		all = all[:limit]
	}
	return all, ""
}

// describeDir lists the first few names inside dir so the "wrong directory"
// diagnostic can show what IS there — usually enough to recognise the mistake
// at a glance (e.g. an empty directory, or NPM's /data instead of /data/logs).
func describeDir(dir string) string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "unreadable: " + err.Error()
	}
	if len(entries) == 0 {
		return "the directory is empty"
	}
	names := make([]string, 0, 5)
	for _, entry := range entries {
		if len(names) == 5 {
			names = append(names, "…")
			break
		}
		names = append(names, entry.Name())
	}
	return "it contains: " + strings.Join(names, ", ")
}

// requestsResponse is the JSON shape of GET /api/requests: the entries plus,
// when the list is empty for a fixable reason, the explanation to render in
// place of the table.
type requestsResponse struct {
	Requests []RequestEntry `json:"requests"`
	Error    string         `json:"error,omitempty"`
}

// handleRequests serves GET /api/requests: the backend of the "Requests"
// tile. It returns the most recent proxied HTTP requests as JSON. The client
// polls this on its own timer and does all filtering (by domain / method /
// status) in the browser, so this handler stays trivial.
//
// The optional ?limit=N query bounds how many entries come back (default 200,
// clamped to 1000 so a crafted URL can't ask us to sort a huge slice).
func handleRequests(w http.ResponseWriter, r *http.Request) {
	// Default limit, overridable via ?limit= within sane bounds.
	limit := 200
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 && n <= 1000 {
		limit = n
	}

	// Collect and stream the entries straight to the response as JSON,
	// matching how every other handler encodes its reply.
	entries, diagnostic := collectRequests(limit)
	if entries == nil {
		entries = []RequestEntry{} // encode as [] rather than null
	}
	writeJSON(w, http.StatusOK, requestsResponse{Requests: entries, Error: diagnostic})
}

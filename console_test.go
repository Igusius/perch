package main

// Tests for the Redis console. The round-trip tests run against a real TCP
// listener speaking RESP, so the wire encoding, the reply parser and the HTTP
// handler are all exercised the way a browser would hit them - not mocked out
// one layer below the bug.

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeRedis listens on a local port and answers each command with a canned
// reply, recording what it was asked. reply is looked up by the uppercased
// command name; "" means "any command", used by the single-reply tests.
type fakeRedis struct {
	t        *testing.T
	ln       net.Listener
	replies  map[string]string
	gotMu    chan struct{}
	received []([]string)
}

func newFakeRedis(t *testing.T, replies map[string]string) *fakeRedis {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeRedis{t: t, ln: ln, replies: replies, gotMu: make(chan struct{}, 1)}
	f.gotMu <- struct{}{}
	go f.serve()
	t.Cleanup(func() { ln.Close() })
	return f
}

func (f *fakeRedis) addr() string { return f.ln.Addr().String() }

func (f *fakeRedis) serve() {
	for {
		conn, err := f.ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer conn.Close()
			br := bufio.NewReader(conn)
			for {
				args, err := readFakeCommand(br)
				if err != nil {
					return
				}
				<-f.gotMu
				f.received = append(f.received, args)
				f.gotMu <- struct{}{}
				reply, ok := f.replies[strings.ToUpper(args[0])]
				if !ok {
					reply = f.replies[""]
				}
				if reply == "" {
					reply = "+OK\r\n"
				}
				if _, err := io.WriteString(conn, reply); err != nil {
					return
				}
			}
		}()
	}
}

// readFakeCommand decodes the RESP array of bulk strings a client sends.
func readFakeCommand(br *bufio.Reader) ([]string, error) {
	header, err := br.ReadString('\n')
	if err != nil {
		return nil, err
	}
	var n int
	if _, err := fmtSscan(strings.TrimSpace(header[1:]), &n); err != nil {
		return nil, err
	}
	args := make([]string, 0, n)
	for i := 0; i < n; i++ {
		lenLine, err := br.ReadString('\n')
		if err != nil {
			return nil, err
		}
		var size int
		if _, err := fmtSscan(strings.TrimSpace(lenLine[1:]), &size); err != nil {
			return nil, err
		}
		buf := make([]byte, size+2)
		if _, err := io.ReadFull(br, buf); err != nil {
			return nil, err
		}
		args = append(args, string(buf[:size]))
	}
	return args, nil
}

func (f *fakeRedis) commands() [][]string {
	<-f.gotMu
	defer func() { f.gotMu <- struct{}{} }()
	out := make([][]string, len(f.received))
	copy(out, f.received)
	return out
}

// postConsole drives the real HTTP handler and decodes its response.
func postConsole(t *testing.T, body string) (int, redisConsoleResponse) {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/console/redis", strings.NewReader(body))
	handleRedisConsole(rec, req)
	var resp redisConsoleResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		// Error responses use the shared {"error": …} shape, which decodes into
		// the same struct's Error field.
		t.Fatalf("response is not JSON: %s", rec.Body.String())
	}
	return rec.Code, resp
}

func TestRedisConsole_RoundTripRendersLikeRedisCli(t *testing.T) {
	// An array reply must come back numbered the way redis-cli prints it, and
	// the command must reach the server in RESP form.
	f := newFakeRedis(t, map[string]string{
		"KEYS": "*3\r\n$5\r\nuser1\r\n$5\r\nuser2\r\n$7\r\nsession\r\n",
	})
	code, resp := postConsole(t, `{"target":"`+f.addr()+`","command":"KEYS *"}`)

	if code != 200 {
		t.Fatalf("status %d, body %+v", code, resp)
	}
	if resp.Error != "" {
		t.Fatalf("unexpected error: %s", resp.Error)
	}
	want := "1) user1\n2) user2\n3) session"
	if resp.Reply != want {
		t.Errorf("reply = %q, want %q", resp.Reply, want)
	}
	got := f.commands()
	if len(got) != 1 || got[0][0] != "KEYS" || got[0][1] != "*" {
		t.Errorf("server received %v, want [[KEYS *]]", got)
	}
}

func TestRedisConsole_BlocksDestructiveCommands(t *testing.T) {
	// The allowlist is the security boundary: these must be refused BEFORE a
	// connection is opened, so a reachable Redis is never even dialed.
	f := newFakeRedis(t, nil)
	for _, cmd := range []string{
		"FLUSHALL", "FLUSHDB", "SET k v", "DEL k", "CONFIG SET maxmemory 0",
		"SHUTDOWN NOSAVE", "DEBUG SEGFAULT", "EVAL \"return 1\" 0", "SCRIPT FLUSH",
		"CLIENT KILL ID 4", "MIGRATE host 6379 k 0 100", "SUBSCRIBE news",
	} {
		body, err := json.Marshal(redisConsoleRequest{Target: f.addr(), Command: cmd})
		if err != nil {
			t.Fatal(err)
		}
		code, resp := postConsole(t, string(body))
		if code != 403 {
			t.Errorf("%q returned %d, want 403 (%s)", cmd, code, resp.Error)
		}
	}
	if got := f.commands(); len(got) != 0 {
		t.Errorf("blocked commands still reached the server: %v", got)
	}
}

func TestRedisCommandAllowed_SubcommandSplit(t *testing.T) {
	// CONFIG GET is read-only, CONFIG SET is not, and both share a command
	// name - the subcommand allowlist is what separates them.
	allowed := [][]string{
		{"CONFIG", "GET", "maxmemory"}, {"CLIENT", "LIST"}, {"SLOWLOG", "GET", "10"},
		{"MEMORY", "USAGE", "k"}, {"info"}, {"scan", "0", "COUNT", "100"},
	}
	for _, args := range allowed {
		if err := redisCommandAllowed(args); err != nil {
			t.Errorf("%v should be allowed: %v", args, err)
		}
	}
	blocked := [][]string{
		{"CONFIG", "SET", "maxmemory", "0"}, {"CONFIG", "RESETSTAT"},
		{"CLIENT", "KILL"}, {"MEMORY", "PURGE"}, {"SLOWLOG", "RESET"},
		{"XINFO", "BOGUS"},
	}
	for _, args := range blocked {
		if err := redisCommandAllowed(args); err == nil {
			t.Errorf("%v should be blocked", args)
		}
	}
	// A container command with no subcommand at all must not slip through.
	if err := redisCommandAllowed([]string{"CONFIG"}); err == nil {
		t.Error("bare CONFIG should be rejected")
	}
}

func TestRedisConsole_AuthAndSelectPrecedeTheCommand(t *testing.T) {
	// Credentials and the database must be applied on the same connection,
	// before the command, or the command runs against the wrong db.
	f := newFakeRedis(t, map[string]string{"DBSIZE": ":42\r\n"})
	code, resp := postConsole(t,
		`{"target":"`+f.addr()+`","command":"DBSIZE","password":"s3cret","db":3}`)

	if code != 200 || resp.Error != "" {
		t.Fatalf("status %d, error %q", code, resp.Error)
	}
	if resp.Reply != "(integer) 42" {
		t.Errorf("reply = %q", resp.Reply)
	}
	got := f.commands()
	if len(got) != 3 {
		t.Fatalf("want AUTH, SELECT, DBSIZE; got %v", got)
	}
	if got[0][0] != "AUTH" || got[0][1] != "s3cret" {
		t.Errorf("first command = %v, want AUTH", got[0])
	}
	if got[1][0] != "SELECT" || got[1][1] != "3" {
		t.Errorf("second command = %v, want SELECT 3", got[1])
	}
	if got[2][0] != "DBSIZE" {
		t.Errorf("third command = %v, want DBSIZE", got[2])
	}
}

func TestRedisConsole_ServerErrorIsReportedNotSwallowed(t *testing.T) {
	// A -ERR reply is a real answer, not a transport failure: it must reach the
	// user verbatim with is_error set, so a typo looks different from a
	// connection problem.
	f := newFakeRedis(t, map[string]string{"GET": "-WRONGTYPE Operation against a key\r\n"})
	code, resp := postConsole(t, `{"target":"`+f.addr()+`","command":"GET mylist"}`)
	if code != 200 {
		t.Fatalf("status %d", code)
	}
	if !resp.IsError {
		t.Error("is_error should be set for a -ERR reply")
	}
	if !strings.Contains(resp.Reply, "WRONGTYPE") {
		t.Errorf("reply = %q, want the server's message", resp.Reply)
	}
}

func TestRedisConsole_UnreachableTargetReportsCleanly(t *testing.T) {
	// A dead target must produce a readable error, not a 500.
	code, resp := postConsole(t, `{"target":"127.0.0.1:1","command":"PING"}`)
	if code != 200 {
		t.Fatalf("status %d", code)
	}
	if resp.Error == "" {
		t.Error("expected a connection error")
	}
}

func TestSplitRedisCommand(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"KEYS *", []string{"KEYS", "*"}},
		{"  INFO   server  ", []string{"INFO", "server"}},
		{`GET "key with spaces"`, []string{"GET", "key with spaces"}},
		{`GET 'single quoted'`, []string{"GET", "single quoted"}},
		{`HGET user:1 ""`, []string{"HGET", "user:1", ""}},
		{`GET a\b`, []string{"GET", `a\b`}}, // backslashes are literal
	}
	for _, c := range cases {
		got, err := splitRedisCommand(c.in)
		if err != nil {
			t.Errorf("%q: %v", c.in, err)
			continue
		}
		if strings.Join(got, "|") != strings.Join(c.want, "|") {
			t.Errorf("%q = %v, want %v", c.in, got, c.want)
		}
	}
	if _, err := splitRedisCommand(`GET "unbalanced`); err == nil {
		t.Error("unbalanced quote should error")
	}
	if _, err := splitRedisCommand("   "); err == nil {
		t.Error("empty command should error")
	}
}

func TestNormalizeRedisTarget(t *testing.T) {
	cases := map[string]string{
		"redis":               "redis:6379",
		"redis:6380":          "redis:6380",
		"redis://cache:6379":  "cache:6379",
		"redis://cache:6379/": "cache:6379",
		" 10.0.0.5:6379 ":     "10.0.0.5:6379",
		"[::1]:6379":          "[::1]:6379",
		"my-redis.internal":   "my-redis.internal:6379",
	}
	for in, want := range cases {
		got, err := normalizeRedisTarget(in)
		if err != nil {
			t.Errorf("%q: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("%q = %q, want %q", in, got, want)
		}
	}
	for _, bad := range []string{"", "   ", "redis:0", "redis:99999", "redis:abc"} {
		if _, err := normalizeRedisTarget(bad); err == nil {
			t.Errorf("%q should be rejected", bad)
		}
	}
}

func TestRenderRedisReply_NestedArraysIndent(t *testing.T) {
	// SLOWLOG GET returns arrays of arrays; nested entries must line up under
	// their parent rather than running together at column zero.
	reply := redisReply{kind: '*', array: []redisReply{
		{kind: '*', array: []redisReply{
			{kind: ':', num: 1},
			{kind: '$', str: "get"},
		}},
		{kind: '$', null: true},
	}}
	var b strings.Builder
	renderRedisReply(reply, "", &b)
	want := "1) 1) (integer) 1\n   2) get\n2) (nil)"
	if b.String() != want {
		t.Errorf("got:\n%s\nwant:\n%s", b.String(), want)
	}
}

// fmtSscan is a thin wrapper kept separate so the fake server's parsing stays
// readable; it exists only in tests.
func fmtSscan(s string, n *int) (int, error) { return fmt.Sscan(s, n) }

func TestRedisConsole_ConfigGetDoesNotLeakCredentials(t *testing.T) {
	// CONFIG GET is read-only to Redis, but a password read out of the config is
	// a WRITE credential: whoever sees it can connect directly and FLUSHALL. An
	// operator who sets REDIS_PASSWORD in the stack must not be publishing it to
	// every logged-in browser.
	f := newFakeRedis(t, map[string]string{
		"CONFIG": "*6\r\n$11\r\nrequirepass\r\n$14\r\nSuperSecret123\r\n" +
			"$10\r\nmasterauth\r\n$12\r\nReplicaPass1\r\n" +
			"$9\r\nmaxmemory\r\n$1\r\n0\r\n",
	})
	body, err := json.Marshal(redisConsoleRequest{Target: f.addr(), Command: "CONFIG GET *"})
	if err != nil {
		t.Fatal(err)
	}
	code, resp := postConsole(t, string(body))
	if code != 200 || resp.Error != "" {
		t.Fatalf("status %d, error %q", code, resp.Error)
	}
	for _, secret := range []string{"SuperSecret123", "ReplicaPass1"} {
		if strings.Contains(resp.Reply, secret) {
			t.Errorf("CONFIG GET leaked %q:\n%s", secret, resp.Reply)
		}
	}
	// Redaction must be surgical: the parameter names stay, and non-secret
	// values are untouched, or the command stops being useful.
	for _, keep := range []string{"requirepass", "masterauth", "maxmemory"} {
		if !strings.Contains(resp.Reply, keep) {
			t.Errorf("redaction removed the parameter name %q:\n%s", keep, resp.Reply)
		}
	}
	if !strings.Contains(resp.Reply, "(redacted by perch)") {
		t.Errorf("expected a redaction marker so the reader knows why:\n%s", resp.Reply)
	}
	if !strings.HasSuffix(strings.TrimSpace(resp.Reply), "0") {
		t.Errorf("maxmemory's value should survive untouched:\n%s", resp.Reply)
	}
}

func TestRedactRedisConfig_UnsetPasswordIsNotRedacted(t *testing.T) {
	// "requirepass is empty" means no password is set. That is worth knowing and
	// leaks nothing, so it must not be masked into looking like a secret.
	reply := redisReply{kind: '*', array: []redisReply{
		{kind: '$', str: "requirepass"}, {kind: '$', str: ""},
	}}
	redactRedisConfig(&reply)
	if reply.array[1].str != "" {
		t.Errorf("empty requirepass should stay empty, got %q", reply.array[1].str)
	}
}

// --- regression tests for the security review findings -----------------------

func TestRedisEndpoint_OperatorCredentialNeverLeavesForAnUndeclaredHost(t *testing.T) {
	// The original bug: target was free text and an empty request password fell
	// back to REDIS_PASSWORD, so a logged-in user could name a host they control
	// and collect the operator's production credential off the wire.
	t.Setenv("REDIS_USERNAME", "perch-ro")
	t.Setenv("REDIS_PASSWORD", "TheRealProductionPassword")

	t.Run("no targets declared: credential is never sent", func(t *testing.T) {
		t.Setenv("REDIS_TARGETS", "")
		ep, err := resolveRedisEndpoint(redisConsoleRequest{Target: "attacker.example:6379"})
		if err != nil {
			t.Fatal(err)
		}
		if ep.password != "" || ep.username != "" {
			t.Errorf("operator credential attached to an undeclared host: %+v", ep)
		}
	})

	t.Run("targets declared: an undeclared host is refused outright", func(t *testing.T) {
		t.Setenv("REDIS_TARGETS", "cache=redis:6379")
		if _, err := resolveRedisEndpoint(redisConsoleRequest{Target: "attacker.example:6379"}); err == nil {
			t.Error("an address outside REDIS_TARGETS should be refused")
		}
	})

	t.Run("declared host does get the credential", func(t *testing.T) {
		t.Setenv("REDIS_TARGETS", "cache=redis:6379, other:6380")
		ep, err := resolveRedisEndpoint(redisConsoleRequest{Target: "redis"}) // port defaulted
		if err != nil {
			t.Fatal(err)
		}
		if ep.password != "TheRealProductionPassword" || ep.username != "perch-ro" {
			t.Errorf("declared target should receive the operator credential, got %+v", ep)
		}
	})

	t.Run("a typed credential is not replaced by the environment", func(t *testing.T) {
		t.Setenv("REDIS_TARGETS", "cache=redis:6379")
		ep, err := resolveRedisEndpoint(redisConsoleRequest{
			Target: "redis:6379", Username: "typed-by-user", Password: "typed-pw",
		})
		if err != nil {
			t.Fatal(err)
		}
		if ep.username != "typed-by-user" || ep.password != "typed-pw" {
			t.Errorf("typed credential was overridden: %+v", ep)
		}
	})
}

func TestReadRedisReply_BulkLengthIsNotTrusted(t *testing.T) {
	// A wire-supplied length was used for the allocation before any read, so the
	// byte budget could not help: "$200000000" cost 200 MB, and the maximum int64
	// overflowed n+2 negative and panicked makeslice.
	cases := []struct{ name, payload string }{
		{"overflows int", "$9223372036854775807\r\n"},
		{"claims 200MB", "$200000000\r\n"},
		{"negative below null", "$-2\r\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			limiter := &io.LimitedReader{R: strings.NewReader(c.payload), N: redisMaxReplyBytes}
			br := bufio.NewReader(limiter)
			// Must not panic, and must not allocate what the wire asked for.
			reply, err := readRedisReply(br, 0)
			if err == nil && len(reply.str) > redisMaxReplyBytes {
				t.Errorf("allocated %d bytes for a hostile length", len(reply.str))
			}
		})
	}
}

func TestReadRedisReply_OversizedBulkReturnsAPrefixAndSaysSo(t *testing.T) {
	// Previously an oversized reply produced zero bytes and truncated=false, so
	// the UI's "(truncated)" hint was unreachable and the user got nothing.
	payload := "$400000\r\n" + strings.Repeat("x", 400000) + "\r\n"
	limiter := &io.LimitedReader{R: strings.NewReader(payload), N: 10 * 1024 * 1024}
	reply, err := readRedisReply(bufio.NewReader(limiter), 0)
	if err != nil {
		t.Fatalf("oversized bulk should degrade, not fail: %v", err)
	}
	if !reply.truncated {
		t.Error("an oversized bulk must be marked truncated")
	}
	if len(reply.str) == 0 {
		t.Error("the user should get the prefix, not an empty reply")
	}
	if len(reply.str) > redisMaxReplyBytes {
		t.Errorf("returned %d bytes, over the %d budget", len(reply.str), redisMaxReplyBytes)
	}
}

func TestRedisSecretParam_MatchesRenamedSpellings(t *testing.T) {
	// Valkey 8 renamed masterauth to primaryauth and CONFIG GET returns BOTH, so
	// an exact-name denylist redacted one and printed the other beneath it.
	secret := []string{
		"requirepass", "masterauth", "primaryauth", "masteruser", "primaryuser",
		"tls-key-file-pass", "tls-client-key-file-pass", "REQUIREPASS",
	}
	for _, name := range secret {
		if !redisSecretParam(name) {
			t.Errorf("%q should be redacted", name)
		}
	}
	// Redacting a non-secret is its own bug: it lies about the value.
	public := []string{"maxmemory", "tls-auth-clients", "appendonly", "databases", "port"}
	for _, name := range public {
		if redisSecretParam(name) {
			t.Errorf("%q is not a secret and must stay visible", name)
		}
	}
}

func TestReadRedisReply_DepthAllowsRealNestedCommands(t *testing.T) {
	// COMMAND DOCS is on our own allowlist and nests past 8, so the old cap
	// rejected it and blamed the server.
	var payload strings.Builder
	const depth = 12
	for i := 0; i < depth; i++ {
		payload.WriteString("*1\r\n")
	}
	payload.WriteString("$2\r\nok\r\n")
	limiter := &io.LimitedReader{R: strings.NewReader(payload.String()), N: redisMaxReplyBytes}
	if _, err := readRedisReply(bufio.NewReader(limiter), 0); err != nil {
		t.Errorf("a %d-deep reply should parse: %v", depth, err)
	}
}

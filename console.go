package main

// The Redis console - run Redis commands against any Redis this container can
// reach on the network, WITHOUT docker exec. Perch speaks the RESP wire
// protocol directly (it is small enough to implement here), so this unlocks no
// new Docker privileges: the socket-proxy stays read-only and POST-less, and a
// hijacked Perch is no closer to the host than it was before. It is the same
// trade the Inspect tab makes - answer what people want a shell for, without
// handing out a shell.
//
// The allowlist below is the point of the feature rather than a limitation of
// it. A real redis-cli prompt is one typo away from FLUSHALL; this console can
// only read. Commands that mutate data, rewrite config, run scripts, or stop
// the server are refused here in the server, so the browser cannot ask for
// them at all.

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	redisDialTimeout = 5 * time.Second
	redisIOTimeout   = 10 * time.Second
	// One reply may cost us at most this many bytes on the wire. KEYS on a
	// large instance returns millions of entries; the browser wants a page of
	// them, not all of them, and an unbounded read is how a monitoring tool
	// gets OOM-killed by the thing it is monitoring.
	redisMaxReplyBytes = 256 * 1024
	// RESP arrays nest. COMMAND DOCS and XINFO STREAM ... FULL legitimately go
	// well past a handful of levels, so this is only a stop against a cyclic or
	// malformed server, not a budget: the byte cap above is what actually bounds
	// the work. An earlier value of 8 rejected COMMAND DOCS, a command on our own
	// allowlist, and blamed the server for it.
	redisMaxDepth = 32
)

// redisReadOnlyCommands is the allowlist, and the security boundary of this
// feature. A nil value allows the command whatever its arguments; a non-nil
// value restricts it to the listed subcommands, which is how the container
// commands get their read-only halves in without their dangerous ones -
// CONFIG GET is reachable, CONFIG SET cannot be spelled.
var redisReadOnlyCommands = map[string][]string{
	// keyspace
	"GET": nil, "MGET": nil, "STRLEN": nil, "GETRANGE": nil, "SUBSTR": nil,
	"EXISTS": nil, "TYPE": nil, "TTL": nil, "PTTL": nil, "EXPIRETIME": nil,
	"KEYS": nil, "SCAN": nil, "RANDOMKEY": nil, "DBSIZE": nil,
	"OBJECT": {"ENCODING", "FREQ", "IDLETIME", "REFCOUNT", "HELP"},
	// hashes
	"HGET": nil, "HMGET": nil, "HGETALL": nil, "HKEYS": nil, "HVALS": nil,
	"HLEN": nil, "HEXISTS": nil, "HSTRLEN": nil, "HSCAN": nil, "HRANDFIELD": nil,
	// lists
	"LRANGE": nil, "LLEN": nil, "LINDEX": nil, "LPOS": nil,
	// sets
	"SMEMBERS": nil, "SCARD": nil, "SISMEMBER": nil, "SMISMEMBER": nil,
	"SRANDMEMBER": nil, "SSCAN": nil, "SINTER": nil, "SUNION": nil, "SDIFF": nil,
	"SINTERCARD": nil,
	// sorted sets
	"ZRANGE": nil, "ZRANGEBYSCORE": nil, "ZRANGEBYLEX": nil, "ZREVRANGE": nil,
	"ZREVRANGEBYSCORE": nil, "ZCARD": nil, "ZSCORE": nil, "ZMSCORE": nil,
	"ZCOUNT": nil, "ZLEXCOUNT": nil, "ZRANK": nil, "ZREVRANK": nil,
	"ZSCAN": nil, "ZRANDMEMBER": nil,
	// bitmaps and hyperloglog
	"BITCOUNT": nil, "BITPOS": nil, "GETBIT": nil, "PFCOUNT": nil,
	// geo
	"GEOPOS": nil, "GEODIST": nil, "GEOHASH": nil,
	// streams
	"XLEN": nil, "XRANGE": nil, "XREVRANGE": nil, "XPENDING": nil,
	"XINFO": {"STREAM", "GROUPS", "CONSUMERS", "HELP"},
	// pub/sub introspection (not SUBSCRIBE: that would block the connection)
	"PUBSUB": {"CHANNELS", "NUMSUB", "NUMPAT", "SHARDCHANNELS", "SHARDNUMSUB", "HELP"},
	// server introspection - the reason most people open a console at all
	"PING": nil, "ECHO": nil, "INFO": nil, "TIME": nil, "LASTSAVE": nil, "LOLWUT": nil,
	"COMMAND": {"COUNT", "DOCS", "INFO", "GETKEYS", "LIST", "HELP"},
	"CONFIG":  {"GET", "HELP"},
	"CLIENT":  {"LIST", "INFO", "ID", "GETNAME", "HELP"},
	"MEMORY":  {"USAGE", "STATS", "DOCTOR", "HELP"},
	"LATENCY": {"LATEST", "HISTORY", "DOCTOR", "HELP"},
	"SLOWLOG": {"GET", "LEN", "HELP"},
	"CLUSTER": {"INFO", "NODES", "SLOTS", "SHARDS", "MYID", "COUNTKEYSINSLOT", "HELP"},
}

// redisCommandAllowed reports why a parsed command line may not be sent, or nil
// if it may. Callers must pass a non-empty args slice.
func redisCommandAllowed(args []string) error {
	name := strings.ToUpper(args[0])
	subcommands, known := redisReadOnlyCommands[name]
	if !known {
		return fmt.Errorf("%s is not on the read-only allowlist - this console cannot write, "+
			"reconfigure, or run scripts", name)
	}
	if subcommands == nil {
		return nil
	}
	if len(args) < 2 {
		return fmt.Errorf("%s needs a subcommand: %s", name, strings.Join(subcommands, ", "))
	}
	sub := strings.ToUpper(args[1])
	for _, allowed := range subcommands {
		if sub == allowed {
			return nil
		}
	}
	return fmt.Errorf("%s %s is not read-only; allowed: %s", name, sub, strings.Join(subcommands, ", "))
}

// redisSecretParam reports whether a CONFIG parameter's VALUE is a credential.
//
// CONFIG GET is read-only to Redis, but a password read out of the config is a
// WRITE credential everywhere else. This matches on the SHAPE of the name rather
// than on a list of exact names, because upstream renames them: Valkey 8 made
// "primaryauth" the canonical spelling of "masterauth" and CONFIG GET returns
// both, so an exact-name denylist redacted one and printed the other in
// plaintext directly beneath it.
//
// Suffix rather than substring on auth/pass: "tls-auth-clients" holds yes/no and
// redacting it would be a lie about a value that is not a secret.
func redisSecretParam(name string) bool {
	n := strings.ToLower(name)
	if strings.HasSuffix(n, "auth") || strings.HasSuffix(n, "pass") ||
		strings.Contains(n, "password") || strings.Contains(n, "secret") {
		return true
	}
	// Usernames are not secrets, but these two name the replication identity
	// that the matching credential belongs to.
	return n == "masteruser" || n == "primaryuser"
}

// redactRedisConfig blanks credential values in a CONFIG GET reply, which is a
// flat [name, value, name, value, ...] array. An unset credential is left as
// the empty string it is: "no password configured" is worth knowing and leaks
// nothing.
func redactRedisConfig(reply *redisReply) {
	if reply.kind != '*' {
		return
	}
	for i := 0; i+1 < len(reply.array); i += 2 {
		name := reply.array[i]
		if name.kind != '$' && name.kind != '+' {
			continue
		}
		if !redisSecretParam(name.str) {
			continue
		}
		if reply.array[i+1].str == "" {
			continue
		}
		reply.array[i+1] = redisReply{kind: '$', str: "(redacted by perch)"}
	}
}

// splitRedisCommand splits a typed line into arguments the way redis-cli does:
// whitespace separates, single or double quotes group. Backslash escapes are
// deliberately NOT interpreted - keys containing backslashes are more common
// than keys needing escapes, and silently rewriting what someone typed is the
// wrong surprise for a tool whose job is to tell the truth.
func splitRedisCommand(line string) ([]string, error) {
	var (
		args  []string
		cur   strings.Builder
		inArg bool
		quote byte
	)
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
				continue
			}
			cur.WriteByte(c)
		case c == '\'' || c == '"':
			quote = c
			inArg = true
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			if inArg {
				args = append(args, cur.String())
				cur.Reset()
				inArg = false
			}
		default:
			cur.WriteByte(c)
			inArg = true
		}
	}
	if quote != 0 {
		return nil, errors.New("unbalanced quote")
	}
	if inArg {
		args = append(args, cur.String())
	}
	if len(args) == 0 {
		return nil, errors.New("enter a command")
	}
	return args, nil
}

// normalizeRedisTarget turns what someone typed into a dialable host:port,
// defaulting the port to 6379. An IPv6 literal must be bracketed, as in a URL.
func normalizeRedisTarget(target string) (string, error) {
	t := strings.TrimSpace(target)
	t = strings.TrimPrefix(t, "redis://")
	t = strings.TrimPrefix(t, "rediss://")
	t = strings.TrimSuffix(t, "/")
	if t == "" {
		return "", errors.New("enter a target, for example redis:6379")
	}
	if !strings.Contains(t, ":") {
		t += ":6379"
	}
	host, port, err := net.SplitHostPort(t)
	if err != nil {
		return "", fmt.Errorf("target must be host:port - %v", err)
	}
	if host == "" {
		return "", errors.New("target needs a host")
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return "", errors.New("target port must be a number between 1 and 65535")
	}
	return net.JoinHostPort(host, port), nil
}

// redisEndpoint is a target that has been resolved against configuration: an
// address to dial, together with the credentials that belong to THAT address.
//
// It exists because the two used to be independent inputs. The handler took a
// free-text target from the browser and an ambient REDIS_PASSWORD from the
// environment, then sent AUTH to whichever host was named - so any user could
// point perch at a server they controlled and collect the operator's production
// Redis password in cleartext. Credentials are now only reachable by producing
// one of these, which is the one place that decides whether the operator's
// secret is allowed to travel to that address.
type redisEndpoint struct {
	addr       string
	username   string
	password   string
	configured bool // the address was declared in REDIS_TARGETS
}

// configuredRedisTargets parses REDIS_TARGETS into the set of addresses the
// operator has declared, normalised so "redis" and "redis:6379" compare equal.
// An empty set means the operator declared none.
func configuredRedisTargets() map[string]bool {
	out := map[string]bool{}
	for _, entry := range splitList(os.Getenv("REDIS_TARGETS")) {
		// Tolerate "name=host:port" so the variable can stay readable.
		if _, addr, found := strings.Cut(entry, "="); found {
			entry = addr
		}
		addr, err := normalizeRedisTarget(entry)
		if err != nil {
			// Silently dropping a typo would quietly widen the allowlist, and if
			// every entry is a typo the console falls back to accepting any
			// address. That must be loud, not invisible.
			log.Printf("redis console: ignoring unparseable REDIS_TARGETS entry %q: %v", entry, err)
			continue
		}
		out[addr] = true
	}
	return out
}

// resolveRedisEndpoint is the boundary parse: one place turns the request plus
// the environment into an endpoint, and everything inside can then trust it.
func resolveRedisEndpoint(req redisConsoleRequest) (redisEndpoint, error) {
	addr, err := normalizeRedisTarget(req.Target)
	if err != nil {
		return redisEndpoint{}, err
	}
	allowed := configuredRedisTargets()
	ep := redisEndpoint{addr: addr, configured: allowed[addr]}

	// When the operator has declared targets, that list is the whole world: an
	// undeclared address is refused outright rather than merely denied the
	// credentials, which also takes away the port scanner.
	if len(allowed) > 0 && !ep.configured {
		names := make([]string, 0, len(allowed))
		for a := range allowed {
			names = append(names, a)
		}
		sort.Strings(names)
		return redisEndpoint{}, fmt.Errorf("%s is not in REDIS_TARGETS; allowed: %s",
			addr, strings.Join(names, ", "))
	}

	// A credential typed into the browser belongs to whoever typed it, so it
	// goes wherever they are dialling.
	if req.Username != "" || req.Password != "" {
		ep.username, ep.password = req.Username, req.Password
		return ep, nil
	}
	// The operator's credential only ever travels to an address the operator
	// named. With no REDIS_TARGETS declared it is never sent at all.
	if ep.configured {
		ep.username, ep.password = os.Getenv("REDIS_USERNAME"), os.Getenv("REDIS_PASSWORD")
	}
	return ep, nil
}

// warnRedisConsoleConfig points out a configuration that silently does less than
// it looks like it does, at the one moment anybody reads the logs.
func warnRedisConsoleConfig() {
	if os.Getenv("REDIS_PASSWORD") == "" && os.Getenv("REDIS_USERNAME") == "" {
		return
	}
	if len(configuredRedisTargets()) == 0 {
		log.Print("redis console: REDIS_PASSWORD is set but REDIS_TARGETS is empty, " +
			"so it will never be sent (it would otherwise leak to any address a user types). " +
			"List your redis in REDIS_TARGETS to use it.")
	}
}

// redisReply is one decoded RESP value. RESP2 only: we never send HELLO 3, so
// the server never answers in RESP3 and its extra types cannot appear.
type redisReply struct {
	kind  byte // '+' status, '-' error, ':' integer, '$' bulk, '*' array
	str   string
	num   int64
	null  bool
	array []redisReply
	// truncated marks a bulk string we deliberately cut short rather than
	// allocate in full. It propagates up so the user is told, instead of being
	// handed a short value that looks complete.
	truncated bool
}

// writeRedisCommand sends args as a RESP array of bulk strings.
func writeRedisCommand(w io.Writer, args []string) error {
	var b strings.Builder
	fmt.Fprintf(&b, "*%d\r\n", len(args))
	for _, a := range args {
		fmt.Fprintf(&b, "$%d\r\n%s\r\n", len(a), a)
	}
	_, err := io.WriteString(w, b.String())
	return err
}

// readRedisLine reads one CRLF-terminated protocol line without its terminator.
func readRedisLine(br *bufio.Reader) (string, error) {
	line, err := br.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// readRedisReply decodes one reply, recursing into arrays.
func readRedisReply(br *bufio.Reader, depth int) (redisReply, error) {
	if depth > redisMaxDepth {
		return redisReply{}, errors.New("reply nested too deeply")
	}
	prefix, err := br.ReadByte()
	if err != nil {
		return redisReply{}, err
	}
	line, err := readRedisLine(br)
	if err != nil {
		return redisReply{}, err
	}
	switch prefix {
	case '+', '-':
		return redisReply{kind: prefix, str: line}, nil
	case ':':
		n, err := strconv.ParseInt(line, 10, 64)
		if err != nil {
			return redisReply{}, fmt.Errorf("bad integer reply %q", line)
		}
		return redisReply{kind: ':', num: n}, nil
	case '$':
		n, err := strconv.Atoi(line)
		if err != nil || n < -1 {
			return redisReply{}, fmt.Errorf("bad bulk length %q", line)
		}
		if n < 0 {
			return redisReply{kind: '$', null: true}, nil
		}
		// The length is chosen by whatever is on the other end of the socket, and
		// this allocation happens BEFORE any read, so the byte budget on the
		// reader cannot save us: "$200000000" costs 200 MB before a single
		// payload byte arrives, and "$9223372036854775807" overflows n+2 negative
		// and panics makeslice. Allocate what the budget permits, never what the
		// wire asks for.
		//
		// Reading only a prefix is safe because the connection carries exactly one
		// command and is closed immediately after, so a desynced stream is never
		// reused.
		if n > redisMaxReplyBytes {
			buf := make([]byte, redisMaxReplyBytes)
			read, _ := io.ReadFull(br, buf)
			return redisReply{kind: '$', str: string(buf[:read]), truncated: true}, nil
		}
		buf := make([]byte, n+2) // payload plus the trailing CRLF
		if _, err := io.ReadFull(br, buf); err != nil {
			return redisReply{}, err
		}
		return redisReply{kind: '$', str: string(buf[:n])}, nil
	case '*':
		n, err := strconv.Atoi(line)
		if err != nil {
			return redisReply{}, fmt.Errorf("bad array length %q", line)
		}
		if n < 0 {
			return redisReply{kind: '*', null: true}, nil
		}
		// Grown by append rather than pre-sized from the wire: a server
		// claiming a billion elements should run out of bytes, not make us
		// allocate for it first.
		var items []redisReply
		for i := 0; i < n; i++ {
			item, err := readRedisReply(br, depth+1)
			if err != nil {
				return redisReply{}, err
			}
			items = append(items, item)
		}
		return redisReply{kind: '*', array: items}, nil
	default:
		return redisReply{}, fmt.Errorf("unexpected reply byte %q: the target answered, "+
			"but not in the Redis protocol", string(prefix))
	}
}

// renderRedisReply formats a reply the way redis-cli prints it, so what lands
// in the browser is what someone would recognise from a terminal.
func renderRedisReply(r redisReply, indent string, b *strings.Builder) {
	switch r.kind {
	case '+':
		b.WriteString(r.str)
	case '-':
		b.WriteString("(error) " + r.str)
	case ':':
		b.WriteString("(integer) " + strconv.FormatInt(r.num, 10))
	case '$':
		if r.null {
			b.WriteString("(nil)")
			return
		}
		b.WriteString(r.str)
	case '*':
		if r.null {
			b.WriteString("(nil)")
			return
		}
		if len(r.array) == 0 {
			b.WriteString("(empty array)")
			return
		}
		width := len(strconv.Itoa(len(r.array)))
		for i, item := range r.array {
			if i > 0 {
				b.WriteString("\n" + indent)
			}
			label := fmt.Sprintf("%*d) ", width, i+1)
			b.WriteString(label)
			renderRedisReply(item, indent+strings.Repeat(" ", len(label)), b)
		}
	}
}

// redisConn is one short-lived connection to a Redis, already authenticated and
// pointed at the requested database.
type redisConn struct {
	conn    net.Conn
	reader  *bufio.Reader
	limiter *io.LimitedReader
}

func (c *redisConn) Close() { _ = c.conn.Close() }

// do sends one command and returns its decoded reply.
func (c *redisConn) do(args ...string) (redisReply, error) {
	if err := c.conn.SetDeadline(time.Now().Add(redisIOTimeout)); err != nil {
		return redisReply{}, err
	}
	if err := writeRedisCommand(c.conn, args); err != nil {
		return redisReply{}, err
	}
	c.limiter.N = redisMaxReplyBytes // a fresh budget per command
	return readRedisReply(c.reader, 0)
}

// truncated reports whether the last reply used up its whole byte budget, which
// means we stopped reading before the server stopped sending.
func (c *redisConn) truncated() bool { return c.limiter.N <= 0 }

// dialRedis opens a connection, authenticates if credentials were given, and
// selects the requested database.
func dialRedis(ctx context.Context, ep redisEndpoint, db int) (*redisConn, error) {
	dialer := net.Dialer{Timeout: redisDialTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", ep.addr)
	if err != nil {
		return nil, err
	}
	limiter := &io.LimitedReader{R: conn, N: redisMaxReplyBytes}
	c := &redisConn{conn: conn, reader: bufio.NewReader(limiter), limiter: limiter}

	if ep.password != "" {
		args := []string{"AUTH", ep.password}
		if ep.username != "" {
			args = []string{"AUTH", ep.username, ep.password}
		}
		reply, err := c.do(args...)
		if err != nil {
			c.Close()
			return nil, fmt.Errorf("auth failed: %w", err)
		}
		if reply.kind == '-' {
			c.Close()
			// The server's message names the reason (wrong pass, no ACL user)
			// without echoing the credential back.
			return nil, fmt.Errorf("auth rejected: %s", reply.str)
		}
	}
	if db != 0 {
		reply, err := c.do("SELECT", strconv.Itoa(db))
		if err != nil {
			c.Close()
			return nil, fmt.Errorf("select db %d: %w", db, err)
		}
		if reply.kind == '-' {
			c.Close()
			return nil, fmt.Errorf("select db %d: %s", db, reply.str)
		}
	}
	return c, nil
}

type redisConsoleRequest struct {
	Target   string `json:"target"`
	Command  string `json:"command"`
	Username string `json:"username"`
	Password string `json:"password"`
	DB       int    `json:"db"`
}

type redisConsoleResponse struct {
	Command   string `json:"command"`
	Reply     string `json:"reply"`
	IsError   bool   `json:"is_error"`
	LatencyMs int64  `json:"latency_ms"`
	Truncated bool   `json:"truncated"`
	Error     string `json:"error,omitempty"`
}

// handleRedisConsole serves POST /api/console/redis: parse, check against the
// allowlist, run exactly one command, render the reply.
func handleRedisConsole(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	var req redisConsoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad request: "+err.Error())
		return
	}

	endpoint, err := resolveRedisEndpoint(req)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	args, err := splitRedisCommand(req.Command)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := redisCommandAllowed(args); err != nil {
		writeErr(w, http.StatusForbidden, err.Error())
		return
	}
	if req.DB < 0 || req.DB > 15 {
		writeErr(w, http.StatusBadRequest, "db must be between 0 and 15")
		return
	}

	start := time.Now()
	conn, err := dialRedis(r.Context(), endpoint, req.DB)
	if err != nil {
		writeJSON(w, http.StatusOK, redisConsoleResponse{
			Command:   strings.Join(args, " "),
			LatencyMs: time.Since(start).Milliseconds(),
			Error:     err.Error(),
		})
		return
	}
	defer conn.Close()

	reply, err := conn.do(args...)
	latency := time.Since(start).Milliseconds()
	if err != nil {
		msg := err.Error()
		if conn.truncated() {
			msg = fmt.Sprintf("reply exceeded %d KB and was cut off - narrow it down "+
				"(SCAN with COUNT, LRANGE with a range)", redisMaxReplyBytes/1024)
		}
		writeJSON(w, http.StatusOK, redisConsoleResponse{
			Command: strings.Join(args, " "), LatencyMs: latency, Error: msg,
		})
		return
	}

	// CONFIG GET can name a credential; never let one reach the browser.
	if strings.EqualFold(args[0], "CONFIG") && len(args) > 1 && strings.EqualFold(args[1], "GET") {
		redactRedisConfig(&reply)
	}

	var rendered strings.Builder
	renderRedisReply(reply, "", &rendered)
	writeJSON(w, http.StatusOK, redisConsoleResponse{
		Command:   strings.Join(args, " "),
		Reply:     rendered.String(),
		IsError:   reply.kind == '-',
		LatencyMs: latency,
		Truncated: reply.truncated || conn.truncated(),
	})
}

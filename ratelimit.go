package main

import (
	"bufio"
	"fmt"
	"log"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Global IP rate limiting + temporary bans, for public deployments.
//
// Design: a fixed 10-second window counts requests per client IP. An IP that
// exceeds the limit (default 50) is banned for 10 hours, and bans are
// appended to a plain-text file on the /data volume so they survive
// container restarts. A janitor goroutine — the in-app replacement for an
// external cronjob — prunes stale counters and expired bans every 10
// minutes.
//
// Two deliberate scope decisions:
//   - Active only when ACCESS_KEY is set (public mode). Local open mode is
//     trusted and unlimited.
//   - Requests with a VALID session cookie are never counted or banned: the
//     dashboard legitimately fires many requests (overview poll + log
//     cards), and spam protection is about strangers without the key.
//     An attacker cannot use this to bypass the limiter without already
//     possessing a valid signed session.

type rateLimiter struct {
	mu             sync.Mutex
	requestWindows map[string]*ipWindow // ip -> current request-count window
	bans           map[string]time.Time // ip -> when it was banned
	maxRequests    int                  // requests allowed per window before a ban
	windowDuration time.Duration        // length of the counting window
	banDuration    time.Duration        // how long a ban lasts
	banFilePath    string               // where bans are persisted across restarts
}

type ipWindow struct {
	start        time.Time // when this counting window opened
	requestCount int       // requests seen so far in this window
}

// newRateLimiter builds the limiter from env knobs (RATE_LIMIT,
// RATE_WINDOW_SECONDS, BAN_HOURS, BAN_FILE), restores previously banned IPs
// from the ban file, and starts the janitor goroutine.
func newRateLimiter() *rateLimiter {
	envInt := func(envName string, fallback int) int {
		if value, err := strconv.Atoi(os.Getenv(envName)); err == nil && value > 0 {
			return value
		}
		return fallback
	}
	limiter := &rateLimiter{
		requestWindows: map[string]*ipWindow{},
		bans:           map[string]time.Time{},
		maxRequests:    envInt("RATE_LIMIT", 50),
		windowDuration: time.Duration(envInt("RATE_WINDOW_SECONDS", 10)) * time.Second,
		banDuration:    time.Duration(envInt("BAN_HOURS", 10)) * time.Hour,
		banFilePath:    envOr("BAN_FILE", "/data/banned_ips.txt"),
	}
	limiter.load()
	go limiter.janitor()
	log.Printf("ratelimit: %d requests / %s, ban %s, file %s",
		limiter.maxRequests, limiter.windowDuration, limiter.banDuration, limiter.banFilePath)
	return limiter
}

// middleware wraps the whole router: banned IPs are rejected first, valid
// sessions pass untouched, everything else is counted against the window.
func (limiter *rateLimiter) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !authEnabled() {
			next.ServeHTTP(w, r)
			return
		}
		if cookie, err := r.Cookie(cookieName); err == nil {
			if _, ok := parseToken(cookie.Value); ok {
				next.ServeHTTP(w, r) // authenticated: never counted
				return
			}
		}
		ip := clientIP(r)
		now := time.Now()

		limiter.mu.Lock()
		if bannedAt, isBanned := limiter.bans[ip]; isBanned {
			if now.Sub(bannedAt) < limiter.banDuration {
				limiter.mu.Unlock()
				limiter.reject(w)
				return
			}
			delete(limiter.bans, ip) // ban served its 10 hours — lift it
			limiter.persistLocked()
		}
		window := limiter.requestWindows[ip]
		if window == nil || now.Sub(window.start) > limiter.windowDuration {
			limiter.requestWindows[ip] = &ipWindow{start: now, requestCount: 1}
			limiter.mu.Unlock()
			next.ServeHTTP(w, r)
			return
		}
		window.requestCount++
		if window.requestCount > limiter.maxRequests {
			limiter.bans[ip] = now
			limiter.persistLocked()
			limiter.mu.Unlock()
			log.Printf("ratelimit: BANNED %s (%d requests in %s)", ip, window.requestCount, limiter.windowDuration)
			limiter.reject(w)
			return
		}
		limiter.mu.Unlock()
		next.ServeHTTP(w, r)
	})
}

// reject answers a banned/over-limit client. 429 is the standard
// "Too Many Requests" status; the JSON shape matches what the login overlay
// already knows how to display.
func (limiter *rateLimiter) reject(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusTooManyRequests)
	fmt.Fprintf(w, `{"error":"too many requests — this IP is banned for %s"}`, limiter.banDuration)
}

// janitor is the in-app cronjob: every 10 minutes it drops finished count
// windows (bounding memory even against spoofed-IP floods) and lifts bans
// older than the ban duration, rewriting the file when something changed.
func (limiter *rateLimiter) janitor() {
	ticker := time.NewTicker(10 * time.Minute)
	for range ticker.C {
		now := time.Now()
		limiter.mu.Lock()
		for ip, window := range limiter.requestWindows {
			if now.Sub(window.start) > limiter.windowDuration {
				delete(limiter.requestWindows, ip)
			}
		}
		changed := false
		for ip, bannedAt := range limiter.bans {
			if now.Sub(bannedAt) >= limiter.banDuration {
				delete(limiter.bans, ip)
				changed = true
				log.Printf("ratelimit: ban expired for %s", ip)
			}
		}
		if changed {
			limiter.persistLocked()
		}
		limiter.mu.Unlock()
	}
}

// BanEntry is one banned IP as shown in the dashboard's Banned IPs panel.
type BanEntry struct {
	IP        string `json:"ip"`
	BannedAt  int64  `json:"banned_at"`  // unix seconds
	ExpiresAt int64  `json:"expires_at"` // unix seconds
}

// list snapshots the current bans for the API, newest first.
func (limiter *rateLimiter) list() []BanEntry {
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	entries := make([]BanEntry, 0, len(limiter.bans))
	for ip, bannedAt := range limiter.bans {
		entries = append(entries, BanEntry{
			IP:        ip,
			BannedAt:  bannedAt.Unix(),
			ExpiresAt: bannedAt.Add(limiter.banDuration).Unix(),
		})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].BannedAt > entries[j].BannedAt })
	return entries
}

// unban lifts one ban (or every ban when ip is ""), rewrites the file, and
// returns how many were removed. The IP's request-count window is reset too,
// so a freshly unbanned client isn't instantly re-banned by its old counter.
func (limiter *rateLimiter) unban(ip string) int {
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	removed := 0
	if ip == "" {
		removed = len(limiter.bans)
		limiter.bans = map[string]time.Time{}
		limiter.requestWindows = map[string]*ipWindow{}
	} else if _, isBanned := limiter.bans[ip]; isBanned {
		delete(limiter.bans, ip)
		delete(limiter.requestWindows, ip)
		removed = 1
	}
	if removed > 0 {
		limiter.persistLocked()
		log.Printf("ratelimit: unbanned %d IP(s) via dashboard", removed)
	}
	return removed
}

// load restores bans from the text file at startup, keeping only the ones
// that haven't expired. Format: one "IP<TAB>RFC3339-timestamp" per line.
// A missing file (first run, or no /data volume) is fine.
func (limiter *rateLimiter) load() {
	file, err := os.Open(limiter.banFilePath)
	if err != nil {
		return
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		parts := strings.Split(scanner.Text(), "\t")
		if len(parts) != 2 {
			continue
		}
		bannedAt, err := time.Parse(time.RFC3339, parts[1])
		if err == nil && time.Since(bannedAt) < limiter.banDuration {
			limiter.bans[parts[0]] = bannedAt
		}
	}
	if len(limiter.bans) > 0 {
		log.Printf("ratelimit: restored %d active ban(s) from %s", len(limiter.bans), limiter.banFilePath)
	}
}

// persistLocked rewrites the ban file from the current map (caller holds
// limiter.mu). Writing the whole small file each time is simpler and more
// robust than appending + compacting. Failure (e.g. no /data volume mounted)
// is logged once per write but never fatal — bans still work in memory.
func (limiter *rateLimiter) persistLocked() {
	var builder strings.Builder
	for ip, bannedAt := range limiter.bans {
		fmt.Fprintf(&builder, "%s\t%s\n", ip, bannedAt.Format(time.RFC3339))
	}
	if err := os.WriteFile(limiter.banFilePath, []byte(builder.String()), 0644); err != nil {
		log.Printf("ratelimit: cannot write %s: %v", limiter.banFilePath, err)
	}
}

package main

import (
	"log"
	"os"
	"strings"
)

// loadDotEnv loads KEY=VALUE pairs from a .env file in the working directory
// into the process environment, WITHOUT overriding anything already set. This
// makes `go run .` pick up local config the same way `docker compose` does
// (compose reads .env itself, so inside a container this is just a no-op — the
// image ships no .env and the real environment always wins). A missing file is
// fine and silent.
//
// It's intentionally minimal (no external dependency): blank lines and #
// comments are skipped, an optional leading "export " is allowed, and simple
// surrounding quotes are stripped.
func loadDotEnv() {
	data, err := os.ReadFile(".env")
	if err != nil {
		return // no .env — nothing to do
	}
	loaded := 0
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		// skip blanks and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// tolerate "export KEY=VALUE"
		line = strings.TrimPrefix(line, "export ")
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		// strip a matching pair of surrounding quotes
		if len(value) >= 2 && (value[0] == '"' || value[0] == '\'') && value[len(value)-1] == value[0] {
			value = value[1 : len(value)-1]
		}
		if key == "" {
			continue
		}
		// real environment variables take precedence over the file
		if _, exists := os.LookupEnv(key); !exists {
			os.Setenv(key, value)
			loaded++
		}
	}
	if loaded > 0 {
		log.Printf("env: loaded %d variable(s) from .env", loaded)
	}
}

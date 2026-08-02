package main

// The Inspect panel — a read-only "peek inside a container" that answers most
// of what people want a shell for (what's running, what's the config/env, what
// changed on disk) WITHOUT exec. Every field comes from Docker GET endpoints
// the read-only socket-proxy already permits (CONTAINERS=1), so this unlocks
// NO new privileges: nothing here can start, stop, modify, or run anything.

import (
	"net/http"
	"strings"
)

// InspectResult is the assembled read-only view of one container.
type InspectResult struct {
	ID           string       `json:"id"`
	Name         string       `json:"name"`
	Image        string       `json:"image"`
	Command      string       `json:"command"`
	State        string       `json:"state"`
	Health       string       `json:"health"`
	StartedAt    string       `json:"started_at"`
	RestartCount int          `json:"restart_count"`
	Mounts       []mountInfo  `json:"mounts"`
	Env          []string     `json:"env"` // "KEY=VALUE" — the UI masks values by default
	ProcTitles   []string     `json:"proc_titles"`
	Processes    [][]string   `json:"processes"`
	Changes      []fileChange `json:"changes"`
	Error        string       `json:"error,omitempty"`
}

type mountInfo struct {
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Mode        string `json:"mode"`
	RW          bool   `json:"rw"`
}

type fileChange struct {
	Path string `json:"path"`
	Kind string `json:"kind"` // modified / added / deleted
}

// handleInspect serves GET /api/inspect?id=<id>. It stitches together three
// read-only Docker calls — inspect (config/state/mounts/env), top (processes),
// and changes (filesystem diff) — into one payload. The container-id regexp
// (see docker.go) keeps anything but a hex id out of the API path.
func handleInspect(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if !containerIDRe.MatchString(id) {
		writeErr(w, http.StatusBadRequest, "invalid container id")
		return
	}
	result := InspectResult{ID: id}

	// 1. Inspect: the container's configuration and current state. We declare
	//    only the subset of the (large) response we actually render.
	var raw struct {
		Name  string `json:"Name"`
		State struct {
			Status    string `json:"Status"`
			StartedAt string `json:"StartedAt"`
			Health    *struct {
				Status string `json:"Status"`
			} `json:"Health"`
		} `json:"State"`
		RestartCount int `json:"RestartCount"`
		Config       struct {
			Image string   `json:"Image"`
			Cmd   []string `json:"Cmd"`
			Env   []string `json:"Env"`
		} `json:"Config"`
		Mounts []struct {
			Source      string `json:"Source"`
			Destination string `json:"Destination"`
			Mode        string `json:"Mode"`
			RW          bool   `json:"RW"`
		} `json:"Mounts"`
	}
	// Inspect is the one call we can't do without — if it fails, report and stop.
	if err := dockerGet("/containers/"+id+"/json", &raw); err != nil {
		result.Error = err.Error()
		writeJSON(w, http.StatusOK, result)
		return
	}
	result.Name = strings.TrimPrefix(raw.Name, "/")
	result.Image = raw.Config.Image
	result.Command = strings.Join(raw.Config.Cmd, " ")
	result.State = raw.State.Status
	result.StartedAt = raw.State.StartedAt
	result.RestartCount = raw.RestartCount
	result.Env = raw.Config.Env
	// Health is a nested object only when the image defines a HEALTHCHECK.
	if raw.State.Health != nil {
		result.Health = raw.State.Health.Status
	} else {
		result.Health = "none"
	}
	for _, m := range raw.Mounts {
		result.Mounts = append(result.Mounts, mountInfo{m.Source, m.Destination, m.Mode, m.RW})
	}

	// 2. Top: the process table (like `ps`). Only meaningful while running, so
	//    a failure here (stopped container) is non-fatal — we just omit it.
	var top struct {
		Titles    []string   `json:"Titles"`
		Processes [][]string `json:"Processes"`
	}
	if err := dockerGet("/containers/"+id+"/top", &top); err == nil {
		result.ProcTitles = top.Titles
		result.Processes = top.Processes
	}

	// 3. Changes: files added/modified/deleted vs the image (like `docker diff`).
	//    Kind is 0=modified, 1=added, 2=deleted. Also non-fatal.
	var changes []struct {
		Path string `json:"Path"`
		Kind int    `json:"Kind"`
	}
	if err := dockerGet("/containers/"+id+"/changes", &changes); err == nil {
		kindName := map[int]string{0: "modified", 1: "added", 2: "deleted"}
		for _, c := range changes {
			result.Changes = append(result.Changes, fileChange{Path: c.Path, Kind: kindName[c.Kind]})
		}
	}

	writeJSON(w, http.StatusOK, result)
}

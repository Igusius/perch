package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Container is the dashboard's view of one Docker container: identity,
// state/health, live resource usage and published ports (as "public→private"
// strings ready for display).
type Container struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Image    string   `json:"image"`
	State    string   `json:"state"`  // running, exited, ...
	Status   string   `json:"status"` // "Up 2 hours (healthy)"
	Health   string   `json:"health"` // healthy, unhealthy, starting, none
	Ports    []string `json:"ports"`
	CPUPct   float64  `json:"cpu_pct"`
	MemUsed  uint64   `json:"mem_used"`
	MemLimit uint64   `json:"mem_limit"`
	MemPct   float64  `json:"mem_pct"`
}

// dockerHTTP is an http.Client that talks to the Docker daemon over its UNIX
// socket instead of TCP. The trick: a custom Transport whose DialContext
// ignores the requested host/port and always dials /var/run/docker.sock.
// This is how we use the full Docker Engine REST API with zero SDK
// dependencies — it's just HTTP+JSON underneath.
//
// Security option for public servers: set DOCKER_HOST=tcp://host:port to
// talk to a docker-socket-proxy instead of the raw socket. The proxy only
// permits harmless read endpoints, so even a fully hijacked perch
// cannot start/stop/create containers (see docker-compose.vps.yml).
var dockerHTTP = &http.Client{
	Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			if h, ok := strings.CutPrefix(envOr("DOCKER_HOST", ""), "tcp://"); ok {
				return (&net.Dialer{}).DialContext(ctx, "tcp", h)
			}
			return (&net.Dialer{}).DialContext(ctx, "unix",
				envOr("DOCKER_SOCK", "/var/run/docker.sock"))
		},
	},
	Timeout: 15 * time.Second,
}

// dockerGet performs one GET against the Docker Engine API and decodes the
// JSON response into `target` (any pointer type — Go's generics-free "any"
// works because json.Decoder does the reflection). The "http://docker" host is
// a dummy: the custom dialer above sends the request to the socket regardless.
func dockerGet(path string, target any) error {
	resp, err := dockerHTTP.Get("http://docker" + path)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("docker api %s: HTTP %d", path, resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(target)
}

// apiContainer mirrors (a subset of) the JSON the Docker API returns from
// GET /containers/json. We only declare the fields we need — encoding/json
// simply ignores the rest of the payload.
type apiContainer struct {
	ID     string   `json:"Id"`
	Names  []string `json:"Names"`
	Image  string   `json:"Image"`
	State  string   `json:"State"`
	Status string   `json:"Status"`
	Ports  []struct {
		IP          string `json:"IP"`
		PrivatePort int    `json:"PrivatePort"`
		PublicPort  int    `json:"PublicPort"`
		Type        string `json:"Type"`
	} `json:"Ports"`
}

// apiStats mirrors the parts of GET /containers/{id}/stats we use for CPU
// and memory calculations.
type apiStats struct {
	CPUStats    cpuStats `json:"cpu_stats"`
	PreCPUStats cpuStats `json:"precpu_stats"`
	MemoryStats struct {
		Usage uint64            `json:"usage"`
		Limit uint64            `json:"limit"`
		Stats map[string]uint64 `json:"stats"`
	} `json:"memory_stats"`
}

// cpuStats is one CPU sample from the stats endpoint (used twice: current
// sample and the "pre" sample one second earlier).
type cpuStats struct {
	CPUUsage struct {
		TotalUsage uint64 `json:"total_usage"`
	} `json:"cpu_usage"`
	SystemUsage uint64 `json:"system_cpu_usage"`
	OnlineCPUs  int    `json:"online_cpus"`
}

// collectContainers lists every container on the machine and enriches the
// running ones with live CPU/memory stats.
//
// How it works:
//  1. GET /containers/json?all=1 returns all containers (running + stopped).
//  2. Each is mapped to our Container struct: the leading "/" is stripped
//     from names, ports are formatted as "8080→80/tcp" and deduplicated.
//  3. Stats are the slow part (~1s each, see fillStats), so instead of
//     fetching them one by one we launch ONE GOROUTINE PER RUNNING CONTAINER
//     and wait for all of them with a sync.WaitGroup — 10 containers cost
//     ~1 second total instead of ~10. Each goroutine writes to its own slice
//     index (&containers[i]), so no two goroutines touch the same memory and
//     no mutex is needed.
//  4. Results are sorted: running containers first, then alphabetically.
func collectContainers() ([]Container, error) {
	var rawContainers []apiContainer
	if err := dockerGet("/containers/json?all=1", &rawContainers); err != nil {
		return nil, err
	}

	containers := make([]Container, len(rawContainers))
	var waitGroup sync.WaitGroup
	for index, rawContainer := range rawContainers {
		container := Container{
			ID:     rawContainer.ID[:12],
			Image:  rawContainer.Image,
			State:  rawContainer.State,
			Status: rawContainer.Status,
			Health: healthFromStatus(rawContainer.Status),
		}
		if len(rawContainer.Names) > 0 {
			container.Name = strings.TrimPrefix(rawContainer.Names[0], "/")
		}
		seenPorts := map[string]bool{}
		for _, port := range rawContainer.Ports {
			portLabel := fmt.Sprintf("%d/%s", port.PrivatePort, port.Type)
			if port.PublicPort != 0 {
				portLabel = fmt.Sprintf("%d→%d/%s", port.PublicPort, port.PrivatePort, port.Type)
			}
			if !seenPorts[portLabel] {
				seenPorts[portLabel] = true
				container.Ports = append(container.Ports, portLabel)
			}
		}
		containers[index] = container

		if rawContainer.State == "running" {
			waitGroup.Add(1)
			// index and containerID are passed as arguments (not captured) so
			// each goroutine gets its own copy of the loop variables.
			go func(index int, containerID string) {
				defer waitGroup.Done()
				fillStats(&containers[index], containerID)
			}(index, rawContainer.ID)
		}
	}
	waitGroup.Wait()
	sort.Slice(containers, func(i, j int) bool {
		if containers[i].State != containers[j].State {
			return containers[i].State == "running"
		}
		return containers[i].Name < containers[j].Name
	})
	return containers, nil
}

// fillStats fetches live CPU/memory usage for one container and writes it
// into `container` (a pointer into the shared slice — safe because each
// goroutine owns exactly one index).
//
// How it works: one non-streaming stats call (stream=false) makes the daemon
// sample the container twice ~1s apart and return both samples. CPU% is then
// the classic Docker formula:
//
//	(container cpu time delta / whole-system cpu time delta) × nCPUs × 100
//
// Memory subtracts the kernel page cache (inactive_file) from raw usage so
// the number matches what `docker stats` shows, and MemPct is usage against
// the container's limit (the limit defaults to total machine RAM when the
// container is unconstrained).
func fillStats(container *Container, containerID string) {
	var stats apiStats
	if err := dockerGet("/containers/"+containerID+"/stats?stream=false", &stats); err != nil {
		return
	}
	cpuDelta := float64(stats.CPUStats.CPUUsage.TotalUsage) - float64(stats.PreCPUStats.CPUUsage.TotalUsage)
	systemDelta := float64(stats.CPUStats.SystemUsage) - float64(stats.PreCPUStats.SystemUsage)
	if cpuDelta > 0 && systemDelta > 0 {
		cpuCount := float64(stats.CPUStats.OnlineCPUs)
		if cpuCount == 0 {
			cpuCount = 1
		}
		container.CPUPct = cpuDelta / systemDelta * cpuCount * 100
	}
	usedBytes := stats.MemoryStats.Usage
	// subtract page cache so the number matches `docker stats`
	for _, statKey := range []string{"total_inactive_file", "inactive_file"} {
		if cachedBytes, ok := stats.MemoryStats.Stats[statKey]; ok && cachedBytes < usedBytes {
			usedBytes -= cachedBytes
			break
		}
	}
	container.MemUsed = usedBytes
	container.MemLimit = stats.MemoryStats.Limit
	if stats.MemoryStats.Limit > 0 {
		container.MemPct = 100 * float64(usedBytes) / float64(stats.MemoryStats.Limit)
	}
}

// containerIDRe validates the id query parameter of /api/logs: only hex
// container IDs are accepted, so nothing can smuggle path segments or query
// tricks into the Docker API URL we build from it.
var containerIDRe = regexp.MustCompile(`^[a-fA-F0-9]{10,64}$`)

// handleContainerLogs serves GET /api/logs?id=<containerID>&tail=<n> — the
// backend of the log cards, equivalent to `docker logs --tail n <id>`.
//
// How it works: it forwards the request to the Docker Engine API
// (GET /containers/{id}/logs), reads at most 512KB of the response, strips
// Docker's stream framing with demuxDockerStream, and returns the text as
// JSON. The frontend polls this every 15 seconds per card.
func handleContainerLogs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	id := r.URL.Query().Get("id")
	if !containerIDRe.MatchString(id) {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid container id"})
		return
	}
	tailLines := 200
	if parsedTail, err := strconv.Atoi(r.URL.Query().Get("tail")); err == nil && parsedTail > 0 && parsedTail <= 1000 {
		tailLines = parsedTail
	}
	resp, err := dockerHTTP.Get(fmt.Sprintf(
		"http://docker/containers/%s/logs?stdout=1&stderr=1&tail=%d", id, tailLines))
	if err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		json.NewEncoder(w).Encode(map[string]string{
			"error": fmt.Sprintf("docker api: HTTP %d", resp.StatusCode)})
		return
	}
	rawLogs, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	json.NewEncoder(w).Encode(map[string]any{"text": string(demuxDockerStream(rawLogs))})
}

// demuxDockerStream strips Docker's log multiplexing frames.
//
// Containers started without a TTY interleave stdout and stderr in one
// stream using 8-byte frame headers: [streamType, 0, 0, 0, size(4B big-
// endian)] followed by size payload bytes. This function walks the frames
// and concatenates the payloads. If the first bytes don't look like a frame
// header (TTY mode — plain text), the input is returned unchanged.
func demuxDockerStream(data []byte) []byte {
	if len(data) < 8 || data[0] > 2 || data[1] != 0 || data[2] != 0 || data[3] != 0 {
		return data
	}
	var output []byte
	for len(data) >= 8 {
		frameSize := int(binary.BigEndian.Uint32(data[4:8]))
		if 8+frameSize > len(data) {
			output = append(output, data[8:]...)
			break
		}
		output = append(output, data[8:8+frameSize]...)
		data = data[8+frameSize:]
	}
	return output
}

// healthFromStatus extracts the healthcheck verdict Docker embeds in the
// human-readable status line — e.g. "Up 2 hours (healthy)" → "healthy".
// Containers without a HEALTHCHECK defined return "none".
func healthFromStatus(status string) string {
	switch {
	case strings.Contains(status, "(healthy)"):
		return "healthy"
	case strings.Contains(status, "(unhealthy)"):
		return "unhealthy"
	case strings.Contains(status, "(health: starting)"):
		return "starting"
	default:
		return "none"
	}
}

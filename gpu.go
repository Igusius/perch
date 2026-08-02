package main

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// GPU holds one graphics card's live readings as reported by nvidia-smi.
type GPU struct {
	Name       string  `json:"name"`
	UtilPct    float64 `json:"util_pct"`
	MemUsedMB  float64 `json:"mem_used_mb"`
	MemTotalMB float64 `json:"mem_total_mb"`
	TempC      float64 `json:"temp_c"`
	PowerW     float64 `json:"power_w"`
}

// nvidiaSMIPath caches the resolved nvidia-smi location so we only search
// the filesystem once, not on every 5-second collection tick.
var nvidiaSMIPath string

// findNvidiaSMI locates the nvidia-smi binary and memoizes the result.
//
// How it works: it tries, in order, an explicit NVIDIA_SMI_PATH override,
// the Docker-Desktop-on-WSL2 injection path (/usr/lib/wsl/lib — where the
// Windows GPU driver is mounted into containers), the normal Linux path,
// and finally a $PATH lookup. Returns "" when no GPU tooling exists, which
// callers treat as "machine has no (NVIDIA) GPU".
func findNvidiaSMI() string {
	if nvidiaSMIPath != "" {
		return nvidiaSMIPath
	}
	candidatePaths := []string{
		os.Getenv("NVIDIA_SMI_PATH"),
		"/usr/lib/wsl/lib/nvidia-smi", // Docker Desktop on WSL2 injects it here
		"/usr/bin/nvidia-smi",
	}
	for _, candidatePath := range candidatePaths {
		if candidatePath == "" {
			continue
		}
		if _, err := os.Stat(candidatePath); err == nil {
			nvidiaSMIPath = candidatePath
			return candidatePath
		}
	}
	if pathFromLookup, err := exec.LookPath("nvidia-smi"); err == nil {
		nvidiaSMIPath = pathFromLookup
		return pathFromLookup
	}
	return ""
}

// collectGPUs queries every NVIDIA GPU via nvidia-smi and returns their
// current utilization, VRAM, temperature and power draw.
//
// How it works: instead of linking NVIDIA's C library (which would need cgo
// and driver headers), it runs nvidia-smi as a subprocess with --query-gpu in
// CSV mode — one line per GPU, e.g.:
//
//	NVIDIA GeForce RTX 3060, 67, 3168, 12288, 67, 109.35
//
// and parses each comma-separated field with strconv.ParseFloat. Any failure
// (no GPU, driver asleep) returns nil and the UI shows "not detected".
func collectGPUs() []GPU {
	smiPath := findNvidiaSMI()
	if smiPath == "" {
		return nil
	}
	output, err := exec.Command(smiPath,
		"--query-gpu=name,utilization.gpu,memory.used,memory.total,temperature.gpu,power.draw",
		"--format=csv,noheader,nounits").Output()
	if err != nil {
		return nil
	}
	var gpus []GPU
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		fields := strings.Split(line, ",")
		if len(fields) < 6 {
			continue
		}
		// parseField is a closure: a small helper function that captures
		// `fields` from the enclosing scope and parses column `index` as a float.
		parseField := func(index int) float64 {
			value, _ := strconv.ParseFloat(strings.TrimSpace(fields[index]), 64)
			return value
		}
		gpus = append(gpus, GPU{
			Name:    strings.TrimSpace(fields[0]),
			UtilPct: parseField(1), MemUsedMB: parseField(2), MemTotalMB: parseField(3),
			TempC: parseField(4), PowerW: parseField(5),
		})
	}
	return gpus
}

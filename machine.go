package main

import (
	"bufio"
	"os"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/load"
	"github.com/shirou/gopsutil/v4/mem"
)

// Disk is one row of the "df -h" view: a real filesystem mounted on the host,
// with its size and usage. The `json:"..."` tags control the field names the
// frontend sees when this struct is serialized by encoding/json.
type Disk struct {
	Mount   string  `json:"mount"`
	FSType  string  `json:"fstype"`
	Device  string  `json:"device"`
	Total   uint64  `json:"total"`
	Used    uint64  `json:"used"`
	Free    uint64  `json:"free"`
	UsedPct float64 `json:"used_pct"`
}

// MachineSnapshot is everything we know about the host machine at one moment:
// CPU load, memory, swap, load averages, uptime and the disk list. One of
// these is produced every 5 seconds by the background collector loop.
type MachineSnapshot struct {
	Hostname  string  `json:"hostname"`
	CPUPct    float64 `json:"cpu_pct"`
	CPUCount  int     `json:"cpu_count"`
	MemTotal  uint64  `json:"mem_total"`
	MemUsed   uint64  `json:"mem_used"`
	MemPct    float64 `json:"mem_pct"`
	SwapTotal uint64  `json:"swap_total"`
	SwapUsed  uint64  `json:"swap_used"`
	Load1     float64 `json:"load1"`
	Load5     float64 `json:"load5"`
	Load15    float64 `json:"load15"`
	UptimeSec uint64  `json:"uptime_sec"`
	Disks     []Disk  `json:"disks"`
}

// realFSTypes whitelists filesystems worth showing in the disk list;
// everything else in the host's mount table is virtual/pseudo (proc, sysfs,
// tmpfs, cgroup, ...) or a docker overlay layer. 9p/drvfs are how WSL2
// exposes the Windows drives (C:, D:).
var realFSTypes = map[string]bool{
	"ext2": true, "ext3": true, "ext4": true, "xfs": true, "btrfs": true,
	"zfs": true, "f2fs": true, "vfat": true, "exfat": true, "ntfs": true,
	"ntfs3": true, "fuseblk": true, "9p": true, "drvfs": true, "virtiofs": true,
}

// collectMachine gathers one full MachineSnapshot.
//
// How it works: the container cannot see the host directly, so docker-compose
// bind-mounts the host's /proc to /host/proc and gopsutil is pointed there via
// the HOST_PROC environment variable. Each gopsutil call (cpu.Percent,
// mem.VirtualMemory, load.Avg, host.Uptime) then reads the HOST's kernel
// files, not the container's. cpu.Percent(0, false) is special: with interval
// 0 it returns the CPU usage since the PREVIOUS call, which is why main()
// calls collectMachine once at startup to "prime" that internal counter.
// Errors are deliberately soft: a failing probe leaves its field at zero
// instead of aborting the whole snapshot.
func collectMachine() *MachineSnapshot {
	snapshot := &MachineSnapshot{}
	snapshot.Hostname, _ = os.Hostname()

	if cpuPercents, err := cpu.Percent(0, false); err == nil && len(cpuPercents) > 0 {
		snapshot.CPUPct = cpuPercents[0]
	}
	snapshot.CPUCount, _ = cpu.Counts(true)

	if virtualMem, err := mem.VirtualMemory(); err == nil {
		snapshot.MemTotal = virtualMem.Total
		snapshot.MemUsed = virtualMem.Used
		snapshot.MemPct = virtualMem.UsedPercent
	}
	if swap, err := mem.SwapMemory(); err == nil {
		snapshot.SwapTotal = swap.Total
		snapshot.SwapUsed = swap.Used
	}
	if loadAvg, err := load.Avg(); err == nil {
		snapshot.Load1, snapshot.Load5, snapshot.Load15 = loadAvg.Load1, loadAvg.Load5, loadAvg.Load15
	}
	snapshot.UptimeSec, _ = host.Uptime()
	snapshot.Disks = collectDisks()
	return snapshot
}

// collectDisks builds the "df -h" view of the HOST's filesystems.
//
// How it works, in three steps:
//  1. Read the host's mount table. /host/proc/1/mounts is the mount list of
//     the host's PID 1 (init) — reading it through the bind-mounted procfs
//     gives us the host's view even though we run inside a container.
//  2. Filter: keep only real filesystem types (realFSTypes) and skip
//     docker/WSL-internal noise mounts, deduplicating by mount point.
//  3. Measure: the host's root is bind-mounted at /host/root, so the host
//     path "/mnt/c" is reachable as "/host/root/mnt/c". syscall.Statfs on
//     that path asks the kernel directly for block counts (same syscall df
//     uses), which we turn into total/used/free bytes.
//
// If the host mount table is unreadable (running outside docker, say), it
// falls back to the container's own /proc/mounts so the app still works.
func collectDisks() []Disk {
	hostRoot := envOr("HOST_ROOT", "/host/root")
	mountsPath := envOr("HOST_PROC", "/proc") + "/1/mounts"

	mountsFile, err := os.Open(mountsPath)
	if err != nil {
		mountsFile, err = os.Open("/proc/mounts")
		if err != nil {
			return nil
		}
		hostRoot = ""
	}
	defer mountsFile.Close()

	seenMounts := map[string]bool{}
	var disks []Disk
	scanner := bufio.NewScanner(mountsFile)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 3 {
			continue
		}
		device, mountPoint, fsType := fields[0], unescapeMount(fields[1]), fields[2]
		if !realFSTypes[fsType] || seenMounts[mountPoint] {
			continue
		}
		if strings.Contains(mountPoint, "/var/lib/docker") ||
			mountPoint == "/snap" || strings.HasPrefix(mountPoint, "/snap/") ||
			strings.HasPrefix(mountPoint, "/Docker/") || // Docker Desktop internal remount of the host drive
			strings.HasPrefix(mountPoint, "/usr/lib/wsl") || strings.HasPrefix(mountPoint, "/mnt/wsl") {
			continue
		}
		var stat syscall.Statfs_t
		if err := syscall.Statfs(hostRoot+mountPoint, &stat); err != nil {
			continue
		}
		blockSize := uint64(stat.Bsize)
		totalBytes := stat.Blocks * blockSize
		if totalBytes == 0 {
			continue
		}
		freeBytes := stat.Bavail * blockSize
		usedBytes := (stat.Blocks - stat.Bfree) * blockSize
		seenMounts[mountPoint] = true
		disks = append(disks, Disk{
			Mount: mountPoint, FSType: fsType, Device: device,
			Total: totalBytes, Used: usedBytes, Free: freeBytes,
			UsedPct: 100 * float64(usedBytes) / float64(usedBytes+freeBytes),
		})
	}
	sort.Slice(disks, func(i, j int) bool { return disks[i].Mount < disks[j].Mount })
	return disks
}

// unescapeMount decodes the octal escapes /proc/mounts uses for special
// characters in mount paths — e.g. a space is written as `\040`
// ("/mnt/my\040disk" means "/mnt/my disk").
func unescapeMount(rawPath string) string {
	replacer := strings.NewReplacer(`\040`, " ", `\011`, "\t", `\134`, `\`)
	return replacer.Replace(rawPath)
}

// envOr returns the value of the environment variable named `key`, or
// `fallback` when it is unset/empty — a tiny helper for configurable defaults
// (paths, port).
func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

// envInt reads key as an integer, returning fallback when unset or unparseable
// and clamping to at least min (so e.g. an interval can't be set to 0).
func envInt(key string, fallback, min int) int {
	if n, err := strconv.Atoi(os.Getenv(key)); err == nil {
		if n < min {
			return min
		}
		return n
	}
	return fallback
}

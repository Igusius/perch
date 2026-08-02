package main

// Trends: a small rolling history of machine metrics so the UI can draw
// sparklines instead of showing only the instantaneous value. One sample is
// recorded per collect cycle (see collectLoop) into a bounded ring — no disk,
// no dependency.

import (
	"net/http"
	"sync"
	"time"
)

// metricSample is one moment of the machine's headline percentages.
type metricSample struct {
	T    int64   `json:"t"`    // unix seconds
	CPU  float64 `json:"cpu"`  // percent
	Mem  float64 `json:"mem"`  // percent
	Swap float64 `json:"swap"` // percent
}

var (
	historyMu  sync.Mutex
	metricHist []metricSample
	// historyMax caps the ring. The collector ticks every 15s, so 240 samples
	// is ~1 hour of history — plenty for a sparkline, trivial memory.
	historyMax = 240
)

// recordSample appends one machine sample to the ring, dropping the oldest once
// the cap is reached.
func recordSample(m *MachineSnapshot) {
	if m == nil {
		return
	}
	// Swap is a percentage of total, guarding against divide-by-zero when the
	// host has no swap configured.
	swapPct := 0.0
	if m.SwapTotal > 0 {
		swapPct = 100 * float64(m.SwapUsed) / float64(m.SwapTotal)
	}
	historyMu.Lock()
	defer historyMu.Unlock()
	metricHist = append(metricHist, metricSample{
		T: time.Now().Unix(), CPU: m.CPUPct, Mem: m.MemPct, Swap: swapPct,
	})
	if len(metricHist) > historyMax {
		metricHist = metricHist[len(metricHist)-historyMax:]
	}
}

// handleTrends serves GET /api/trends — the recorded machine samples, oldest
// first, for the sparklines.
func handleTrends(w http.ResponseWriter, _ *http.Request) {
	historyMu.Lock()
	out := make([]metricSample, len(metricHist))
	copy(out, metricHist)
	historyMu.Unlock()
	writeJSON(w, http.StatusOK, out)
}

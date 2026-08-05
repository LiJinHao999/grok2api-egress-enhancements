package main

import (
	"path/filepath"
	"testing"
	"time"
)

func TestNodeAvailabilityObservationBased(t *testing.T) {
	n := &nodeRecord{ID: "1", Name: "sg"}
	base := float64(1_700_000_000)

	// Select node — must NOT invent healthy credit.
	applyClashActiveTransition(n, true, base)
	if !n.ClashActive || n.LastActiveAt != base || n.ActiveSessions != 1 {
		t.Fatalf("select: %+v", n)
	}
	snap := nodeAvailabilitySnapshot(n, base+3600) // idle 1h
	if snap["current_active_ms"].(int64) != 0 {
		t.Fatalf("idle selected must not count as healthy usage, got %v", snap["current_active_ms"])
	}
	if snap["current_selected_ms"].(int64) != 3_600_000 {
		t.Fatalf("selected wall clock want 3600000 got %v", snap["current_selected_ms"])
	}
	if snap["quality_score"] != nil {
		t.Fatalf("no observations yet, score should be nil, got %v", snap["quality_score"])
	}

	// Two healthy responses (5s + 7s generation)
	recordHealthyObservation(n, 5_000)
	recordHealthyObservation(n, 7_000)
	if n.HealthyObsCount != 2 || n.SessionHealthyUsageMs != 12_000 {
		t.Fatalf("healthy obs: %+v", n)
	}
	snap = nodeAvailabilitySnapshot(n, base+3600)
	if snap["current_active_ms"].(int64) != 12_000 {
		t.Fatalf("current healthy usage want 12000 got %v", snap["current_active_ms"])
	}
	if score := snap["quality_score"].(float64); score != 100 {
		t.Fatalf("score want 100 got %v", score)
	}

	// One hard degradation observation
	recordDegradedObservation(n)
	snap = nodeAvailabilitySnapshot(n, base+3600)
	// 2 healthy / 3 total = 66.7
	if score := snap["quality_score"].(float64); score < 66.6 || score > 66.8 {
		t.Fatalf("score want ~66.7 got %v", score)
	}

	// Quarantine after real usage
	markNodeQuarantined(n, base+3600)
	n.DisabledByGuard = true
	if n.SessionHealthyUsageMs != 0 || n.TotalActiveMs != 12_000 {
		t.Fatalf("quarantine should flush healthy usage: %+v", n)
	}
	if n.LastQuarantinedAt != base+3600 || n.QuarantineCount != 1 {
		t.Fatalf("quarantine start: %+v", n)
	}

	// 10 min quarantine open
	snap = nodeAvailabilitySnapshot(n, base+3600+600)
	if snap["current_quarantined_ms"].(int64) != 600_000 {
		t.Fatalf("current q want 600000 got %v", snap["current_quarantined_ms"])
	}
	// obs score still 2/3
	if score := snap["quality_score"].(float64); score < 66.6 || score > 66.8 {
		t.Fatalf("obs score should remain ~66.7 got %v", score)
	}

	// restore
	markNodeRestored(n, base+3600+600)
	n.DisabledByGuard = false
	if n.TotalQuarantinedMs != 600_000 || n.LastQuarantinedAt != 0 {
		t.Fatalf("restore: %+v", n)
	}
	// still selected → new window, no free healthy credit
	if n.LastActiveAt != base+3600+600 || n.SessionHealthyUsageMs != 0 {
		t.Fatalf("restore selection without free credit: %+v", n)
	}
	if n.ActiveSessions != 2 {
		t.Fatalf("sessions want 2 got %d", n.ActiveSessions)
	}

	// switch away with no extra healthy obs — totals unchanged for healthy
	applyClashActiveTransition(n, false, base+3600+700)
	if n.ClashActive || n.LastActiveAt != 0 {
		t.Fatalf("switch away: %+v", n)
	}
	if n.TotalActiveMs != 12_000 {
		t.Fatalf("healthy total still 12000, got %d", n.TotalActiveMs)
	}
}

func TestQuarantineAndRestoreTrackAvailability(t *testing.T) {
	dir := t.TempDir()
	s := newStateStore(filepath.Join(dir, "state.json"))
	a, err := s.createNode("node-a", "socks5h://127.0.0.1:1080", true, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.createNode("node-b", "socks5h://127.0.0.1:1081", true, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = s.updateNode(a.ID, func(n *nodeRecord) error {
		n.Source = nodeSourceClash
		n.ClashName = "A"
		applyClashActiveTransition(n, true, float64(time.Now().Add(-2*time.Minute).Unix()))
		recordHealthyObservation(n, 3_000)
		return nil
	})
	_, _ = s.updateNode(b.ID, func(n *nodeRecord) error {
		n.Source = nodeSourceClash
		n.ClashName = "B"
		return nil
	})

	updated, err := manualQuarantineNode(s, a.ID, "人工降智隔离")
	if err != nil {
		t.Fatal(err)
	}
	if !updated.DisabledByGuard || updated.QuarantineCount != 1 {
		t.Fatalf("quarantine result: %+v", updated)
	}
	if updated.HealthyObsCount != 1 || updated.TotalActiveMs != 3_000 {
		t.Fatalf("healthy usage should flush on quarantine: %+v", updated)
	}

	restored, err := restoreQuarantinedNode(s, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if restored.DisabledByGuard || restored.LastQuarantinedAt != 0 {
		t.Fatalf("restore result: %+v", restored)
	}
	pub := publicNode(restored)
	if pub["healthy_obs_count"].(int64) != 1 {
		t.Fatalf("public healthy_obs_count: %#v", pub["healthy_obs_count"])
	}
	if _, ok := pub["quality_score"]; !ok {
		t.Fatalf("publicNode missing quality_score: %#v", pub)
	}
}

func TestReQuarantineKeepsOriginalStart(t *testing.T) {
	n := &nodeRecord{ID: "1"}
	base := float64(1_700_000_000)
	markNodeQuarantined(n, base)
	n.DisabledByGuard = true
	markNodeQuarantined(n, base+100)
	if n.LastQuarantinedAt != base || n.QuarantineCount != 1 {
		t.Fatalf("re-quarantine should keep start/count: %+v", n)
	}
}

func TestApplyObservationCreditsHealthyAndDegraded(t *testing.T) {
	dir := t.TempDir()
	s := newStateStore(filepath.Join(dir, "state.json"))
	n, err := s.createNode("n1", "socks5h://127.0.0.1:1080", true, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	applyObservation(s, n.ID, "passive", qualityResult{
		Classification: "healthy",
		TPS:            40,
		OutputTokens:   100,
		DurationMs:     2500,
		HasThinking:    true,
	})
	got, _ := s.getNode(n.ID)
	if got.HealthyObsCount != 1 || got.SessionHealthyUsageMs != 2500 {
		t.Fatalf("healthy credit: %+v", got)
	}
	applyObservation(s, n.ID, "active", qualityResult{
		Classification: "hard",
		TPS:            900,
		OutputTokens:   50,
		DurationMs:     1000,
		HasThinking:    false,
		ErrorKind:      "missing_thinking",
	})
	got, _ = s.getNode(n.ID)
	if got.DegradedObsCount < 1 {
		t.Fatalf("degraded credit missing: %+v", got)
	}
	// With only one healthy node, auto quarantine may be suppressed — still must
	// count the degraded observation so quality score drops.
	if got.HealthyObsCount != 1 {
		t.Fatalf("healthy obs should stay 1: %+v", got)
	}
	snap := nodeAvailabilitySnapshot(got, float64(time.Now().Unix()))
	if score := snap["quality_score"].(float64); score != 50 {
		t.Fatalf("score want 50 (1/2) got %v", score)
	}
}

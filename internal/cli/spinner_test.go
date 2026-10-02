package cli

import (
	"bytes"
	"testing"

	"github.com/nexutils/StackGuard/internal/engine"
)

func TestPhaseLine(t *testing.T) {
	cases := []struct {
		in   engine.ScanPhase
		want string
	}{
		{engine.ScanPhase{Stage: "discovering"}, "Discovering files"},
		{engine.ScanPhase{Stage: "parsing", Files: 1}, "Parsing  1 file"},
		{engine.ScanPhase{Stage: "parsing", Files: 11}, "Parsing  11 files"},
		{engine.ScanPhase{Stage: "evaluating", Files: 11, Resources: 26, Rules: 225},
			"Evaluating rules  11 files · 26 resources · 225 rules"},
		{engine.ScanPhase{Stage: "bogus"}, "Scanning"},
	}
	for _, c := range cases {
		if got := phaseLine(c.in); got != c.want {
			t.Errorf("phaseLine(%+v) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestSpinnerSilentBeforeDelay verifies a scan that finishes within the startup
// delay (the common fast case) draws no spinner frames — only the erase
// sequence stop always emits.
func TestSpinnerSilentBeforeDelay(t *testing.T) {
	var buf bytes.Buffer
	s := newSpinner(&buf)
	s.start()
	s.stop() // start→stop takes microseconds, far below spinnerDelay
	if got := buf.String(); got != "\r\x1b[2K" {
		t.Errorf("spinner wrote %q before its delay, want only the erase sequence", got)
	}
}

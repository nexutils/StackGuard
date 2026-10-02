package cli

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/nexutils/StackGuard/internal/engine"
)

// spinnerFrames are braille dots; one is drawn per tick.
var spinnerFrames = []rune("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏")

const (
	// spinnerDelay is how long a scan must run before the spinner appears, so
	// fast scans (the common case) show nothing at all.
	spinnerDelay = 150 * time.Millisecond
	spinnerTick  = 90 * time.Millisecond
)

// spinner draws a single-line phase indicator to a TTY while a scan runs. It
// stays silent until spinnerDelay has elapsed and erases itself on stop, so the
// report that follows starts on a clean line. Its methods are safe to call from
// another goroutine; nothing is written after stop returns.
type spinner struct {
	w    io.Writer
	mu   sync.Mutex
	line string
	quit chan struct{}
	done chan struct{}
}

func newSpinner(w io.Writer) *spinner {
	s := &spinner{w: w, quit: make(chan struct{}), done: make(chan struct{})}
	s.line = phaseLine(engine.ScanPhase{})
	return s
}

// start begins the animation in the background.
func (s *spinner) start() { go s.run() }

// update sets the text drawn on the next tick.
func (s *spinner) update(p engine.ScanPhase) {
	line := phaseLine(p)
	s.mu.Lock()
	s.line = line
	s.mu.Unlock()
}

// stop halts the animation, waits for the goroutine to finish, and erases the
// line. It is safe to call exactly once.
func (s *spinner) stop() {
	close(s.quit)
	<-s.done
	fmt.Fprint(s.w, "\r\x1b[2K")
}

func (s *spinner) run() {
	defer close(s.done)
	// Hold off until the scan has run long enough to be worth a spinner.
	select {
	case <-s.quit:
		return
	case <-time.After(spinnerDelay):
	}
	ticker := time.NewTicker(spinnerTick)
	defer ticker.Stop()
	for frame := 0; ; frame = (frame + 1) % len(spinnerFrames) {
		s.mu.Lock()
		line := s.line
		s.mu.Unlock()
		// \r returns to column 0; \x1b[2K clears the whole line first so a
		// shorter label never leaves stale characters behind.
		fmt.Fprintf(s.w, "\r\x1b[2K\x1b[36m%c\x1b[0m %s", spinnerFrames[frame], line)
		select {
		case <-s.quit:
			return
		case <-ticker.C:
		}
	}
}

// phaseLine renders a scan phase as "<label>  <counts>".
func phaseLine(p engine.ScanPhase) string {
	label := "Scanning"
	switch p.Stage {
	case "discovering":
		label = "Discovering files"
	case "parsing":
		label = "Parsing"
	case "evaluating":
		label = "Evaluating rules"
	}
	var counts []string
	if p.Files > 0 {
		counts = append(counts, count(p.Files, "file"))
	}
	if p.Resources > 0 {
		counts = append(counts, count(p.Resources, "resource"))
	}
	if p.Rules > 0 {
		counts = append(counts, count(p.Rules, "rule"))
	}
	if len(counts) == 0 {
		return label
	}
	return label + "  " + strings.Join(counts, " · ")
}

// count renders "<n> <noun>", pluralising the noun with a trailing "s".
func count(n int, noun string) string {
	if n == 1 {
		return fmt.Sprintf("1 %s", noun)
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

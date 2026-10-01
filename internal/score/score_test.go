package score

import (
	"testing"

	"github.com/nexutils/StackGuard/internal/models"
)

func findings(sev ...models.Severity) []models.Finding {
	out := make([]models.Finding, len(sev))
	for i, s := range sev {
		out[i] = models.Finding{Severity: s}
	}
	return out
}

func TestDefaultScorer(t *testing.T) {
	E, W, I := models.SeverityError, models.SeverityWarning, models.SeverityInfo
	tests := []struct {
		name string
		in   []models.Finding
		want models.Score
	}{
		{"clean", nil, models.Score{Total: 100, Max: 100}},
		{"mixed", findings(E, W, W, I), models.Score{Total: 83, Max: 100, Errors: 1, Warnings: 2, Infos: 1}},
		{"floor at zero", findings(E, E, E, E, E, E, E, E, E, E, E), models.Score{Total: 0, Max: 100, Errors: 11}},
	}
	for _, tt := range tests {
		if got := Default().Score(tt.in); got != tt.want {
			t.Errorf("%s: got %+v, want %+v", tt.name, got, tt.want)
		}
	}
}

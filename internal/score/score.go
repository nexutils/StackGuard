// Package score turns findings into a single production-readiness score.
package score

import "github.com/nexutils/StackGuard/internal/models"

// Scorer computes a Score from findings. Alternative strategies (per
// category, normalised per resource, ...) can be added by implementing it.
type Scorer interface {
	Score(findings []models.Finding) models.Score
}

// Deduction starts at Max and subtracts a fixed amount per finding by
// severity, never going below zero.
type Deduction struct {
	Max     int
	Error   int
	Warning int
	Info    int
}

// Default returns the standard scorer: 100 points, -10 per ERROR, -3 per
// WARNING and -1 per INFO.
func Default() Scorer {
	return Deduction{Max: 100, Error: 10, Warning: 3, Info: 1}
}

func (d Deduction) Score(findings []models.Finding) models.Score {
	s := models.Score{Max: d.Max}
	for _, f := range findings {
		switch f.Severity {
		case models.SeverityError:
			s.Errors++
		case models.SeverityWarning:
			s.Warnings++
		default:
			s.Infos++
		}
	}
	s.Total = max(0, d.Max-s.Errors*d.Error-s.Warnings*d.Warning-s.Infos*d.Info)
	return s
}

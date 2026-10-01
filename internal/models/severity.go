package models

import (
	"fmt"
	"strings"
)

// Severity ranks how serious a finding is. Higher values are more severe, so
// severities can be compared directly (e.g. f.Severity >= SeverityWarning).
type Severity int

const (
	SeverityInfo Severity = iota
	SeverityWarning
	SeverityError
)

// Severities lists all severities from most to least severe.
var Severities = []Severity{SeverityError, SeverityWarning, SeverityInfo}

func (s Severity) String() string {
	switch s {
	case SeverityInfo:
		return "INFO"
	case SeverityWarning:
		return "WARNING"
	case SeverityError:
		return "ERROR"
	default:
		return fmt.Sprintf("Severity(%d)", int(s))
	}
}

// ParseSeverity parses a severity name case-insensitively. "WARN" is accepted
// as an alias for WARNING.
func ParseSeverity(s string) (Severity, error) {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "INFO":
		return SeverityInfo, nil
	case "WARNING", "WARN":
		return SeverityWarning, nil
	case "ERROR":
		return SeverityError, nil
	default:
		return 0, fmt.Errorf("unknown severity %q (want ERROR, WARNING or INFO)", s)
	}
}

func (s Severity) MarshalText() ([]byte, error) {
	return []byte(s.String()), nil
}

func (s *Severity) UnmarshalText(b []byte) error {
	v, err := ParseSeverity(string(b))
	if err != nil {
		return err
	}
	*s = v
	return nil
}

package models

import (
	"fmt"
	"strings"
)

// Profile controls which rules a scan evaluates.
type Profile int

const (
	ProfileStandard Profile = iota
	ProfileQuick
	ProfileStrict
)

// Profiles lists all valid profiles.
var Profiles = []Profile{ProfileQuick, ProfileStandard, ProfileStrict}

func (p Profile) String() string {
	switch p {
	case ProfileQuick:
		return "quick"
	case ProfileStandard:
		return "standard"
	case ProfileStrict:
		return "strict"
	default:
		return fmt.Sprintf("Profile(%d)", int(p))
	}
}

// ParseProfile parses a profile name case-insensitively.
func ParseProfile(s string) (Profile, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "quick":
		return ProfileQuick, nil
	case "standard", "":
		return ProfileStandard, nil
	case "strict":
		return ProfileStrict, nil
	default:
		return ProfileStandard, fmt.Errorf("unknown profile %q (want quick, standard or strict)", s)
	}
}

// MinSeverity returns the minimum severity a rule must have to be included.
func (p Profile) MinSeverity() Severity {
	switch p {
	case ProfileQuick:
		return SeverityError
	case ProfileStrict:
		return SeverityInfo
	default:
		return SeverityWarning
	}
}

// CategoryAllowed reports whether a rule category is included in the profile.
func (p Profile) CategoryAllowed(category string) bool {
	if p != ProfileQuick {
		return true
	}
	return category == CategorySecurity || category == CategoryReliability
}

// EnableOffByDefault reports whether the profile auto-enables off-by-default rules.
func (p Profile) EnableOffByDefault() bool {
	return p == ProfileStrict
}

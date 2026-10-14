package models

import "testing"

func TestParseProfile(t *testing.T) {
	tests := []struct {
		input   string
		want    Profile
		wantErr bool
	}{
		{"quick", ProfileQuick, false},
		{"QUICK", ProfileQuick, false},
		{" Quick ", ProfileQuick, false},
		{"standard", ProfileStandard, false},
		{"", ProfileStandard, false},
		{"strict", ProfileStrict, false},
		{"STRICT", ProfileStrict, false},
		{"unknown", ProfileStandard, true},
	}
	for _, tt := range tests {
		got, err := ParseProfile(tt.input)
		if (err != nil) != tt.wantErr {
			t.Errorf("ParseProfile(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			continue
		}
		if !tt.wantErr && got != tt.want {
			t.Errorf("ParseProfile(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestProfileString(t *testing.T) {
	tests := []struct {
		p    Profile
		want string
	}{
		{ProfileQuick, "quick"},
		{ProfileStandard, "standard"},
		{ProfileStrict, "strict"},
	}
	for _, tt := range tests {
		if got := tt.p.String(); got != tt.want {
			t.Errorf("Profile(%d).String() = %q, want %q", tt.p, got, tt.want)
		}
	}
}

func TestProfileMinSeverity(t *testing.T) {
	if ProfileQuick.MinSeverity() != SeverityError {
		t.Errorf("quick min severity = %v, want ERROR", ProfileQuick.MinSeverity())
	}
	if ProfileStandard.MinSeverity() != SeverityWarning {
		t.Errorf("standard min severity = %v, want WARNING", ProfileStandard.MinSeverity())
	}
	if ProfileStrict.MinSeverity() != SeverityInfo {
		t.Errorf("strict min severity = %v, want INFO", ProfileStrict.MinSeverity())
	}
}

func TestProfileCategoryAllowed(t *testing.T) {
	for _, cat := range Categories {
		if !ProfileStandard.CategoryAllowed(cat) {
			t.Errorf("standard should allow %q", cat)
		}
		if !ProfileStrict.CategoryAllowed(cat) {
			t.Errorf("strict should allow %q", cat)
		}
	}
	if !ProfileQuick.CategoryAllowed(CategorySecurity) {
		t.Error("quick should allow security")
	}
	if !ProfileQuick.CategoryAllowed(CategoryReliability) {
		t.Error("quick should allow reliability")
	}
	for _, cat := range []string{CategoryOperational, CategoryMaintainability, CategoryPerformance} {
		if ProfileQuick.CategoryAllowed(cat) {
			t.Errorf("quick should not allow %q", cat)
		}
	}
}

func TestProfileEnableOffByDefault(t *testing.T) {
	if ProfileQuick.EnableOffByDefault() {
		t.Error("quick should not enable off-by-default")
	}
	if ProfileStandard.EnableOffByDefault() {
		t.Error("standard should not enable off-by-default")
	}
	if !ProfileStrict.EnableOffByDefault() {
		t.Error("strict should enable off-by-default")
	}
}

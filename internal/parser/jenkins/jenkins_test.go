package jenkins

import "testing"

func TestMaskNonCode(t *testing.T) {
	in := "a('x{') // }\nb(\"\"\"{\"\"\") /* } */ c { }"
	got := maskNonCode(in)
	if len(got) != len(in) {
		t.Fatalf("masking must preserve length: %d vs %d", len(got), len(in))
	}
	if matchBrace(got, len(got)-3) != len(got)-1 {
		t.Errorf("braces in strings/comments were not masked: %q", got)
	}
}

func FuzzMaskNonCode(f *testing.F) {
	f.Add("pipeline { stage('a') { sh '''x''' } }")
	f.Add(`"unterminated`)
	f.Add("/* open")
	f.Fuzz(func(t *testing.T, s string) {
		if got := maskNonCode(s); len(got) != len(s) {
			t.Fatalf("length changed")
		}
	})
}

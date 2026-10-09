package imageref

import "testing"

func TestParse(t *testing.T) {
	tests := map[string]Ref{
		"nginx":                      {Name: "nginx"},
		"nginx:1.25":                 {Name: "nginx", Tag: "1.25"},
		"registry:5000/team/app":     {Name: "registry:5000/team/app"},
		"registry:5000/team/app:2":   {Name: "registry:5000/team/app", Tag: "2"},
		"alpine@sha256:abc":          {Name: "alpine", Digest: "sha256:abc"},
		"ghcr.io/a/b:1.0@sha256:def": {Name: "ghcr.io/a/b", Tag: "1.0", Digest: "sha256:def"},
		"  padded:latest  ":          {Name: "padded", Tag: "latest"},
	}
	for in, want := range tests {
		if got := Parse(in); got != want {
			t.Errorf("Parse(%q) = %+v, want %+v", in, got, want)
		}
	}
}

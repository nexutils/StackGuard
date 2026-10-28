package git

import (
	"os"
	"os/exec"
	"testing"
)

func TestParseRepoName(t *testing.T) {
	tests := []struct {
		remote string
		want   string
	}{
		{"https://github.com/nexutils/StackGuard.git", "nexutils/StackGuard"},
		{"https://github.com/nexutils/StackGuard", "nexutils/StackGuard"},
		{"git@github.com:nexutils/StackGuard.git", "nexutils/StackGuard"},
		{"git@github.com:nexutils/StackGuard", "nexutils/StackGuard"},
		{"https://gitlab.com/org/sub/project.git", "org/sub/project"},
		{"git@gitlab.com:org/sub/project.git", "org/sub/project"},
		{"", ""},
	}
	for _, tt := range tests {
		t.Run(tt.remote, func(t *testing.T) {
			got := ParseRepoName(tt.remote)
			if got != tt.want {
				t.Errorf("ParseRepoName(%q) = %q, want %q", tt.remote, got, tt.want)
			}
		})
	}
}

func TestSanitizeURL(t *testing.T) {
	tests := []struct {
		raw  string
		want string
	}{
		{"https://github.com/org/repo.git", "https://github.com/org/repo.git"},
		{"https://token@github.com/org/repo.git", "https://github.com/org/repo.git"},
		{"https://user:pass@github.com/org/repo.git", "https://github.com/org/repo.git"},
		{"git@github.com:org/repo.git", "git@github.com:org/repo.git"},
	}
	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			got := SanitizeURL(tt.raw)
			if got != tt.want {
				t.Errorf("SanitizeURL(%q) = %q, want %q", tt.raw, got, tt.want)
			}
		})
	}
}

func TestDetect(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}

	t.Run("non-repo directory", func(t *testing.T) {
		dir := t.TempDir()
		info, err := Detect(dir)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if info != nil {
			t.Fatalf("expected nil info for non-repo dir, got %+v", info)
		}
	})

	t.Run("real git repo", func(t *testing.T) {
		dir := t.TempDir()
		run := func(args ...string) {
			t.Helper()
			cmd := exec.Command(args[0], args[1:]...)
			cmd.Dir = dir
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			if err := cmd.Run(); err != nil {
				t.Fatalf("%v failed: %v", args, err)
			}
		}
		run("git", "init")
		run("git", "config", "user.email", "test@test.com")
		run("git", "config", "user.name", "Test")
		if err := os.WriteFile(dir+"/f.txt", []byte("hello"), 0644); err != nil {
			t.Fatal(err)
		}
		run("git", "add", ".")
		run("git", "commit", "-m", "init")

		info, err := Detect(dir)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if info == nil {
			t.Fatal("expected non-nil info")
		}
		if info.CommitSHA == "" {
			t.Error("CommitSHA is empty")
		}
		if len(info.CommitSHA) != 40 {
			t.Errorf("CommitSHA length = %d, want 40", len(info.CommitSHA))
		}
		if info.CommitDate == "" {
			t.Error("CommitDate is empty")
		}
		// No remote set, so Name and RemoteURL should be empty.
		if info.Name != "" {
			t.Errorf("Name = %q, want empty (no remote)", info.Name)
		}
		if len(info.Tags) != 0 {
			t.Errorf("Tags = %v, want empty (no tags)", info.Tags)
		}
	})

	t.Run("tags at HEAD", func(t *testing.T) {
		dir := t.TempDir()
		run := func(args ...string) {
			t.Helper()
			cmd := exec.Command(args[0], args[1:]...)
			cmd.Dir = dir
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			if err := cmd.Run(); err != nil {
				t.Fatalf("%v failed: %v", args, err)
			}
		}
		run("git", "init")
		run("git", "config", "user.email", "test@test.com")
		run("git", "config", "user.name", "Test")
		if err := os.WriteFile(dir+"/f.txt", []byte("hello"), 0644); err != nil {
			t.Fatal(err)
		}
		run("git", "add", ".")
		run("git", "commit", "-m", "init")
		run("git", "tag", "v1.0.0")
		run("git", "tag", "latest")

		info, err := Detect(dir)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if info == nil {
			t.Fatal("expected non-nil info")
		}
		if len(info.Tags) != 2 {
			t.Fatalf("Tags = %v, want 2 tags", info.Tags)
		}
		tagSet := map[string]bool{}
		for _, tag := range info.Tags {
			tagSet[tag] = true
		}
		if !tagSet["v1.0.0"] || !tagSet["latest"] {
			t.Errorf("Tags = %v, want [v1.0.0, latest]", info.Tags)
		}
	})
}

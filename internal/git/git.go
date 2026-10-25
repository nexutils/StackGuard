// Package git extracts repository metadata from a scanned directory by
// shelling out to the git binary. All functions are best-effort: a missing
// git binary or a non-repo directory is never an error — the metadata is
// simply absent.
package git

import (
	"net/url"
	"os/exec"
	"path"
	"strings"
)

// RepoInfo holds the metadata extracted from a git repository.
type RepoInfo struct {
	Name       string // "owner/repo", parsed from the remote URL
	RemoteURL  string // sanitised origin URL (userinfo stripped)
	Branch     string // current branch (or "HEAD" when detached)
	CommitSHA  string // full 40-char HEAD SHA
	CommitDate string // ISO 8601 commit date of HEAD
}

// Detect discovers git repository metadata for dir. It returns nil, nil
// when dir is not inside a git repository or when the git binary is not
// installed.
func Detect(dir string) (*RepoInfo, error) {
	if _, err := exec.LookPath("git"); err != nil {
		return nil, nil
	}

	toplevel, err := git(dir, "rev-parse", "--show-toplevel")
	if err != nil {
		return nil, nil
	}
	if toplevel == "" {
		return nil, nil
	}

	info := &RepoInfo{}

	if sha, err := git(dir, "rev-parse", "HEAD"); err == nil {
		info.CommitSHA = sha
	}

	if branch, err := git(dir, "rev-parse", "--abbrev-ref", "HEAD"); err == nil {
		info.Branch = branch
	}

	if date, err := git(dir, "log", "-1", "--format=%cI"); err == nil {
		info.CommitDate = date
	}

	if remote, err := git(dir, "remote", "get-url", "origin"); err == nil && remote != "" {
		info.RemoteURL = SanitizeURL(remote)
		info.Name = ParseRepoName(remote)
	}

	return info, nil
}

// git runs a git command in dir and returns the trimmed stdout. An error
// means git failed or produced no output; both are non-fatal in this package.
func git(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// SanitizeURL strips embedded credentials from a remote URL.
// SSH URLs (git@host:owner/repo.git) pass through unchanged.
func SanitizeURL(raw string) string {
	if strings.Contains(raw, "://") {
		u, err := url.Parse(raw)
		if err != nil {
			return raw
		}
		u.User = nil
		return u.String()
	}
	return raw
}

// ParseRepoName extracts an "owner/repo" string from a remote URL.
// It handles HTTPS (https://github.com/owner/repo.git) and SSH
// (git@github.com:owner/repo.git) formats.
func ParseRepoName(remote string) string {
	remote = strings.TrimSpace(remote)
	if remote == "" {
		return ""
	}

	// SSH: git@github.com:owner/repo.git
	if idx := strings.Index(remote, ":"); idx > 0 && !strings.Contains(remote, "://") {
		remote = remote[idx+1:]
		remote = strings.TrimSuffix(remote, ".git")
		return remote
	}

	// HTTPS: https://github.com/owner/repo.git
	u, err := url.Parse(remote)
	if err != nil {
		return ""
	}
	p := strings.TrimPrefix(u.Path, "/")
	p = strings.TrimSuffix(p, ".git")
	if p == "" {
		return ""
	}
	return path.Clean(p)
}

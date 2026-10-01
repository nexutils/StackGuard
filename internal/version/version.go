// Package version exposes build metadata injected at link time:
//
//	go build -ldflags "-X github.com/nexutils/StackGuard/internal/version.Version=v1.2.3 ..."
package version

import (
	"runtime"
	"runtime/debug"
)

var (
	Version = "dev"
	Commit  = ""
	Date    = ""
)

// Info is the full set of build metadata.
type Info struct {
	Version   string `json:"version"`
	Commit    string `json:"commit,omitempty"`
	Date      string `json:"date,omitempty"`
	GoVersion string `json:"go_version"`
	Platform  string `json:"platform"`
}

// Get returns build metadata, falling back to VCS info embedded by the Go
// toolchain when ldflags were not set (e.g. `go install ...@latest`).
func Get() Info {
	info := Info{
		Version:   Version,
		Commit:    Commit,
		Date:      Date,
		GoVersion: runtime.Version(),
		Platform:  runtime.GOOS + "/" + runtime.GOARCH,
	}
	if bi, ok := debug.ReadBuildInfo(); ok {
		if info.Version == "dev" && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
			info.Version = bi.Main.Version
		}
		for _, s := range bi.Settings {
			switch s.Key {
			case "vcs.revision":
				if info.Commit == "" {
					info.Commit = s.Value
				}
			case "vcs.time":
				if info.Date == "" {
					info.Date = s.Value
				}
			}
		}
	}
	return info
}

package dockerfile

import (
	"regexp"
	"strings"
)

// pkg is one package an install command adds to the image. Version is empty
// when the install did not pin one.
type pkg struct {
	Manager string
	Name    string
	Version string
}

// installer describes a package-manager entry point: the verbs that mean
// "install", and whether a global flag is required (npm).
type installer struct {
	manager    string
	verbs      map[string]bool
	needGlobal bool
}

var installers = map[string]installer{
	"apt":      {"apt", set("install"), false},
	"apt-get":  {"apt", set("install"), false},
	"apk":      {"apk", set("add"), false},
	"yum":      {"rpm", set("install"), false},
	"dnf":      {"rpm", set("install"), false},
	"microdnf": {"rpm", set("install"), false},
	"zypper":   {"zypper", set("in", "install"), false},
	"pip":      {"pip", set("install"), false},
	"pip3":     {"pip", set("install"), false},
	"gem":      {"gem", set("install"), false},
	"npm":      {"npm", set("install", "i", "add"), true},
}

var (
	reDebVer = regexp.MustCompile(`^([^=<>~]+)(?:[=<>~]+(.+))?$`)                   // apt/apk/zypper: name=version
	rePipVer = regexp.MustCompile(`^([A-Za-z0-9._-]+?)(?:==|>=|<=|~=|!=|>|<)(.+)$`) // pip: name==version
	reRPMVer = regexp.MustCompile(`^(.+)-(\d[A-Za-z0-9._]*)$`)                      // rpm: name-1.2.3
	reEnvSet = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)
)

// extractPackages scans a stage's RUN command strings for install invocations.
func extractPackages(runs []string) []pkg {
	var out []pkg
	for _, run := range runs {
		for _, cmd := range splitCommands(run) {
			out = append(out, packagesInCommand(cmd)...)
		}
	}
	return out
}

// splitCommands breaks a RUN body into individual commands on &&, ||, |, ; and
// newlines, so each install invocation is inspected on its own.
func splitCommands(s string) []string {
	return regexp.MustCompile(`&&|\|\||[;\n|]`).Split(s, -1)
}

func packagesInCommand(cmd string) []pkg {
	fields := strings.Fields(cmd)
	// Skip leading `sudo`, `-E` and `KEY=value` environment prefixes.
	for len(fields) > 0 {
		f := fields[0]
		if f == "sudo" || f == "-E" || reEnvSet.MatchString(f) {
			fields = fields[1:]
			continue
		}
		break
	}
	if len(fields) == 0 {
		return nil
	}
	inst, ok := installers[fields[0]]
	if !ok {
		return nil
	}
	// Find the install verb after the command name.
	verb := -1
	for i := 1; i < len(fields); i++ {
		if inst.verbs[fields[i]] {
			verb = i
			break
		}
	}
	if verb < 0 {
		return nil
	}
	rest := fields[verb+1:]
	if inst.needGlobal && !hasGlobalFlag(rest) {
		return nil
	}

	var out []pkg
	for i := 0; i < len(rest); i++ {
		tok := rest[i]
		if tok == "" {
			continue
		}
		if strings.HasPrefix(tok, "-") || strings.HasPrefix(tok, ">") || strings.HasPrefix(tok, "<") {
			// Skip flags, and the argument of pip's requirements flag.
			if inst.manager == "pip" && (tok == "-r" || tok == "--requirement") {
				i++
			}
			continue
		}
		name, ver := splitNameVersion(inst.manager, tok)
		if name == "" {
			continue
		}
		out = append(out, pkg{Manager: inst.manager, Name: name, Version: ver})
	}
	return out
}

func splitNameVersion(manager, tok string) (name, version string) {
	switch manager {
	case "apt", "apk", "zypper":
		if m := reDebVer.FindStringSubmatch(tok); m != nil {
			return m[1], m[2]
		}
	case "pip":
		if m := rePipVer.FindStringSubmatch(tok); m != nil {
			return m[1], m[2]
		}
	case "npm":
		// name@version, @scope/name@version; the leading @ of a scope is not a
		// version separator.
		if i := strings.LastIndex(tok, "@"); i > 0 {
			return tok[:i], tok[i+1:]
		}
	case "rpm":
		if m := reRPMVer.FindStringSubmatch(tok); m != nil {
			return m[1], m[2]
		}
	}
	return tok, ""
}

func hasGlobalFlag(fields []string) bool {
	for _, f := range fields {
		if f == "-g" || f == "--global" {
			return true
		}
	}
	return false
}

func set(words ...string) map[string]bool {
	m := make(map[string]bool, len(words))
	for _, w := range words {
		m[w] = true
	}
	return m
}

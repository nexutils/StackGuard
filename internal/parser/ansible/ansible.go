// Package ansible parses an Ansible playbook (and the project files beside it)
// into a single "ansible" resource.
//
// Like the Dockerfile parser emits one resource per Dockerfile and reads the
// sibling .dockerignore, this emits one resource per playbook and reads sibling
// project files (roles/, group_vars/, host_vars/, ansible.cfg, requirements*,
// .ansible-lint). The resource exposes tasks[*], plays[*], vars[*] +
// var_counts.<name>, roles[*], strings[*], config.<section>.<key> and context.*
// — see model.go. Non-playbook YAML yields no resource (its tasks come in via a
// playbook's roles/tasks).
package ansible

import (
	"context"
	"regexp"
	"strings"

	"github.com/nexutils/StackGuard/internal/models"
	"github.com/nexutils/StackGuard/internal/parser"
)

const Target = "ansible"

var (
	playbookName = regexp.MustCompile(`^(site|main|playbook[\w.-]*)\.ya?ml$`)
	taskDir      = regexp.MustCompile(`(^|/)(tasks|handlers|playbooks)/`)
	listStart    = regexp.MustCompile(`(?m)^-\s`)
	hostsKey     = regexp.MustCompile(`(?m)^\s*-?\s*(hosts|import_playbook):`)
)

// taskKeywords are task-level keys that are not the module invocation.
var taskKeywords = map[string]bool{
	"name": true, "when": true, "become": true, "become_user": true, "become_method": true,
	"register": true, "loop": true, "loop_control": true, "tags": true, "notify": true,
	"vars": true, "environment": true, "ignore_errors": true, "ignore_unreachable": true,
	"no_log": true, "changed_when": true, "failed_when": true, "delegate_to": true,
	"delegate_facts": true, "run_once": true, "args": true, "until": true, "retries": true,
	"delay": true, "block": true, "rescue": true, "always": true, "listen": true,
	"check_mode": true, "diff": true, "any_errors_fatal": true, "async": true, "poll": true,
	"connection": true, "throttle": true, "timeout": true, "module_defaults": true,
	"collections": true, "debugger": true,
}

// Parser implements parser.Parser for Ansible.
type Parser struct{}

func New() *Parser { return &Parser{} }

func (*Parser) Name() string { return Target }

func (*Parser) CanParse(f *parser.FileInfo) bool {
	if !f.IsYAML() {
		return false
	}
	path := f.SlashPath()
	if strings.Contains(path, ".github/") {
		return false
	}
	head := f.Head()
	if !listStart.Match(head) {
		return false
	}
	return playbookName.MatchString(strings.ToLower(f.Base())) ||
		taskDir.MatchString(path) ||
		hostsKey.Match(head)
}

// Parse emits one resource for a playbook file (nil for non-playbooks).
func (*Parser) Parse(_ context.Context, src parser.Source) ([]models.Resource, error) {
	return build(src)
}

// moduleOf returns the module key (FQCN as written) of a task.
func moduleOf(task map[string]any) string {
	if a, ok := task["action"].(string); ok {
		return strings.Fields(a + " ")[0]
	}
	if a, ok := task["local_action"].(string); ok {
		return strings.Fields(a + " ")[0]
	}
	best := ""
	for k := range task {
		if taskKeywords[k] || strings.HasPrefix(k, "with_") || k == "action" || k == "local_action" {
			continue
		}
		if best == "" || k < best {
			best = k
		}
	}
	return best
}

func shortModule(fqcn string) string {
	fqcn = strings.TrimPrefix(fqcn, "ansible.builtin.")
	fqcn = strings.TrimPrefix(fqcn, "ansible.legacy.")
	if i := strings.LastIndex(fqcn, "."); i >= 0 && strings.Count(fqcn, ".") >= 2 {
		return fqcn[i+1:]
	}
	return fqcn
}

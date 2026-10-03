// Package github parses a GitHub Actions workflow into a single "github"
// resource per workflow file.
//
// Like the Dockerfile parser emits one resource per Dockerfile and reads the
// sibling .dockerignore, this emits one resource per workflow and reads the
// sibling workflows (and .github/dependabot.yml) for the repository-wide
// signals under context.*.
//
// The property model (see model.go) is:
//
//	workflows[*]   this workflow: file, name, env, concurrency, permissions,
//	               triggers[*], on, jobs[*]
//	jobs[*]        id, name, runs_on, permissions, timeout_minutes,
//	               concurrency, if, needs[*], strategy, container, services,
//	               env, outputs, environment {name,url}, uses, action,
//	               is_deploy, steps[*], workflow {file,triggers,permissions}
//	steps[*]       id, name, uses, run, shell, if, env, with, with_pairs[*],
//	               continue_on_error, timeout_minutes, action, job, workflow
//	action         parsed `uses`: kind (repo|local|docker), owner, repo, path,
//	               ref, ref_is_sha
//	env_entries[*] {key, value, level, file} at workflow / job / step level
//	strings[*]     every scalar value
//	context        files[*], dependabot, and the repository-wide uses[*],
//	               runs[*] and step_names[*] gathered from every workflow
//
// environment_settings (GitHub environment protection rules) is not modelled:
// it requires GitHub API access, which the scanner does not have.
package github

import (
	"context"
	"strings"

	"github.com/nexutils/StackGuard/internal/models"
	"github.com/nexutils/StackGuard/internal/parser"
	"github.com/nexutils/StackGuard/internal/parser/yamlutil"
)

const Target = "github"

// Parser implements parser.Parser for GitHub Actions workflows.
type Parser struct{}

func New() *Parser { return &Parser{} }

func (*Parser) Name() string { return Target }

func (*Parser) CanParse(f *parser.FileInfo) bool {
	return f.IsYAML() && strings.Contains(f.SlashPath(), ".github/workflows/")
}

func (*Parser) Parse(_ context.Context, src parser.Source) ([]models.Resource, error) {
	docs, err := yamlutil.Documents(src.Content)
	if err != nil {
		return nil, err
	}
	for _, doc := range docs {
		dec := yamlutil.NewDecoder()
		v, err := dec.Decode(doc, "")
		if err != nil {
			return nil, err
		}
		if m, ok := v.(map[string]any); ok {
			return build(src, m), nil
		}
	}
	return nil, nil
}

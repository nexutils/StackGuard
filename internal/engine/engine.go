// Package engine orchestrates a scan: discover files, parse them into
// resources, evaluate rules, and assemble a report.
//
// The engine has no knowledge of the CLI, configuration files or output
// formats, so it can be embedded in other front-ends such as a language
// server that scans unsaved editor buffers via ScanSources.
package engine

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"slices"
	"sort"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/nexutils/StackGuard/internal/discovery"
	"github.com/nexutils/StackGuard/internal/models"
	"github.com/nexutils/StackGuard/internal/parser"
	"github.com/nexutils/StackGuard/internal/parser/all"
	"github.com/nexutils/StackGuard/internal/score"
)

// Options configures an Engine.
type Options struct {
	// Parsers to use; nil means every built-in parser.
	Parsers *parser.Registry
	// Targets restricts scanning to these targets; empty means all.
	Targets []string
	// DisabledRules are rule IDs to skip.
	DisabledRules []string
	// EnabledRules turns on rules that are off by default. DisabledRules
	// wins if a rule is in both.
	EnabledRules []string
	// SeverityOverrides replace the severity of rules by ID.
	SeverityOverrides map[string]models.Severity
	// Exclude holds glob patterns for discovery (see discovery.Options).
	Exclude []string
	// MaxFileSize skips larger files; zero means discovery's default.
	MaxFileSize int64
	// Jobs bounds parse concurrency; zero means GOMAXPROCS.
	Jobs int
	// Scorer computes the score; nil means score.Default().
	Scorer score.Scorer
	Logger *slog.Logger
}

// Engine evaluates a fixed set of rules. It is safe for concurrent use.
type Engine struct {
	opts     Options
	rules    []*CompiledRule
	byTarget map[string][]*CompiledRule
	parsers  *parser.Registry
	log      *slog.Logger
}

// New compiles rules, applying disabled rules, severity overrides and target
// filters from opts.
func New(rules []*models.Rule, opts Options) (*Engine, error) {
	e := &Engine{
		opts:     opts,
		byTarget: map[string][]*CompiledRule{},
		parsers:  opts.Parsers,
		log:      opts.Logger,
	}
	if e.parsers == nil {
		e.parsers = all.Registry()
	}
	if e.log == nil {
		e.log = slog.New(slog.DiscardHandler)
	}
	if e.opts.Scorer == nil {
		e.opts.Scorer = score.Default()
	}
	disabled := map[string]bool{}
	for _, id := range opts.DisabledRules {
		disabled[strings.ToUpper(id)] = true
	}
	enabled := map[string]bool{}
	for _, id := range opts.EnabledRules {
		enabled[strings.ToUpper(id)] = true
	}
	for _, r := range rules {
		if disabled[r.ID] || (r.OffByDefault && !enabled[r.ID]) || !e.targetEnabled(r.Target) {
			continue
		}
		if sev, ok := opts.SeverityOverrides[r.ID]; ok && sev != r.Severity {
			cp := *r
			cp.Severity = sev
			r = &cp
		}
		cr, err := Compile(r)
		if err != nil {
			return nil, err
		}
		e.rules = append(e.rules, cr)
		e.byTarget[r.Target] = append(e.byTarget[r.Target], cr)
	}
	sort.Slice(e.rules, func(i, j int) bool { return e.rules[i].Rule.ID < e.rules[j].Rule.ID })
	return e, nil
}

// Rules returns the compiled rules the engine will evaluate.
func (e *Engine) Rules() []*CompiledRule { return e.rules }

func (e *Engine) targetEnabled(t string) bool {
	return len(e.opts.Targets) == 0 || slices.Contains(e.opts.Targets, t)
}

// Scan discovers and scans files under the given paths.
func (e *Engine) Scan(ctx context.Context, paths []string) (*models.Report, error) {
	start := time.Now()
	files, err := discovery.Discover(ctx, paths, discovery.Options{
		Exclude:     e.opts.Exclude,
		MaxFileSize: e.opts.MaxFileSize,
		Logger:      e.log,
	})
	if err != nil {
		return nil, err
	}
	inputs := make([]input, len(files))
	for i, f := range files {
		inputs[i] = input{info: parser.NewFileInfo(f.Path), explicit: f.Explicit}
	}
	return e.run(ctx, inputs, start)
}

// ScanSources scans in-memory sources, e.g. unsaved editor buffers.
func (e *Engine) ScanSources(ctx context.Context, sources []parser.Source) (*models.Report, error) {
	start := time.Now()
	inputs := make([]input, len(sources))
	for i, s := range sources {
		inputs[i] = input{info: parser.NewFileInfoFromBytes(s.Path, s.Content), content: s.Content, explicit: true}
	}
	return e.run(ctx, inputs, start)
}

type input struct {
	info     *parser.FileInfo
	content  []byte // nil: read from disk
	explicit bool
}

type parsed struct {
	resources    []models.Resource
	suppressions suppressions
	diag         *models.Diagnostic
	ok           bool
}

func (e *Engine) run(ctx context.Context, inputs []input, start time.Time) (*models.Report, error) {
	results := make([]parsed, len(inputs))
	g, gctx := errgroup.WithContext(ctx)
	jobs := e.opts.Jobs
	if jobs <= 0 {
		jobs = runtime.GOMAXPROCS(0)
	}
	g.SetLimit(jobs)
	for i := range inputs {
		g.Go(func() error {
			if err := gctx.Err(); err != nil {
				return err
			}
			results[i] = e.parseOne(gctx, inputs[i])
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}

	rep := &models.Report{
		SchemaVersion: models.ReportSchemaVersion,
		Findings:      []models.Finding{},
		Diagnostics:   []models.Diagnostic{},
	}
	rep.Stats.FilesDiscovered = len(inputs)
	var resources []models.Resource
	supp := map[string]suppressions{}
	for _, r := range results {
		if r.diag != nil {
			rep.Diagnostics = append(rep.Diagnostics, *r.diag)
		}
		if !r.ok {
			continue
		}
		rep.Stats.FilesParsed++
		resources = append(resources, r.resources...)
		if r.suppressions != nil && len(r.resources) > 0 {
			supp[r.resources[0].File] = r.suppressions
		}
	}
	rep.Stats.Resources = len(resources)

	findings, ruleResults := e.Evaluate(resources)
	for _, f := range findings {
		if s := supp[f.File]; s != nil && s.suppressed(f.RuleID, f.Line) {
			rep.Stats.Suppressed++
			continue
		}
		rep.Findings = append(rep.Findings, f)
	}
	if rep.Stats.Suppressed > 0 {
		// Recount per-rule findings after suppression.
		counts := map[string]int{}
		for _, f := range rep.Findings {
			counts[f.RuleID]++
		}
		for i := range ruleResults {
			rr := &ruleResults[i]
			rr.Findings = counts[rr.RuleID]
			if rr.Status == models.RuleFailed && rr.Findings == 0 {
				rr.Status = models.RulePassed
			}
		}
	}
	rep.Results = ruleResults
	rep.Stats.RulesEvaluated = len(e.rules)
	rep.Score = e.opts.Scorer.Score(rep.Findings)
	rep.Stats.DurationMillis = time.Since(start).Milliseconds()
	return rep, nil
}

func (e *Engine) parseOne(ctx context.Context, in input) parsed {
	p := e.parsers.Detect(in.info)
	if p == nil {
		if in.explicit {
			e.log.Warn("no parser recognises file", "file", in.info.Path)
		}
		return parsed{}
	}
	if !e.targetEnabled(p.Name()) {
		return parsed{}
	}
	content := in.content
	if content == nil {
		var err error
		content, err = os.ReadFile(in.info.Path)
		if err != nil {
			return parsed{diag: &models.Diagnostic{File: in.info.Path, Parser: p.Name(), Message: err.Error()}}
		}
	}
	res, err := safeParse(ctx, p, parser.Source{Path: in.info.Path, Content: content})
	if err != nil {
		e.log.Debug("parse failed", "file", in.info.Path, "parser", p.Name(), "error", err)
		return parsed{diag: &models.Diagnostic{File: in.info.Path, Parser: p.Name(), Message: err.Error()}}
	}
	e.log.Debug("parsed", "file", in.info.Path, "parser", p.Name(), "resources", len(res))
	return parsed{resources: res, suppressions: parseSuppressions(content), ok: true}
}

// safeParse shields the scan from a panicking parser: one bad file must not
// abort the whole run.
func safeParse(ctx context.Context, p parser.Parser, src parser.Source) (res []models.Resource, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("parser %s panicked: %v", p.Name(), r)
		}
	}()
	return p.Parse(ctx, src)
}

// Evaluate runs every rule against the resources it applies to. Findings are
// sorted by file, line, rule and resource.
func (e *Engine) Evaluate(resources []models.Resource) ([]models.Finding, []models.RuleResult) {
	byTarget := map[string][]*models.Resource{}
	for i := range resources {
		r := &resources[i]
		byTarget[r.Target] = append(byTarget[r.Target], r)
	}

	var findings []models.Finding
	results := make([]models.RuleResult, 0, len(e.rules))
	for _, cr := range e.rules {
		rr := models.RuleResult{Rule: cr.Rule, RuleID: cr.Rule.ID, Status: models.RuleSkipped}
		for _, res := range byTarget[cr.Rule.Target] {
			if !cr.Applies(res) {
				continue
			}
			rr.Evaluated++
			if f, ok := cr.Evaluate(res); ok {
				findings = append(findings, f)
				rr.Findings++
			}
		}
		switch {
		case rr.Findings > 0:
			rr.Status = models.RuleFailed
		case rr.Evaluated > 0:
			rr.Status = models.RulePassed
		}
		results = append(results, rr)
	}
	SortFindings(findings)
	return findings, results
}

// SortFindings orders findings deterministically.
func SortFindings(fs []models.Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		if a.RuleID != b.RuleID {
			return a.RuleID < b.RuleID
		}
		return a.Resource < b.Resource
	})
}

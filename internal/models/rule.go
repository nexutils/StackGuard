package models

// Rule categories.
const (
	CategorySecurity        = "security"
	CategoryReliability     = "reliability"
	CategoryOperational     = "operational"
	CategoryMaintainability = "maintainability"
	CategoryPerformance     = "performance"
)

// Categories lists every valid rule category.
var Categories = []string{
	CategorySecurity,
	CategoryReliability,
	CategoryOperational,
	CategoryMaintainability,
	CategoryPerformance,
}

// Rule is a declarative check loaded from YAML. The Query is kept in its raw
// decoded form here and compiled by the engine, so this package stays free of
// evaluation logic.
type Rule struct {
	ID          string   `json:"id" yaml:"id"`
	Title       string   `json:"title" yaml:"title"`
	Severity    Severity `json:"severity" yaml:"severity"`
	Category    string   `json:"category" yaml:"category"`
	Target      string   `json:"target" yaml:"target"`
	Resources   []string `json:"resource,omitempty" yaml:"resource,omitempty"`
	Message     string   `json:"message" yaml:"message"`
	PassMessage string   `json:"pass_message,omitempty" yaml:"pass_message,omitempty"`
	Description string   `json:"description,omitempty" yaml:"description,omitempty"`
	Remediation string   `json:"remediation,omitempty" yaml:"remediation,omitempty"`
	References  []string `json:"references,omitempty" yaml:"references,omitempty"`
	Tags        []string `json:"tags,omitempty" yaml:"tags,omitempty"`
	Query       any      `json:"query" yaml:"query"`
	// QueryYAML is the query as written by the rule author, for display.
	QueryYAML string `json:"-" yaml:"-"`
	// When is an optional precondition with the same syntax as Query. A
	// resource for which it does not hold is not evaluated at all (it counts
	// neither as a pass nor as a failure).
	When     any    `json:"when,omitempty" yaml:"when,omitempty"`
	WhenYAML string `json:"-" yaml:"-"`
	// OffByDefault marks rules that only run when listed in enabled_rules,
	// typically because they encode organisation-specific conventions.
	OffByDefault bool `json:"off_by_default,omitempty" yaml:"-"`
	// Fix is reserved for the autofix engine and ignored for now.
	Fix any `json:"fix,omitempty" yaml:"fix,omitempty"`
	// Source records where the rule was loaded from, e.g.
	// "embedded:compose/COMP_SEC_001.yaml" or an absolute file path.
	Source string `json:"source,omitempty" yaml:"-"`
}

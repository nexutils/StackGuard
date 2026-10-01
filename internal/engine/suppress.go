package engine

import (
	"bufio"
	"bytes"
	"regexp"
	"strings"
)

// Inline suppressions: a comment containing `stackguard:ignore` silences
// findings on the same line or the line directly below it. Rule IDs can be
// listed to narrow it; without IDs every rule is silenced.
//
//	# stackguard:ignore COMP_SEC_001,COMP_REL_001 -- reviewed, see JIRA-12
//	privileged: true
var ignoreRe = regexp.MustCompile(`stackguard:ignore(?:\s+([A-Z0-9_,\s]+))?`)

// suppressions maps line numbers to suppressed rule IDs. An empty, non-nil
// set means all rules.
type suppressions map[int]map[string]bool

func parseSuppressions(content []byte) suppressions {
	if !bytes.Contains(content, []byte("stackguard:ignore")) {
		return nil
	}
	s := suppressions{}
	sc := bufio.NewScanner(bytes.NewReader(content))
	sc.Buffer(make([]byte, 0, 64*1024), 10*1024*1024)
	for line := 1; sc.Scan(); line++ {
		m := ignoreRe.FindStringSubmatch(sc.Text())
		if m == nil {
			continue
		}
		ids := map[string]bool{}
		for _, f := range strings.FieldsFunc(m[1], func(r rune) bool { return r == ',' || r == ' ' || r == '\t' }) {
			if idPattern.MatchString(f) {
				ids[f] = true
			}
		}
		s[line] = ids
	}
	return s
}

var idPattern = regexp.MustCompile(`^[A-Z][A-Z0-9]*_[A-Z]+_[0-9]+$`)

func (s suppressions) suppressed(ruleID string, line int) bool {
	for _, l := range []int{line, line - 1} {
		if ids, ok := s[l]; ok && (len(ids) == 0 || ids[ruleID]) {
			return true
		}
	}
	return false
}

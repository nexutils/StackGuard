package operators

import (
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"strings"
)

func init() {
	Register(Func{"equals", compileEquals(false)})
	Register(Func{"not_equals", compileEquals(true)})
	Register(Func{"exists", compileExists(false)})
	Register(Func{"not_exists", compileExists(true)})
	Register(Func{"contains", compileContains})
	Register(Func{"regex", compileRegex})
	Register(Func{"matches", compileRegex})
	Register(Func{"not_matches", compileNotMatches})
	Register(Func{"in", compileIn(false)})
	Register(Func{"not_in", compileIn(true)})
	Register(Func{"contains_any", compileContainsAny})
	Register(Func{"length_gte", compileLengthGte})
	Register(Func{"type", compileType})

	gt := compileCompare(func(a, b float64) bool { return a > b })
	gte := compileCompare(func(a, b float64) bool { return a >= b })
	lt := compileCompare(func(a, b float64) bool { return a < b })
	lte := compileCompare(func(a, b float64) bool { return a <= b })
	Register(Func{"greater_than", gt})
	Register(Func{"gt", gt})
	Register(Func{"gte", gte})
	Register(Func{"less_than", lt})
	Register(Func{"lt", lt})
	Register(Func{"lte", lte})
}

// compileNotMatches matches present scalars whose string form does not match
// the pattern (for a list: no element matches).
func compileNotMatches(arg any) (Matcher, error) {
	m, err := compileRegex(arg)
	if err != nil {
		return nil, err
	}
	return func(v any, present bool) bool {
		if !present || v == nil {
			return false
		}
		if _, isMap := v.(map[string]any); isMap {
			return false
		}
		return !m(v, true)
	}, nil
}

// compileIn matches values equal (or, negated, equal to none) of a list.
func compileIn(negate bool) func(any) (Matcher, error) {
	return func(arg any) (Matcher, error) {
		list, ok := arg.([]any)
		if !ok {
			return nil, fmt.Errorf("expects a list, got %T", arg)
		}
		return func(v any, present bool) bool {
			if !present {
				return false
			}
			for _, want := range list {
				if Equal(v, want) {
					return !negate
				}
			}
			return negate
		}, nil
	}
}

// compileContainsAny is contains with several candidates.
func compileContainsAny(arg any) (Matcher, error) {
	list, ok := arg.([]any)
	if !ok || len(list) == 0 {
		return nil, fmt.Errorf("expects a non-empty list, got %T", arg)
	}
	matchers := make([]Matcher, 0, len(list))
	for _, item := range list {
		m, err := compileContains(item)
		if err != nil {
			return nil, err
		}
		matchers = append(matchers, m)
	}
	return func(v any, present bool) bool {
		for _, m := range matchers {
			if m(v, present) {
				return true
			}
		}
		return false
	}, nil
}

// compileLengthGte matches lists, maps and strings with at least n elements.
func compileLengthGte(arg any) (Matcher, error) {
	n, ok := ToFloat(arg)
	if !ok {
		return nil, fmt.Errorf("expects a number, got %v", arg)
	}
	return func(v any, present bool) bool {
		if !present {
			return false
		}
		var l int
		switch t := v.(type) {
		case []any:
			l = len(t)
		case map[string]any:
			l = len(t)
		case string:
			l = len(t)
		default:
			return false
		}
		return float64(l) >= n
	}, nil
}

// compileType matches values of a given kind: map, list, string, number,
// bool or null.
func compileType(arg any) (Matcher, error) {
	want, _ := arg.(string)
	switch want {
	case "map", "list", "string", "number", "bool", "null":
	default:
		return nil, fmt.Errorf("expects one of map, list, string, number, bool, null; got %v", arg)
	}
	return func(v any, present bool) bool {
		return present && kindOf(v) == want
	}, nil
}

func kindOf(v any) string {
	switch v.(type) {
	case nil:
		return "null"
	case map[string]any:
		return "map"
	case []any:
		return "list"
	case string:
		return "string"
	case bool:
		return "bool"
	}
	if _, ok := numeric(v); ok {
		return "number"
	}
	return ""
}

// compileEquals builds equals / not_equals. Both require the value to be
// present; combine with not_exists to also match missing values.
func compileEquals(negate bool) func(any) (Matcher, error) {
	return func(arg any) (Matcher, error) {
		return func(v any, present bool) bool {
			if !present {
				return false
			}
			return Equal(v, arg) != negate
		}, nil
	}
}

func compileExists(negate bool) func(any) (Matcher, error) {
	return func(arg any) (Matcher, error) {
		want, ok := arg.(bool)
		if !ok {
			return nil, fmt.Errorf("expects true or false, got %T", arg)
		}
		if negate {
			want = !want
		}
		return func(_ any, present bool) bool { return present == want }, nil
	}
}

// compileContains matches substrings in strings, elements in lists and keys
// in maps.
func compileContains(arg any) (Matcher, error) {
	if !isScalar(arg) {
		return nil, fmt.Errorf("expects a scalar value, got %T", arg)
	}
	needle := ToString(arg)
	return func(v any, present bool) bool {
		if !present {
			return false
		}
		switch t := v.(type) {
		case string:
			return strings.Contains(t, needle)
		case []any:
			for _, e := range t {
				if Equal(e, arg) {
					return true
				}
			}
		case map[string]any:
			_, ok := t[needle]
			return ok
		}
		return false
	}, nil
}

// compileRegex matches scalars by their string form, and lists if any scalar
// element matches. Patterns use RE2 syntax.
func compileRegex(arg any) (Matcher, error) {
	s, ok := arg.(string)
	if !ok {
		return nil, fmt.Errorf("expects a string pattern, got %T", arg)
	}
	re, err := regexp.Compile(s)
	if err != nil {
		return nil, fmt.Errorf("invalid pattern: %w", err)
	}
	return func(v any, present bool) bool {
		if !present || v == nil {
			return false
		}
		if list, ok := v.([]any); ok {
			for _, e := range list {
				if isScalar(e) && e != nil && re.MatchString(ToString(e)) {
					return true
				}
			}
			return false
		}
		return isScalar(v) && re.MatchString(ToString(v))
	}, nil
}

func compileCompare(cmp func(a, b float64) bool) func(any) (Matcher, error) {
	return func(arg any) (Matcher, error) {
		want, ok := ToFloat(arg)
		if !ok {
			return nil, fmt.Errorf("expects a number, got %v", arg)
		}
		return func(v any, present bool) bool {
			if !present {
				return false
			}
			got, ok := ToFloat(v)
			return ok && cmp(got, want)
		}, nil
	}
}

// Equal compares a resolved value with a rule argument the way a rule author
// would expect: numbers compare numerically, and scalars of different types
// compare by string form, so 8080 equals "8080" and true equals "true".
func Equal(v, arg any) bool {
	if isScalar(v) && isScalar(arg) {
		if v == nil || arg == nil {
			return v == nil && arg == nil
		}
		fv, okv := numeric(v)
		fa, oka := numeric(arg)
		if okv && oka {
			return fv == fa
		}
		return ToString(v) == ToString(arg)
	}
	return reflect.DeepEqual(v, arg)
}

// ToString renders a scalar in its natural textual form.
func ToString(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case bool:
		return strconv.FormatBool(t)
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case float32:
		return strconv.FormatFloat(float64(t), 'f', -1, 32)
	default:
		return fmt.Sprint(t)
	}
}

// ToFloat converts numbers and numeric strings to float64.
func ToFloat(v any) (float64, bool) {
	if f, ok := numeric(v); ok {
		return f, true
	}
	if s, ok := v.(string); ok {
		f, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
		return f, err == nil
	}
	return 0, false
}

// numeric converts only genuine numeric types, not strings.
func numeric(v any) (float64, bool) {
	switch t := v.(type) {
	case int:
		return float64(t), true
	case int8:
		return float64(t), true
	case int16:
		return float64(t), true
	case int32:
		return float64(t), true
	case int64:
		return float64(t), true
	case uint:
		return float64(t), true
	case uint8:
		return float64(t), true
	case uint16:
		return float64(t), true
	case uint32:
		return float64(t), true
	case uint64:
		return float64(t), true
	case float32:
		return float64(t), true
	case float64:
		return t, true
	}
	return 0, false
}

func isScalar(v any) bool {
	switch v.(type) {
	case nil, string, bool, int, int8, int16, int32, int64,
		uint, uint8, uint16, uint32, uint64, float32, float64:
		return true
	}
	return false
}

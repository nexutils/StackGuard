package ansible

import (
	"bufio"
	"bytes"
	"strings"
)

// parseINI parses ansible.cfg into config.<section>.<key> values, lower-cased,
// as the rules expect (e.g. config.defaults.host_key_checking == "false").
func parseINI(content []byte) map[string]any {
	out := map[string]any{}
	section := "defaults"
	sc := bufio.NewScanner(bytes.NewReader(content))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		sec, _ := out[section].(map[string]any)
		if sec == nil {
			sec = map[string]any{}
			out[section] = sec
		}
		sec[strings.ToLower(strings.TrimSpace(k))] = strings.ToLower(strings.TrimSpace(v))
	}
	return out
}

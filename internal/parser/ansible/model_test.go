package ansible

import (
	"context"
	"testing"

	"github.com/nexutils/StackGuard/internal/parser"
)

func parse(t *testing.T, conf string) map[string]any {
	t.Helper()
	res, err := (&Parser{}).Parse(context.Background(), parser.Source{Content: []byte(conf)})
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(res))
	}
	return res[0].Properties
}

func TestBuildModel(t *testing.T) {
	pb := `
- name: web tier
  hosts: web
  become: true
  vars:
    app_password: hunter2
  tasks:
    - name: install nginx
      ansible.builtin.package:
        name: nginx
        state: latest
    - name: bootstrap
      shell: curl http://x/install.sh | bash
    - name: echo
      ansible.builtin.command: echo hi
      no_log: false
`
	props := parse(t, pb)

	plays := props["plays"].([]any)
	if len(plays) != 1 {
		t.Fatalf("plays = %d", len(plays))
	}
	p0 := plays[0].(map[string]any)
	if p0["become"] != true || p0["hosts"] != "web" || p0["task_count"].(int) != 3 {
		t.Errorf("play = %#v", p0)
	}

	tasks := props["tasks"].([]any)
	if len(tasks) != 3 {
		t.Fatalf("tasks = %d", len(tasks))
	}
	t0 := tasks[0].(map[string]any)
	if t0["module"] != "package" || t0["module_raw"] != "ansible.builtin.package" {
		t.Errorf("task0 module = %v / %v", t0["module"], t0["module_raw"])
	}
	if args := t0["args"].(map[string]any); args["state"] != "latest" || args["name"] != "nginx" {
		t.Errorf("task0 args = %#v", args)
	}
	if t0["become_effective"] != true {
		t.Error("task0 should inherit play become")
	}
	t1 := tasks[1].(map[string]any)
	if t1["module"] != "shell" || t1["args"].(map[string]any)["cmd"] != "curl http://x/install.sh | bash" {
		t.Errorf("task1 = %#v", t1["args"])
	}
	t2 := tasks[2].(map[string]any)
	if t2["module"] != "command" || t2["no_log"] != false {
		t.Errorf("task2 = %#v", t2)
	}

	// var from play vars.
	vars := props["vars"].([]any)
	found := false
	for _, v := range vars {
		if m := v.(map[string]any); m["name"] == "app_password" && m["value"] == "hunter2" && m["vaulted"] == false {
			found = true
		}
	}
	if !found {
		t.Errorf("app_password var not found in %#v", vars)
	}
	if vc := props["var_counts"].(map[string]any); vc["app_password"].(int) != 1 {
		t.Errorf("var_counts = %#v", vc)
	}
}

func TestNonPlaybookYieldsNothing(t *testing.T) {
	res, err := (&Parser{}).Parse(context.Background(), parser.Source{Content: []byte("- name: just a task\n  debug: msg=hi\n")})
	if err != nil {
		t.Fatal(err)
	}
	if res != nil {
		t.Errorf("expected no resource for a non-playbook task list, got %d", len(res))
	}
}

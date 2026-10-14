package jenkins

import (
	"context"
	"testing"

	"github.com/nexutils/StackGuard/internal/parser"
)

func parseJenkins(t *testing.T, content string) map[string]any {
	t.Helper()
	res, err := (&Parser{}).Parse(context.Background(), parser.Source{Path: "Jenkinsfile", Content: []byte(content)})
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(res))
	}
	return res[0].Properties
}

func findStep(steps []any, name string) map[string]any {
	for _, s := range steps {
		m := s.(map[string]any)
		if m["name"] == name {
			return m
		}
	}
	return nil
}

func findStage(stages []any, name string) map[string]any {
	for _, s := range stages {
		m := s.(map[string]any)
		if m["name"] == name {
			return m
		}
	}
	return nil
}

func TestDeclarativeModel(t *testing.T) {
	props := parseJenkins(t, `@Library('shared@v1.2.3') _
pipeline {
    agent { label 'linux' }
    options {
        timeout(time: 30, unit: 'MINUTES')
        buildDiscarder(logRotator(numToKeepStr: '20'))
    }
    tools {
        maven 'maven-3.9.9'
    }
    triggers {
        cron('H 2 * * *')
    }
    environment {
        REGION   = 'eu-west-1'
        API_KEY  = 'sk-live-0123456789abcdef'
        DB_TOKEN = credentials('db-token')
    }
    stages {
        stage('Build') {
            steps {
                sh 'make build'
            }
        }
        stage('Deploy Prod') {
            options {
                timeout(time: 20, unit: 'MINUTES')
            }
            input {
                message 'Deploy?'
            }
            steps {
                withCredentials([string(credentialsId: 'k', variable: 'K')]) {
                    sh "kubectl apply -f k8s/ --namespace production"
                }
            }
            post {
                success { slackSend message: 'ok' }
            }
        }
    }
    post {
        always { cleanWs() }
    }
}`)

	pipeline := props["pipeline"].(map[string]any)
	if pipeline["kind"] != "declarative" {
		t.Errorf("kind = %v", pipeline["kind"])
	}
	if pipeline["has_global_timeout"] != true {
		t.Errorf("has_global_timeout should be true")
	}
	if !contains(pipeline["options_names"].([]any), "buildDiscarder") {
		t.Errorf("options_names = %v", pipeline["options_names"])
	}
	if !contains(pipeline["post_conditions"].([]any), "always") {
		t.Errorf("post_conditions = %v", pipeline["post_conditions"])
	}
	if !contains(pipeline["triggers"].([]any), "cron") {
		t.Errorf("triggers = %v", pipeline["triggers"])
	}
	tools := pipeline["tools"].([]any)
	if len(tools) != 1 || tools[0].(map[string]any)["name"] != "maven-3.9.9" {
		t.Errorf("tools = %v", tools)
	}

	// env_entries with value_kind
	env := props["env_entries"].([]any)
	var key, tok map[string]any
	for _, e := range env {
		m := e.(map[string]any)
		switch m["key"] {
		case "API_KEY":
			key = m
		case "DB_TOKEN":
			tok = m
		}
	}
	if key == nil || key["value_kind"] != "literal" || key["value"] != "sk-live-0123456789abcdef" {
		t.Errorf("API_KEY entry = %#v", key)
	}
	if tok == nil || tok["value_kind"] != "credentials" {
		t.Errorf("DB_TOKEN entry = %#v", tok)
	}

	// libraries with version
	libs := props["libraries"].([]any)
	if len(libs) != 1 || libs[0].(map[string]any)["version"] != "v1.2.3" {
		t.Errorf("libraries = %#v", libs)
	}

	// agents: label at pipeline level
	if ag := props["agents"].([]any); len(ag) == 0 || ag[0].(map[string]any)["type"] != "label" {
		t.Errorf("agents = %#v", props["agents"])
	}

	// stages
	stages := props["stages"].([]any)
	build := findStage(stages, "Build")
	deploy := findStage(stages, "Deploy Prod")
	if build == nil || deploy == nil {
		t.Fatalf("stages = %#v", stages)
	}
	if deploy["is_deploy"] != true {
		t.Errorf("Deploy Prod is_deploy should be true")
	}
	if deploy["targets_prod"] != true {
		t.Errorf("Deploy Prod targets_prod should be true")
	}
	if deploy["has_timeout"] != true {
		t.Errorf("Deploy Prod has_timeout should be true")
	}
	if deploy["gated"] != true {
		t.Errorf("Deploy Prod gated should be true (has input)")
	}
	if deploy["environment_name"] != "prod" {
		t.Errorf("Deploy Prod environment_name = %v", deploy["environment_name"])
	}
	if !contains(deploy["post_step_names"].([]any), "slackSend") {
		t.Errorf("Deploy Prod post_step_names = %v", deploy["post_step_names"])
	}

	// steps: the kubectl sh is inside withCredentials (creds in scope) and its
	// stage has a timeout.
	steps := props["steps"].([]any)
	var kubectl map[string]any
	for _, s := range steps {
		m := s.(map[string]any)
		if m["name"] == "sh" && containsStr(m["script"], "kubectl") {
			kubectl = m
		}
	}
	if kubectl == nil {
		t.Fatalf("kubectl sh step not found in %d steps", len(steps))
	}
	if kubectl["credentials_in_scope"] != true {
		t.Errorf("kubectl step credentials_in_scope should be true")
	}
	if kubectl["quote"] != "double" {
		t.Errorf("kubectl step quote = %v (want double)", kubectl["quote"])
	}
	if kubectl["stage_has_timeout"] != true {
		t.Errorf("kubectl step stage_has_timeout should be true")
	}
	if !contains(kubectl["enclosing"].([]any), "withCredentials") {
		t.Errorf("kubectl enclosing = %v", kubectl["enclosing"])
	}

	// cleanWs is in post
	if cw := findStep(steps, "cleanWs"); cw == nil || cw["in_post"] != true {
		t.Errorf("cleanWs in_post = %#v", cw)
	}

	// strings collected the literal secret
	if !contains(props["strings"].([]any), "sk-live-0123456789abcdef") {
		t.Errorf("strings missing the literal secret")
	}
}

func TestScriptedModel(t *testing.T) {
	props := parseJenkins(t, `node('build-agent') {
    stage('Checkout') {
        git url: 'https://github.com/org/repo.git'
    }
    stage('Test') {
        sh 'make test'
    }
}`)
	pipeline := props["pipeline"].(map[string]any)
	if pipeline["kind"] != "scripted" {
		t.Errorf("kind = %v", pipeline["kind"])
	}
	if ag := props["agents"].([]any); len(ag) == 0 || ag[0].(map[string]any)["type"] != "node" {
		t.Errorf("agents = %#v", props["agents"])
	}
	stages := props["stages"].([]any)
	if findStage(stages, "Checkout") == nil || findStage(stages, "Test") == nil {
		t.Fatalf("scripted stages = %#v", stages)
	}
	if findStep(props["steps"].([]any), "sh") == nil {
		t.Errorf("scripted sh step not found")
	}
}

func TestInlineAgentAny(t *testing.T) {
	props := parseJenkins(t, `pipeline {
    agent any
    stages {
        stage('x') { steps { sh 'echo hi' } }
    }
}`)
	ag := props["agents"].([]any)
	if len(ag) == 0 || ag[0].(map[string]any)["type"] != "any" {
		t.Errorf("agents = %#v", props["agents"])
	}
}

func containsStr(v any, sub string) bool {
	s, _ := v.(string)
	return s != "" && index(s, sub) >= 0
}

func index(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

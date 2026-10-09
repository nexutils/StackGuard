package terraform

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/nexutils/StackGuard/internal/parser"
)

// writeModule lays out a module in a temp dir and returns the first .tf path.
func writeModule(t *testing.T, files map[string]string) (string, string) {
	t.Helper()
	dir := t.TempDir()
	first := ""
	for name, body := range files {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		if first == "" || name < first {
			first = name
		}
	}
	return dir, filepath.Join(dir, first)
}

func parseModule(t *testing.T, anchor string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(anchor)
	if err != nil {
		t.Fatal(err)
	}
	res, err := (&Parser{}).Parse(context.Background(), parser.Source{Path: anchor, Content: data})
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1 module resource, got %d", len(res))
	}
	return res[0].Properties
}

func TestBuildModule(t *testing.T) {
	_, anchor := writeModule(t, map[string]string{
		"providers.tf": `provider "aws" {
  region = var.region
  default_tags {
    tags = {
      Team = "platform"
      Env  = "prod"
    }
  }
}
`,
		"main.tf": `terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
  backend "s3" {
    bucket = "tfstate"
    key    = "app/terraform.tfstate"
  }
}

variable "region" {
  type    = string
  default = "eu-west-1"
}

variable "db_password" {
  type      = string
  sensitive = true
  validation {
    condition     = length(var.db_password) > 8
    error_message = "too short"
  }
}

locals {
  name = "app-${var.region}"
}

resource "aws_db_instance" "main" {
  identifier          = "app"
  password            = "hunter2hardcoded"
  publicly_accessible = true
  tags = {
    Env = "override"
  }
}

resource "aws_security_group" "web" {
  name = local.name
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_iam_role_policy" "inline" {
  name   = "inline"
  role   = aws_security_group.web.id
  policy = <<EOT
{
  "Version": "2012-10-17",
  "Statement": [
    { "Effect": "Allow", "Action": "*", "Resource": "*" }
  ]
}
EOT
}

data "aws_ami" "ubuntu" {
  most_recent = true
}

output "sg_id" {
  value     = aws_security_group.web.id
  sensitive = false
}

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "5.0.0"
}
`,
	})
	props := parseModule(t, anchor)

	resources := props["resources"].([]any)
	if len(resources) != 3 {
		t.Fatalf("resources = %d, want 3", len(resources))
	}

	byAddr := map[string]map[string]any{}
	for _, r := range resources {
		m := r.(map[string]any)
		byAddr[m["address"].(string)] = m
	}

	// provider derived, stateful + taggable flags, default_tags merge (resource wins)
	db := byAddr["aws_db_instance.main"]
	if db["provider"] != "aws" {
		t.Errorf("provider = %v", db["provider"])
	}
	if db["stateful"] != true {
		t.Errorf("aws_db_instance should be stateful")
	}
	if db["taggable"] != true {
		t.Errorf("aws_db_instance should be taggable")
	}
	tags := db["tags"].(map[string]any)
	if tags["Team"] != "platform" || tags["Env"] != "override" {
		t.Errorf("tags merge = %#v (want Team=platform, Env=override)", tags)
	}

	// attr_pairs expose the hardcoded password literal (not a ${...} reference)
	var foundPw bool
	for _, p := range db["attr_pairs"].([]any) {
		m := p.(map[string]any)
		if m["key"] == "password" {
			foundPw = true
			if m["value"] != "hunter2hardcoded" {
				t.Errorf("password attr_pair value = %v", m["value"])
			}
		}
	}
	if !foundPw {
		t.Error("attr_pairs missing password")
	}

	// nested ingress block reachable, descends list without [*] via the engine;
	// here just confirm the parser kept it as a list of maps.
	sg := byAddr["aws_security_group.web"]
	ingress := sg["attrs"].(map[string]any)["ingress"].([]any)
	if len(ingress) != 1 {
		t.Fatalf("ingress = %#v", sg["attrs"])
	}
	if ing := ingress[0].(map[string]any); ing["from_port"] != 22 {
		t.Errorf("ingress.from_port = %v", ing["from_port"])
	}

	// references + referenced_by graph: the inline policy role points at the SG.
	if rb := sg["referenced_by"].([]any); len(rb) == 0 {
		t.Error("aws_security_group.web should be referenced_by the policy/output")
	}

	// policy_statements parsed from the heredoc JSON policy
	pol := byAddr["aws_iam_role_policy.inline"]
	stmts := pol["policy_statements"].([]any)
	if len(stmts) != 1 {
		t.Fatalf("policy_statements = %#v", stmts)
	}
	st := stmts[0].(map[string]any)
	if st["effect"] != "Allow" || len(st["actions"].([]any)) != 1 {
		t.Errorf("policy statement = %#v", st)
	}

	// data source classified separately, not stateful/taggable
	data := props["data_sources"].([]any)
	if len(data) != 1 {
		t.Fatalf("data_sources = %d", len(data))
	}

	// variables: sensitive flag + validation detection
	var sawDBVar bool
	for _, v := range props["variables"].([]any) {
		m := v.(map[string]any)
		if m["name"] == "db_password" {
			sawDBVar = true
			if m["sensitive"] != true || m["has_validation"] != true {
				t.Errorf("db_password var = %#v", m)
			}
		}
	}
	if !sawDBVar {
		t.Error("variables missing db_password")
	}

	// providers: default_tags captured
	provs := props["providers"].([]any)
	if len(provs) != 1 {
		t.Fatalf("providers = %d", len(provs))
	}
	if dt := provs[0].(map[string]any)["default_tags"].(map[string]any); dt["Team"] != "platform" {
		t.Errorf("provider default_tags = %#v", dt)
	}

	// terraform block: required_version, required_providers, backend
	tf := props["terraform"].(map[string]any)
	if tf["required_version"] != ">= 1.6" {
		t.Errorf("required_version = %v", tf["required_version"])
	}
	if be := tf["backend"].(map[string]any); be["type"] != "s3" {
		t.Errorf("backend = %#v", be)
	}

	// summary
	sum := props["summary"].(map[string]any)
	if sum["resource_count"] != 3 || sum["has_backend"] != true {
		t.Errorf("summary = %#v", sum)
	}
	if types := sum["types"].(map[string]any); types["aws_db_instance"] != 1 {
		t.Errorf("summary.types = %#v", types)
	}

	// module call
	if mods := props["module_calls"].([]any); len(mods) != 1 || mods[0].(map[string]any)["version"] != "5.0.0" {
		t.Errorf("module_calls = %#v", props["module_calls"])
	}

	// strings collected the literals, skipped references
	if len(props["strings"].([]any)) == 0 {
		t.Error("strings empty")
	}
}

func TestAnchorDedup(t *testing.T) {
	dir, _ := writeModule(t, map[string]string{
		"a.tf": `resource "aws_s3_bucket" "one" {}`,
		"b.tf": `resource "aws_s3_bucket" "two" {}`,
	})
	// Parsing the non-anchor file yields nothing; the module emits once, via a.tf.
	bPath := filepath.Join(dir, "b.tf")
	data, _ := os.ReadFile(bPath)
	res, err := (&Parser{}).Parse(context.Background(), parser.Source{Path: bPath, Content: data})
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 0 {
		t.Fatalf("non-anchor file produced %d resources, want 0", len(res))
	}

	aPath := filepath.Join(dir, "a.tf")
	adata, _ := os.ReadFile(aPath)
	res, err = (&Parser{}).Parse(context.Background(), parser.Source{Path: aPath, Content: adata})
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 1 {
		t.Fatalf("anchor produced %d resources, want 1", len(res))
	}
	if n := len(res[0].Properties["resources"].([]any)); n != 2 {
		t.Errorf("module should aggregate both files: resources = %d, want 2", n)
	}
}

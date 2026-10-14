# Writing rules

A rule is a YAML file. It says which resources it applies to, and describes
the **bad** condition as a query. When the query matches a resource, that
resource gets a finding.

```yaml
id: COMP_OPS_001                   # TARGET_CATEGORY_NNN
title: Missing memory limit        # short, neutral name
severity: WARNING                  # ERROR | WARNING | INFO
category: operational              # security | reliability | operational | maintainability | performance
target: compose                    # which parser's resources to check
resource: service                  # optional glob, or list of globs, on Resource.Type
message: "Service '{{ .Resource.Name }}' has no memory limit"
pass_message: All services have a memory limit   # shown under "Passed"
description: |
  Why this matters.
remediation: |
  How to fix it.
references:
  - https://docs.docker.com/reference/compose-file/deploy/#resources
tags: [cis-docker-5.10]
query:
  all:
    - path: deploy.resources.limits.memory
      not_exists: true
    - path: mem_limit
      not_exists: true
```

Unknown keys are rejected, so a typo like `sevrity:` fails loudly instead of
being silently ignored. Check your rules with:

```bash
stackguard rules --validate --rules-dir ./my-rules
stackguard explain ACME_SEC_001 --rules-dir ./my-rules
```

## Paths

Paths are evaluated against `Resource.Properties`, not against the whole
file.

| Syntax | Meaning |
|---|---|
| `a.b.c` | nested keys |
| `ports.0.target` or `ports[0].target` | list index |
| `ports.*.target` or `ports[*].target` | every element of a list, or every value of a map |
| `labels."com.example.team"` or `labels["com.example.team"]` | a key that contains dots or slashes |
| `services.*.**` | every scalar anywhere below the node (keys beginning with `_` are skipped) |
| `depends_on.{dep}` | capture a map **key** into the variable `dep` |
| `depends_on[{dep}]` | capture a list **item** into `dep` |
| `@` | the current value (useful inside `where`) |

Captures let one condition constrain another. A `{name}` first binds to each key
or item it visits; reusing `{name}` elsewhere in the same rule substitutes the
bound value, and the engine backtracks over bindings until the whole rule holds:

```yaml
# A dependency declared with condition: service_healthy whose target has no healthcheck.
query:
  all:
    - path: "depends_on.{dep}.condition"
      equals: service_healthy
    - path: "_services.{dep}.healthcheck.test"
      not_exists: true
message: "'{{ .Resource.Name }}' waits on '{{ .Captures.dep }}', which has no healthcheck"
```

A path with wildcards can resolve to several values. A leaf condition matches
if **any** of the values matches.

## Operators

| Operator | Matches when |
|---|---|
| `equals: v` | the value equals `v`. Numbers compare numerically, and `8080` equals `"8080"`. |
| `not_equals: v` | the value exists and differs from `v` |
| `exists: true` | the path resolves to at least one value (`false` inverts this) |
| `not_exists: true` | the path resolves to nothing |
| `contains: v` | a substring of a string, an element of a list, or a key of a map |
| `contains_any: [a, b]` | `contains` for any of the listed values |
| `in: [a, b]` / `not_in: [a, b]` | the value is (not) one of the listed values |
| `matches: 'p'` / `regex: 'p'` | the value's string form matches the RE2 pattern (for a list: any element) |
| `not_matches: 'p'` | the value is present and does **not** match the pattern |
| `greater_than` / `gt` / `gte`, `less_than` / `lt` / `lte` | numeric comparison against a literal |
| `gt_ref: <path>` / `lt_ref: <path>` | numeric value compared with the number at another path |
| `length_gte: n` | a list, map or string has at least `n` elements |
| `type: <kind>` | value is a `map`, `list`, `string`, `number`, `bool` or `null` |

Value operators (everything except `exists` / `not_exists`) never match a
missing value. Combine them with `not_exists` in an `any` when a missing value
should also count as bad.

**Regex is RE2** (Go's engine): fast and linear-time, but no look-around
(`(?=...)`, `(?!...)`). Express "matches A but not B" as `matches` and
`not_matches` inside an `all`.

## Combinators

```yaml
all:  [<condition>, ...]      # every condition matches
any:  [<condition>, ...]      # at least one matches
not:  <condition>             # the condition does not match
```

### `where`: conditions on the same element

`all` over wildcard paths checks each path independently. To require that one
list element satisfies several conditions at once, use `where`:

```yaml
# Some port targets 5432 AND is bound to all interfaces.
query:
  path: ports.*
  where:
    all:
      - path: target
        equals: 5432
      - path: host_ip
        not_exists: true
```

Inside `where`, paths are relative to the element. Use `@` for the element
itself when it is a scalar:

```yaml
query:
  path: run.*
  where:
    all:
      - path: "@"
        regex: 'apt-get\s+install'
      - not:
          path: "@"
          regex: '--no-install-recommends'
```

## Preconditions and off-by-default rules

`when` is an optional condition, in the same language as `query`. A resource for
which it does not hold is skipped entirely (it counts as neither a pass nor a
failure). Use it to scope a rule, for example to database images:

```yaml
when:
  path: image
  regex: '(^|/)(postgres|mysql|redis)(:|@|$)'
query:
  path: shm_size
  not_exists: true
```

`enabled: false` ships a rule turned off. It only runs when its ID is listed in
`enabled_rules` (config) or `--enable` (flag). Use it for organisation-specific
conventions, such as required labels or a trusted-registry allowlist, that would
be false positives for everyone else.

## Messages

`message` and `pass_message` are Go templates with these fields:

| Field | Value |
|---|---|
| `.Resource.Name`, `.Resource.Type`, `.Resource.File` | the resource |
| `.Resource.Properties.<key>` | any property |
| `.Value` | the value that made the query match (when there is one) |
| `.Path` | the property path of that value |
| `.Rule.ID`, `.Rule.Title` | the rule |

## Properties by target

Properties mirror the source file. Keys starting with `_` are derived by
StackGuard to make rules simpler.

### compose (`service`, `network`, `volume`, `project`)

Short and long syntax are normalised so a rule sees one shape. Variable
interpolation is **not** resolved (`${VAR:-x}` stays literal, so secret rules
can see hardcoded defaults).

- `environment`, `build.args`, `sysctls`: lists of `"KEY=VALUE"` strings.
- `labels`: a mapping.
- `ports`: list of `"HOST_IP:PUBLISHED:TARGET/PROTO"` (empty host/published
  when unset), e.g. `"5432:5432"` -> `":5432:5432/tcp"`.
- `volumes`: list of `"TYPE:SOURCE:TARGET:OPTIONS"`, e.g.
  `"./src:/app"` -> `"bind:./src:/app:rw"`; `tmpfs`: list of `"TARGET:OPTIONS"`.
- `cap_add` / `cap_drop`: upper case, without the `CAP_` prefix.
- `command`, `entrypoint`, `healthcheck.test`: single space-joined strings.
- memory sizes are bytes; `cpus` is a float.
- `_image`: `{name, tag, digest}`. `_services`: every service in the file by
  name, for cross-service rules (`_services.{dep}.healthcheck`).
- The `project` resource is the whole file, plus `_index.volume_mounts.<vol>`
  and `_index.volume_writers.<vol>` (services mounting each named volume). Use
  `resource: project` for file-wide rules.

### dockerfile (`stage`)

- `image`, `tag`, `digest`, `platform`, `alias`, `from_stage` (when `FROM`
  names an earlier stage), `index`, `is_final`.
- `user`, `healthcheck`, `workdir`, `entrypoint`, `cmd`: from the last
  occurrence in the stage.
- `run`, `add`, `copy`, `expose`: lists. `env`, `args`: mappings.
- `instructions`: `[{cmd, args, line}]`.

### kubernetes (Type = `kind`)

- The full object.
- `_podSpec`: the pod spec for Pod, Deployment, StatefulSet, DaemonSet,
  ReplicaSet, ReplicationController, Job and CronJob.
- `_namespace`: the object's namespace.

### helm (`chart`, `values`)

- `chart`: the contents of Chart.yaml. `values`: the contents of values.yaml.

### terraform (`resource.<type>`, `data.<type>`, `module`, `variable`, `output`, `provider.<name>`, `terraform`, `locals`)

- Attributes: literal values are evaluated. Anything that needs context
  (`var.x`, references, function calls) is kept as source text.
- Nested blocks are **always lists**: use `ingress.*.from_port`.
- `_block`, `_labels`.

### github (`workflow`, `job`, `step`)

- `workflow`: the whole file. `job`: the job plus `_workflow`.
- `step`: the step plus `_job`, `_action`, `_ref`, `_local`, `_docker`.

### jenkins (`pipeline`, `stage`)

- `pipeline`: `declarative`, `agent`, `options` (a list of names), `stages`,
  `sh` (a list of scripts), `credentials`, `post`.
- `stage`: `sh`, `when`.

### ansible (`play`, `task`)

- `play`: the play. `task`: the task plus `_module` (without the
  `ansible.builtin.` prefix), `_module_fqcn` and `_play`.

### nginx (`http`, `server`, `location`)

- Each directive is a **list of occurrences**: `server_tokens: ["off"]`,
  `add_header: ["X-A 1", "X-B 2"]`. Use `server_tokens.*`.
- `_args` (block arguments, e.g. the location path), `_parent`.

Run `go test ./internal/parser/all -run TestParsersGolden -v` and look at the
`*.golden.json` files under `testdata/parsers/` to see real examples.

## Contributing a built-in rule

1. Add `rules/<target>/<ID>.yaml`. The ID prefix must match the target
   (`COMP`, `DOCK`, `K8S`, `HELM`, `TF`, `GHA`, `JENK`, `ANS`, `NGX`), and the
   middle segment must match the category (`SEC`, `REL`, `OPS`, `MNT`, `PRF`).
2. Add `testdata/rules/<ID>/fail/…` with a file that must trigger the rule.
3. Optionally add `testdata/rules/<ID>/pass/…` with near-misses that must
   **not** trigger it.
4. Make sure `testdata/rules/_clean/<target>/` still produces no findings.
5. Run `make test docs`.

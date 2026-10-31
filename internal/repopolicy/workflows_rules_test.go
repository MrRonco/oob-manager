package repopolicy

import (
	"fmt"
	"maps"
	"slices"
	"strings"
)

// forbiddenTriggers run with a write token or secrets in the context of untrusted code.
var forbiddenTriggers = []string{"pull_request_target", "workflow_run"}

// triggers returns the event names of a workflow's "on" value (string, list or map).
func triggers(on any) []string {
	switch v := on.(type) {
	case string:
		return []string{v}
	case []any:
		var out []string
		for _, e := range v {
			out = append(out, fmt.Sprint(e))
		}
		return out
	case map[string]any:
		return slices.Sorted(maps.Keys(v))
	}
	return nil
}

// permissionProblems: a top-level permissions block must exist, be read-only (no
// write-all, no scope set to write), and no job may ask for write-all.
func permissionProblems(doc map[string]any) []string {
	var problems []string
	switch p := doc["permissions"].(type) {
	case nil:
		problems = append(problems, "no top-level permissions block")
	case string:
		if p != "read-all" {
			problems = append(problems, "top-level permissions: "+p)
		}
	case map[string]any:
		for _, scope := range slices.Sorted(maps.Keys(p)) {
			if p[scope] == "write" {
				problems = append(problems, "top-level permissions: "+scope+": write (grant writes per job)")
			}
		}
	}
	jobs, _ := doc["jobs"].(map[string]any)
	for _, name := range slices.Sorted(maps.Keys(jobs)) {
		if job, ok := jobs[name].(map[string]any); ok && job["permissions"] == "write-all" {
			problems = append(problems, "job "+name+": permissions: write-all")
		}
	}
	return problems
}

// checkoutProblems: no actions/checkout may leave the token in .git/config.
func checkoutProblems(docs []any) []string {
	var problems []string
	for _, d := range docs {
		usesMaps(d, func(m map[string]any) {
			ref, _ := m["uses"].(string)
			with, _ := m["with"].(map[string]any)
			if strings.HasPrefix(ref, "actions/checkout@") && with["persist-credentials"] != false {
				problems = append(problems, "actions/checkout without persist-credentials: false")
			}
		})
	}
	return problems
}

// fileProblems lists every hardening rule a workflow (isWorkflow) or composite action
// file breaks (security.md §6). checked reports whether a repository path is itself
// checked, for local "./" references.
func fileProblems(text string, isWorkflow bool, checked func(string) bool) []string {
	docs, err := yamlDocs(text)
	if err != nil {
		return []string{"not valid YAML: " + err.Error()}
	}
	if len(docs) == 0 {
		return []string{"empty file"}
	}
	problems := usesProblems(text, docs, checked)
	problems = append(problems, checkoutProblems(docs)...)
	for _, t := range forbiddenTriggers {
		if strings.Contains(text, t) {
			problems = append(problems, "mentions the "+t+" trigger")
		}
	}
	if !isWorkflow {
		return problems
	}
	for i, d := range docs {
		doc, ok := d.(map[string]any)
		if !ok {
			problems = append(problems, fmt.Sprintf("document %d is not a mapping", i+1))
			continue
		}
		for _, t := range triggers(doc["on"]) {
			if slices.Contains(forbiddenTriggers, t) {
				problems = append(problems, "trigger "+t+" (runs with a write token on untrusted input)")
			}
		}
		problems = append(problems, permissionProblems(doc)...)
	}
	return problems
}

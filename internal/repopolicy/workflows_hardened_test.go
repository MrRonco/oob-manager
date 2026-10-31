package repopolicy

import (
	"slices"
	"strings"
	"testing"
)

// TestWorkflowsHardened applies fileProblems to every workflow and composite action.
func TestWorkflowsHardened(t *testing.T) {
	workflows, actions := workflowPaths(t), actionPaths(t)
	all := append(slices.Clone(workflows), actions...)
	checked := func(p string) bool { return slices.Contains(all, p) }
	for _, p := range all {
		for _, problem := range fileProblems(readRepoFile(t, p), slices.Contains(workflows, p), checked) {
			t.Errorf("%s: %s", p, problem)
		}
	}
}

const sha = "3d3c42e5aac5ba805825da76410c181273ba90b1"

var checkedForTest = func(p string) bool {
	return p == ".github/actions/setup/action.yml" || p == ".github/workflows/reusable.yml"
}

const hardenedHead = "on: [push]\npermissions:\n  contents: read\njobs:\n  a:\n    steps:\n"

func TestFileProblemsAcceptsHardenedFiles(t *testing.T) {
	workflow := hardenedHead +
		"      - uses: actions/checkout@" + sha + " # v7.0.1\n        with: { persist-credentials: false }\n" +
		"      - uses: ./.github/actions/setup\n      - uses: owner/repo/sub@" + sha + "   # v1\n" +
		"  b:\n    permissions:\n      contents: write\n    uses: ./.github/workflows/reusable.yml\n" +
		"---\non: { push: {} }\npermissions: read-all\njobs: {}\n"
	if p := fileProblems(workflow, true, checkedForTest); len(p) != 0 {
		t.Errorf("problems in a hardened workflow: %v", p)
	}
	action := "name: setup\nruns:\n  using: composite\n  steps:\n    - uses: actions/setup-go@" + sha + " # v7.0.0\n"
	if p := fileProblems(action, false, checkedForTest); len(p) != 0 {
		t.Errorf("problems in a hardened composite action: %v", p)
	}
}

func TestFileProblemsFindsEachWorkflowViolation(t *testing.T) {
	h, checkout := hardenedHead, "      - uses: actions/checkout@"+sha+" # v7.0.1\n"
	pinned := "actions/setup-go@" + sha
	cases := map[string]struct{ text, want string }{
		"tag ref":          {h + "      - uses: actions/setup-go@v7\n", "not pinned to a full commit SHA"},
		"short sha":        {h + "      - uses: actions/setup-go@3d3c42e # v7\n", "not pinned to a full commit SHA"},
		"docker ref":       {h + "      - uses: docker://alpine:3\n", "not pinned to a full commit SHA"},
		"no comment":       {h + "      - uses: " + pinned + "\n", "no \"# v…\" tag comment"},
		"other comment":    {h + "      - uses: " + pinned + " # main\n", "no \"# v…\" tag comment"},
		"flow step":        {h + "      - { uses: actions/setup-go@v7 }\n", "not pinned to a full commit SHA"},
		"flow step pinned": {h + "      - { uses: " + pinned + " }\n", "1 uses in the YAML but 0 block-style"},
		"flow steps list":  {"on: [push]\npermissions: {}\njobs:\n  a:\n    steps: [{uses: " + pinned + "}]\n", "block-style"},
		"quoted key":       {h + "      - \"uses\": actions/setup-go@v7\n", "not pinned to a full commit SHA"},
		"reusable job":     {"on: [push]\npermissions: {}\njobs:\n  a:\n    uses: o/r/.github/workflows/w.yml@main\n", "not pinned"},
		"unchecked local":  {h + "      - uses: ./.github/actions/nope\n", "local reference to a file that is not checked"},
		"second doc uses":  {h + checkout + "        with: { persist-credentials: false }\n---\n" + h + "      - uses: a/b@v1\n", "uses a/b@v1: not pinned"},
		"second doc perms": {h + "      - run: true\n---\non: [push]\njobs: {}\n", "no top-level permissions block"},
		"no perms":         {"on: [push]\njobs:\n  a:\n    steps: []\n", "no top-level permissions block"},
		"write-all":        {"on: [push]\npermissions: write-all\njobs: {}\n", "top-level permissions: write-all"},
		"write scope":      {"on: [push]\npermissions:\n  contents: read\n  packages: write\njobs: {}\n", "packages: write"},
		"job write-all":    {"on: [push]\npermissions: {}\njobs:\n  a:\n    permissions: write-all\n    steps: []\n", "job a: permissions: write-all"},
		"prt":              {"on: [pull_request_target]\npermissions: {}\njobs: {}\n", "trigger pull_request_target"},
		"workflow_run":     {"on:\n  workflow_run:\n    workflows: [ci]\npermissions: {}\njobs: {}\n", "trigger workflow_run"},
		"workflow_run str": {"on: workflow_run\npermissions: {}\njobs: {}\n", "trigger workflow_run"},
		"creds kept":       {h + checkout, "without persist-credentials: false"},
		"creds true":       {h + checkout + "        with: { persist-credentials: true }\n", "without persist-credentials: false"},
		"creds string":     {h + checkout + "        with: { persist-credentials: \"false\" }\n", "without persist-credentials: false"},
		"bad yaml":         {"on: [push\n", "not valid YAML"},
		"empty":            {"", "empty file"},
		"not a mapping":    {"- a\n", "not a mapping"},
	}
	for name, c := range cases {
		got := strings.Join(fileProblems(c.text, true, checkedForTest), "\n")
		if !strings.Contains(got, c.want) {
			t.Errorf("%s: problems %q, want one containing %q", name, got, c.want)
		}
	}
}

func TestFileProblemsFindsCompositeActionViolations(t *testing.T) {
	head := "name: x\nruns:\n  using: composite\n  steps:\n"
	cases := map[string]struct{ text, want string }{
		"tag ref":    {head + "    - uses: actions/setup-go@v7\n", "not pinned"},
		"flow":       {head + "    - {uses: actions/setup-go@" + sha + "}\n", "block-style"},
		"checkout":   {head + "    - uses: actions/checkout@" + sha + " # v7.0.1\n", "persist-credentials"},
		"second doc": {head + "    - run: true\n---\n" + head + "    - uses: x/y@main\n", "uses x/y@main: not pinned"},
	}
	for name, c := range cases {
		got := strings.Join(fileProblems(c.text, false, checkedForTest), "\n")
		if !strings.Contains(got, c.want) {
			t.Errorf("%s: problems %q, want one containing %q", name, got, c.want)
		}
	}
	// Composite actions have no permissions block of their own; none is required.
	if p := fileProblems(head+"    - run: true\n", false, checkedForTest); len(p) != 0 {
		t.Errorf("a composite action was asked for permissions: %v", p)
	}
}

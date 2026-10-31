package repopolicy

import (
	"regexp"
	"slices"
	"strings"
	"testing"
)

var bashBlock = regexp.MustCompile("(?s)```bash\n(.*?)```")

// docCommands returns the commands of the markdown's bash blocks whose first word is in
// firstWords: continuation lines (a trailing "\") joined, comments dropped, whitespace
// collapsed.
func docCommands(md string, firstWords []string) []string {
	var out []string
	for _, m := range bashBlock.FindAllStringSubmatch(md, -1) {
		for _, cmd := range joinedLines(m[1]) {
			if f := strings.Fields(cmd); len(f) > 0 && slices.Contains(firstWords, f[0]) {
				out = append(out, cmd)
			}
		}
	}
	return out
}

// joinedLines joins "\"-continued lines and normalises each command's whitespace.
func joinedLines(script string) []string {
	var out []string
	cur := ""
	for _, line := range strings.Split(script, "\n") {
		if i := strings.Index(line, "  # "); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		cont := strings.HasSuffix(line, "\\")
		cur += " " + strings.TrimSuffix(line, "\\")
		if !cont {
			if c := strings.Join(strings.Fields(cur), " "); c != "" && !strings.HasPrefix(c, "#") {
				out = append(out, c)
			}
			cur = ""
		}
	}
	return out
}

// TestVerifyDocMatchesReleaseWorkflow: the release workflow's verify job runs every
// check docs/verify.md gives users, as written, so a release proves the documented steps
// work (a wrong flag in the docs fails the release instead of a user).
func TestVerifyDocMatchesReleaseWorkflow(t *testing.T) {
	wf := readRepoFile(t, ".github/workflows/release.yml")
	i := strings.Index(wf, "\n  verify:\n")
	if i < 0 {
		t.Fatal("release.yml has no verify job")
	}
	job := " " + strings.Join(joinedLines(wf[i:]), " ") + " "
	cmds := docCommands(readRepoFile(t, "docs/verify.md"),
		[]string{"cosign", "gh", "sha256sum", "docker"})
	if len(cmds) < 6 {
		t.Fatalf("found %d commands in docs/verify.md; the parser is broken", len(cmds))
	}
	for _, c := range cmds {
		if !strings.Contains(job, " "+c) && !strings.Contains(job, "$("+c+")") {
			t.Errorf("docs/verify.md tells users to run\n\t%s\nbut release.yml's verify job does not run it as written", c)
		}
	}
}

func TestDocCommandsParser(t *testing.T) {
	md := "text\n```bash\ncosign verify \"$REF\" \\\n  --flag x   # note\ngh a b  # comment\n# only a comment\nother cmd\n" +
		"for f in *; do\n  gh c \"$f\"\ndone\n```\n```yaml\ncosign no\n```\n"
	got := docCommands(md, []string{"cosign", "gh"})
	want := []string{`cosign verify "$REF" --flag x`, "gh a b", `gh c "$f"`}
	if !slices.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

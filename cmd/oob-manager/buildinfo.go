package main

import (
	"context"
	"runtime"
	"runtime/debug"

	"oob-manager/internal/web/ui"
)

// commitLen shortens vcs.revision for display.
const commitLen = 12

// uiBuild describes this binary for the About page and the footer.
func uiBuild(schema func(ctx context.Context) (int, error)) ui.Build {
	b := ui.Build{Version: version, RepoURL: repoURL, GoVersion: runtime.Version(), SchemaVersion: schema}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return b
	}
	for _, s := range info.Settings {
		if s.Key == "vcs.revision" {
			b.Commit = s.Value[:min(len(s.Value), commitLen)]
		}
	}
	for _, m := range info.Deps {
		v := m.Version
		if m.Replace != nil {
			v = m.Replace.Version + " (replaced)"
		}
		b.Modules = append(b.Modules, ui.Module{Path: m.Path, Version: v})
	}
	return b
}

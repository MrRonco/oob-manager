// Command themegen writes internal/web/ui/static/themes.css: the six palettes' OKLCH
// primitives, generated from a few inputs per palette and contrast-fitted (redesign
// slice B, docs/tech_doc.md §40). A maintainer tool: run it after changing an input,
//
//	go run ./tools/themegen -o internal/web/ui/static/themes.css
//
// and commit both; TestThemesCSSIsGenerated keeps the two in step.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
)

func main() {
	out := flag.String("o", "", "output file (default: standard output)")
	flag.Parse()
	if err := write(*out, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "themegen:", err)
		os.Exit(1)
	}
}

// write renders the palettes into path, or into w when path is empty.
func write(path string, w io.Writer) error {
	css, err := render()
	if err != nil {
		return err
	}
	if path == "" {
		_, err := io.WriteString(w, css)
		return err
	}
	return os.WriteFile(path, []byte(css), 0o644) //nolint:gosec // a stylesheet in the repository
}

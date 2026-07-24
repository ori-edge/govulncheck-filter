// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Radiant

package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/mod/modfile"
)

const (
	levelError   = "error"
	levelWarning = "warning"
)

// annotation is one GitHub Actions workflow-command line to emit.
type annotation struct {
	level   string // levelError or levelWarning
	id      string
	module  string
	message string
}

// annotations flattens the report into GitHub Actions annotations: failures
// become errors, warnings become warnings. Acknowledged (OK) findings produce
// none.
func (r report) annotations() []annotation {
	var out []annotation

	addViolations := func(level string, vs []violation) {
		for _, v := range vs {
			out = append(out, annotation{level: level, id: v.id, module: v.module, message: v.detail})
		}
	}

	addViolations(levelError, r.tooFarFuture)
	addViolations(levelError, r.expired)
	addViolations(levelError, r.missingReview)

	for _, f := range r.unlisted {
		out = append(out, annotation{
			level: levelError, id: f.id, module: f.module,
			message: "called vulnerability is not in the allowlist",
		})
	}

	addViolations(levelWarning, r.stale)

	for _, f := range r.warnUnfixable {
		out = append(out, annotation{
			level: levelWarning, id: f.id, module: f.module,
			message: "called but no fix available yet",
		})
	}

	return out
}

// writeAnnotations emits GitHub Actions workflow commands for each annotation,
// anchored to the require line of the offending module in go.mod. displayPath
// is the go.mod path as GitHub should see it (workspace-relative).
func writeAnnotations(w io.Writer, goModPath, displayPath string, anns []annotation) error {
	lines, err := moduleLines(goModPath)
	if err != nil {
		return err
	}

	for _, a := range anns {
		line := lines[a.module]
		if line == 0 {
			line = 1 // fall back to the top of the file
		}

		fmt.Fprintf(w, "::%s file=%s,line=%d,title=%s::%s\n",
			a.level, displayPath, line, a.id,
			escapeAnnotation(a.id+" ("+a.module+"): "+a.message))
	}

	return nil
}

// moduleLines maps each module path declared in go.mod to the 1-based line of
// its directive (require entries and the module directive itself).
func moduleLines(goModPath string) (map[string]int, error) {
	data, err := os.ReadFile(goModPath)
	if err != nil {
		return nil, err
	}

	mf, err := modfile.Parse(goModPath, data, nil)
	if err != nil {
		return nil, fmt.Errorf("parsing %s: %w", goModPath, err)
	}

	lines := map[string]int{}
	if mf.Module != nil && mf.Module.Syntax != nil {
		lines[mf.Module.Mod.Path] = mf.Module.Syntax.Start.Line
	}

	for _, r := range mf.Require {
		if r.Syntax != nil {
			lines[r.Mod.Path] = r.Syntax.Start.Line
		}
	}

	return lines, nil
}

// escapeAnnotation encodes the characters GitHub reserves in the message of a
// workflow command.
func escapeAnnotation(s string) string {
	r := strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A")
	return r.Replace(s)
}

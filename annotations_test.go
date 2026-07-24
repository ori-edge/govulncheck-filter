// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Radiant

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReportAnnotations(t *testing.T) {
	r := report{
		unlisted:      []finding{{id: "GO-1", module: "m1"}},
		warnUnfixable: []finding{{id: "GO-2", module: "m2"}},
		expired:       []violation{{id: "GO-3", module: "m3", detail: "expired"}},
		suppressed:    []violation{{id: "GO-9", module: "m9", detail: "ok"}},
	}

	anns := r.annotations()

	levels := map[string]string{}
	for _, a := range anns {
		levels[a.id] = a.level
	}

	if levels["GO-1"] != "error" {
		t.Errorf("unlisted GO-1 should be error, got %q", levels["GO-1"])
	}

	if levels["GO-3"] != "error" {
		t.Errorf("expired GO-3 should be error, got %q", levels["GO-3"])
	}

	if levels["GO-2"] != "warning" {
		t.Errorf("warnUnfixable GO-2 should be warning, got %q", levels["GO-2"])
	}

	if _, ok := levels["GO-9"]; ok {
		t.Error("suppressed GO-9 must not produce an annotation")
	}
}

func TestModuleLines(t *testing.T) {
	dir := t.TempDir()
	goMod := filepath.Join(dir, "go.mod")

	content := "module example.com/app\n\ngo 1.26\n\nrequire (\n\tgithub.com/foo/bar v1.2.3\n\tgithub.com/baz/qux v0.4.0 // indirect\n)\n"
	if err := os.WriteFile(goMod, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	lines, err := moduleLines(goMod)
	if err != nil {
		t.Fatal(err)
	}

	if lines["github.com/foo/bar"] != 6 {
		t.Errorf("foo/bar line = %d, want 6", lines["github.com/foo/bar"])
	}

	if lines["github.com/baz/qux"] != 7 {
		t.Errorf("baz/qux line = %d, want 7", lines["github.com/baz/qux"])
	}

	if lines["example.com/app"] != 1 {
		t.Errorf("module directive line = %d, want 1", lines["example.com/app"])
	}
}

func TestWriteAnnotations(t *testing.T) {
	dir := t.TempDir()
	goMod := filepath.Join(dir, "go.mod")

	content := "module example.com/app\n\ngo 1.26\n\nrequire github.com/foo/bar v1.2.3\n"
	if err := os.WriteFile(goMod, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	var sb strings.Builder

	anns := []annotation{
		{level: "error", id: "GO-1", module: "github.com/foo/bar", message: "boom\nsecond line"},
		{level: "warning", id: "GO-2", module: "unknown/module", message: "no require line"},
	}
	if err := writeAnnotations(&sb, goMod, "go.mod", anns); err != nil {
		t.Fatal(err)
	}

	got := sb.String()
	if !strings.Contains(got, "::error file=go.mod,line=5,title=GO-1::") {
		t.Errorf("missing error annotation on line 5:\n%s", got)
	}
	// Newlines in the message must be escaped.
	if strings.Contains(got, "boom\nsecond") || !strings.Contains(got, "boom%0Asecond") {
		t.Errorf("message newline not escaped:\n%s", got)
	}
	// A module not present in go.mod falls back to line 1.
	if !strings.Contains(got, "::warning file=go.mod,line=1,title=GO-2::") {
		t.Errorf("missing fallback annotation on line 1:\n%s", got)
	}
}

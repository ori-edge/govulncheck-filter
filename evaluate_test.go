// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Radiant

package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func day(s string) time.Time {
	t, err := time.Parse(dateLayout, s)
	if err != nil {
		panic(err)
	}

	return t.UTC()
}

func TestEvaluate(t *testing.T) {
	now := day("2026-07-24")

	const netMod = "golang.org/x/net"

	call := func(k findingKey, fixed bool) findings {
		f := findings{called: map[findingKey]bool{k: true}, fixed: map[findingKey]bool{}}
		if fixed {
			f.fixed[k] = true
		}

		return f
	}
	empty := findings{called: map[findingKey]bool{}, fixed: map[findingKey]bool{}}
	netKey := findingKey{"GO-1", netMod}

	tests := []struct {
		name            string
		entries         []allowEntry
		found           findings
		ignoreUnfixable bool
		wantOK          bool
	}{
		{
			name:    "present, acknowledged within window",
			entries: []allowEntry{{ID: "GO-1", Module: netMod, Review: day("2026-08-01")}},
			found:   call(netKey, true),
			wantOK:  true,
		},
		{
			name:    "review date too far in future",
			entries: []allowEntry{{ID: "GO-1", Module: netMod, Review: day("2026-09-30")}},
			found:   call(netKey, true),
			wantOK:  false,
		},
		{
			name:    "review date too far but not present is stale, not a failure",
			entries: []allowEntry{{ID: "GO-1", Module: netMod, Review: day("2026-09-30")}},
			found:   empty,
			wantOK:  true,
		},
		{
			name:    "review date passed and still present",
			entries: []allowEntry{{ID: "GO-1", Module: netMod, Review: day("2026-07-01")}},
			found:   call(netKey, true),
			wantOK:  false,
		},
		{
			name:    "fixable called without a review date fails",
			entries: []allowEntry{{ID: "GO-1", Module: netMod}},
			found:   call(netKey, true),
			wantOK:  false,
		},
		{
			name:    "unfixable called without a review date is acknowledged",
			entries: []allowEntry{{ID: "GO-1", Module: netMod}},
			found:   call(netKey, false),
			wantOK:  true,
		},
		{
			name:    "unfixable called with an in-window review date is acknowledged",
			entries: []allowEntry{{ID: "GO-1", Module: netMod, Review: day("2026-08-01")}},
			found:   call(netKey, false),
			wantOK:  true,
		},
		{
			name:            "unfixable called with an expired review date fails (date honoured irrespective)",
			entries:         []allowEntry{{ID: "GO-1", Module: netMod, Review: day("2026-07-01")}},
			found:           call(netKey, false),
			ignoreUnfixable: true,
			wantOK:          false,
		},
		{
			name:    "review date passed but no longer present is stale, not a failure",
			entries: []allowEntry{{ID: "GO-1", Module: netMod, Review: day("2026-07-01")}},
			found:   empty,
			wantOK:  true,
		},
		{
			name:    "review date today counts as active grace",
			entries: []allowEntry{{ID: "GO-1", Module: netMod, Review: day("2026-07-24")}},
			found:   call(netKey, true),
			wantOK:  true,
		},
		{
			name:    "called vuln not in allowlist fails",
			entries: []allowEntry{},
			found:   call(findingKey{"GO-9", netMod}, true),
			wantOK:  false,
		},
		{
			name:    "allowlist entry in a different module does not cover finding",
			entries: []allowEntry{{ID: "GO-1", Module: "golang.org/x/crypto", Review: day("2026-08-01")}},
			found:   call(netKey, true),
			wantOK:  false,
		},
		{
			name:            "unlisted called-but-unfixable fails by default",
			entries:         []allowEntry{},
			found:           call(netKey, false),
			ignoreUnfixable: false,
			wantOK:          false,
		},
		{
			name:            "unlisted called-but-unfixable downgraded to warning with -ignore-unfixable",
			entries:         []allowEntry{},
			found:           call(netKey, false),
			ignoreUnfixable: true,
			wantOK:          true,
		},
		{
			name:            "unlisted called-and-fixable still fails with -ignore-unfixable",
			entries:         []allowEntry{},
			found:           call(netKey, true),
			ignoreUnfixable: true,
			wantOK:          false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := evaluate(tt.entries, tt.found, now, 30, tt.ignoreUnfixable)
			if got.ok() != tt.wantOK {
				t.Errorf("ok() = %v, want %v (report: %+v)", got.ok(), tt.wantOK, got)
			}
		})
	}
}

func TestParseFindings(t *testing.T) {
	f, err := os.Open("testdata/findings.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	found, err := parseFindings(f)
	if err != nil {
		t.Fatal(err)
	}

	if !found.called[findingKey{"GO-CALLED", "m1"}] {
		t.Error("expected GO-CALLED in m1 to be marked called")
	}

	if !found.called[findingKey{"GO-NOFIX", "m3"}] {
		t.Error("expected GO-NOFIX in m3 to be marked called")
	}

	if found.called[findingKey{"GO-IMPORTED", "m2"}] {
		t.Error("GO-IMPORTED is only imported, must not be marked called")
	}

	if len(found.called) != 2 {
		t.Errorf("expected 2 called findings, got %d: %v", len(found.called), found.called)
	}

	if !found.fixed[findingKey{"GO-CALLED", "m1"}] {
		t.Error("GO-CALLED has a fixed_version, should be marked fixed")
	}

	if found.fixed[findingKey{"GO-NOFIX", "m3"}] {
		t.Error("GO-NOFIX has no fixed_version, must not be marked fixed")
	}
}

func TestRenderTrace(t *testing.T) {
	trace := []*frame{
		{Package: "github.com/kedacore/keda/v2/apis/keda/v1alpha1", Receiver: "*AdvancedConfig", Function: "DeepCopyInto"},
		{Package: "middle/pkg", Function: "Mid"},
		{Package: "k8s.io/client-go/testing", Receiver: "tracker", Function: "Add"},
		{
			Package:  "github.com/ori-edge/apix/pkg/kubevirt/versioned/fake",
			Function: "NewSimpleClientset",
			Position: &position{Filename: "pkg/kubevirt/versioned/fake/clientset_generated.go", Line: 32, Column: 18},
		},
	}

	got := renderTrace(trace)
	want := "pkg/kubevirt/versioned/fake/clientset_generated.go:32:18: " +
		"fake.NewSimpleClientset calls testing.tracker.Add, " +
		"which eventually calls v1alpha1.AdvancedConfig.DeepCopyInto"

	if got != want {
		t.Errorf("renderTrace:\n got %q\nwant %q", got, want)
	}
}

func TestWithJSONFormat(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want []string
	}{
		{"adds format", []string{"./..."}, []string{"-format", "json", "./..."}},
		{"keeps existing -format", []string{"-format", "sarif", "./..."}, []string{"-format", "sarif", "./..."}},
		{"keeps -format=", []string{"-format=json", "./..."}, []string{"-format=json", "./..."}},
		{"keeps -json", []string{"-json", "./..."}, []string{"-json", "./..."}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := withJSONFormat(tt.in)
			if len(got) != len(tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}

			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("got %v, want %v", got, tt.want)
				}
			}
		})
	}
}

func TestResolveAllowlist(t *testing.T) {
	resolved := func(t *testing.T, got string) string {
		t.Helper()

		r, err := filepath.EvalSymlinks(got)
		if err != nil {
			r = got // may not exist (empty-allowlist ceiling case)
		}

		return r
	}
	eval := func(p string) string {
		r, err := filepath.EvalSymlinks(p)
		if err != nil {
			return p
		}

		return r
	}

	t.Run("explicit path wins", func(t *testing.T) {
		got, explicit, err := resolveAllowlist("/some/path.yaml", "")
		if err != nil || !explicit || got != "/some/path.yaml" {
			t.Fatalf("got %q explicit=%v err=%v", got, explicit, err)
		}
	})

	t.Run("found in module root", func(t *testing.T) {
		root := t.TempDir()
		if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module x\n"), 0o644); err != nil {
			t.Fatal(err)
		}

		want := filepath.Join(root, defaultAllowlistName)
		if err := os.WriteFile(want, []byte("allow: []\n"), 0o644); err != nil {
			t.Fatal(err)
		}

		nested := filepath.Join(root, "a", "b")
		if err := os.MkdirAll(nested, 0o755); err != nil {
			t.Fatal(err)
		}

		got, explicit, err := resolveAllowlist("", nested)
		if err != nil || explicit {
			t.Fatalf("explicit=%v err=%v", explicit, err)
		}

		if resolved(t, got) != eval(want) {
			t.Errorf("got %s, want %s", got, want)
		}
	})

	t.Run("nested allowlist below go.mod wins over walking to root", func(t *testing.T) {
		root := t.TempDir()
		if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module x\n"), 0o644); err != nil {
			t.Fatal(err)
		}

		mid := filepath.Join(root, "svc")
		if err := os.MkdirAll(mid, 0o755); err != nil {
			t.Fatal(err)
		}

		want := filepath.Join(mid, defaultAllowlistName)
		if err := os.WriteFile(want, []byte("allow: []\n"), 0o644); err != nil {
			t.Fatal(err)
		}

		got, _, err := resolveAllowlist("", mid)
		if err != nil {
			t.Fatal(err)
		}

		if resolved(t, got) != eval(want) {
			t.Errorf("got %s, want %s", got, want)
		}
	})

	t.Run("stops at go.mod with no allowlist and returns that dir's path", func(t *testing.T) {
		root := t.TempDir()
		if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module x\n"), 0o644); err != nil {
			t.Fatal(err)
		}

		got, _, err := resolveAllowlist("", root)
		if err != nil {
			t.Fatal(err)
		}

		want := filepath.Join(root, defaultAllowlistName)
		if filepath.Base(got) != defaultAllowlistName || eval(filepath.Dir(got)) != eval(root) {
			t.Errorf("got %s, want a non-existent %s", got, want)
		}

		if isFile(got) {
			t.Error("expected the returned ceiling path not to exist")
		}
	})

	t.Run("no go.mod is an error", func(t *testing.T) {
		if _, _, err := resolveAllowlist("", t.TempDir()); err == nil {
			t.Error("expected error when no go.mod exists above the start dir")
		}
	})
}

func TestLoadAllowlist(t *testing.T) {
	entries, err := loadAllowlist("testdata/allow.yaml")
	if err != nil {
		t.Fatal(err)
	}

	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}

	e := entries[0]
	if e.ID != "GO-CALLED" || e.Module != "m1" || e.Reason == "" {
		t.Errorf("unexpected entry: %+v", e)
	}

	if !e.Review.Equal(day("2026-08-01")) {
		t.Errorf("review = %s, want 2026-08-01", e.Review.Format(dateLayout))
	}
}

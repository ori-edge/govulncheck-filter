// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Radiant

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
)

// findingKey identifies a vulnerability within a specific module, matching the
// (id, module) scoping used by .govulncheck-ignore.yaml.
type findingKey struct {
	id     string
	module string
}

// finding is a called vulnerability surfaced in the report.
type finding struct {
	id     string
	module string
}

// osvInfo is the human-facing text of a vulnerability advisory: a one-line
// summary and the longer details description.
type osvInfo struct {
	summary string
	details string
	url     string
}

// vulnDetail is the presentation context for a single (id, module): the
// affected and fixed versions, and govulncheck-style example call traces.
type vulnDetail struct {
	foundVersion string
	fixedVersion string
	traces       []string
}

// findings is the parsed govulncheck output.
type findings struct {
	called map[findingKey]bool
	fixed  map[findingKey]bool
	osv    map[string]osvInfo
	detail map[findingKey]*vulnDetail
}

// govulncheck streaming JSON is a sequence of concatenated JSON objects; each
// carries at most one of these payloads that we care about.
type message struct {
	OSV     *osvMsg     `json:"osv"`
	Finding *findingMsg `json:"finding"`
}

type osvMsg struct {
	ID               string `json:"id"`
	Summary          string `json:"summary"`
	Details          string `json:"details"`
	DatabaseSpecific struct {
		URL string `json:"url"`
	} `json:"database_specific"`
}

type findingMsg struct {
	OSV          string   `json:"osv"`
	FixedVersion string   `json:"fixed_version"`
	Trace        []*frame `json:"trace"`
}

type frame struct {
	Module   string    `json:"module"`
	Version  string    `json:"version"`
	Package  string    `json:"package"`
	Function string    `json:"function"`
	Receiver string    `json:"receiver"`
	Position *position `json:"position"`
}

type position struct {
	Filename string `json:"filename"`
	Line     int    `json:"line"`
	Column   int    `json:"column"`
}

// parseFindings reads the govulncheck streaming JSON (concatenated, pretty-
// printed objects) with a json.Decoder. The leaf frame (trace[0]) carries the
// vulnerable module and version; a vulnerability is "called" when that frame
// names a function. fixed_version and advisory text are aggregated per key.
func parseFindings(r io.Reader) (findings, error) {
	out := findings{
		called: map[findingKey]bool{},
		fixed:  map[findingKey]bool{},
		osv:    map[string]osvInfo{},
		detail: map[findingKey]*vulnDetail{},
	}
	dec := json.NewDecoder(r)

	for {
		var m message

		err := dec.Decode(&m)
		if errors.Is(err, io.EOF) {
			break
		}

		if err != nil {
			return findings{}, fmt.Errorf("decoding message: %w", err)
		}

		if o := m.OSV; o != nil && o.ID != "" {
			url := o.DatabaseSpecific.URL
			if url == "" {
				url = "https://pkg.go.dev/vuln/" + o.ID
			}

			out.osv[o.ID] = osvInfo{summary: o.Summary, details: o.Details, url: url}
		}

		out.addFinding(m.Finding)
	}

	// govulncheck emits findings in a non-deterministic order; sort each key's
	// traces so the output is stable across runs.
	for _, d := range out.detail {
		sort.Strings(d.traces)
	}

	return out, nil
}

func (f findings) addFinding(m *findingMsg) {
	if m == nil || m.OSV == "" || len(m.Trace) == 0 {
		return
	}

	leaf := m.Trace[0]
	if leaf == nil {
		return
	}

	key := findingKey{id: m.OSV, module: leaf.Module}

	d := f.detail[key]
	if d == nil {
		d = &vulnDetail{}
		f.detail[key] = d
	}

	if m.FixedVersion != "" {
		f.fixed[key] = true
		d.fixedVersion = m.FixedVersion
	}

	if leaf.Version != "" && d.foundVersion == "" {
		d.foundVersion = leaf.Version
	}

	if leaf.Function == "" {
		return // imported/required but not called
	}

	f.called[key] = true

	d.traces = append(d.traces, renderTrace(m.Trace))
}

// renderTrace reproduces govulncheck's compact example-trace line: the entry
// point's call site, the function it calls, and the vulnerable symbol it
// eventually reaches. trace[0] is the vulnerable leaf; trace[len-1] is the entry.
func renderTrace(trace []*frame) string {
	n := len(trace)
	entry := trace[n-1]

	var chain string

	switch n {
	case 1:
		chain = frameName(trace[0])
	case 2:
		chain = frameName(trace[1]) + " calls " + frameName(trace[0])
	default:
		chain = frameName(trace[n-1]) + " calls " + frameName(trace[n-2]) +
			", which eventually calls " + frameName(trace[0])
	}

	if pos := framePos(entry); pos != "" {
		return pos + ": " + chain
	}

	return chain
}

// frameName renders a frame as govulncheck does: <pkg>.<receiver>.<func>, with
// the package shortened to its last path element and any pointer receiver star
// removed.
func frameName(f *frame) string {
	pkg := f.Package
	if i := strings.LastIndex(pkg, "/"); i >= 0 {
		pkg = pkg[i+1:]
	}

	name := f.Function
	if recv := strings.TrimPrefix(f.Receiver, "*"); recv != "" {
		name = recv + "." + name
	}

	if pkg != "" {
		name = pkg + "." + name
	}

	return name
}

func framePos(f *frame) string {
	if f == nil || f.Position == nil {
		return ""
	}

	return fmt.Sprintf("%s:%d:%d", f.Position.Filename, f.Position.Line, f.Position.Column)
}

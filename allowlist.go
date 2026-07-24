// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Radiant

package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// allowEntry is a single time-boxed acknowledgement of a vulnerability, scoped
// to a module. The file format is compatible with .govulncheck-ignore.yaml
// (id, module) plus a required review date and an optional justification.
type allowEntry struct {
	ID        string    `yaml:"id"`
	Module    string    `yaml:"module"`
	Review    time.Time `yaml:"-"`
	RawReview string    `yaml:"review"`
	Reason    string    `yaml:"reason"`
}

// allowlistFile is the top-level document: a list under "allow".
type allowlistFile struct {
	Allow []allowEntry `yaml:"allow"`
}

func loadAllowlist(path string) ([]allowEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var doc allowlistFile

	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)

	if err := dec.Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, nil // empty file: no exceptions
		}

		return nil, err
	}

	seen := map[findingKey]bool{}

	for i := range doc.Allow {
		e := &doc.Allow[i]
		if e.ID == "" {
			return nil, fmt.Errorf("entry %d: missing id", i)
		}

		if e.Module == "" {
			return nil, fmt.Errorf("entry %d (%s): missing module", i, e.ID)
		}

		// The review date is optional here: it is required only for fixable
		// vulnerabilities, which is enforced in evaluate where fix availability
		// is known. When present it must be a valid calendar date.
		if e.RawReview != "" {
			d, err := time.Parse(dateLayout, e.RawReview)
			if err != nil {
				return nil, fmt.Errorf("entry %d (%s): invalid review date %q, want YYYY-MM-DD", i, e.ID, e.RawReview)
			}

			e.Review = d.UTC()
		}

		key := findingKey{id: e.ID, module: e.Module}
		if seen[key] {
			return nil, fmt.Errorf("entry %d: duplicate id/module %s (%s)", i, e.ID, e.Module)
		}

		seen[key] = true
	}

	// An empty allowlist is valid: it means no exceptions, so any called
	// vulnerability fails.
	return doc.Allow, nil
}

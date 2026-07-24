// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Radiant

package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

// invokeFlag is a -invoke flag that takes an optional binary path: bare
// "-invoke" enables invocation with the default binary, "-invoke=/path" enables
// it with a specific one. Implementing IsBoolFlag lets the bare form work
// without consuming the next argument.
type invokeFlag struct {
	set bool
	bin string
}

func (f *invokeFlag) String() string {
	if f == nil {
		return ""
	}

	return f.bin
}

func (f *invokeFlag) Set(s string) error {
	f.set = true
	// The bare "-invoke" form arrives as "true" (the IsBoolFlag default); any
	// other value is an explicit binary path.
	if s != "" && s != "true" {
		f.bin = s
	}

	return nil
}

func (f *invokeFlag) IsBoolFlag() bool { return true }

// startGovulncheck launches govulncheck with the user's arguments, ensuring
// JSON output, and returns the started command and its stdout for streaming.
// govulncheck's stderr is passed through so progress remains visible.
func startGovulncheck(bin string, userArgs []string) (*exec.Cmd, io.ReadCloser, error) {
	cmd := exec.Command(bin, withJSONFormat(userArgs)...)
	cmd.Stderr = os.Stderr

	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, err
	}

	if err := cmd.Start(); err != nil {
		return nil, nil, fmt.Errorf("starting %s: %w", bin, err)
	}

	return cmd, out, nil
}

const (
	formatFlag = "-format"
	jsonFlag   = "-json"
)

// withJSONFormat prepends "-format json" unless the caller already selected an
// output format, so the invoker never has to add it.
func withJSONFormat(user []string) []string {
	for _, a := range user {
		switch {
		case a == formatFlag, a == "--format", a == jsonFlag, a == "--json",
			strings.HasPrefix(a, formatFlag+"="), strings.HasPrefix(a, "--format="):
			return user
		}
	}

	return append([]string{formatFlag, "json"}, user...)
}

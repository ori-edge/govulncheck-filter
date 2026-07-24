// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Radiant

// Command govulncheck-filter reads govulncheck JSON output and enforces a
// time-boxed allowlist of Go vulnerability IDs.
//
// It fails (non-zero exit) when:
//   - an allowlist entry's date is more than -max-future-days into the future
//     (an acknowledgement can't be deferred indefinitely), or
//   - an allowlist entry's date is in the past and the vulnerability is still
//     present (called) in the govulncheck output (the grace period expired but
//     the code is still vulnerable), or
//   - a called vulnerability is not covered by the allowlist at all.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	dateLayout           = "2006-01-02"
	defaultAllowlistName = ".govulncheck-ignore.yaml"
)

func main() {
	allowlistPath := flag.String("allowlist", "",
		"path to the allowlist file (default: nearest "+defaultAllowlistName+
			" found by walking up to the module root)")
	chdir := flag.String("C", "",
		"directory to start the module-root search from (default: current directory)")
	inputPath := flag.String("input", "", "path to govulncheck JSON output (default: stdin)")
	invoke := &invokeFlag{bin: "govulncheck"}
	flag.Var(invoke, "invoke",
		"run govulncheck directly, optionally naming the binary "+
			"(-invoke or -invoke=/path/to/govulncheck); pass its args after -- "+
			"(\"-format json\" is added automatically)")

	maxFutureDays := flag.Int("max-future-days", 30,
		"maximum days into the future an allowlist date may be")
	ignoreUnfixable := flag.Bool("ignore-unfixable", false,
		"do not fail on called vulnerabilities that have no fix available yet "+
			"(report them as warnings)")
	githubAnnotations := flag.Bool("github-annotations", false,
		"also emit GitHub Actions ::error/::warning annotations anchored to "+
			"the offending module's require line in go.mod")
	warnOnly := flag.Bool("warn-only", false,
		"report policy violations as warnings and exit 0 instead of failing "+
			"(annotations, if enabled, are emitted at warning level)")

	flag.Parse()

	gvArgs := flag.Args()
	switch {
	case invoke.set && *inputPath != "":
		fatal("-invoke cannot be combined with -input")
	case !invoke.set && len(gvArgs) > 0:
		fatal("unexpected arguments %q; pass govulncheck args with -invoke -- ...", gvArgs)
	}

	resolved, explicit, err := resolveAllowlist(*allowlistPath, *chdir)
	if err != nil {
		fatal("%v", err)
	}

	opts := options{
		allowlistPath:     resolved,
		allowlistExplicit: explicit,
		startDir:          *chdir,
		inputPath:         *inputPath,
		invoke:            invoke.set,
		govulncheckBin:    invoke.bin,
		govulncheckArgs:   gvArgs,
		maxFutureDays:     *maxFutureDays,
		ignoreUnfixable:   *ignoreUnfixable,
		githubAnnotations: *githubAnnotations,
		warnOnly:          *warnOnly,
	}
	if err := run(opts, time.Now().UTC()); err != nil {
		fatal("%v", err)
	}
}

type options struct {
	allowlistPath     string
	allowlistExplicit bool
	startDir          string
	inputPath         string
	invoke            bool
	govulncheckBin    string
	govulncheckArgs   []string
	maxFutureDays     int
	ignoreUnfixable   bool
	githubAnnotations bool
	warnOnly          bool
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", args...)
	os.Exit(2)
}

// resolveAllowlist returns the allowlist path and whether it was set explicitly.
// An explicit -allowlist wins. Otherwise it walks up from startDir (the -C
// directory, or the current directory) looking for the default file at each
// level, stopping at the first directory that contains a go.mod — the module
// root is the ceiling. If that directory has no allowlist either, its (absent)
// path is returned and treated as an empty allowlist by the caller. Reaching
// the filesystem root without seeing a go.mod is an error.
func resolveAllowlist(explicit, startDir string) (string, bool, error) {
	if explicit != "" {
		return explicit, true, nil
	}

	if startDir == "" {
		wd, err := os.Getwd()
		if err != nil {
			return "", false, err
		}

		startDir = wd
	}

	dir, err := filepath.Abs(startDir)
	if err != nil {
		return "", false, err
	}

	for {
		candidate := filepath.Join(dir, defaultAllowlistName)
		if isFile(candidate) {
			return candidate, false, nil
		}

		if isFile(filepath.Join(dir, "go.mod")) {
			// Module root reached without an allowlist here: stop, do not
			// look higher. Missing file is treated as no exceptions.
			return candidate, false, nil
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			return "", false, fmt.Errorf("no go.mod found walking up from %s", startDir)
		}

		dir = parent
	}
}

func isFile(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && !fi.IsDir()
}

func run(o options, now time.Time) error {
	entries, err := loadAllowlist(o.allowlistPath)
	if os.IsNotExist(err) && !o.allowlistExplicit {
		// A defaulted allowlist that does not exist just means "no exceptions".
		entries, err = nil, nil
	}

	if err != nil {
		return fmt.Errorf("loading allowlist: %w", err)
	}

	var (
		in   io.Reader
		wait func() error
	)

	switch {
	case o.invoke:
		cmd, out, err := startGovulncheck(o.govulncheckBin, o.govulncheckArgs)
		if err != nil {
			return err
		}
		defer out.Close()

		in, wait = out, cmd.Wait
	case o.inputPath != "":
		f, err := os.Open(o.inputPath)
		if err != nil {
			return fmt.Errorf("opening input: %w", err)
		}
		defer f.Close()

		in = f
	default:
		in = os.Stdin
	}

	found, err := parseFindings(in)
	if err != nil {
		return fmt.Errorf("parsing govulncheck output: %w", err)
	}

	if wait != nil {
		if err := wait(); err != nil {
			return fmt.Errorf("govulncheck failed: %w", err)
		}
	}

	report := evaluate(entries, found, now, o.maxFutureDays, o.ignoreUnfixable)

	// The per-finding advisory context is verbose; under GitHub Actions collapse
	// it into a group so the status list and summary that follow stand out.
	if o.githubAnnotations {
		fmt.Fprintln(os.Stdout, "::group::govulncheck-filter details")
	}

	report.printDetails(os.Stdout)

	if o.githubAnnotations {
		fmt.Fprintln(os.Stdout, "::endgroup::")
	}

	report.printStatus(os.Stdout)
	report.printSummary(os.Stdout)

	if o.githubAnnotations {
		emitAnnotations(report, o.startDir, o.warnOnly)
	}

	if !report.ok() {
		if o.warnOnly {
			fmt.Fprintln(os.Stdout, "warn-only: violations reported as warnings; not failing the build")
			return nil
		}

		os.Exit(1)
	}

	return nil
}

// emitAnnotations writes GitHub Actions annotations to stdout: one per finding
// anchored to its module's go.mod require line, plus a final non-line-pinned
// summary annotation. When warnOnly is set every annotation is a warning.
// Failure to locate or parse go.mod is reported to stderr but does not change
// the outcome of the scan — annotations are a convenience, not the verdict.
func emitAnnotations(r report, startDir string, warnOnly bool) {
	anns := r.annotations()

	if warnOnly {
		for i := range anns {
			anns[i].level = levelWarning
		}
	}

	if len(anns) > 0 {
		if goModPath, err := findGoMod(startDir); err != nil {
			fmt.Fprintln(os.Stderr, "warning: cannot emit annotations:", err)
		} else if err := writeAnnotations(os.Stdout, goModPath, displayPath(goModPath), anns); err != nil {
			fmt.Fprintln(os.Stderr, "warning: cannot emit annotations:", err)
		}
	}

	level, msg := r.summaryAnnotation(warnOnly)
	fmt.Fprintf(os.Stdout, "::%s::%s\n", level, escapeAnnotation(msg))
}

// summaryAnnotation is the overall, non-line-pinned annotation reflecting the
// scan verdict.
func (r report) summaryAnnotation(warnOnly bool) (string, string) {
	switch {
	case r.failCount() > 0:
		level := levelError
		if warnOnly {
			level = levelWarning
		}

		return level, fmt.Sprintf("govulncheck-filter: %d policy violation(s) in called code", r.failCount())
	case r.warnCount() > 0:
		return levelWarning, fmt.Sprintf("govulncheck-filter: %d warning(s), no policy violations", r.warnCount())
	default:
		return "notice", "govulncheck-filter: no vulnerabilities require attention"
	}
}

// displayPath renders goModPath as GitHub should see it: relative to the
// current directory when possible.
func displayPath(goModPath string) string {
	if wd, err := os.Getwd(); err == nil {
		if rel, err := filepath.Rel(wd, goModPath); err == nil {
			return rel
		}
	}

	return goModPath
}

// findGoMod walks up from startDir (or the current directory) to the first
// directory containing a go.mod, returning that file's path.
func findGoMod(startDir string) (string, error) {
	if startDir == "" {
		wd, err := os.Getwd()
		if err != nil {
			return "", err
		}

		startDir = wd
	}

	dir, err := filepath.Abs(startDir)
	if err != nil {
		return "", err
	}

	for {
		p := filepath.Join(dir, "go.mod")
		if isFile(p) {
			return p, nil
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("no go.mod found walking up from %s", startDir)
		}

		dir = parent
	}
}

// report is the outcome of evaluating the allowlist against the findings. osv
// and detail carry the govulncheck advisory context used to enrich the log.
type report struct {
	tooFarFuture  []violation // allowlist date beyond the future window
	expired       []violation // allowlist date in the past, vuln still present
	missingReview []violation // fixable called vuln allowlisted without a review date
	unlisted      []finding   // called vuln with no allowlist entry
	suppressed    []violation // called vuln acknowledged by an allowlist entry
	stale         []violation // allowlist entry for a vuln no longer present
	warnUnfixable []finding   // unlisted called vuln with no fix, downgraded by -ignore-unfixable

	osv    map[string]osvInfo
	detail map[findingKey]*vulnDetail
}

type violation struct {
	id     string
	module string
	review time.Time
	reason string
	detail string
}

// dayOf truncates t to UTC midnight so comparisons are calendar-date based.
func dayOf(t time.Time) time.Time {
	y, m, d := t.UTC().Date()
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}

func (r report) failCount() int {
	return len(r.tooFarFuture) + len(r.expired) + len(r.missingReview) + len(r.unlisted)
}

func (r report) warnCount() int {
	return len(r.stale) + len(r.warnUnfixable)
}

func (r report) ok() bool {
	return r.failCount() == 0
}

// evaluate applies the allowlist rules. now is expected to be truncated to a
// day boundary by the caller via dayOf. Both the allowlist and the findings are
// scoped by (vulnerability id, module) so an acknowledgement in one module does
// not silence the same vulnerability reached through another.
//
// A review date is required only when the vulnerability is fixable — you cannot
// commit to remediating something with no fix. But a review date, once set on
// any entry, is always honoured: too-far-future and expired both fail
// regardless of fixability. The -ignore-unfixable flag therefore only affects
// unlisted vulnerabilities: an unlisted called vulnerability with no fix is
// downgraded to a warning rather than failing.
func evaluate(entries []allowEntry, f findings, now time.Time, maxFutureDays int, ignoreUnfixable bool) report {
	today := dayOf(now)
	horizon := today.AddDate(0, 0, maxFutureDays)

	var r report

	covered := map[findingKey]bool{}

	for _, e := range entries {
		key := findingKey{id: e.ID, module: e.Module}
		covered[key] = true
		v := violation{id: e.ID, module: e.Module, review: e.Review, reason: e.Reason}

		switch {
		case !f.called[key]:
			v.detail = "allowlisted but not present in output"
			r.stale = append(r.stale, v)
		case !e.Review.IsZero() && e.Review.After(horizon):
			v.detail = fmt.Sprintf(
				"review date %s is more than %d days in the future",
				e.Review.Format(dateLayout), maxFutureDays)
			r.tooFarFuture = append(r.tooFarFuture, v)
		case !e.Review.IsZero() && e.Review.Before(today):
			v.detail = fmt.Sprintf(
				"review date %s has passed and the vulnerability is still called",
				e.Review.Format(dateLayout))
			r.expired = append(r.expired, v)
		case !e.Review.IsZero():
			v.detail = fmt.Sprintf("acknowledged, review by %s", e.Review.Format(dateLayout))
			r.suppressed = append(r.suppressed, v)
		case f.fixed[key]:
			v.detail = "fixable vulnerability requires a review date"
			r.missingReview = append(r.missingReview, v)
		default:
			v.detail = "acknowledged; no fix available yet"
			r.suppressed = append(r.suppressed, v)
		}
	}

	for key := range f.called {
		if covered[key] {
			continue
		}

		fnd := finding(key)
		if ignoreUnfixable && !f.fixed[key] {
			r.warnUnfixable = append(r.warnUnfixable, fnd)
		} else {
			r.unlisted = append(r.unlisted, fnd)
		}
	}

	sortFindings(r.unlisted)
	sortFindings(r.warnUnfixable)

	r.osv = f.osv
	r.detail = f.detail

	return r
}

func sortFindings(fs []finding) {
	sort.Slice(fs, func(i, j int) bool {
		if fs[i].id != fs[j].id {
			return fs[i].id < fs[j].id
		}

		return fs[i].module < fs[j].module
	})
}

// statusLine is one finding rendered for output: a status, the concise note,
// and — for findings reached in code — the advisory context (reason + traces).
type statusLine struct {
	status     string // "OK", "WARN", "FAIL"
	id         string
	module     string
	note       string
	reason     string
	review     time.Time
	hasContext bool
}

// lines returns every finding in a stable severity order: acknowledged (OK)
// first, then warnings, then failures.
func (r report) lines() []statusLine {
	var ls []statusLine

	fromViolation := func(status string, vs []violation, hasContext bool) {
		for _, v := range vs {
			ls = append(ls, statusLine{status, v.id, v.module, v.detail, v.reason, v.review, hasContext})
		}
	}

	fromFinding := func(status, note string, fs []finding) {
		for _, f := range fs {
			ls = append(ls, statusLine{status: status, id: f.id, module: f.module, note: note, hasContext: true})
		}
	}

	fromViolation("OK", r.suppressed, true)
	fromViolation("WARN", r.stale, false)
	fromFinding("WARN", "called but no fix available yet", r.warnUnfixable)
	fromViolation("FAIL", r.tooFarFuture, true)
	fromViolation("FAIL", r.expired, true)
	fromViolation("FAIL", r.missingReview, true)
	fromFinding("FAIL", "called vulnerability is not in the allowlist", r.unlisted)

	return ls
}

// printDetails writes the govulncheck advisory context for every finding
// reached in code: a header, then the detail block. This is the verbose section
// that GitHub Actions collapses.
func (r report) printDetails(w io.Writer) {
	for _, l := range r.lines() {
		if !l.hasContext {
			continue
		}

		fmt.Fprintf(w, "%s (%s)\n", l.id, l.module)
		r.printDetail(w, l)
		fmt.Fprintln(w)
	}
}

// printStatus writes the concise one-line-per-finding status list.
func (r report) printStatus(w io.Writer) {
	for _, l := range r.lines() {
		fmt.Fprintf(w, "%-4s %s (%s): %s\n", l.status, l.id, l.module, l.note)
	}
}

// printDetail writes the govulncheck advisory context for one finding: summary
// and details, more-info URL, affected/fixed versions, our acknowledgement
// reason and review date when present, and example call traces.
func (r report) printDetail(w io.Writer, l statusLine) {
	const indent = "    "

	if info, ok := r.osv[l.id]; ok {
		if info.summary != "" {
			fmt.Fprintf(w, "%s%s\n", indent, info.summary)
		}

		// details is the longer description; skip it when it just repeats the
		// summary (some advisories set both to the same text).
		if d := strings.TrimRight(info.details, "\n"); d != "" && d != info.summary {
			for dl := range strings.SplitSeq(d, "\n") {
				fmt.Fprintf(w, "%s%s\n", indent, dl)
			}
		}

		fmt.Fprintf(w, "%sMore info: %s\n", indent, info.url)
	}

	fmt.Fprintf(w, "%sModule: %s\n", indent, l.module)

	if d := r.detail[findingKey{id: l.id, module: l.module}]; d != nil {
		if d.foundVersion != "" {
			fmt.Fprintf(w, "%sFound in: %s@%s\n", indent, l.module, d.foundVersion)
		}

		if d.fixedVersion != "" {
			fmt.Fprintf(w, "%sFixed in: %s@%s\n", indent, l.module, d.fixedVersion)
		}

		printTraces(w, indent, d.traces)
	}

	if !l.review.IsZero() {
		fmt.Fprintf(w, "%sReview by: %s\n", indent, l.review.Format(dateLayout))
	}

	if l.reason != "" {
		fmt.Fprintf(w, "%sReason: %s\n", indent, l.reason)
	}
}

func printTraces(w io.Writer, indent string, traces []string) {
	if len(traces) == 0 {
		return
	}

	fmt.Fprintf(w, "%sExample traces found:\n", indent)

	for i, tr := range traces {
		fmt.Fprintf(w, "%s  #%d: %s\n", indent, i+1, tr)
	}
}

// printSummary writes the one-line verdict.
func (r report) printSummary(w io.Writer) {
	if r.ok() {
		fmt.Fprintln(w, "PASS: no policy violations")
		return
	}

	fmt.Fprintf(w, "FAILED: %d policy violation(s)\n", r.failCount())
}

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"

	"github.com/califio/rediver-sdk-go"
)

// SemgrepDefaults holds CLI-level defaults for the semgrep scanner parameters.
type SemgrepDefaults struct {
	Config         string
	BaselineCommit string
}

// NewSemgrepScanner creates a scanner for SAST analysis using semgrep.
func NewSemgrepScanner(defaults SemgrepDefaults) rediver.Scanner {
	return rediver.NewScanner(
		"semgrep",
		[]rediver.TargetType{rediver.TargetTypeRepository},
		semgrepHandler(defaults),
		rediver.WithParam(rediver.StringParam("semgrep_config").
			Label("Semgrep Config").
			Description("Semgrep ruleset or path (e.g. auto, p/default, p/owasp-top-ten)").
			Default(defaults.Config).
			Build()),
	)
}

func semgrepHandler(defaults SemgrepDefaults) rediver.ScanFunc {
	return func(ctx context.Context, job rediver.Job, emit func(rediver.Result)) error {
		log := job.Logger()

		repoDir := job.RepoDir()
		if repoDir == "" {
			return fmt.Errorf("no repository available")
		}

		config := defaults.Config
		if p := job.Param("semgrep_config"); p != nil {
			if v := p.String(); v != "" {
				config = v
			}
		}

		// Use baseline commit for PR/MR scans: SDK context first, CLI fallback
		var baselineCommit string
		if repo, ok := job.Repository(); ok && repo.BaseCommitSHA != "" {
			baselineCommit = repo.BaseCommitSHA
		} else if defaults.BaselineCommit != "" {
			baselineCommit = defaults.BaselineCommit
		}

		log.Info("scanning repository with semgrep", "path", repoDir, "config", config, "baseline", baselineCommit)

		findings, err := scan(ctx, log, repoDir, config, baselineCommit)
		if err != nil {
			return fmt.Errorf("semgrep scan error: %w", err)
		}

		if len(findings) == 0 {
			log.Info("no findings detected")
			return nil
		}

		log.Info("findings detected", "count", len(findings))
		emit(rediver.SASTFindings(findings...))
		return nil
	}
}

// semgrep JSON output types

type semgrepOutput struct {
	Results []semgrepResult `json:"results"`
	Errors  []any           `json:"errors"`
}

type semgrepResult struct {
	CheckID string       `json:"check_id"`
	Path    string       `json:"path"`
	Start   semgrepPos   `json:"start"`
	End     semgrepPos   `json:"end"`
	Extra   semgrepExtra `json:"extra"`
}

type semgrepPos struct {
	Line   int `json:"line"`
	Col    int `json:"col"`
	Offset int `json:"offset"`
}

type semgrepExtra struct {
	Message  string          `json:"message"`
	Severity string          `json:"severity"`
	Lines    string          `json:"lines"`
	Metadata semgrepMetadata `json:"metadata"`
}

type semgrepMetadata struct {
	Category           string   `json:"category"`
	Confidence         string   `json:"confidence"`
	CWE                jsonList `json:"cwe"`
	Impact             string   `json:"impact"`
	Likelihood         string   `json:"likelihood"`
	OWASP              jsonList `json:"owasp"`
	References         jsonList `json:"references"`
	Subcategory        jsonList `json:"subcategory"`
	Technology         jsonList `json:"technology"`
	VulnerabilityClass jsonList `json:"vulnerability_class"`
}

// jsonList handles semgrep metadata fields that can be either a string or []string.
type jsonList []string

func (jl *jsonList) UnmarshalJSON(data []byte) error {
	var list []string
	if err := json.Unmarshal(data, &list); err == nil {
		*jl = list
		return nil
	}
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		if s != "" {
			*jl = []string{s}
		}
		return nil
	}
	return nil
}

// extractSemgrepErrors parses JSON stdout from a failed semgrep run
// and returns concatenated error messages. Semgrep with --quiet writes
// errors to the JSON "errors" array, not stderr.
func extractSemgrepErrors(out []byte) string {
	var parsed struct {
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if json.Unmarshal(out, &parsed) != nil || len(parsed.Errors) == 0 {
		return ""
	}
	var msgs []string
	for _, e := range parsed.Errors {
		if e.Message != "" {
			msgs = append(msgs, e.Message)
		}
	}
	return strings.Join(msgs, "; ")
}

// scan runs semgrep CLI on the given directory and returns SAST findings.
// When baselineCommit is set, only new findings since that commit are reported.
func scan(ctx context.Context, log *slog.Logger, repoPath, config, baselineCommit string) ([]rediver.SASTFinding, error) {
	// Safety net: verify baseline commit is usable for diff.
	// SDK already deepens the clone, but check in case it's still unreachable.
	if baselineCommit != "" {
		check := exec.CommandContext(ctx, "git", "merge-base", baselineCommit, "HEAD")
		check.Dir = repoPath
		if err := check.Run(); err != nil {
			log.Warn("baseline commit not reachable, scanning without baseline",
				"baseline", baselineCommit)
			baselineCommit = ""
		}
	}

	log.Info("running semgrep", "path", repoPath, "config", config, "baseline", baselineCommit)

	args := []string{
		"scan",
		"--config", config,
		"--json",
		"--no-git-ignore",
		"--quiet",
	}
	if baselineCommit != "" {
		args = append(args, "--baseline-commit", baselineCommit)
	}
	args = append(args, ".")

	cmd := exec.CommandContext(ctx, "semgrep", args...)
	cmd.Dir = repoPath // semgrep runs git commands from CWD, not from the path argument
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()

	// Semgrep exits with code 1 when findings are present — not an error.
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			if exitErr.ExitCode() > 1 {
				// Semgrep with --quiet outputs errors in JSON stdout, not stderr.
				// Try to extract error message from JSON output first.
				errMsg := extractSemgrepErrors(out)
				if errMsg == "" {
					errMsg = stderr.String()
				}
				return nil, fmt.Errorf("semgrep exited with code %d: %s", exitErr.ExitCode(), errMsg)
			}
		} else {
			return nil, fmt.Errorf("run semgrep: %w", err)
		}
	}

	var parsed semgrepOutput
	if err := json.Unmarshal(out, &parsed); err != nil {
		return nil, fmt.Errorf("parse semgrep output: %w", err)
	}

	if len(parsed.Errors) > 0 {
		log.Warn("semgrep reported errors", "count", len(parsed.Errors))
	}

	if len(parsed.Results) == 0 {
		return nil, nil
	}

	findings := make([]rediver.SASTFinding, 0, len(parsed.Results))
	for _, r := range parsed.Results {
		findings = append(findings, toSASTFinding(r))
	}
	return findings, nil
}

func toSASTFinding(r semgrepResult) rediver.SASTFinding {
	return rediver.SASTFinding{
		Name:        findingName(r.CheckID, r.Path),
		Description: r.Extra.Message,
		Severity:    mapSeverity(r.Extra.Severity, r.Extra.Metadata.Impact),
		File:        r.Path,
		StartLine:   r.Start.Line,
		EndLine:     r.End.Line,
		Snippet:     r.Extra.Lines,
		Category:    findingCategory(r.Extra.Metadata),
		RuleID:      r.CheckID,
		CWEs:        r.Extra.Metadata.CWE,
		References:  r.Extra.Metadata.References,
	}
}

// findingCategory returns the best category for a finding:
// vulnerability_class (first element) → category → "Unknown".
func findingCategory(m semgrepMetadata) string {
	if len(m.VulnerabilityClass) > 0 && m.VulnerabilityClass[0] != "" {
		return m.VulnerabilityClass[0]
	}
	if m.Category != "" {
		return m.Category
	}
	return "Unknown"
}

// findingName builds a human-readable name from check_id and file path.
// e.g., ("yaml.docker-compose.security.writable-filesystem-service", "docker-compose.yml")
// → "Writable filesystem service at docker-compose.yml"
func findingName(checkID, path string) string {
	parts := strings.Split(checkID, ".")
	slug := parts[len(parts)-1]
	name := strings.ReplaceAll(slug, "-", " ")
	if len(name) > 0 {
		name = strings.ToUpper(name[:1]) + name[1:]
	}
	return name + " at " + path
}

// mapSeverity converts semgrep severity + impact to rediver severity.
// Semgrep uses ERROR/WARNING/NOTE for severity and HIGH/MEDIUM/LOW for impact.
func mapSeverity(severity, impact string) rediver.Severity {
	sev := strings.ToUpper(severity)
	imp := strings.ToUpper(impact)

	switch sev {
	case "ERROR":
		switch imp {
		case "HIGH":
			return rediver.SeverityHigh
		case "MEDIUM":
			return rediver.SeverityMedium
		default:
			return rediver.SeverityMedium
		}
	case "WARNING":
		switch imp {
		case "HIGH":
			return rediver.SeverityMedium
		default:
			return rediver.SeverityLow
		}
	case "NOTE", "INFO":
		return rediver.SeverityInfo
	default:
		return rediver.SeverityLow
	}
}

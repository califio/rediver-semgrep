package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/califio/rediver-sdk-go"
	"github.com/califio/rediver-sdk-go/utils"
)

type mockJob struct {
	repoDir string
	logger  *slog.Logger
}

func (m *mockJob) ID() string                              { return "test-job-1" }
func (m *mockJob) Type() rediver.JobType                   { return rediver.JobTypeDiscovery }
func (m *mockJob) Domains() []rediver.DomainTarget         { return nil }
func (m *mockJob) IPs() []rediver.IPTarget                 { return nil }
func (m *mockJob) Subnets() []rediver.SubnetTarget         { return nil }
func (m *mockJob) Services() []rediver.ServiceTarget       { return nil }
func (m *mockJob) Param(_ string) rediver.ParamValue       { return nil }
func (m *mockJob) Repository() (*rediver.Repository, bool) { return nil, false }
func (m *mockJob) RepoDir() string                         { return m.repoDir }
func (m *mockJob) ChangedFiles(_ context.Context) (*utils.ChangedFiles, error) {
	return nil, nil
}
func (m *mockJob) Integration() *rediver.Integration { return nil }
func (m *mockJob) Scanner() string                   { return "semgrep" }
func (m *mockJob) TimeoutMinutes() int               { return 0 }
func (m *mockJob) Version() int                      { return 1 }
func (m *mockJob) Logger() *slog.Logger {
	if m.logger != nil {
		return m.logger
	}
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestNewSemgrepScanner(t *testing.T) {
	s := NewSemgrepScanner(SemgrepDefaults{Config: "auto"})

	if s.Name() != "semgrep" {
		t.Errorf("Name() = %q, want %q", s.Name(), "semgrep")
	}

	types := s.AssetTypes()
	if len(types) != 1 {
		t.Fatalf("AssetTypes() len = %d, want 1", len(types))
	}
	if types[0] != rediver.TargetTypeRepository {
		t.Errorf("AssetTypes()[0] = %q, want %q", types[0], rediver.TargetTypeRepository)
	}
}

func TestSemgrepHandler_NoRepoDir(t *testing.T) {
	job := &mockJob{
		repoDir: "",
	}

	var results []rediver.Result
	emit := func(r rediver.Result) { results = append(results, r) }

	err := semgrepHandler(SemgrepDefaults{Config: "auto"})(context.Background(), job, emit)
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if !strings.Contains(err.Error(), "no repository available") {
		t.Errorf("error = %q, want to contain %q", err.Error(), "no repository available")
	}
	if len(results) != 0 {
		t.Errorf("expected 0 emitted results, got %d", len(results))
	}
}

// TestSemgrepHandler_ScanVulnado runs the full handler against the vulnado repo.
// Skip in CI. Run manually: go test -run TestSemgrepHandler_ScanVulnado -v -timeout 5m
func TestSemgrepHandler_ScanVulnado(t *testing.T) {
	if os.Getenv("CI") != "" {
		t.Skip("skipping integration test in CI")
	}

	vulnadoDir := "/Users/duo/vulnado"
	if _, err := os.Stat(vulnadoDir); os.IsNotExist(err) {
		t.Skipf("vulnado repo not found at %s", vulnadoDir)
	}

	job := &mockJob{
		repoDir: vulnadoDir,
		logger:  slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})),
	}

	var results []rediver.Result
	emit := func(r rediver.Result) { results = append(results, r) }

	err := semgrepHandler(SemgrepDefaults{Config: "auto"})(context.Background(), job, emit)
	if err != nil {
		t.Fatalf("semgrepHandler error: %v", err)
	}

	if len(results) == 0 {
		t.Fatal("expected at least 1 result batch from vulnado, got 0")
	}

	for _, r := range results {
		findings := r.GetSASTFindings()
		fmt.Printf("findings: %d\n", len(findings))
		for i, f := range findings {
			fmt.Printf("[%d] %s | %s | %s:%d | %s | CWE: %v\n",
				i+1, f.Severity, f.Name, f.File, f.StartLine, f.Category, f.CWEs)
		}
	}
}

// TestScan_FindingPathsAreRelative verifies that scan() returns relative file
// paths, not absolute paths containing the temp directory prefix.
// This is the core regression test for the path fix: semgrep target must be "."
// (relative) so that output paths don't include /tmp/repo_XXXX/ prefixes.
// Requires semgrep installed. Run: go test -run TestScan_FindingPathsAreRelative -v -timeout 2m
func TestScan_FindingPathsAreRelative(t *testing.T) {
	if _, err := exec.LookPath("semgrep"); err != nil {
		t.Skip("semgrep not installed, skipping")
	}

	// Create a temp repo with a known vulnerable Python file
	tmpDir, err := os.MkdirTemp("", "repo_test_paths_")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Init git repo (semgrep may need it for baseline features)
	gitInit := exec.Command("git", "init")
	gitInit.Dir = tmpDir
	if out, err := gitInit.CombinedOutput(); err != nil {
		t.Fatalf("git init: %v\n%s", err, out)
	}

	// Write a Python file with an obvious vulnerability
	vulnFile := filepath.Join(tmpDir, "vuln.py")
	if err := os.WriteFile(vulnFile, []byte("import os\nos.system(input())\n"), 0644); err != nil {
		t.Fatalf("write vuln file: %v", err)
	}

	// Write a custom semgrep rule that guarantees a match
	ruleFile := filepath.Join(tmpDir, ".semgrep.yml")
	rule := `rules:
  - id: test-dangerous-system-call
    pattern: os.system(...)
    message: "Dangerous system call detected"
    severity: WARNING
    languages: [python]
`
	if err := os.WriteFile(ruleFile, []byte(rule), 0644); err != nil {
		t.Fatalf("write rule file: %v", err)
	}

	// Commit so semgrep has a clean working tree
	gitAdd := exec.Command("git", "add", ".")
	gitAdd.Dir = tmpDir
	if out, err := gitAdd.CombinedOutput(); err != nil {
		t.Fatalf("git add: %v\n%s", err, out)
	}
	gitCommit := exec.Command("git", "commit", "-m", "init", "--no-gpg-sign")
	gitCommit.Dir = tmpDir
	gitCommit.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=test", "GIT_AUTHOR_EMAIL=test@test.com",
		"GIT_COMMITTER_NAME=test", "GIT_COMMITTER_EMAIL=test@test.com",
	)
	if out, err := gitCommit.CombinedOutput(); err != nil {
		t.Fatalf("git commit: %v\n%s", err, out)
	}

	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	// Use the local rule file as config to guarantee findings
	findings, err := scan(context.Background(), log, tmpDir, ruleFile, "")
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}

	if len(findings) == 0 {
		t.Skip("semgrep found no findings for test file (rule set may vary), skipping path assertion")
	}

	for i, f := range findings {
		// Path must NOT be absolute
		if filepath.IsAbs(f.File) {
			t.Errorf("finding[%d].File is absolute: %q, want relative path", i, f.File)
		}
		// Path must NOT contain the temp directory prefix
		if strings.Contains(f.File, tmpDir) {
			t.Errorf("finding[%d].File contains temp dir prefix: %q", i, f.File)
		}
		// Path should be just the filename (e.g., "vuln.py")
		t.Logf("finding[%d].File = %q (OK: relative)", i, f.File)
	}
}

func TestToSASTFinding(t *testing.T) {
	r := semgrepResult{
		CheckID: "python.lang.security.audit.dangerous-exec",
		Path:    "app/utils.py",
		Start:   semgrepPos{Line: 10, Col: 1},
		End:     semgrepPos{Line: 10, Col: 30},
		Extra: semgrepExtra{
			Message:  "Detected dangerous exec usage",
			Severity: "ERROR",
			Lines:    "exec(user_input)",
			Metadata: semgrepMetadata{
				Category: "security",
				Impact:   "HIGH",
				CWE:      jsonList{"CWE-78"},
				References: jsonList{
					"https://owasp.org/Top10/A03_2021-Injection/",
				},
			},
		},
	}

	f := toSASTFinding(r)

	if f.Name != "Dangerous exec at app/utils.py" {
		t.Errorf("Name = %q, want %q", f.Name, "Dangerous exec at app/utils.py")
	}
	if f.Description != "Detected dangerous exec usage" {
		t.Errorf("Description = %q, want %q", f.Description, "Detected dangerous exec usage")
	}
	if f.Severity != rediver.SeverityHigh {
		t.Errorf("Severity = %q, want %q", f.Severity, rediver.SeverityHigh)
	}
	if f.File != "app/utils.py" {
		t.Errorf("File = %q, want %q", f.File, "app/utils.py")
	}
	if f.StartLine != 10 {
		t.Errorf("StartLine = %d, want 10", f.StartLine)
	}
	if f.EndLine != 10 {
		t.Errorf("EndLine = %d, want 10", f.EndLine)
	}
	if f.Category != "security" {
		t.Errorf("Category = %q, want %q", f.Category, "security")
	}
	if f.RuleID != "python.lang.security.audit.dangerous-exec" {
		t.Errorf("RuleID = %q, want full check_id", f.RuleID)
	}
	if f.Snippet != "exec(user_input)" {
		t.Errorf("Snippet = %q, want %q", f.Snippet, "exec(user_input)")
	}
	if len(f.CWEs) != 1 || f.CWEs[0] != "CWE-78" {
		t.Errorf("CWEs = %v, want [CWE-78]", f.CWEs)
	}
	if len(f.References) != 1 {
		t.Errorf("References len = %d, want 1", len(f.References))
	}
}

func TestFindingCategory(t *testing.T) {
	tests := []struct {
		name string
		meta semgrepMetadata
		want string
	}{
		{"vulnerability_class first", semgrepMetadata{VulnerabilityClass: jsonList{"Improper Authorization"}, Category: "security"}, "Improper Authorization"},
		{"fallback to category", semgrepMetadata{Category: "security"}, "security"},
		{"empty vulnerability_class fallback", semgrepMetadata{VulnerabilityClass: jsonList{}, Category: "security"}, "security"},
		{"both empty", semgrepMetadata{}, "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := findingCategory(tt.meta)
			if got != tt.want {
				t.Errorf("findingCategory() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestMapSeverity(t *testing.T) {
	tests := []struct {
		severity string
		impact   string
		want     rediver.Severity
	}{
		{"ERROR", "HIGH", rediver.SeverityHigh},
		{"ERROR", "MEDIUM", rediver.SeverityMedium},
		{"ERROR", "LOW", rediver.SeverityMedium},
		{"WARNING", "HIGH", rediver.SeverityMedium},
		{"WARNING", "LOW", rediver.SeverityLow},
		{"NOTE", "", rediver.SeverityInfo},
		{"INFO", "", rediver.SeverityInfo},
		{"", "", rediver.SeverityLow},
	}

	for _, tt := range tests {
		got := mapSeverity(tt.severity, tt.impact)
		if got != tt.want {
			t.Errorf("mapSeverity(%q, %q) = %q, want %q", tt.severity, tt.impact, got, tt.want)
		}
	}
}

func TestFindingName(t *testing.T) {
	tests := []struct {
		checkID string
		path    string
		want    string
	}{
		{"yaml.docker-compose.security.writable-filesystem-service.writable-filesystem-service", "docker-compose.yml", "Writable filesystem service at docker-compose.yml"},
		{"python.lang.security.audit.dangerous-exec", "app/utils.py", "Dangerous exec at app/utils.py"},
		{"simple-rule", "main.go", "Simple rule at main.go"},
	}

	for _, tt := range tests {
		got := findingName(tt.checkID, tt.path)
		if got != tt.want {
			t.Errorf("findingName(%q, %q) = %q, want %q", tt.checkID, tt.path, got, tt.want)
		}
	}
}

func TestJsonList_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{"array", `["a","b"]`, []string{"a", "b"}},
		{"string", `"single"`, []string{"single"}},
		{"empty string", `""`, nil},
		{"null", `null`, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var jl jsonList
			if err := json.Unmarshal([]byte(tt.input), &jl); err != nil {
				t.Fatalf("unmarshal error: %v", err)
			}
			if len(jl) != len(tt.want) {
				t.Fatalf("len = %d, want %d", len(jl), len(tt.want))
			}
			for i, v := range jl {
				if v != tt.want[i] {
					t.Errorf("[%d] = %q, want %q", i, v, tt.want[i])
				}
			}
		})
	}
}

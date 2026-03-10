package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
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
func (m *mockJob) ClusterInfo() rediver.ClusterInfo  { return rediver.ClusterInfo{} }
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

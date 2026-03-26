package main

import (
	"context"
	"os/signal"
	"syscall"
	"time"

	"github.com/alecthomas/kong"
	rediver "github.com/califio/rediver-sdk-go"
	"github.com/joho/godotenv"
)

var Version = "0.0.1"

type CLI struct {
	Url              string `help:"Rediver API URL" env:"REDIVER_URL" default:"https://api.rediver.ai" required:"true"`
	Token            string `help:"Rediver cluster token" env:"REDIVER_TOKEN" required:"true"`
	MaxConcurrentJob int    `help:"Max concurrent job" env:"MAX_CONCURRENT_JOB" default:"1"`
	PollingInterval  int    `help:"Polling interval in seconds" env:"POLLING_INTERVAL" default:"10"`
	Mode             string `help:"Run mode: worker (long-running poll loop), ci (auto-detect CI env, scan, exit), task (single job, exit)" env:"MODE" enum:"worker,ci,task" default:"ci"`
	JobID            string `help:"Direct job ID — skip poll, execute this job directly" env:"REDIVER_JOB_ID"`
	SemgrepConfig    string `help:"Semgrep config (ruleset or path). e.g. auto, p/default, p/owasp-top-ten, path/to/rules.yaml" env:"SEMGREP_CONFIG" default:"auto"`
	RepoDir          string `help:"Override repository directory for scanning" env:"REPO_DIR"`
	BaselineCommit   string `help:"Baseline commit SHA for PR/MR diff scanning" env:"BASELINE_COMMIT"`
}

func (cli *CLI) Run() error {
	opts := []rediver.Option{
		rediver.WithVersion(Version),
		rediver.WithMaxConcurrency(cli.MaxConcurrentJob),
		rediver.WithPollInterval(time.Duration(cli.PollingInterval) * time.Second),
	}
	if cli.RepoDir != "" {
		opts = append(opts, rediver.WithRepoDir(cli.RepoDir))
	}

	runner, err := rediver.NewRunner(cli.Url, cli.Token, opts...)
	if err != nil {
		return err
	}
	if err := runner.Add(NewSemgrepScanner(SemgrepDefaults{
		Config:         cli.SemgrepConfig,
		BaselineCommit: cli.BaselineCommit,
	})); err != nil {
		return err
	}

	ctx, cancel := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	switch cli.Mode {
	case "worker":
		return runner.Run(ctx)
	case "ci":
		return runner.RunCI(ctx)
	case "task":
		return runner.RunOnce(ctx, cli.JobID)
	default:
		return runner.RunCI(ctx)
	}
}

func main() {
	_ = godotenv.Load(".env")
	cli := CLI{}
	ctx := kong.Parse(&cli, kong.Name("rediver-semgrep"), kong.UsageOnError())
	err := ctx.Run()
	ctx.FatalIfErrorf(err)
}

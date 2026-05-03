package core

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/adrian-griffin/nfty/internal/colour"
	"github.com/adrian-griffin/nfty/internal/config"
	"github.com/adrian-griffin/nfty/internal/nft"
	"github.com/adrian-griffin/nfty/internal/tools"
)

// validates a config file without applying
func RunCheck(args []string) {
	// separate flags from positional args so order doesn't matter
	args = tools.SortFlags(args)

	// new flagset for check sub-opts
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	listNFTRules := fs.Bool("list-ruleset", false, "print generated nftables script from nfty toml")
	fs.Parse(args)

	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "usage: nfty check [--list-ruleset] <config.toml>")
		os.Exit(1)
	}

	// hostname for the header line
	hostname, _ := os.Hostname()
	now := time.Now().Format("2006-01-02 15:04:05")

	// execution header
	fmt.Printf("  %s %s%s%s\n",
		colour.Grey("nfty"),
		colour.Bold("check"),
		strings.Repeat(" ", 15),
		colour.DarkGrey(hostname+" · "+now),
	)

	tools.Divider()

	// load config
	configPath := fs.Arg(0) // fixed to grab first non-flag arg, rather than raw first flag
	cfg, err := config.Load(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: %v\n", err)
		os.Exit(1)
	}

	// generate nft ruleset from toml config
	script, err := nft.Generate(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "rule generation failed: %v\n", err)
		os.Exit(1)
	}

	// validate script syntax with nft
	if err := nft.ValidateScript(script); err != nil {
		fmt.Fprintf(os.Stderr, "nft syntax validation failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("  %s\n", colour.Green("✓ config validation success"))

	fmt.Printf("    %s%s\n", tools.Label("name"), cfg.Core.Name)
	fmt.Printf("    %s%s\n", tools.Label("table"), cfg.Core.Table)
	fmt.Printf("    %s%v\n", tools.Label("docker_compat"), cfg.Core.DockerCompat)
	fmt.Printf("    %s%v\n", tools.Label("persist"), cfg.Core.Persist)
	fmt.Printf("    %s%v\n", tools.Label("default_rules"), cfg.Core.DefaultRules)
	fmt.Printf("    %s%v\n", tools.Label("log_ssh_fails"), cfg.Core.LogSSHFails)

	fmt.Println()
	fmt.Printf("    %s%s\n", tools.Label("checksum"), colour.DarkGrey(nft.ScriptChecksum(script)))

	tools.Divider()

	// count rules per chain for a quick summary
	v4in := len(cfg.Chains.IPv4.Input)
	v4fwd := len(cfg.Chains.IPv4.Forward)
	v4out := len(cfg.Chains.IPv4.Output)
	v4post := len(cfg.Chains.IPv4.Postrouting)
	v6in := len(cfg.Chains.IPv6.Input)
	v6fwd := len(cfg.Chains.IPv6.Forward)
	v6out := len(cfg.Chains.IPv6.Output)
	v6post := len(cfg.Chains.IPv6.Postrouting)

	fmt.Printf("  %s%s\n", tools.Label("ipv4"), fmt.Sprintf("%d in, %d fwd, %d out, %d post", v4in, v4fwd, v4out, v4post))
	fmt.Printf("  %s%s\n", tools.Label("ipv6"), fmt.Sprintf("%d in, %d fwd, %d out, %d post", v6in, v6fwd, v6out, v6post))

	fmt.Printf("  %s%s\n", tools.Label("address lists"), fmt.Sprintf("%d ipv4, %d ipv6", len(cfg.Lists.IPv4), len(cfg.Lists.IPv6)))

	tools.Divider()

	// run safety checks w/ pre-apply prompt
	issues := config.RunStaticChecks(cfg)
	errCount := config.PrintIssues(issues)

	if errCount > 0 {
		fmt.Fprintf(os.Stderr, "\n  %s\n",
			colour.Yellow(fmt.Sprintf("%d safety error(s) detected in config", errCount)),
		)
	}

	fmt.Println()

	// if list-ruleset run, output spacer & generated NFTables config
	if *listNFTRules {
		fmt.Println("--- generated nftables script ---")
		fmt.Println()
		fmt.Print(script)
	}
}

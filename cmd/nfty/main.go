package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/adrian-griffin/nfty/config"
	"github.com/adrian-griffin/nfty/meta"
	"github.com/adrian-griffin/nfty/nft"
)

func main() {

	// handle version flagging before any checks
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version":
			fmt.Printf("nfty  ~  version: %s\n", meta.Version)
			os.Exit(0)
		case "check":
			runCheck(os.Args[2:])
			os.Exit(0)
		}
	}

	// validate running as root
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "please run nfty with sudo or as the root user")
		fmt.Fprintln(os.Stderr, "this is required for interacting with system networking")
		fmt.Fprintln(os.Stderr, "for details and security considerations, see the GitHub README <3")
		os.Exit(1)
	}

	// before continuing, check nft binary
	if err := nft.CheckBinary(); err != nil {
		fmt.Fprintf(os.Stderr, "nfty startup failed: %v\n", err)
		os.Exit(1)
	}

	// subcommand routing
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "apply":
		runApply(os.Args[2:])
	case "status":
		runStatus()
	case "confirm":
		fmt.Println("confirm not yet implemented")
	case "rollback":
		runRollback()
	case "restore":
		runRestore()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

// applies parsed config as active nftables ruleset
func runApply(args []string) {
	// define new flagset for apply sub-options
	flagSet := flag.NewFlagSet("apply", flag.ExitOnError)
	// sub-option flags for apply set
	dryRun := flagSet.Bool("dry-run", false, "show diffs, no changes")
	// confirmTimer := flagSet.Bool("commit-confirm", false, "set auto-rollback if not confirmed")
	noRollback := flagSet.Bool("skip-confirm", false, "skip automatic rollback (dangerous)")
	flagSet.Parse(args)

	// if supplied .toml is empty err & exit
	configPath := flagSet.Arg(0)
	if configPath == "" {
		fmt.Fprintln(os.Stderr, "usage: nfty apply [--dry-run] [--commit-confirm] [--skip-confirm] <config.toml>")
		os.Exit(1)
	}

	// load configfile from path
	cfg, err := config.Load(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("loaded config: %s (%s)\n", cfg.Core.Name, cfg.Core.Description)

	// warn loudly for skip-confirms
	if *noRollback {
		fmt.Fprintln(os.Stderr, "WARNING: --skip-confirm disabled automatic rollback. if the ruleset is bad, you WILL be locked out")
		// [TODO]: add `y` approval for pushing if skip-confirm is passed
	}

	if *dryRun {
		fmt.Println("dry-run mode — no changes will be made")
		// [TODO]: generate ruleset via rules package
		// [TODO]: show diff against current ruleset
		// [TODO]: run safety checks and display results
		os.Exit(0)
	}

	// [TODO]: run safety checks (safety package)
	// [TODO]: snapshot current ruleset for rollback
	// [TODO]: generate nft script (rules package)
	// [TODO]: validate via nft.ValidateScript()
	// [TODO]: apply via nft.ApplyScript()
	// [TODO]: start confirmation timer (default 30s)
	// [TODO]: on confirm → persist to /var/nfty/active.nft
	// [TODO]: on timeout → rollback from snapshot
}

// validates a config file without applying
func runCheck(args []string) {
	// if no path supplied, err
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: nfty check <config.toml>")
		os.Exit(1)
	}

	// load config
	configPath := args[0]
	cfg, err := config.Load(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Check OK\n")
	fmt.Printf("Config Name: %s (%s)\n", cfg.Core.Name, cfg.Core.Description)
	fmt.Printf("  table:         %s\n", cfg.Core.Table)
	fmt.Printf("  docker_compat: %v\n", cfg.Core.DockerCompat)
	fmt.Printf("  persist:       %v\n", cfg.Core.Persist)

	// count rules per chain for a quick summary
	v4in := len(cfg.Chains.IPv4.Input)
	v4fwd := len(cfg.Chains.IPv4.Forward)
	v4out := len(cfg.Chains.IPv4.Output)
	v4post := len(cfg.Chains.IPv4.Postrouting)
	v6in := len(cfg.Chains.IPv6.Input)
	v6fwd := len(cfg.Chains.IPv6.Forward)
	v6out := len(cfg.Chains.IPv6.Output)
	v6post := len(cfg.Chains.IPv6.Postrouting)

	fmt.Printf("  ipv4 rules:    %d input, %d forward, %d output, %d postrouting\n", v4in, v4fwd, v4out, v4post)
	fmt.Printf("  ipv6 rules:    %d input, %d forward, %d output, %d postrouting\n", v6in, v6fwd, v6out, v6post)

	// count sets
	fmt.Printf("  ipv4 sets:     %d\n", len(cfg.Sets.IPv4))
	fmt.Printf("  ipv6 sets:     %d\n", len(cfg.Sets.IPv6))
}

// shows currently loaded nftables ruleset summary
func runStatus() {
	out, err := nft.ListRulesetScript()
	if err != nil {
		fmt.Fprintf(os.Stderr, "status failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Print(string(out))
}

// manually rolls back to the last snapshot
func runRollback() {
	// [TODO]: read /var/nfty/rollback.nft
	// [TODO]: apply snapshot via nft.ApplyScript()
	fmt.Println("rollback not yet implemented")
}

// reapplies last known good ruleset (used by systemd on boot)
func runRestore() {
	// [TODO]: read /var/nfty/active.nft
	// [TODO]: apply via nft.ApplyScript()
	fmt.Println("restore not yet implemented")
}

func printUsage() {
	fmt.Printf("nfty  ~  version: %s\n", meta.Version)
	fmt.Println("usage: nfty <command> [options]")
	fmt.Println()
	fmt.Println("commands:")
	fmt.Println("  apply <config.toml>              apply config with safety checks")
	fmt.Println("      --dry-run                      show diffs, no changes")
	fmt.Println("      --commit-confirm <seconds>     set rollback timer (default: 30)")
	fmt.Println("      --skip-confirm                 skip rollback timer (dangerous)")
	fmt.Println("  check <config.toml>              validate config, no changes")
	fmt.Println("  status                           show current ruleset")
	fmt.Println("  confirm                          confirm applied config")
	fmt.Println("  rollback                         revert to previous rule snapshot")
	fmt.Println("  version                          show version info")
}

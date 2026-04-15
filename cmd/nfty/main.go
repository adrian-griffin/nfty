package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/adrian-griffin/nfty/commit"
	"github.com/adrian-griffin/nfty/config"
	"github.com/adrian-griffin/nfty/meta"
	"github.com/adrian-griffin/nfty/nft"
	"github.com/adrian-griffin/nfty/rules"
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
	case "rollback-if-pending":
		runRollbackIfPending()
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
	// sort args
	args = sortFlags(args)
	// define new flagset for apply sub-options
	flagSet := flag.NewFlagSet("apply", flag.ExitOnError)
	// sub-option flags for apply set
	dryRun := flagSet.Bool("dry-run", false, "show diffs, no changes")
	skipConfirm := flagSet.Bool("skip-confirm", false, "skip automatic rollback (dangerous)")
	confirmSeconds := flagSet.Int("commit-confirm", 30, "rollback timer in seconds (30s default)")
	flagSet.Parse(args)

	// if supplied .toml is empty err & exit
	configPath := flagSet.Arg(0)
	if configPath == "" {
		fmt.Fprintln(os.Stderr, "usage: nfty apply [--dry-run] [--skip-confirm] [--commit-confirm <seconds>] <config.toml>")
		os.Exit(1)
	}

	// reject if theres already pending apply
	if commit.IsPending() {
		fmt.Fprintln(os.Stderr, "a pending apply already exists, run 'nfty confirm' or 'nfty rollback' first")
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
	if *skipConfirm {
		fmt.Fprintln(os.Stderr, "WARNING: --skip-confirm disabled automatic rollback. if the ruleset is bad, you WILL be locked out")
		// [TODO]: add `y` approval for pushing if skip-confirm is passed
	}

	// [TODO]: run safety checks (safety package)

	// generate nft script
	script, err := rules.Generate(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "rule generation failed: %v\n", err)
		os.Exit(1)
	}

	// validate script syntax with `nft --cf`
	if err := nft.ValidateScript(script); err != nil {
		fmt.Fprintf(os.Stderr, "nft syntax validation failed: %v\n", err)
		os.Exit(1)
	}

	// end dry-run attempt here
	if *dryRun {
		fmt.Println("\ndry-run mode. no changes applied")
		fmt.Println("--- generated nftables script ---")
		fmt.Print(script)
		os.Exit(0)
	}

	// ensure /var/nfty/ exists
	if err := commit.CheckDir(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to create nfty directory: %v\n", err)
		os.Exit(1)
	}

	// collect current ruleset for rollback config
	currentRuleset, err := nft.ListRulesetScript()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to snapshot current ruleset: %v\n", err)
		os.Exit(1)
	}
	// save current ruleset as snapshot to disk
	if err := commit.SaveRollbackSnapshot(currentRuleset); err != nil {
		fmt.Fprintf(os.Stderr, "failed to save rollback snapshot: %v\n", err)
		os.Exit(1)
	}

	// formally apply generated NFT config
	if err := nft.ApplyScript(script); err != nil {
		fmt.Fprintf(os.Stderr, "apply failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("ruleset applied successfully")

	// skip-confirm: persist immediately, no timer
	if *skipConfirm {
		fmt.Fprintln(os.Stderr, "WARNING: --skip-confirm used, automatic lockout prevention & rollback is disabled")
		if cfg.Core.Persist {
			if err := commit.SaveRunningRuleset(script); err != nil {
				fmt.Fprintf(os.Stderr, "failed to persist ruleset: %v\n", err)
			}
		}
		return
	}

	// write pending state to .json file on disk
	if err := commit.WritePending(configPath, *confirmSeconds); err != nil {
		fmt.Fprintf(os.Stderr, "failed to write pending state: %v\n", err)
		os.Exit(1)
	}

	// schedule systemd rollback timer
	nftyPath, _ := os.Executable()
	if err := commit.ScheduleRollback(*confirmSeconds, nftyPath); err != nil {
		fmt.Fprintf(os.Stderr, "failed to schedule rollback timer: %v\n", err)
		fmt.Fprintln(os.Stderr, "WARNING: auto-rollback is NOT active. please confirm or manually rollback") // maybe kill process?
	}

	fmt.Printf("\nrun 'nfty confirm' within %d seconds to approve changes\n", *confirmSeconds)
	fmt.Println("if not confirmed (due to lockout, terminated ssh session, etc), firewall will revert to previous known good state")
}

// perform change-approval/confirmation logic
func runConfirm() {
	if !commit.IsPending() {
		fmt.Println("there is nothing to confirm and no pending apply state")
		return
	}

	state, err := commit.LoadPending()
	if err == nil {
		fmt.Printf("confirming application of: %s\n", state.ConfigPath)
		fmt.Printf("applied by: %s at %s\n", state.AppliedBy, state.AppliedAt.Format("15:04:05"))
	}

	// cancel systemd execution timer
	commit.CancelRollback()

	// persist current ruleset for boot restore
	currentRuleset, err := nft.ListRulesetScript()
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not read current ruleset for persistence: %v\n", err)
	} else {
		if err := commit.SaveRunningRuleset(string(currentRuleset)); err != nil {
			fmt.Fprintf(os.Stderr, "warning: could not apply ruleset to running configuration: %v\n", err)
		}
	}

	commit.ClearPending()
	fmt.Println("ruleset committed and confirmed")
}

// perform rollback functionality if pending state is detected
func runRollbackIfPending() {
	if !commit.IsPending() {
		return
	}

	fmt.Println("nfty: commit-confirm timed out, reverting firewall config to previous know good state")

	snapshot, err := commit.LoadRollbackSnapshot()
	if err != nil {
		fmt.Fprintf(os.Stderr, "rollback failed! could not load snapshot: %v\n", err)
		os.Exit(1)
	}

	if err := nft.ApplyScript(snapshot); err != nil {
		fmt.Fprintf(os.Stderr, "rollback failed! could not apply snapshot: %v\n", err)
		os.Exit(1)
	}

	commit.ClearPending()
	fmt.Println("nfty: restored previous ruleset")
}

// validates a config file without applying
func runCheck(args []string) {
	// separate flags from positional args so order doesn't matter
	args = sortFlags(args)

	// new flagset for check sub-opts
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	listNFTRules := fs.Bool("list-ruleset", false, "print generated nftables script from nfty toml")
	fs.Parse(args)

	// if flag is ??, output usage help message
	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "usage: nfty check [--list-ruleset] <config.toml>")
		os.Exit(1)
	}

	// load config
	configPath := fs.Arg(0) // fixed to grab first non-flag arg, rather than raw first flag
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
	fmt.Printf("  default_rules: %v\n", cfg.Core.DefaultRules)
	fmt.Printf("\n")
	fmt.Printf("  icmpv4_limit:  %v\n", cfg.Core.ICMPv4Limit)
	fmt.Printf("  icmpv6_limit:  %v\n", cfg.Core.ICMPv6Limit)
	fmt.Printf("  log_ssh_fails: %v\n", cfg.Core.LogSSHFails)

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

	// if list-ruleset run, output spacer & generated NFTables config
	if *listNFTRules {
		fmt.Println("\n--- generated nftables script ---\n")
		// perform nfty -> nftables conversion and print output script
		script, err := rules.Generate(cfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "rule generation failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Print(script)
	}
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

// grabs previous snapshot and applies it
func runRollback() {
	snapshot, err := commit.LoadRollbackSnapshot()
	if err != nil {
		fmt.Fprintf(os.Stderr, "rollback failed: %v\n", err)
		os.Exit(1)
	}

	if err := nft.ApplyScript(snapshot); err != nil {
		fmt.Fprintf(os.Stderr, "rollback apply failed: %v\n", err)
		os.Exit(1)
	}

	// cleans pending and rollback states
	if commit.IsPending() {
		commit.CancelRollback()
		commit.ClearPending()
	}

	fmt.Println("rolled back to previous ruleset")
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
	fmt.Println("      --list-ruleset                 list NFT ruleset output")
	fmt.Println("  status                           show current ruleset")
	fmt.Println("  confirm                          confirm applied config")
	fmt.Println("  rollback                         revert to previous rule snapshot")
	fmt.Println("  version                          show version info")
}

// reorders flag args to allow dynamic flag inputs from user
func sortFlags(args []string) []string {
	var flags, positional []string
	for _, arg := range args {
		if strings.HasPrefix(arg, "-") {
			flags = append(flags, arg)
		} else {
			positional = append(positional, arg)
		}
	}
	return append(flags, positional...)
}

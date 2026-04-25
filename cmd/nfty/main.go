package main

import (
	"crypto/sha256"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/adrian-griffin/nfty/colour"
	"github.com/adrian-griffin/nfty/commit"
	"github.com/adrian-griffin/nfty/config"
	"github.com/adrian-griffin/nfty/counters"
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
		runConfirm()
	case "rollback":
		runRollback()
	case "rollback-if-pending":
		runRollbackIfPending()
	case "restore":
		runRestore()
	case "counters":
		runCounters()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

// calculate checksum/hash off of nft config
// first 8 chars only
func scriptChecksum(script string) string {
	h := sha256.Sum256([]byte(script))
	return fmt.Sprintf("%x", h[:4])
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

	// hostname for the header line
	hostname, _ := os.Hostname()
	now := time.Now().Format("2006-01-02 15:04:05")

	// in case user has dementia
	fmt.Printf("  %s %s%s%s\n",
		colour.Grey("nfty"),
		colour.Bold("apply"),
		strings.Repeat(" ", 15),
		colour.DarkGrey(hostname+" · "+now),
	)
	fmt.Println()

	divider()

	// load configfile from path
	cfg, err := config.Load(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(1)
	}

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

	checksum := scriptChecksum(script)

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

	// [TODO]: run safety checks (safety package)

	fmt.Printf("  %s %s %s\n", colour.Grey("loaded config:"), cfg.Core.Name, colour.DarkGrey(cfg.Core.Description))
	fmt.Printf("  %s\n", colour.Grey("if not confirmed (due to lockout, terminated ssh session, etc), firewall will revert to previous known good state"))
	fmt.Println()
	fmt.Printf("  %s %s\n", colour.Grey("checksum:"), colour.DarkGrey(checksum))

	divider()

	// warn loudly if skip-confirm passed
	if *skipConfirm {
		fmt.Printf("  %s\n", colour.Red("⚠ WARNING: --skip-confirm is active"))

		fmt.Printf("    %s %s\n",
			colour.Grey("automatic rollback is disabled. if this ruleset is bad, you can"),
			colour.Red("be locked out"),
		)
		divider()
		// TODO: POLL FOR 'y/n'

		// formally apply generated NFT config
		if err := nft.ApplyScript(script); err != nil {
			fmt.Fprintf(os.Stderr, "apply failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("%s\n", colour.Green("  ✓ ruleset applied and committed"))

		// skip-confirm: persist immediately, no timer
		if cfg.Core.Persist {
			if err := commit.SaveRunningRuleset(script); err != nil {
				fmt.Fprintf(os.Stderr, "failed to persist ruleset: %v\n", err)
			}
		}

		divider()

		fmt.Printf("  %s  %s\n",
			colour.Grey("run "+colour.Cyan("nfty rollback")+" to revert"),
			colour.Grey("·  "+colour.Cyan("nfty counters")+" for statistics"),
		)
	} else {
		// formally apply generated NFT config
		if err := nft.ApplyScript(script); err != nil {
			fmt.Fprintf(os.Stderr, "apply failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("  %s\n", colour.Green("✓ ruleset applied - awaiting confirm"))
		divider()

		// write pending state to .json file on disk
		if err := commit.WritePending(configPath, checksum, *confirmSeconds); err != nil {
			fmt.Fprintf(os.Stderr, "failed to write pending state: %v\n", err)
			os.Exit(1)
		}

		// schedule systemd rollback timer
		nftyPath, _ := os.Executable()
		if err := commit.ScheduleRollback(*confirmSeconds, nftyPath); err != nil {
			fmt.Fprintf(os.Stderr, "failed to schedule rollback timer: %v\n", err)
			fmt.Fprintln(os.Stderr, "WARNING: auto-rollback is NOT active. please confirm or manually rollback") // maybe kill process?
		}

		// output confirmation details
		deadline := time.Now().Add(time.Duration(*confirmSeconds) * time.Second)
		fmt.Printf("  %s%s %s\n",
			label("confirm window"),
			colour.Yellow(fmt.Sprintf("%ds", *confirmSeconds)),
			colour.DarkGrey("(expires "+deadline.Format("15:04:05")+")"),
		)

		fmt.Printf("  %s%s\n", label("rollback via"), colour.Grey("systemd timer - survives shell death"))
		divider()

		fmt.Printf("  %s  %s  %s\n",
			colour.Grey("run "+colour.Cyan("nfty confirm")+" to approve"),
			colour.Grey("·  "+colour.Cyan("nfty rollback")+" to undo"),
			colour.Grey("·  "+colour.Cyan("nfty status")+" for more info"),
		)
	}
}

// perform change-approval/confirmation logic
func runConfirm() {
	if !commit.IsPending() {
		fmt.Println(colour.Grey("there are no pending changes to confirm"))
		return
	}

	// hostname for the header line
	hostname, _ := os.Hostname()
	now := time.Now().Format("2006-01-02 15:04:05")

	// execution header
	fmt.Printf("  %s %s%s%s\n",
		colour.Grey("nfty"),
		colour.Bold("confirm"),
		strings.Repeat(" ", 15),
		colour.DarkGrey(hostname+" · "+now),
	)
	fmt.Println()

	divider()

	state, err := commit.LoadPending()
	if err == nil {
		fmt.Printf("  %s%s\n", label("confirming"), colour.Blue(state.ConfigPath))
		fmt.Printf("  %s%s %s\n", label("applied by"), colour.Grey(state.AppliedBy), colour.DarkGrey("("+state.AppliedAt.Format("15:04:05")+")"))
		fmt.Printf("  %s%s\n", label("checksum"), colour.DarkGrey(state.Checksum))
		divider()
	}

	// cancel systemd execution timer
	commit.CancelRollback()

	// persist current ruleset for boot restore
	currentRuleset, err := nft.ListRulesetScript()
	if err != nil {
		fmt.Fprintf(os.Stderr, "WARNING: could not read current ruleset for persistence: %v\n", err)
	} else {
		if err := commit.SaveRunningRuleset(string(currentRuleset)); err != nil {
			fmt.Fprintf(os.Stderr, "WARNING: could not apply ruleset to running configuration: %v\n", err)
		}
	}

	// prior to clearing, write state to last-apply.json
	if state != nil {
		if err := commit.WriteLastApply(state); err != nil {
			fmt.Fprintf(os.Stderr, "WARNING: could not persists last apply state to last-apply.json: %v\n", err)
		}
	}

	commit.ClearPending()
	fmt.Printf("  %s\n", colour.Green("✓ ruleset applied and committed"))
	fmt.Printf("  %s  %s\n",
		colour.Grey("rollback timer cancelled"),
		colour.Grey("·  "+"pending state cleared"),
	)
}

// perform rollback functionality if pending state is detected
func runRollbackIfPending() {
	if !commit.IsPending() {
		return
	}

	fmt.Printf("%s\n", colour.DarkGrey("[ systemd: nfty-rollback.timer fired ]"))
	fmt.Printf("%s\n", colour.Red("commit-confirm timer expired"))
	fmt.Printf("%s\n", colour.Grey("reverting to previous known good state"))

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
	divider()
	fmt.Printf("%s\n", colour.Green("✓ previous ruleset restored"))
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

	// count lists
	fmt.Printf("  ipv4 address lists:     %d\n", len(cfg.Lists.IPv4))
	fmt.Printf("  ipv6 address lists:     %d\n", len(cfg.Lists.IPv6))

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

// max length left-column for labels
const labelWidth = 18

// return grey for left-column labels
func label(s string) string {
	return colour.Grey(fmt.Sprintf("%-*s", labelWidth, s))
}

// writes section divier
func divider() {
	fmt.Println(colour.Grey("  " + strings.Repeat("─", 52)))
}

// gathers file path & last-edited time
func fileInfo(path string) string {
	info, err := os.Stat(path)
	if err != nil {
		return ""
	}

	// make that shit human readable tho
	size := info.Size()
	var sizeStr string
	switch {
	// if < 1048576b (1MB)
	case size >= 1<<20:
		sizeStr = fmt.Sprintf("%.1fMB", float64(size)/float64(1<<20))
		// if < 1024 (1KB)
	case size >= 1<<10:
		sizeStr = fmt.Sprintf("%.1fKB", float64(size)/float64(1<<10))
	default:
		sizeStr = fmt.Sprintf("%dB", size)
	}

	// convert time into HR
	age := time.Since(info.ModTime()).Round(time.Second)
	var ageStr string
	switch {
	case age < time.Minute:
		ageStr = fmt.Sprintf("%ds ago", int(age.Seconds()))
	case age < time.Hour:
		ageStr = fmt.Sprintf("%dm ago", int(age.Minutes()))
	case age < 24*time.Hour:
		ageStr = fmt.Sprintf("%dh ago", int(age.Hours()))
	default:
		ageStr = fmt.Sprintf("%dh ago", int(age.Hours()))
	}

	return fmt.Sprintf("%s, %s", sizeStr, ageStr)
}

// build status output
func runStatus() {
	args := sortFlags(os.Args[2:]) // sort flags
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	listRuleset := fs.Bool("list-ruleset", false, "show full nftables ruleset")
	fs.Parse(args)

	// hostname for the header line
	hostname, _ := os.Hostname()
	now := time.Now().Format("2006-01-02 15:04:05")

	// execution header
	fmt.Printf("  %s %s%s%s\n",
		colour.Grey("nfty"),
		colour.Bold("status"),
		strings.Repeat(" ", 15),
		colour.DarkGrey(hostname+" · "+now),
	)
	fmt.Println()

	divider()

	// ~~ pending output
	if commit.IsPending() {
		state, err := commit.LoadPending()
		if err == nil {
			remaining := time.Until(state.Deadline).Round(time.Second)

			// apply header & badge
			fmt.Printf("  %s   %s\n", colour.Bold(colour.Yellow("▲ pending changes")), colour.Yellow("awaiting confirm"))

			// detail rows
			fmt.Printf("    %s%s\n", label("config"), colour.Blue(state.ConfigPath))
			fmt.Printf("    %s%s\n", label("checksum"), colour.Blue(state.Checksum))
			fmt.Printf("    %s%s\n", label("applied by"), colour.Grey(state.AppliedBy))
			fmt.Printf("    %s%s\n", label("applied at"), colour.Grey(state.AppliedAt.Format("15:04:05")))

			// deadline turns red when <10s
			if remaining > 0 {
				deadlinecolour := colour.Yellow
				if remaining < 10*time.Second {
					deadlinecolour = colour.Red
				}
				fmt.Printf("    %s%s %s\n",
					label("deadline"),
					deadlinecolour(remaining.String()+" remaining"),
					// expiry time stays grey
					colour.DarkGrey("(expires "+state.Deadline.Format("15:04:05")+")"),
				)
			} else {
				fmt.Printf("    %s%s\n", label("deadline"), colour.Red("expired (rollback in progress)"))
			}

			fmt.Printf("    %s%s\n", label("rollback via"), colour.Grey("systemd timer - survives shell death"))
		}
	} else {
		fmt.Printf("  %s\n", colour.Green("✓ no pending changes"))

		// show last confirmed apply
		if last, err := commit.LoadLastApply(); err == nil {
			fmt.Printf("    %s%s\n", label("last apply by"), colour.Grey(last.AppliedBy))
			fmt.Printf("    %s%s %s\n",
				label("last apply at"),
				colour.Grey(last.ConfirmedAt.Format("15:04:05")),
				colour.DarkGrey(last.ConfirmedAt.Format("(2006-01-02)")),
			)
			fmt.Printf("    %s%s\n", label("checksum"), colour.DarkGrey(last.Checksum))
		}
	}

	divider()

	// ~~ status/state files
	fmt.Printf("  %s\n", colour.Grey("state files"))

	// build transient struct for each statefile
	for _, f := range []struct {
		label string
		path  string
	}{
		{"running.nft", commit.RunningFile},
		{"rollback.nft", commit.RollbackFile},
		{"last-apply.json", commit.LastApplyFile},
	} {
		if _, err := os.Stat(f.path); err == nil {
			finfo := fileInfo(f.path)
			fmt.Printf("    %s%s", label(f.label), colour.Green("present"))
			if finfo != "" {
				fmt.Printf(" %s", colour.Grey("- "+finfo))
			}
			fmt.Println()
		} else {
			fmt.Printf("    %s%s\n", label(f.label), colour.Red("not found"))
		}
	}

	divider()

	// ~~ active ruleset stats
	out, err := nft.ListRulesetScript()
	if err != nil {
		fmt.Fprintf(os.Stderr, "  %s %v\n", colour.Red("error:"), err)
		os.Exit(1)
	}

	// stringify
	ruleset := string(out)
	tables, chains, ruleCount := countNftObjects(ruleset)

	fmt.Printf("  %s\n", colour.Grey("active ruleset"))
	fmt.Printf("    %s%d\n", label("tables"), tables)
	fmt.Printf("    %s%d\n", label("chains"), chains)
	fmt.Printf("    %s%d\n", label("rules"), ruleCount)

	// ~~ footer
	if commit.IsPending() {
		divider()
		fmt.Printf("  %s  %s\n",
			colour.Grey("run "+colour.Cyan("nfty confirm")+" to approve"),
			colour.Grey("·  "+colour.Cyan("nfty rollback")+" to undo"),
		)
	} else {
		divider()
		fmt.Printf("  %s  %s\n",
			colour.Grey("run "+colour.Cyan("nfty counters")+" for statistics"),
			colour.Grey("·  "+colour.Cyan("nfty status --list-ruleset")+" for full firewall"),
		)
	}

	// ~~ optional full nft dump
	if *listRuleset {
		fmt.Println()
		divider()
		fmt.Println()
		fmt.Println(colour.Grey("--- live nftables ruleset ---"))
		fmt.Println()
		fmt.Print(ruleset)
	}
}

// runs counters parsing and displays output
func runCounters() {
	counts, err := counters.ParseCounters()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read counters: %v\n", err)
		os.Exit(1)
	}

	if len(counts) == 0 {
		fmt.Println("no nfty counters found, try re-applying nfty config")
		return
	}

	// group by ip family in display
	currentFamily := ""
	fmt.Printf("\n  %-50s %12s %10s\n", "RULE", "PACKETS", "BYTES")
	fmt.Printf("  %-50s %12s %10s\n", strings.Repeat("-", 50), strings.Repeat("-", 12), strings.Repeat("-", 10))

	for _, c := range counts {
		// print family/chain header when it changes
		familyChain := c.Family + " " + c.Chain
		if familyChain != currentFamily {
			fmt.Printf("\n [%s/%s]\n", c.Family, c.Chain)
			currentFamily = familyChain
		}

		fmt.Printf("  %-50s %12s %10s\n",
			c.Comment,
			counters.FormatPackets(c.Packets),
			counters.FormatBytes(c.Bytes))
	}
	fmt.Println()
}

// performs a rough count of tables, chains, and rules from raw nft
func countNftObjects(ruleset string) (tables, chains, rules int) {
	for _, line := range strings.Split(ruleset, "\n") {
		trimmed := strings.TrimSpace(line)
		// every hit of 'table' is probably a table
		if strings.HasPrefix(trimmed, "table ") {
			tables++
			// likewise with chain
		} else if strings.HasPrefix(trimmed, "chain ") {
			chains++
		} else if trimmed != "" &&
			// everything else, so long as it doesnt include these
			// keywords, is probably a rule
			!strings.HasPrefix(trimmed, "}") &&
			!strings.HasPrefix(trimmed, "type ") &&
			!strings.HasPrefix(trimmed, "set ") &&
			!strings.HasPrefix(trimmed, "elements") &&
			!strings.HasPrefix(trimmed, "flags ") &&
			!strings.HasPrefix(trimmed, "auto-merge") &&
			!strings.HasPrefix(trimmed, "comment ") &&
			!strings.HasPrefix(trimmed, "table ") &&
			!strings.HasPrefix(trimmed, "chain ") {
			rules++
		}
	}
	return
}

// grabs previous snapshot and applies it
func runRollback() {

	// hostname for the header line
	hostname, _ := os.Hostname()
	now := time.Now().Format("2006-01-02 15:04:05")

	// execution header
	fmt.Printf("  %s %s%s%s\n",
		colour.Grey("nfty"),
		colour.Bold("rollback"),
		strings.Repeat(" ", 15),
		colour.DarkGrey(hostname+" · "+now),
	)
	fmt.Println()

	divider()

	fmt.Printf("  %s\n", colour.Yellow("↺ rolling back to previous ruleset"))
	divider()

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

	fmt.Printf("  %s\n", colour.Green("✓ previous ruleset restored"))
	fmt.Printf("  %s  %s\n",
		colour.Grey("rollback timer cancelled"),
		colour.Grey("·  "+"pending state cleared"),
	)
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
	fmt.Println("  counters                         display counters/statistics")
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

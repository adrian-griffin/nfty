// apply.go
// logic for new ruleset application
package commit

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/adrian-griffin/nfty/internal/colour"
	"github.com/adrian-griffin/nfty/internal/config"
	"github.com/adrian-griffin/nfty/internal/nft"
	"github.com/adrian-griffin/nfty/internal/tools"
)

// applies parsed config as active nftables ruleset
func RunApply(args []string) {
	// sort args
	args = tools.SortFlags(args)
	// define new flagset for apply sub-options
	flagSet := flag.NewFlagSet("apply", flag.ExitOnError)
	// sub-option flags for apply set
	skipConfirm := flagSet.Bool("skip-confirm", false, "skip automatic rollback (use with caution)")
	confirmSeconds := flagSet.Int("commit-confirm", DefaultConfirmSeconds,
		fmt.Sprintf("rollback timer in seconds (%ds default, %ds minimum)",
			DefaultConfirmSeconds, MinConfirmSeconds))
	flagSet.Parse(args)

	// reject rollback timers less than MinConfirmSeconds
	// ScheduleRollback enforces this as well, this check is purely for UX
	if !*skipConfirm && *confirmSeconds < MinConfirmSeconds {
		fmt.Fprintf(os.Stderr, "ERROR: --commit-confirm must be at least %ds, got %ds\n",
			MinConfirmSeconds, *confirmSeconds)
		os.Exit(1)
	}

	// if supplied .toml is empty err & exit
	configPath := flagSet.Arg(0)
	if configPath == "" {
		fmt.Fprintln(os.Stderr, "usage: nfty apply [--skip-confirm] [--commit-confirm <seconds>] <config.toml>")
		os.Exit(1)
	}

	// reject if theres already pending apply
	if IsPending() {
		fmt.Fprintln(os.Stderr, "a pending apply already exists, run 'nfty confirm' or 'nfty rollback' first")
		os.Exit(1)
	}

	// print header output
	tools.CommandExecuteHeader("apply")

	// load configfile from path
	cfg, err := config.Load(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(1)
	}

	// generate nft script
	script, err := nft.Generate(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "rule generation failed: %v\n", err)
		os.Exit(1)
	}

	// validate script syntax with `nft --cf`
	if err := nft.ValidateScript(script); err != nil {
		fmt.Fprintf(os.Stderr, "nft syntax validation failed: %v\n", err)
		os.Exit(1)
	}

	// collect first 8 chars of nft (not nfty) config hash for display
	checksum := nft.ScriptChecksum(script)

	// ensure /var/nfty/ exists
	if err := CheckDir(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to create nfty directory: %v\n", err)
		os.Exit(1)
	}

	// run safety checks w/ pre-apply prompt
	issues := config.RunSafetyChecks(cfg)
	errCount := tools.PrintIssues(issues)

	if errCount > 0 {
		fmt.Fprintf(os.Stderr, "\n  %s\n",
			colour.Yellow(fmt.Sprintf("%d safety error(s) detected in config", errCount)),
		)
		// prompt y/n to proceed
		proceed, err := tools.ConfirmYesNo("  continue anyway? (y/n): ")
		if err != nil {
			// if non-interactive tty or reader err, reject changes
			fmt.Fprintln(os.Stderr, "ERROR: safety errors require confirmation but stdin is not interactive")
			os.Exit(1)
		}
		if !proceed {
			fmt.Fprintf(os.Stderr, "  %s\n", colour.Yellow("⏹ apply cancelled"))
			os.Exit(1)
		}
	}

	// collect current ruleset for rollback config
	currentRuleset, err := nft.ListRulesetScript()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to snapshot current ruleset: %v\n", err)
		os.Exit(1)
	}
	// save current ruleset as snapshot to disk
	if err := SaveRollbackSnapshot(currentRuleset); err != nil {
		fmt.Fprintf(os.Stderr, "failed to save rollback snapshot: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("  %s %s %s\n", colour.Grey("loaded config:"), cfg.Core.Name, colour.DarkGrey(cfg.Core.Description))
	fmt.Printf("  %s\n", colour.Grey("if not confirmed (due to lockout, terminated ssh session, etc), firewall will revert to previous known good state"))
	fmt.Println()
	fmt.Printf("  %s %s\n", colour.Grey("checksum:"), colour.DarkGrey(checksum))

	tools.Divider()

	// warn loudly if skip-confirm passed
	if *skipConfirm {
		// check if terminal is cli/tty and interactive
		// if not, reject changes
		if !tools.StdinIsTTY() {
			fmt.Fprintln(os.Stderr, "ERROR: --skip-confirm requires an interactive terminal")
			os.Exit(1)
		}

		fmt.Printf("  %s\n", colour.Red("⚠ WARNING: --skip-confirm is active"))

		fmt.Printf("    %s %s\n",
			colour.Grey("automatic rollback is disabled. if this ruleset is bad,"),
			colour.Red("you can be locked out"),
		)

		tools.Divider()

		// prompt for --skip-confirm proceed
		proceed, err := tools.ConfirmYesNo("\n  proceed? (y/n): ")
		// check again for interactive tty
		// if prompt reader receives err or EOF, reject
		if err != nil {
			fmt.Fprintln(os.Stderr, "ERROR: --skip-confirm requires an interactive terminal")
			os.Exit(1)
		}
		// if proceed cancelled, return and notify
		if !proceed {
			fmt.Printf("%s\n", colour.Yellow("  ⏹ application cancelled"))
			return
		}

		// formally apply generated NFT config
		if err := nft.ApplyScript(script); err != nil {
			fmt.Fprintf(os.Stderr, "  apply failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("%s\n", colour.Green("  ✓ ruleset applied and committed"))

		// save running.nft after application
		currentRuleset, err := nft.ListRulesetScript()
		if err != nil {
			// never write on a failed read, empty output would clobber the boot-restore ruleset
			fmt.Fprintf(os.Stderr, "WARNING: failed to collect current running NFT ruleset: %v\n", err)
		} else {
			// write running nft output to persist file
			if err := SaveRunningRuleset(string(currentRuleset)); err != nil {
				fmt.Fprintf(os.Stderr, "WARNING: failed to save NFT ruleset to disk: %v\n", err)
			}
		}

		if err := WriteLastApplyDirect(configPath, checksum); err != nil {
			fmt.Fprintf(os.Stderr, "WARNING: could not save last apply state: %v\n", err)
		}

		tools.Divider()

		fmt.Printf("  %s  %s\n",
			colour.Grey("run "+colour.Cyan("nfty rollback")+" to revert"),
			colour.Grey("·  "+colour.Cyan("nfty counters")+" for statistics"),
		)
	} else {

		// resolve currently-running nfty path
		// exit gracefully upon err
		nftyPath, err := os.Executable()
		if err != nil {
			fmt.Fprintf(os.Stderr, "could not locate nfty binary for rollback timer: %v\n", err)
			os.Exit(1)
		}

		// write pending state to .json file on disk
		if err := WritePending(configPath, checksum, *confirmSeconds); err != nil {
			fmt.Fprintf(os.Stderr, "failed to write pending state: %v\n", err)
			os.Exit(1)
		}

		// schedule systemd rollback timer
		if err := ScheduleRollback(*confirmSeconds, nftyPath); err != nil {
			fmt.Fprintf(os.Stderr, "failed to schedule rollback timer: %v\n", err)
			fmt.Fprintln(os.Stderr, "ERROR: rollback scheduling failed -- rejecting apply")
			if err := ClearPending(); err != nil {
				fmt.Fprintf(os.Stderr, "WARNING: could not clear pending state file: %v\n", err)
			}
			os.Exit(1)
		}

		// formally apply generated NFT config
		// timer is running at this stage, so any failure must disarm the timer
		if err := nft.ApplyScript(script); err != nil {
			fmt.Fprintf(os.Stderr, "apply failed: %v\n", err)
			// cancel rollback timer
			if err := CancelRollback(); err != nil {
				fmt.Fprintf(os.Stderr, "WARNING: could not cancel rollback timer: %v\n", err)
			}
			// clear pending state
			if err := ClearPending(); err != nil {
				fmt.Fprintf(os.Stderr, "WARNING: could not clear pending state: %v\n", err)
			}
			os.Exit(1)
		}

		fmt.Printf("  %s\n", colour.Green("✓ ruleset applied - awaiting confirm"))
		tools.Divider()

		// output confirmation details
		deadline := time.Now().Add(time.Duration(*confirmSeconds) * time.Second)
		fmt.Printf("  %s%s %s\n",
			tools.Label("confirm window"),
			colour.Yellow(fmt.Sprintf("%ds", *confirmSeconds)),
			colour.DarkGrey("(expires "+deadline.Format("15:04:05")+")"),
		)

		fmt.Printf("  %s%s\n", tools.Label("rollback via"), colour.Grey("systemd timer - survives shell death"))
		tools.Divider()

		fmt.Printf("  %s  %s  %s\n",
			colour.Grey("run "+colour.Cyan("nfty confirm")+" to approve"),
			colour.Grey("·  "+colour.Cyan("nfty rollback")+" to undo"),
			colour.Grey("·  "+colour.Cyan("nfty status")+" for more info"),
		)
	}
	os.Exit(0)
}

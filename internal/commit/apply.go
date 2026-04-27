package commit

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

// applies parsed config as active nftables ruleset
func RunApply(args []string) {
	// sort args
	args = tools.SortFlags(args)
	// define new flagset for apply sub-options
	flagSet := flag.NewFlagSet("apply", flag.ExitOnError)
	// sub-option flags for apply set
	skipConfirm := flagSet.Bool("skip-confirm", false, "skip automatic rollback (dangerous)")
	confirmSeconds := flagSet.Int("commit-confirm", 30, "rollback timer in seconds (30s default)")
	flagSet.Parse(args)

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

	// hostname for the header line
	hostname, _ := os.Hostname()
	now := time.Now().Format("2006-01-02 15:04:05")

	fmt.Printf("  %s %s%s%s\n",
		colour.Grey("nfty"),
		colour.Bold("apply"),
		strings.Repeat(" ", 15),
		colour.DarkGrey(hostname+" · "+now),
	)

	tools.Divider()

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

	checksum := nft.ScriptChecksum(script)

	// ensure /var/nfty/ exists
	if err := CheckDir(); err != nil {
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
	if err := SaveRollbackSnapshot(currentRuleset); err != nil {
		fmt.Fprintf(os.Stderr, "failed to save rollback snapshot: %v\n", err)
		os.Exit(1)
	}

	// [TODO]: run safety checks (safety package)

	fmt.Printf("  %s %s %s\n", colour.Grey("loaded config:"), cfg.Core.Name, colour.DarkGrey(cfg.Core.Description))
	fmt.Printf("  %s\n", colour.Grey("if not confirmed (due to lockout, terminated ssh session, etc), firewall will revert to previous known good state"))
	fmt.Println()
	fmt.Printf("  %s %s\n", colour.Grey("checksum:"), colour.DarkGrey(checksum))

	tools.Divider()

	// warn loudly if skip-confirm passed
	if *skipConfirm {
		fmt.Printf("  %s\n", colour.Red("⚠ WARNING: --skip-confirm is active"))

		fmt.Printf("    %s %s\n",
			colour.Grey("automatic rollback is disabled. if this ruleset is bad,"),
			colour.Red("you can be locked out"),
		)

		tools.Divider()

		var userConfirmSkip string
		// poll for user confirmation on skip
		for {
			fmt.Printf("\n  proceed? (y/n): ")

			// scan for input
			fmt.Scanln(&userConfirmSkip)

			// switch to catch input choices
			switch strings.ToLower(userConfirmSkip) {
			case "y":
				// formally apply generated NFT config
				if err := nft.ApplyScript(script); err != nil {
					fmt.Fprintf(os.Stderr, "  apply failed: %v\n", err)
					os.Exit(1)
				}
				fmt.Printf("%s\n", colour.Green("  ✓ ruleset applied and committed"))

				// skip-confirm: persist immediately, no timer
				if cfg.Core.Persist {
					// save running.nft after application
					currentRuleset, err := nft.ListRulesetScript()
					if err != nil {
						fmt.Fprintf(os.Stderr, "failed to collect current ruleset: %v\n", err)
					}

					if err := SaveRunningRuleset(string(currentRuleset)); err != nil {
						fmt.Fprintf(os.Stderr, "failed to persist ruleset: %v\n", err)
					}
				}

				if err := WriteLastApplyDirect(configPath, checksum); err != nil {
					fmt.Fprintf(os.Stderr, "WARNING: could not save last apply state: %v\n", err)
				}

			case "n":
				fmt.Printf("%s\n", colour.Yellow("  ⏹ application cancelled"))
				return

			default:
				fmt.Println("invalid input, please try again")
				continue
			}
			break
		}

		tools.Divider()

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
		tools.Divider()

		// write pending state to .json file on disk
		if err := WritePending(configPath, checksum, *confirmSeconds); err != nil {
			fmt.Fprintf(os.Stderr, "failed to write pending state: %v\n", err)
			os.Exit(1)
		}

		// schedule systemd rollback timer
		nftyPath, _ := os.Executable()
		if err := ScheduleRollback(*confirmSeconds, nftyPath); err != nil {
			fmt.Fprintf(os.Stderr, "failed to schedule rollback timer: %v\n", err)
			fmt.Fprintln(os.Stderr, "WARNING: auto-rollback is NOT active. please confirm or manually rollback") // maybe kill process?
		}

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
}

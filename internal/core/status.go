package core

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/adrian-griffin/nfty/internal/colour"
	"github.com/adrian-griffin/nfty/internal/commit"
	"github.com/adrian-griffin/nfty/internal/nft"
	"github.com/adrian-griffin/nfty/internal/tools"
)

// build status output
func RunStatus() {
	args := tools.SortFlags(os.Args[2:]) // sort flags
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	listRuleset := fs.Bool("list-ruleset", false, "show full nftables ruleset")
	fs.Parse(args)

	// print header output
	tools.CommandExecuteHeader("status")

	// ~~ pending output
	if commit.IsPending() {
		state, err := commit.LoadPending()
		if err == nil {
			remaining := time.Until(state.Deadline).Round(time.Second)

			// apply header & badge
			fmt.Printf("  %s   %s\n", colour.Bold(colour.Yellow("▲ pending changes")), colour.Yellow("awaiting confirm"))

			// detail rows
			fmt.Printf("    %s%s\n", tools.Label("config"), colour.Blue(state.ConfigPath))
			fmt.Printf("    %s%s\n", tools.Label("checksum"), colour.Blue(state.Checksum))
			fmt.Printf("    %s%s\n", tools.Label("applied by"), colour.Grey(state.AppliedBy))
			fmt.Printf("    %s%s\n", tools.Label("applied at"), colour.Grey(state.AppliedAt.Format("15:04:05")))

			// deadline turns red when <10s
			if remaining > 0 {
				deadlinecolour := colour.Yellow
				if remaining < 10*time.Second {
					deadlinecolour = colour.Red
				}
				fmt.Printf("    %s%s %s\n",
					tools.Label("deadline"),
					deadlinecolour(remaining.String()+" remaining"),
					// expiry time stays grey
					colour.DarkGrey("(expires "+state.Deadline.Format("15:04:05")+")"),
				)
			} else {
				fmt.Printf("    %s%s\n", tools.Label("deadline"), colour.Red("expired (rollback in progress)"))
			}

			fmt.Printf("    %s%s\n", tools.Label("rollback via"), colour.Grey("systemd timer - survives shell death"))
		}
	} else {
		fmt.Printf("  %s\n", colour.Green("✓ no pending changes"))

		// show last confirmed apply
		if last, err := commit.LoadLastApply(); err == nil {
			fmt.Printf("    %s%s\n", tools.Label("last apply by"), colour.Grey(last.AppliedBy))
			fmt.Printf("    %s%s %s\n",
				tools.Label("last apply at"),
				colour.Grey(last.ConfirmedAt.Format("15:04:05")),
				colour.DarkGrey(last.ConfirmedAt.Format("(2006-01-02)")),
			)
			fmt.Printf("    %s%s\n", tools.Label("checksum"), colour.DarkGrey(last.Checksum))
		}
	}

	tools.Divider()

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
			finfo := tools.FileInfo(f.path)
			fmt.Printf("    %s%s", tools.Label(f.label), colour.Green("present"))
			if finfo != "" {
				fmt.Printf(" %s", colour.Grey("- "+finfo))
			}
			fmt.Println()
		} else {
			fmt.Printf("    %s%s\n", tools.Label(f.label), colour.Red("not found"))
		}
	}

	tools.Divider()

	// ~~ active ruleset stats
	out, err := nft.ListRulesetScript()
	if err != nil {
		fmt.Fprintf(os.Stderr, "  %s %v\n", colour.Red("error:"), err)
		os.Exit(1)
	}

	// stringify
	ruleset := string(out)
	tables, chains, ruleCount := tools.CountNftObjects(ruleset)

	fmt.Printf("  %s\n", colour.Grey("active ruleset"))
	fmt.Printf("    %s%d\n", tools.Label("tables"), tables)
	fmt.Printf("    %s%d\n", tools.Label("chains"), chains)
	fmt.Printf("    %s%d\n", tools.Label("rules"), ruleCount)

	// ~~ footer
	if commit.IsPending() {
		tools.Divider()
		fmt.Printf("  %s  %s\n",
			colour.Grey("run "+colour.Cyan("nfty confirm")+" to approve"),
			colour.Grey("·  "+colour.Cyan("nfty rollback")+" to undo"),
		)
	} else {
		tools.Divider()
		fmt.Printf("  %s  %s\n",
			colour.Grey("run "+colour.Cyan("nfty counters")+" for statistics"),
			colour.Grey("·  "+colour.Cyan("nfty status --list-ruleset")+" for full firewall"),
		)
	}

	// ~~ optional full nft dump
	if *listRuleset {
		fmt.Println()
		tools.Divider()
		fmt.Println()
		fmt.Println(colour.Grey("--- live nftables ruleset ---"))
		fmt.Println()
		fmt.Print(ruleset)
	}
}

// statusview.go
// renders status snapshot. writes to io.Writer directly
// cli-native emits on os.Stdout, tui buffers it in the frame, tests hand it bytes.Buffer
package core

import (
	"fmt"
	"io"
	"time"

	"github.com/adrian-griffin/nfty/internal/colour"
	"github.com/adrian-griffin/nfty/internal/tools"
)

// what the caller wants included with status
type StatusOpts struct {
	ListRuleset bool // append full `nft list ruleset` dump to buffer
}

// renders pending confirm details, or a "no pending changes" message
func RenderPending(w io.Writer, s *Status) {
	// if not pending, emit "no pending changes" and previous apply's deets
	if !s.HasPending {
		fmt.Fprintf(w, "  %s\n", colour.Green("✓ no pending changes"))

		last := s.LastApply // grab last apply details
		if last == nil {
			return
		}
		// print last apply's details
		fmt.Fprintf(w, "    %s%s\n", tools.Label("last apply by"), colour.Grey(last.AppliedBy))
		fmt.Fprintf(w, "    %s%s %s\n",
			tools.Label("last apply at"),
			colour.Grey(last.ConfirmedAt.Format("15:04:05")),
			colour.DarkGrey(last.ConfirmedAt.Format("(2006-01-02)")),
		)
		fmt.Fprintf(w, "    %s%s\n", tools.Label("checksum"), colour.DarkGrey(last.Checksum))
		return
	}

	// if pending.json fails to parse, alert user with unique pending message and return
	state := s.Pending
	if state == nil {
		fmt.Fprintf(w, "  %s\n  %s\n  %s\n",
			colour.Bold(colour.Yellow("▲ pending changes")),
			colour.Red("the pending.json state file is unreadable!"),
			colour.Red("confirm will still work as intended"),
		)
		return
	}

	// print default pending changes header
	fmt.Fprintf(w, "  %s   %s\n",
		colour.Bold(colour.Yellow("▲ pending changes")),
		colour.Yellow("awaiting confirm"),
	)
	// print pending state details
	fmt.Fprintf(w, "    %s%s\n", tools.Label("config"), colour.Blue(state.ConfigPath))
	fmt.Fprintf(w, "    %s%s\n", tools.Label("checksum"), colour.Blue(state.Checksum))
	fmt.Fprintf(w, "    %s%s\n", tools.Label("applied by"), colour.Grey(state.AppliedBy))
	fmt.Fprintf(w, "    %s%s\n", tools.Label("applied at"), colour.Grey(state.AppliedAt.Format("15:04:05")))

	// pending note is yellow, turns red if less than 30 seconds remain
	remaining := time.Until(state.Deadline).Round(time.Second)
	if remaining > 0 {
		deadlinecolour := colour.Yellow
		if remaining < 30*time.Second {
			deadlinecolour = colour.Red
		}
		fmt.Fprintf(w, "    %s%s %s\n",
			tools.Label("deadline"),
			deadlinecolour(remaining.String()+" remaining"),
			// expiry time stays grey
			colour.DarkGrey("(expires "+state.Deadline.Format("15:04:05")+")"),
		)
	} else {
		fmt.Fprintf(w, "    %s%s\n", tools.Label("deadline"), colour.Red("expired (rollback, can take a few seconds)"))
	}

	fmt.Fprintf(w, "    %s%s\n", tools.Label("rollback via"), colour.Grey("systemd timer - survives shell death"))
}

// report status of on-disk state files
func RenderStateFiles(w io.Writer, s *Status) {
	// state files header
	fmt.Fprintf(w, "  %s\n", colour.Grey("state files"))

	// iterate over state files, report present/missing and extra info
	for _, f := range s.StateFiles {
		// if a file is missing, report red and skip
		if !f.Present {
			fmt.Fprintf(w, "    %s%s\n", tools.Label(f.Label), colour.Red("not found"))
			continue
		}
		// otherwise print green and additional info
		fmt.Fprintf(w, "    %s%s", tools.Label(f.Label), colour.Green("present"))
		if f.Info != "" {
			fmt.Fprintf(w, " %s", colour.Grey("- "+f.Info))
		}
		fmt.Fprintln(w)
	}
}

// displays rule counts scraped from the live nftables ruleset
func RenderRulesetInfo(w io.Writer, s *Status) {
	fmt.Fprintf(w, "  %s\n", colour.Grey("active ruleset")) // header
	fmt.Fprintf(w, "    %s%d\n", tools.Label("tables"), s.Ruleset.Tables)
	fmt.Fprintf(w, "    %s%d\n", tools.Label("chains"), s.Ruleset.Chains)
	fmt.Fprintf(w, "    %s%d\n", tools.Label("rules"), s.Ruleset.Rules)
}

// emit cli status body with dividers, footer, optional dump
// tui does not call this
func RenderStatus(w io.Writer, s *Status, opts StatusOpts) {
	// pending output
	RenderPending(w, s)
	tools.FDivider(w)
	// state file output
	RenderStateFiles(w, s)
	tools.FDivider(w)
	// ruleset info output
	RenderRulesetInfo(w, s)
	tools.FDivider(w)
	// footer output (next-steps/hints)
	renderStatusFooter(w, s)

	// optional nftables full ruleset dump
	if opts.ListRuleset {
		fmt.Fprintln(w)
		tools.FDivider(w)
		fmt.Fprintln(w)
		fmt.Fprintln(w, colour.Grey("--- start live nftables ruleset ---"))
		fmt.Fprintln(w)
		fmt.Fprint(w, s.Ruleset.Script, "\n")
		fmt.Fprintln(w)
		fmt.Fprintln(w, colour.Grey("---- end live nftables ruleset ----"))
	}
}

// next-step hints. hints emitted vary depending on the active state
func renderStatusFooter(w io.Writer, s *Status) {
	if s.HasPending {
		fmt.Fprintf(w, "  %s  %s\n",
			colour.Cyan("nfty confirm")+colour.Grey(" to approve"),
			colour.Grey("·  ")+colour.Cyan("nfty rollback")+colour.Grey(" to undo"),
		)
		return
	}

	fmt.Fprintf(w, "  %s  %s\n",
		colour.Cyan("nfty counters")+colour.Grey(" for statistics"),
		colour.Grey("·  ")+colour.Cyan("nfty status --list-ruleset")+colour.Grey(" for full firewall"),
	)
}

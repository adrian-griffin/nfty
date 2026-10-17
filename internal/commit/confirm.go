// confirm.go
// confirm nfty changes and clear systemd unit

package commit

import (
	"fmt"
	"os"

	"github.com/adrian-griffin/nfty/internal/colour"
	"github.com/adrian-griffin/nfty/internal/tools"
)

// perform change-approval/confirmation logic
func RunConfirm() {
	if !IsPending() {
		fmt.Println(colour.Grey("there are no pending changes to confirm"))
		return
	}

	// print header output
	tools.CommandExecuteHeader("confirm")

	// a failed load must not abort the run, cancelling the rollback timer is the
	// whole point of confirm and it has to stay reachable with a bad pending.json
	state, err := LoadPending()
	if err != nil {
		fmt.Fprintf(os.Stderr, "WARNING: could not load pending state: %v\n", err)
	} else {
		fmt.Printf("  %s%s\n", tools.Label("confirming"), colour.Blue(state.ConfigPath))
		fmt.Printf("  %s%s %s\n", tools.Label("applied by"), colour.Grey(state.AppliedBy), colour.DarkGrey("("+state.AppliedAt.Format("15:04:05")+")"))
		fmt.Printf("  %s%s\n", tools.Label("checksum"), colour.DarkGrey(state.Checksum))
		tools.Divider()
	}

	// cancel systemd execution timer
	if err := CancelRollback(); err != nil {
		fmt.Fprintf(os.Stderr, "WARNING: could not cancel rollback timer: %v\n", err)
	}

	// promote what was applied to the confirmed ruleset
	// last-apply.json describes confirmed.nft, so only write it once the promote has landed
	persisted := false
	if state == nil {
		fmt.Fprintln(os.Stderr, "ERROR: could not persist confirmed ruleset without pending state")
	} else if err := PromotePending(state); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: could not persist confirmed ruleset: %v\n", err)
	} else {
		persisted = true
		if err := WriteLastApply(state); err != nil {
			fmt.Fprintf(os.Stderr, "WARNING: could not persist last apply state to last-apply.json: %v\n", err)
		}
	}

	// rollback is already cancelled at this point, clear pending
	if err := ClearPending(); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: could not clear pending state: %v\n", err)
		os.Exit(1)
	}

	// the live ruleset stays, but nothing on disk describes it, so say so and fail the run
	if !persisted {
		fmt.Fprintln(os.Stderr, "ERROR: the live ruleset was not persisted! A rollback will restore the previous confirmed ruleset, re-run nfty apply to persist it")
		os.Exit(1)
	}

	fmt.Printf("  %s\n", colour.Green("✓ ruleset applied and committed"))
	fmt.Printf("  %s  %s\n",
		colour.Grey("rollback timer cancelled"),
		colour.Grey("·  "+"pending state cleared"),
	)
}

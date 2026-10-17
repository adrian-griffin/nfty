// rollback.go
// handles systemd daemon rollback timer

package commit

import (
	"fmt"
	"os"

	"github.com/adrian-griffin/nfty/internal/colour"
	"github.com/adrian-griffin/nfty/internal/config"
	"github.com/adrian-griffin/nfty/internal/nft"
	"github.com/adrian-griffin/nfty/internal/tools"
)

// outcome of a rollback/undo
type undoResult int

// state struct, tracks what happened
const (
	restoredConfirmed  undoResult = iota // confirmed ruleset is live again
	removedNoConfirmed                   // nothing ever confirmed, so nfty tables removed rather than restored
	removedFallback                      // confirmed ruleset failed to apply, emergency wipe nfty tables
	undoFailed                           // nothing could be applied, the unconfirmed ruleset is still live
)

// undoes a pending apply by restoring the previously-confirmed ruleset
// upon error or failure, emergency-fallback to wiping nfty tables and warning loudly about it
func undoPending(state *PendingState) undoResult {
	pendingTable := ""
	// grab pending table from state files
	if state != nil && state.Table != "" {
		if err := config.ValidateTableName(state.Table); err != nil {
			fmt.Fprintf(os.Stderr, "WARNING: ignoring invalid table name in %s: %v\n", PendingFile, err)
		} else {
			pendingTable = state.Table
		}
	}
	confirmedTable := confirmedTableName()

	// any previously confirmed ruleset?
	confirmed, haveConfirmed, err := LoadConfirmed()
	if err != nil {
		fmt.Fprintf(os.Stderr, "WARNING: %v\n", err)
	}

	// if previous-confirm found or non-empty pending table
	// then build + apply the rollback nftables script
	if haveConfirmed || pendingTable != "" {
		script := buildRollbackScript(confirmed, haveConfirmed, pendingTable, confirmedTable)
		err := nft.ApplyScript(script)
		switch {
		// if clean apply and previous confirm found, full success
		case err == nil && haveConfirmed:
			return restoredConfirmed
		// if clean apply but no previous confirm found
		case err == nil:
			return removedNoConfirmed
		default:
			fmt.Fprintf(os.Stderr, "WARNING: could not restore confirmed ruleset: %v\n", err)
		}
	}

	// if the rollback apply fails, as a last resort, wipe nfty tables
	// wipe both the pending and confirmed tables
	if script := buildDeleteScript(pendingTable, confirmedTable); script != "" {
		if err := nft.ApplyScript(script); err != nil {
			fmt.Fprintf(os.Stderr, "WARNING: could not remove nfty tables: %v\n", err)
		} else {
			return removedFallback
		}
	}
	return undoFailed
}

// reports on the undo outcome and settles pending state, returns false if the run exits non-zero
func settleUndo(result undoResult) bool {
	switch result {
	case restoredConfirmed:
		fmt.Printf("  %s\n", colour.Green("✓ confirmed ruleset restored"))
	case removedNoConfirmed:
		fmt.Printf("  %s\n", colour.Green("✓ nfty tables removed"))
		fmt.Printf("    %s\n", colour.Grey("no ruleset has been confirmed yet, so there was nothing to restore"))
	case removedFallback:
		fmt.Fprintln(os.Stderr, "ERROR: confirmed ruleset failed to apply, nfty's tables were REMOVED instead! nfty is not filtering traffic !!")
	case undoFailed:
		// keep pending so status keeps showing the unresolved apply, and apply keeps refusing
		fmt.Fprintln(os.Stderr, "ERROR: rollback failed, the unconfirmed ruleset is still live, pending state kept")
		return false
	}
	if err := ClearPending(); err != nil {
		fmt.Fprintf(os.Stderr, "WARNING: could not clear pending state: %v\n", err)
	}
	return result != removedFallback
}

// loads pending statefile for an undo, warn rather than fail on a bad pending.json
func loadPendingForUndo() *PendingState {
	state, err := LoadPending()
	if err != nil {
		fmt.Fprintf(os.Stderr, "WARNING: could not load pending state: %v\n", err)
		return nil
	}
	return state
}

// perform rollback functionality if pending state is detected
func RunRollbackIfPending() {
	if !IsPending() {
		return
	}

	fmt.Printf("%s\n", colour.DarkGrey("[ systemd: nfty-rollback.timer fired ]"))
	fmt.Printf("%s\n", colour.Red("commit-confirm timer expired"))
	fmt.Printf("%s\n", colour.Grey("reverting to the last confirmed ruleset"))
	tools.Divider()

	if !settleUndo(undoPending(loadPendingForUndo())) {
		os.Exit(1)
	}
}

// undoes a pending apply, or re-asserts the confirmed ruleset if nothing is pending
func RunRollback() {

	// print header output
	tools.CommandExecuteHeader("rollback")

	fmt.Printf("  %s\n", colour.Yellow("↺ rolling back to the last confirmed ruleset"))
	tools.Divider()

	if IsPending() {
		// stop timer first so it cant fire mid-rollback
		if err := CancelRollback(); err != nil {
			fmt.Fprintf(os.Stderr, "WARNING: could not cancel rollback timer: %v\n", err)
		}
		// if rollback fails exit status 1
		if !settleUndo(undoPending(loadPendingForUndo())) {
			os.Exit(1)
		}
		fmt.Printf("  %s  %s\n",
			colour.Grey("rollback timer cancelled"),
			colour.Grey("·  "+"pending state cleared"),
		)
		return
	}

	// when nothing is pending (eg after nfty tables are edited by hand), and put the confirmed ruleset back
	confirmed, found, err := LoadConfirmed()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		os.Exit(1)
	}
	if !found {
		fmt.Fprintln(os.Stderr, "ERROR: no confirmed ruleset to roll back to")
		os.Exit(1)
	}
	if err := nft.ApplyScript(confirmed); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: could not restore confirmed ruleset: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("  %s\n", colour.Green("✓ confirmed ruleset restored"))
}

// reapply the last known, good ruleset (for systemd on boot)
func RunRestore() {
	// [TODO]: read /var/nfty/active.nft
	// [TODO]: apply via nft.ApplyScript()
	fmt.Println("reboot restore not yet implemented")
}

// rollback.go
// handles systemd daemon rollback timer

package commit

import (
	"fmt"
	"os"

	"github.com/adrian-griffin/nfty/internal/colour"
	"github.com/adrian-griffin/nfty/internal/nft"
	"github.com/adrian-griffin/nfty/internal/tools"
)

// perform rollback functionality if pending state is detected
func RunRollbackIfPending() {
	if !IsPending() {
		return
	}

	fmt.Printf("%s\n", colour.DarkGrey("[ systemd: nfty-rollback.timer fired ]"))
	fmt.Printf("%s\n", colour.Red("commit-confirm timer expired"))
	fmt.Printf("%s\n", colour.Grey("reverting to previous known good state"))

	snapshot, err := LoadRollbackSnapshot()
	if err != nil {
		fmt.Fprintf(os.Stderr, "rollback failed! could not load snapshot: %v\n", err)
		os.Exit(1)
	}

	if err := nft.ApplyScript(snapshot); err != nil {
		fmt.Fprintf(os.Stderr, "rollback failed! could not apply snapshot: %v\n", err)
		os.Exit(1)
	}

	ClearPending()
	tools.Divider()
	fmt.Printf("%s\n", colour.Green("✓ previous ruleset restored"))
}

// grabs previous snapshot and applies it
func RunRollback() {

	// print header output
	tools.CommandExecuteHeader("rollback")

	fmt.Printf("  %s\n", colour.Yellow("↺ rolling back to previous ruleset"))
	tools.Divider()

	snapshot, err := LoadRollbackSnapshot()
	if err != nil {
		fmt.Fprintf(os.Stderr, "rollback failed: %v\n", err)
		os.Exit(1)
	}

	if err := nft.ApplyScript(snapshot); err != nil {
		fmt.Fprintf(os.Stderr, "rollback apply failed: %v\n", err)
		os.Exit(1)
	}

	// cleans pending and rollback states
	if IsPending() {
		CancelRollback()
		ClearPending()
	}

	fmt.Printf("  %s\n", colour.Green("✓ previous ruleset restored"))
	fmt.Printf("  %s  %s\n",
		colour.Grey("rollback timer cancelled"),
		colour.Grey("·  "+"pending state cleared"),
	)
}

// reapplies last known good ruleset (used by systemd on boot)
func RunRestore() {
	// [TODO]: read /var/nfty/active.nft
	// [TODO]: apply via nft.ApplyScript()
	fmt.Println("restore not yet implemented")
}

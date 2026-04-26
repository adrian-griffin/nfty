package commit

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/adrian-griffin/nfty/internal/colour"
	"github.com/adrian-griffin/nfty/internal/nft"
	"github.com/adrian-griffin/nfty/internal/tools"
)

// perform change-approval/confirmation logic
func RunConfirm() {
	if !IsPending() {
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

	tools.Divider()

	state, err := LoadPending()
	if err == nil {
		fmt.Printf("  %s%s\n", tools.Label("confirming"), colour.Blue(state.ConfigPath))
		fmt.Printf("  %s%s %s\n", tools.Label("applied by"), colour.Grey(state.AppliedBy), colour.DarkGrey("("+state.AppliedAt.Format("15:04:05")+")"))
		fmt.Printf("  %s%s\n", tools.Label("checksum"), colour.DarkGrey(state.Checksum))
		tools.Divider()
	}

	// cancel systemd execution timer
	CancelRollback()

	// persist current ruleset for boot restore
	currentRuleset, err := nft.ListRulesetScript()
	if err != nil {
		fmt.Fprintf(os.Stderr, "WARNING: could not read current ruleset for persistence: %v\n", err)
	} else {
		if err := SaveRunningRuleset(string(currentRuleset)); err != nil {
			fmt.Fprintf(os.Stderr, "WARNING: could not apply ruleset to running configuration: %v\n", err)
		}
	}

	// prior to clearing, write state to last-apply.json
	if state != nil {
		if err := WriteLastApply(state); err != nil {
			fmt.Fprintf(os.Stderr, "WARNING: could not persists last apply state to last-apply.json: %v\n", err)
		}
	}

	ClearPending()
	fmt.Printf("  %s\n", colour.Green("✓ ruleset applied and committed"))
	fmt.Printf("  %s  %s\n",
		colour.Grey("rollback timer cancelled"),
		colour.Grey("·  "+"pending state cleared"),
	)
}

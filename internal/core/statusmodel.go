// statusmodel.go
// builds nfty status data, which is then rendered by `status` cli flag or in the tui
package core

import (
	"os"

	"github.com/adrian-griffin/nfty/internal/commit"
	"github.com/adrian-griffin/nfty/internal/nft"
	"github.com/adrian-griffin/nfty/internal/tools"
)

// full, instantaneous status snapshot
type Status struct {
	HasPending bool                 `json:"has_pending"`          // true if a confirm window is open
	Pending    *commit.PendingState `json:"pending,omitempty"`    // pending detail; nil if unreadable
	LastApply  *commit.LastApply    `json:"last_apply,omitempty"` // last-apply detail; nil if unreadable
	StateFiles []StateFile          `json:"state_files"`          // nfty's on-disk state files info
	Ruleset    RulesetStats         `json:"ruleset"`              // live ruleset counts
}

// nfty on-disk state file struct
type StateFile struct {
	Label   string `json:"label"`
	Path    string `json:"path"`
	Present bool   `json:"present"`        // exists?
	Info    string `json:"info,omitempty"` // size + age, empty if unreadable
}

// counts scraped from live nftables ruleset, including the ruleset itself for --list-ruleset
type RulesetStats struct {
	Tables int    `json:"tables"`
	Chains int    `json:"chains"`
	Rules  int    `json:"rules"`
	Script string `json:"-"` // raw `nft list ruleset`, too big for json
}

// reads pending/last-apply state, stats state files, counts live rulesets
func GatherStatus() (*Status, error) {
	status := &Status{}

	// pending state when a confirm window is open
	status.HasPending = commit.IsPending()
	// if pending, read the .json file for deets
	// if not, read last-apply.json instead
	if status.HasPending {
		if state, err := commit.LoadPending(); err == nil {
			status.Pending = state
		}
	} else if last, err := commit.LoadLastApply(); err == nil {
		status.LastApply = last
	}

	// loop through state files, check if exist, gather size + age info
	for _, f := range []StateFile{
		{Label: "running.nft", Path: commit.RunningFile},
		{Label: "rollback.nft", Path: commit.RollbackFile},
		{Label: "last-apply.json", Path: commit.LastApplyFile},
	} {
		// if file exists, mark as present and gather fileinfo
		if _, err := os.Stat(f.Path); err == nil {
			f.Present = true
			f.Info = tools.FileInfo(f.Path)
		}
		status.StateFiles = append(status.StateFiles, f)
	}

	// without the live ruleset, there's no status to collect
	// only possible hard failure here
	out, err := nft.ListRulesetScript() // `nft list ruleset` output
	if err != nil {
		return nil, err
	}
	ruleset := string(out) // convert raw []byte to str

	// count tables, chains, and rules from the raw nft output
	tables, chains, ruleCount := tools.CountNftObjects(ruleset)
	// populate status struct w/ counts and raw ruleset
	status.Ruleset = RulesetStats{
		Tables: tables,
		Chains: chains,
		Rules:  ruleCount,
		Script: ruleset,
	}

	return status, nil
}

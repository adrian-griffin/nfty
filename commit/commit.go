package commit

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

const (
	BaseDir      = "/var/nfty"
	RollbackFile = "/var/nfty/rollback.nft"
	RunningFile  = "/var/nfty/running.nft"
	PendingFile  = "/var/nfty/pending.json"
)

// struct for 'in-flight' config application that has yet to be `nfty confirm`
// ie: written to pending.json after `nfty apply`, removed after confirm or rollback.
type PendingState struct {
	ConfigPath string    `json:"config_path"`
	AppliedBy  string    `json:"applied_by"`
	AppliedAt  time.Time `json:"applied_at"`
	Deadline   time.Time `json:"deadline"`
}

// ensure nfty homedir exists
func CheckDir() error {
	return os.MkdirAll(BaseDir, 0700)
}

// writes pre-nfty-apply NFT ruleset to rollback.nft for use in emergency
func SaveRollbackSnapshot(currentRuleset []byte) error {
	return os.WriteFile(RollbackFile, currentRuleset, 0600)
}

// reads the previiously-written rollback config for restoration
func LoadRollbackSnapshot() (string, error) {
	data, err := os.ReadFile(RollbackFile)
	if err != nil {
		return "", fmt.Errorf("reading rollback snapshot: %w", err)
	}
	return string(data), nil
}

// writes currently-running ruleset to running.nft for persistence
func SaveRunningRuleset(script string) error {
	return os.WriteFile(RunningFile, []byte(script), 0600)
}

// loads running.nft file for application upon boot
func LoadRunningRuleset() (string, error) {
	data, err := os.ReadFile(RunningFile)
	if err != nil {
		return "", fmt.Errorf("reading running ruleset: %w", err)
	}
	return string(data), nil
}

// creates .json file for tracking pending confirm changes
// writes some metadata
func WritePending(configPath string, deadlineSeconds int) error {
	now := time.Now()
	state := PendingState{
		ConfigPath: configPath,
		AppliedBy:  os.Getenv("USER"),
		AppliedAt:  now,
		Deadline:   now.Add(time.Duration(deadlineSeconds) * time.Second),
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("marshalling pending state: %w", err)
	}
	return os.WriteFile(PendingFile, data, 0600)
}

// bools whether there exists any pending changes needed
func IsPending() bool {
	_, err := os.Stat(PendingFile)
	return err == nil
}

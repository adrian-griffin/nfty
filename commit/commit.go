package commit

import (
	"fmt"
	"os"
)

const (
	BaseDir      = "/var/nfty"
	RollbackFile = "/var/nfty/rollback.nft"
	RunningFile  = "/var/nfty/running.nft"
)

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

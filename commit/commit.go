package commit

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"time"
)

const (
	BaseDir      = "/var/nfty"
	RollbackFile = "/var/nfty/rollback.nft"
	RunningFile  = "/var/nfty/running.nft"
	PendingFile  = "/var/nfty/pending.json"
	TimerUnit    = "nfty-commit-confirm"
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
	prependFlushRuleset := append([]byte("flush ruleset\n"), currentRuleset...)
	return os.WriteFile(RollbackFile, prependFlushRuleset, 0600)
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

// reads/loads pending state file
func LoadPending() (*PendingState, error) {
	data, err := os.ReadFile(PendingFile)
	if err != nil {
		return nil, fmt.Errorf("reading pending state: %w", err)
	}
	var state PendingState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("parsing pending state: %w", err)
	}
	return &state, nil
}

// remove pending.json file once confirmed/rolled back
func ClearPending() error {
	err := os.Remove(PendingFile)
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

// create systemd timer for nfty rollback
// if left to run for the full duration, runs `nfty rollback-if-pending`
func ScheduleRollback(seconds int, nftyBinary string) error {
	err := exec.Command("systemd-run",
		"--on-active="+fmt.Sprintf("%ds", seconds),
		"--unit="+TimerUnit,
		"--description=nfty commit rollback timer",
		nftyBinary, "rollback-if-pending",
	).Run()
	if err != nil {
		return fmt.Errorf("scheduling rollback timer: %w", err)
	}
	return nil
}

// stops the pending rollback timer
func CancelRollback() error {
	// stop both the timer and the service unit systemd creates
	exec.Command("systemctl", "stop", TimerUnit+".timer").Run()
	exec.Command("systemctl", "stop", TimerUnit+".service").Run()
	return nil
}

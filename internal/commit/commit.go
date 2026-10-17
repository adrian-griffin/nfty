// commit.go
// handles base nft config commit to systems
package commit

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/adrian-griffin/nfty/internal/config"
	"github.com/adrian-griffin/nfty/internal/nft"
)

const (
	BaseDir = "/var/nfty"
	// last-operator confirmed nftables script
	// the statefile used for failsafe operations, like rollback, rollback timer, and boot
	ConfirmedFile = "/var/nfty/confirmed.nft"
	// applied/pending nftables script, moves > ConfirmedFile on confirm
	PendingScriptFile = "/var/nfty/pending.nft"
	PendingFile       = "/var/nfty/pending.json"
	LastApplyFile     = "/var/nfty/last-apply.json"
	TimerUnit         = "nfty-commit-confirm"

	// if rollback timer is set to a shorter duration than the nftables apply takes
	// it can lead to an edge-case race condition/conflict
	// nftables apply should take no more than ~1-2 seconds tops, but lowering is not advised
	MinConfirmSeconds     = 20
	DefaultConfirmSeconds = 120
)

// struct for pending/staged config application that has yet to be confirmed
// written to pending.json after a `nfty apply`, removed after confirm or rollback
type PendingState struct {
	ConfigPath string    `json:"config_path"`
	AppliedBy  string    `json:"applied_by"`
	AppliedAt  time.Time `json:"applied_at"`
	Deadline   time.Time `json:"deadline"`
	Checksum   string    `json:"checksum"`
	Table      string    `json:"table"`
}

// same deal for last-apply.json output
type LastApply struct {
	ConfigPath  string    `json:"config_path"`
	AppliedBy   string    `json:"applied_by"`
	AppliedAt   time.Time `json:"applied_at"`
	ConfirmedAt time.Time `json:"confirmed_at"`
	Checksum    string    `json:"checksum"`
	Table       string    `json:"table,omitempty"`
}

// ensure nfty homedir exists
func CheckDir() error {
	return os.MkdirAll(BaseDir, 0700)
}

// write confirmed ruleset. this file is fairly load-bearing, so file is written
// to a temp file and renamed/moved to safeguard against crashes mid-write or truncated files
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	// does nothing if file is moved successfully
	defer os.Remove(tmp.Name())

	// partial iterations, with error returnal each step

	// write file data
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	// adjust permissions
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	// ensure kernel has flushed meta/data to storage
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	// close file writer
	if err := tmp.Close(); err != nil {
		return err
	}
	// rename file and move to final confirm.nft path
	if err := os.Rename(tmp.Name(), path); err != nil {
		return err
	}

	// fsync the directory too, otherwise the rename itself can be lost on power failure
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// writes a script as the confirmed ruleset, used by --skip-confirm
func WriteConfirmed(script string) error {
	return writeFileAtomic(ConfirmedFile, []byte(script), 0600)
}

// reads the confirmed ruleset, found is false if no apply has ever been confirmed
func LoadConfirmed() (script string, found bool, err error) {
	data, err := os.ReadFile(ConfirmedFile)
	if os.IsNotExist(err) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("reading confirmed ruleset: %w", err)
	}
	return string(data), true, nil
}

// wrapper to promote pending nfty-rendered nftables config to confirmed
func PromotePending(state *PendingState) error {
	return promoteScript(PendingScriptFile, ConfirmedFile, state.Checksum)
}

// open pending path, compare pending.json and pending.nft
// if they match, write pending to promoted/confirmed
func promoteScript(pendingPath, confirmedPath, checksum string) error {
	data, err := os.ReadFile(pendingPath)
	if err != nil {
		return fmt.Errorf("reading pending script: %w", err)
	}
	// pending.json and pending.nft are written separately, refuse a pair that don't match
	if got := nft.ScriptChecksum(string(data)); got != checksum {
		return fmt.Errorf("pending script checksum %s does not match pending state %s", got, checksum)
	}
	return writeFileAtomic(confirmedPath, data, 0600)
}

// build the nftables script that is used for rollback / undoes a pending apply
func buildRollbackScript(confirmed string, haveConfirmed bool, pendingTable, confirmedTable string) string {
	var b strings.Builder
	// check pending AND previously confirmed table-names to prevent leaving behind
	// previous nfty rulesets on table name change, write clears to new rollback table
	if pendingTable != "" && (!haveConfirmed || pendingTable != confirmedTable) {
		b.WriteString(nft.DeleteTables(pendingTable))
	}
	// if previous confirmed file exists, use that as rollback target
	if haveConfirmed {
		b.WriteString(confirmed)
	}
	return b.String()
}

// builds the last-resort script that removes nfty's tables entirely
// leaves the box unfirewalled by nfty, which is the reachable state, same as a reboot
func buildDeleteScript(tables ...string) string {
	var b strings.Builder
	seen := map[string]bool{}
	for _, t := range tables {
		if t == "" || seen[t] {
			continue
		}
		seen[t] = true
		b.WriteString(nft.DeleteTables(t))
	}
	return b.String()
}

// returns the table name recorded with the confirmed ruleset, or "" if unknown or invalid
func confirmedTableName() string {
	last, err := LoadLastApply()
	if err != nil || last.Table == "" {
		return ""
	}
	if err := config.ValidateTableName(last.Table); err != nil {
		fmt.Fprintf(os.Stderr, "WARNING: ignoring invalid table name in %s: %v\n", LastApplyFile, err)
		return ""
	}
	return last.Table
}

// creates .json file for tracking pending confirm changes
// writes some metadata, plus the exact script being applied for promotion on confirm
func WritePending(configPath, checksum, table, script string, deadlineSeconds int) error {
	now := time.Now()

	user := os.Getenv("SUDO_USER")
	if user == "" {
		user = os.Getenv("USER")
		if user == "" {
			return fmt.Errorf("failed to collect active user information")
		}
	}
	state := PendingState{
		ConfigPath: configPath,
		AppliedBy:  user,
		AppliedAt:  now,
		Deadline:   now.Add(time.Duration(deadlineSeconds) * time.Second),
		Checksum:   checksum,
		Table:      table,
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("marshalling pending state: %w", err)
	}
	// script first, pending.json is the marker IsPending checks for
	if err := writeFileAtomic(PendingScriptFile, []byte(script), 0600); err != nil {
		return fmt.Errorf("writing pending script: %w", err)
	}
	return writeFileAtomic(PendingFile, data, 0600)
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
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	// best effort, an orphaned pending.nft is inert and overwritten by the next apply
	os.Remove(PendingScriptFile)
	return nil
}

// write data from last apply to disk for persistence
func WriteLastApply(state *PendingState) error {
	record := LastApply{
		ConfigPath:  state.ConfigPath,
		AppliedBy:   state.AppliedBy,
		AppliedAt:   state.AppliedAt,
		ConfirmedAt: time.Now(),
		Checksum:    state.Checksum,
		Table:       state.Table,
	}
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(LastApplyFile, data, 0600)
}

// writes a last-apply record without an existing pending state
// used by --skip-confirm where no pending.json is ever created
func WriteLastApplyDirect(configPath, checksum, table string) error {
	user := os.Getenv("SUDO_USER")
	if user == "" {
		user = os.Getenv("USER")
		if user == "" {
			return fmt.Errorf("failed to collect active user information")
		}
	}

	record := LastApply{
		ConfigPath:  configPath,
		AppliedBy:   user,
		AppliedAt:   time.Now(),
		ConfirmedAt: time.Now(),
		Checksum:    checksum,
		Table:       table,
	}
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(LastApplyFile, data, 0600)
}

// reads/loads last apply state file
func LoadLastApply() (*LastApply, error) {
	data, err := os.ReadFile(LastApplyFile)
	if err != nil {
		return nil, err
	}
	var record LastApply
	// unm data into LA struct
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, err
	}
	return &record, nil
}

// clears lingering unit timers
// systemd refuses --unit= if the name still exists
// any unit left in a failed state can prevent creation of a new timer
func resetTimerUnits() {
	// best effort as reset-failed errs out if unit does not exist
	// err is discarded since we actually do *want* this to err (or clear timer successfully)
	exec.Command("systemctl", "reset-failed", TimerUnit+".timer", TimerUnit+".service").Run()
}

// create systemd timer for nfty rollback
// if left to run for the full duration, runs `nfty rollback-if-pending`
func ScheduleRollback(seconds int, nftyBinary string) error {
	// reject if confirm timer is below minimum limit
	// prevents race of apply and rollback
	if seconds < MinConfirmSeconds {
		return fmt.Errorf("commit-confirm window of %ds is below the %ds minimum",
			seconds, MinConfirmSeconds)
	}

	// reset/wipe nfty unit timers
	resetTimerUnits()
	// create new unit timer
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
	// stop both the timer and the service unit
	err := exec.Command("systemctl", "stop", TimerUnit+".timer").Run()
	exec.Command("systemctl", "stop", TimerUnit+".service").Run()

	// always clear units on the way out
	resetTimerUnits()

	if err != nil {
		return fmt.Errorf("stopping rollback timer: %w", err)
	}
	return nil
}

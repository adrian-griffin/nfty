// nft.go
// builds rules to be passed to nftables
package nft

import (
	"fmt"
	"os/exec"
	"strings"
)

var nftPath string

func init() {
	// best-effort for caching, CheckBinary will catch if missing
	nftPath, _ = exec.LookPath("nft")
}

// calls nft binary with trailing args, returns stdout+stderr
func nftCall(args ...string) ([]byte, error) {
	if nftPath == "" {
		return nil, fmt.Errorf("nft not found, please ensure is nftables installed")
	}
	cmd := exec.Command(nftPath, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("nft %s: %w\noutput: %s", strings.Join(args, " "), err, string(out))
	}
	return out, nil
}

// returns nft output for a single table by ip-family & name
func ListTable(family, name string) ([]byte, error) {
	return nftCall("list", "table", family, name)
}

// validates binary
func CheckBinary() error {
	if _, err := nftCall("--version"); err != nil {
		return fmt.Errorf("nft check failed: %w", err)
	}
	return nil
}

// returns current, raw nft json output
func ListRulesetJson() ([]byte, error) {
	out, err := nftCall("-j", "list", "ruleset")
	if err != nil {
		return nil, fmt.Errorf("listing ruleset: %w", err)
	}
	return out, nil
}

// collects ruleset script for simple rollback
func ListRulesetScript() ([]byte, error) {
	out, err := nftCall("list", "ruleset")
	if err != nil {
		return nil, fmt.Errorf("listing ruleset script: %w", err)
	}
	return out, nil
}

// check nft config for syntax or errors
func ValidateScript(script string) error {
	if nftPath == "" {
		return fmt.Errorf("nft not found - is nftables installed?")
	}

	cmd := exec.Command(nftPath, "--check", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("validation failed: %w\noutput: %s", err, string(out))
	}
	return nil
}

// hard-applies ruleset to NFT
func ApplyScript(script string) error {
	if nftPath == "" {
		return fmt.Errorf("nft not found - is nftables installed?")
	}
	cmd := exec.Command(nftPath, "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("apply failed: %w\noutput: %s", err, string(out))
	}
	return nil
}

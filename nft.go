// package nft handles all interaction with the nftables subsystem.
// Shells out to the nft binary using JSON mode (-j) for reliable,
// parseable output.
package nft

import (
	"fmt"
	"os/exec"
	"strings"
)

// calls nft binary with trailing args, returns stdout+stderr
func nftCall(args ...string) ([]byte, error) {
	path, err := exec.LookPath("nft")
	if err != nil {
		return nil, fmt.Errorf("nft not found — is nftables installed?")
	}

	cmd := exec.Command(path, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("nft %s: %w\noutput: %s", strings.Join(args, " "), err, string(out))
	}
	return out, nil
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

// check nft config for syntax or errors
func ValidateScript(script string) error {
	path, err := exec.LookPath("nft")
	if err != nil {
		return fmt.Errorf("nft binary not found in PATH")
	}

	cmd := exec.Command(path, "--check", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("validation failed: %w\noutput: %s", err, string(out))
	}
	return nil
}

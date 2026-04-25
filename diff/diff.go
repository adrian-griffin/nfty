package diff

import (
	"fmt"
	"os"
	"os/exec"
	"regexp"
)

// normalizes counter values for diffing
var counterRegex = regexp.MustCompile(`counter packets \d+ bytes \d+`)

func stripCounters(script string) string {
	return counterRegex.ReplaceAllString(script, "counter")
}

// diffs two configs by shelling out
func diffScripts(oldLabel, newLabel, oldScript, newScript string) (string, bool, error) {
	// strip counter values
	oldScript = stripCounters(oldScript)
	newScript = stripCounters(newScript)

	// write both scripts to temp files for diff
	oldFile, err := os.CreateTemp("", "nfty-old-*.nft")
	if err != nil {
		return "", false, fmt.Errorf("creating temp file: %w", err)
	}
	defer os.Remove(oldFile.Name())

	newFile, err := os.CreateTemp("", "nfty-new-*.nft")
	if err != nil {
		return "", false, fmt.Errorf("creating temp file: %w", err)
	}
	defer os.Remove(newFile.Name())

	oldFile.WriteString(oldScript)
	newFile.WriteString(newScript)
	oldFile.Close()
	newFile.Close()

	// run diffing
	out, err := exec.Command("diff", "-u",
		"--label", oldLabel,
		"--label", newLabel,
		oldFile.Name(), newFile.Name(),
	).CombinedOutput()

	if err != nil {
		// diff exits (1) when files actually differ, handle
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
			return string(out), true, nil
		}
		return "", false, fmt.Errorf("running diff: %w", err)
	}

	// exit 0 if no differences
	return "", false, nil
}

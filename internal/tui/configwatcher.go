// configwatcher.go
// resolves which .toml the tui is looking at, and watches it for drift
package tui

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strconv"
	"time"

	"github.com/adrian-griffin/nfty/internal/config"
	"github.com/adrian-griffin/nfty/internal/core"
	"github.com/adrian-griffin/nfty/internal/nft"
)

// fallback path, only used when no apply has ever recorded one
const defaultConfigPath = "/etc/nfty/nfty.toml"

type configState struct {
	Path   string // resolved .toml path, empty if cannot resolve
	Source string // how the path was chosen, displays to user

	Exists  bool
	ModTime time.Time
	Err     error // load or render failure, displayed rather than fatal

	fileHash string // sha256 hash of the file raw bytes
	Checksum string // sha256 hash of the nftables script (stored by last-apply.json)
	Script   string // kept so the diff stat can run without re-rendering
	Table    string // config table name
}

// stores statistics of ruleset diffs
type diffStat struct {
	forHash    string // config fileHash that the counts were computed for (new config)
	forApplied string // applied checksum that the counts were computed against (previous config)
	adds       int
	removes    int
	ok         bool
}

// checks whether the previously calculated diff is still valid for the current ruleset
func diffMatches(d diffStat, cfg configState, applied string) bool {
	return d.forHash == cfg.fileHash && d.forApplied == applied
}

// determines the config path, preferring most explicit sources first
// once an apply is completed once/the first, this func no longer needs to guess
func resolveConfigPath(override string, s *core.Status) (path, source string) {
	if override != "" {
		return override, "argument"
	}
	if s != nil {
		if s.Pending != nil && s.Pending.ConfigPath != "" {
			return s.Pending.ConfigPath, "pending apply"
		}
		if s.LastApply != nil && s.LastApply.ConfigPath != "" {
			return s.LastApply.ConfigPath, "last apply"
		}
	}
	if _, err := os.Stat(defaultConfigPath); err == nil {
		return defaultConfigPath, "default path"
	}
	return "", ""
}

// reads and renders the config to get its checksum
func pollConfig(path, source string, prev configState) configState {
	next := configState{Path: path, Source: source}
	if path == "" {
		return next
	}

	info, err := os.Stat(path)
	if err != nil {
		next.Err = err
		return next
	}
	next.Exists = true
	next.ModTime = info.ModTime()

	// collect raw .toml data
	raw, err := os.ReadFile(path)
	if err != nil {
		next.Err = err
		return next
	}
	// sha256 hash of raw data
	sum := sha256.Sum256(raw)
	next.fileHash = hex.EncodeToString(sum[:])

	// if current path, hash, and checksum ALL match previous, reuse previous result
	if prev.Path == path && prev.fileHash == next.fileHash && prev.Checksum != "" {
		next.Checksum = prev.Checksum
		next.Script = prev.Script
		next.Table = prev.Table
		return next
	}

	cfg, err := config.Load(path)
	if err != nil {
		next.Err = err
		return next
	}
	// ValidateScript is not run here as that shells out to nft and this runs on a timer
	script, err := nft.Generate(cfg)
	if err != nil {
		next.Err = err
		return next
	}

	next.Table = cfg.Core.Table
	next.Script = script
	next.Checksum = nft.ScriptChecksum(script)
	return next
}

// checksum recorded by the last apply
func appliedChecksum(s *core.Status) string {
	if s == nil {
		return ""
	}
	if s.HasPending && s.Pending != nil {
		return s.Pending.Checksum
	}
	if s.LastApply != nil {
		return s.LastApply.Checksum
	}
	return ""
}

// detects if the .toml on disk renders differently than what is applied
func drifted(cfg configState, s *core.Status) bool {
	applied := appliedChecksum(s)
	return cfg.Checksum != "" && applied != "" && cfg.Checksum != applied
}

// age of the toml file
func editedAgo(t time.Time) string {
	age := time.Since(t).Round(time.Second)
	switch {
	case age < time.Minute:
		return "just now"
	case age < time.Hour:
		return strconv.Itoa(int(age.Minutes())) + "m ago"
	case age < 48*time.Hour:
		return strconv.Itoa(int(age.Hours())) + "h ago"
	default:
		return strconv.Itoa(int(age.Hours()/24)) + "d ago"
	}
}

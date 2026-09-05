// frame.go
// static tui frame, such as header line, nav bar, and footer
// wraps individual screens/panes
package tui

import (
	"path/filepath"
	"unicode/utf8"

	"github.com/adrian-griffin/nfty/internal/colour"
	"github.com/adrian-griffin/nfty/internal/meta"
)

// panes index
type pane int

const (
	paneStatus pane = iota
	paneRules
	paneLists
	paneSettings
	paneLog
	paneCount
)

var paneNames = [paneCount]string{"status", "rules", "lists", "settings", "log"}

// build header (hostname, clock, status badge)
func (m model) header() string {
	edge := contentEdge(m)
	r := newRow().write("nfty", colour.Grey)

	badge, badgePaint := m.badge()
	badgeCol := edge - utf8.RuneCountInString(badge)

	// clock is centred between in header but only if there's space
	stamp := m.hostname + " · " + m.now.Format("2006-01-02 15:04:05")
	stampCol := (edge - utf8.RuneCountInString(stamp)) / 2
	if stampCol > r.col && stampCol+utf8.RuneCountInString(stamp) < badgeCol-1 {
		r.pad(stampCol).write(stamp, colour.DarkGrey)
	}

	return r.right(edge, badge, badgePaint).String()
}

// lifecycle/application state token
func (m model) badge() (string, paint) {
	switch {
	case m.err != nil:
		return "✕ UNREADABLE", boldRed
	case m.status == nil:
		return "· reading state", colour.DarkGrey
	case m.status.HasPending:
		return "▲ PENDING", boldYellow
	default:
		return "✓ CONFIRMED", boldGreen
	}
	// TODO: STAGED, TRACING
}

// nav bar
func (m model) tabs() string {
	r := newRow().pad(indent + 1)
	for i, name := range paneNames {
		if pane(i) == m.pane {
			r.write(name, tabActive)
		} else {
			r.write(name, colour.DarkGrey)
		}
		r.pad(r.col + 4)
	}

	// keep loaded config name visible at all times
	if m.cfg.Path != "" {
		edge := contentEdge(m)
		// path := truncatePath(m.cfg.Path, edge/3)
		file := filepath.Base(m.cfg.Path)
		if edge-utf8.RuneCountInString(file) > r.col+2 {
			r.right(edge, file, colour.Blue)
		}
	}
	return r.String()
}

// key hints, greyed out if action is not available
type keyHint struct {
	key   string
	label string
	on    bool
}

// build footer and hints
func (m model) footer() string {
	r := newRow()
	for i, h := range m.keyHints() {
		// native spacing of 3
		if i > 0 {
			r.pad(r.col + 3)
		}
		// key id highlighted with descriptor text standard
		keyPaint, labelPaint := paint(colour.Cyan), paint(colour.Grey)
		if !h.on {
			keyPaint, labelPaint = colour.DarkGrey, colour.DarkGrey
		}
		r.write("["+h.key+"]", keyPaint).write(" "+h.label, labelPaint)
	}
	return r.String()
}

// defines which key hints are visible
func (m model) keyHints() []keyHint {
	// disable apply if there is an active apply window in progress
	pending := m.status != nil && m.status.HasPending

	hints := []keyHint{
		{"x", "apply", !pending && drifted(m.cfg, m.status)},
		{"/", "config path", true},
		{"r", "refresh", true},
		{"1-5", "pane", true},
		{"?", "help", true},
		{"q", "quit", true},
	}
	return hints
}

// key reference, one row per binding
var helpKeys = [][2]string{
	{"1 - 5", "jump to a specific pane"},
	{"tab / shift+tab", "cycle between panes"},
	{"a / d", "previous / next pane"},
	{"w / s", "scroll up / down"},
	{"/", "edit the target .toml config path"},
	{"r", "refresh ui and re-poll file states"},
	{"x", "apply this config (not functional yet)"},
	{"z", "rollback and undo (not functional yet)"},
	{"c", "confirm changes (not functional yet)"},
	{"?", "close this help"},
	{"q / esc", "quit"},
}

// help section detail text
var helpSections = []struct{ head, body string }{
	{"nfty basics",
		"nfty's config and the firewalls it builds are defined via .toml, and the resulting firewall rulesets " +
			"rendered into nftables script for the system.\n\n nfty simplifies managing linux firewalls, increases visibility, " +
			"lints rulesets for gaps in security, and stops accidental lockouts.\n\n Staged changes are compared against the live " +
			"rules and diffed, and applying changes requires a 2-step confirm process -- changes will always revert unless confirmed."},
	{"lockout prevention",
		"Every apply arms a rollback before any new rules take effect. All changes will be undone " +
			"unless a 2nd confirm is supplied, allowing you to test, check, and validate before committing.\n\n" +
			"Importantly, the rollback timer is a systemd unit and does NOT live within nfty, meaning that exiting nfty, " +
			"accidentally getting disconnected by a bad rule, or even killing the nfty process never stops the rollback from firing."},
}

// builds the help body one line at a time so it can be clipped or scrolled
func helpLines(m model) []string {
	edge := contentEdge(m)
	// indents help-page text past each header
	prose := edge - indent - 4

	lines := []string{
		newRow().write("help", colour.Grey).
			right(edge, "nfty "+meta.Version, colour.DarkGrey).String(),
		"",
		newRow().pad(indent+2).write("keybinds", colour.Grey).String(),
	}

	for _, kv := range helpKeys {
		lines = append(lines, newRow().pad(indent+4).
			write(fit(kv[0], 18), colour.Cyan).
			write(truncate(kv[1], edge-indent-22), colour.Grey).String())
	}

	for _, sec := range helpSections {
		lines = append(lines, "", newRow().pad(indent+2).write(sec.head, colour.Grey).String())
		// wraps help text for terminal size scaling
		for _, ln := range wrapText(sec.body, prose) {
			lines = append(lines, newRow().pad(indent+4).write(ln, colour.DarkGrey).String())
		}
	}

	return lines
}

// how far the help can scroll before the last line is on screen
func helpScrollMax(m model) int {
	height := bodyHeight(m)
	if height <= 0 {
		return 0
	}
	// the marker row costs one line of the window
	if max := len(helpLines(m)) - (height - 1); max > 0 {
		return max
	}
	return 0
}

// full-screen help page, replaces body of other panes
func (m model) help() string {
	return clipLines(helpLines(m), bodyHeight(m), m.helpScroll)
}

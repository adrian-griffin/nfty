// panes.go
// bubbletea/tui's own renderer pane bodies
// core still owns the data, this only draws it

package tui

import (
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/adrian-griffin/nfty/internal/colour"
)

// draws whichever pane currently has focus
func body(m model) string {
	switch m.pane {
	// page 1 - status page
	case paneStatus:
		return statusPane(m)
	// page 2-* - stub for wip panes
	default:
		return stubPane(m)
	}
}

// defines status page layout
func statusPane(m model) string {
	var b strings.Builder
	edge := contentEdge(m)

	// display primary lifecyle/apply snapshot
	m.renderLifecycle(&b)
	b.WriteString(divider(edge) + "\n")
	// display .toml config file-info
	m.renderConfig(&b)
	b.WriteString(divider(edge) + "\n")
	// display state-files file-info
	m.renderStateFiles(&b)
	b.WriteString(divider(edge) + "\n")
	// display ruleset overview
	m.renderRuleset(&b)

	return b.String()
}

// pending confirm window or the record of the most recent apply
func (m model) renderLifecycle(b *strings.Builder) {
	s := m.status

	// if not pending, display who and when regarding the last apply
	if !s.HasPending {
		b.WriteString(newRow().write("✓ no pending changes", colour.Green).String() + "\n")
		last := s.LastApply
		if last == nil {
			b.WriteString(newRow().pad(indent+2).
				write("no record of a previous apply", colour.DarkGrey).String() + "\n")
			return
		}
		// applied by details
		b.WriteString(newRow().pad(indent+2).label("last apply by").
			write(last.AppliedBy, colour.Grey).String() + "\n")
		// apply at details
		b.WriteString(newRow().pad(indent+2).label("last apply at").
			write(last.ConfirmedAt.Format("15:04:05"), colour.Grey).
			write("  "+last.ConfirmedAt.Format("(2006-01-02)"), colour.DarkGrey).String() + "\n")
		return
	}

	// if pending state doesnt parse properly, alert and prompt to continue
	// confirm will still work
	state := s.Pending
	if state == nil {
		b.WriteString(newRow().write("▲ pending changes", boldYellow).String() + "\n")
		b.WriteString(newRow().pad(indent+2).
			write("pending.json is unreadable - ", colour.Red).
			write("nfty confirm", boldCyan).
			write(" will still succeed without issue", colour.Red).String() + "\n")
		return
	}

	// otherwise, emit pending-state details and alert for confirm or rollback
	b.WriteString(newRow().write("▲ pending changes", boldYellow).
		pad(indent+22).write("awaiting confirm", colour.Yellow).String() + "\n")
	b.WriteString(newRow().pad(indent+2).label("applied by").
		write(state.AppliedBy, colour.Grey).String() + "\n")
	b.WriteString(newRow().pad(indent+2).label("applied at").
		write(state.AppliedAt.Format("15:04:05"), colour.Grey).String() + "\n")

	// remainder time is calculated off of deadline in pending.json
	// in order to ensure a confirm from a 2nd shell shows up here on the next poll
	remaining := time.Until(state.Deadline).Round(time.Second)
	r := newRow().pad(indent + 2).label("deadline")
	if remaining > 0 {
		deadlinePaint := paint(colour.Yellow)
		if remaining < 30*time.Second {
			deadlinePaint = colour.Red
		}
		r.write(remaining.String()+" remaining", deadlinePaint).
			write("  (expires "+state.Deadline.Format("15:04:05")+")", colour.DarkGrey)
	} else {
		r.write("expired - rolling back", colour.Red)
	}
	b.WriteString(r.String() + "\n")

	b.WriteString(newRow().pad(indent+2).label("rollback via").
		write("systemd timer - survives shell death/disconnect", colour.Grey).String() + "\n")
	b.WriteString(newRow().pad(indent+2).
		write("nfty confirm", boldCyan).write(" to approve", colour.Grey).
		pad(indent+32).
		write("nfty rollback", boldCyan).write(" to undo", colour.Grey).String() + "\n")
}

// details about the target .toml config
func (m model) renderConfig(b *strings.Builder) {
	edge := contentEdge(m)
	cfg := m.cfg

	b.WriteString(newRow().write("config", colour.Grey).String() + "\n")

	// if path is empty, prompt to add one in-tui or to pass via cli tui flag
	if cfg.Path == "" {
		b.WriteString(newRow().pad(indent+2).label("path").
			write("none resolved", colour.Yellow).String() + "\n")
		b.WriteString(newRow().pad(indent+2).label("").
			write("press [/] to set one, or start with: nfty tui <config.toml>", colour.DarkGrey).String() + "\n")
		return
	}

	// situationally display source/how the path was determined
	// this is right-aligned, so its own width + spacing comes out of the
	// path's budget/visible length itself
	source := ""
	if cfg.Source != "" {
		source = "(" + cfg.Source + ")"
	}

	// display path, truncate at max-edge width, display end of the filepath
	pathRow := newRow().pad(indent+2).label("path").
		write(truncatePath(cfg.Path, edge-valueCol-utf8.RuneCountInString(source)-2), colour.Blue)
	if source != "" {
		pathRow.right(edge, source, colour.DarkGrey)
	}
	b.WriteString(pathRow.String() + "\n")

	// an invalid config is reported in tui and is not fatal
	// live ruleset is unaffected by a bad .toml file on disk
	if cfg.Err != nil {
		// display err in state
		b.WriteString(newRow().pad(indent+2).label("state").
			write("✕ "+truncate(cfg.Err.Error(), edge-indent-labelWidth-4), colour.Red).String() + "\n")
		return
	}

	// checksum recorded by the last apply, read back from the state files
	applied := appliedChecksum(m.status)
	switch {
	// if either are empty, warn about being unable to diff
	case applied == "" || cfg.Checksum == "":
		b.WriteString(newRow().pad(indent+2).label("state").
			write("· nothing to compare against", colour.DarkGrey).String() + "\n")

	// detect if config drifted since last apply (same filename tho)
	case drifted(cfg, m.status):
		r := newRow().pad(indent+2).label("state").
			write("● changed on disk since last apply", colour.Yellow)

		// display quick synopsis of diff/line change count (ie: +4 -2 lines)
		if m.diff.ok && diffMatches(m.diff, cfg, applied) {
			r.write("  ", nil).
				write(fmt.Sprintf("+%d", m.diff.adds), colour.Green).
				write(" ", nil).
				write(fmt.Sprintf("-%d", m.diff.removes), colour.Red).
				write(" lines", colour.DarkGrey)
		}
		b.WriteString(r.String() + "\n")

	// otherwise, display matching-ruleset note
	default:
		b.WriteString(newRow().pad(indent+2).label("state").
			write("✓ matches the applied ruleset", colour.Green).String() + "\n")
	}

	// if nfty can find the configfile, display last edit time
	if cfg.Exists {
		// TODO: also display who edited it
		b.WriteString(newRow().pad(indent+2).label("edited").
			write(editedAgo(cfg.ModTime), colour.Grey).String() + "\n")
	}

	// both checksums, so drift-detection can display before and after sums
	sumRow := newRow().pad(indent + 2).label("checksum")
	if applied != "" {
		sumRow.write(applied, colour.DarkGrey)
	} else {
		sumRow.write("unknown", colour.DarkGrey)
	}
	// display oldsum → (gavin) newsum
	if cfg.Checksum != "" && cfg.Checksum != applied {
		sumRow.write(" → ", colour.DarkGrey).write(cfg.Checksum, colour.Bold)
	}
	b.WriteString(sumRow.String() + "\n")
}

// display state-file details
func (m model) renderStateFiles(b *strings.Builder) {
	b.WriteString(newRow().write("state files", colour.Grey).String() + "\n")
	// iterate through state-files, print whether they exist and last-edit + filesize info
	for _, f := range m.status.StateFiles {
		r := newRow().pad(indent + 2).label(f.Label)
		if !f.Present {
			b.WriteString(r.write("not found", colour.Red).String() + "\n")
			continue
		}
		r.write("present", colour.Green)
		if f.Info != "" {
			r.write("  - "+f.Info, colour.DarkGrey)
		}
		b.WriteString(r.String() + "\n")
	}
}

// display ruleset details
func (m model) renderRuleset(b *strings.Builder) {
	rs := m.status.Ruleset
	r := newRow().write("active ruleset", colour.Grey)
	if m.cfg.Table != "" {
		r.pad(valueCol).write(m.cfg.Table, colour.Cyan)
	}
	b.WriteString(r.String() + "\n")

	// counts are scraped from the live nft ruleset, not from .toml
	for _, kv := range [][2]string{
		{"tables", fmt.Sprint(rs.Tables)},
		{"chains", fmt.Sprint(rs.Chains)},
		{"rules", fmt.Sprint(rs.Rules)},
	} {
		b.WriteString(newRow().pad(indent+2).label(kv[0]).
			write(kv[1], colour.Bold).String() + "\n")
	}
}

// placeholder body for wip panes
func stubPane(m model) string {
	notes := map[pane]string{
		paneRules:    "active rules - planned: chains, per-rule detail, live rates, dead-rule markers, etc",
		paneLists:    "address lists - planned: ip lists and which rules reference them",
		paneSettings: "core settings - planned: edits to primary nfty settings ([core] .toml options)",
		paneLog:      "kernel nft logs - planned: display aggregated firewall logs",
	}
	var b strings.Builder
	b.WriteString(newRow().write(paneNames[m.pane], colour.Grey).String() + "\n\n")
	b.WriteString(newRow().pad(indent+2).write("work-in-progress", colour.DarkGrey).String() + "\n")
	// notes run long, so they get clipped to the frame rather than wrapping past it
	if note, ok := notes[m.pane]; ok {
		b.WriteString(newRow().pad(indent+2).
			write(truncate(note, contentEdge(m)-indent-2), colour.DarkGrey).String() + "\n")
	}
	return b.String()
}

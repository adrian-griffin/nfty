// tui_render_test.go
// tests visual tui render output
package tui

import (
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	tea "charm.land/bubbletea/v2"

	"github.com/adrian-griffin/nfty/internal/colour"
	"github.com/adrian-griffin/nfty/internal/commit"
	"github.com/adrian-griffin/nfty/internal/core"
)

// keypresses to test through bubbletea
// so that all can be tested without a live terminal
func keyPress(key string) tea.KeyPressMsg {
	switch key {
	case "tab":
		return tea.KeyPressMsg{Code: tea.KeyTab}
	case "shift+tab":
		return tea.KeyPressMsg{Code: tea.KeyTab, Mod: tea.ModShift}
	case "enter":
		return tea.KeyPressMsg{Code: tea.KeyEnter}
	case "esc":
		return tea.KeyPressMsg{Code: tea.KeyEscape}
	case "backspace":
		return tea.KeyPressMsg{Code: tea.KeyBackspace}
	default:
		return tea.KeyPressMsg{Code: []rune(key)[0], Text: key}
	}
}

// defines a confirmed-config model for tests
func confirmedModel() model {
	applied := time.Date(2026, 8, 30, 14, 58, 22, 0, time.UTC)
	return model{
		width:    80,
		hostname: "vps-fra1",
		now:      applied.Add(8 * time.Minute),
		status: &core.Status{
			LastApply: &commit.LastApply{
				ConfigPath:  "/etc/nfty/public.toml",
				AppliedBy:   "root@100.10.1.1",
				AppliedAt:   applied,
				ConfirmedAt: applied,
				Checksum:    "a3f91c2e",
			},
			StateFiles: []core.StateFile{
				{Label: "running.nft", Present: true, Info: "6.2KB, 8m ago"},
			},
			Ruleset: core.RulesetStats{Tables: 2, Chains: 7, Rules: 34},
		},
		cfg: configState{
			Path:     "/etc/nfty/public.toml",
			Source:   "last apply",
			Exists:   true,
			ModTime:  applied,
			Checksum: "a3f91c2e",
			Table:    "nfty-public",
			fileHash: "deadbeef",
		},
	}
}

// tests do not run against a live terminal, so colour disables itself
// which means plain text + column counts line up with rune/char counts
func TestRowPadsToColumn(t *testing.T) {
	got := newRow().write("nfty", colour.Grey).pad(20).write("x", nil).String()
	if want := "  nfty" + strings.Repeat(" ", 14) + "x"; got != want {
		t.Fatalf("row padding\n got %q\nwant %q", got, want)
	}
}

// a row that has overrun its slot must keep its text rather than move backwards
func TestRowPadNeverMovesBackwards(t *testing.T) {
	got := newRow().write("a-very-long-value", nil).pad(4).write("!", nil).String()
	if !strings.HasSuffix(got, "a-very-long-value!") {
		t.Fatalf("pad truncated the row: %q", got)
	}
}

// tests that the right-hand side of the row aligns to edge-max properly
func TestRowRightAlignsToEdge(t *testing.T) {
	got := newRow().write("nfty", nil).right(40, "✓ CONFIRMED", nil).String()
	if n := utf8.RuneCountInString(got); n != 40 {
		t.Fatalf("right edge landed at %d, want 40: %q", n, got)
	}
	if !strings.HasSuffix(got, "✓ CONFIRMED") {
		t.Fatalf("right-aligned text missing: %q", got)
	}
}

// tests that truncated paths keep tail visible (ie: ...ath/to/dir/filename.toml)
func TestTruncatePathKeepsTail(t *testing.T) {
	got := truncatePath("/etc/nfty/conf.d/public.toml", 14)
	if utf8.RuneCountInString(got) != 14 {
		t.Fatalf("truncated path is %d runes: %q", utf8.RuneCountInString(got), got)
	}
	if !strings.HasSuffix(got, "public.toml") {
		t.Fatalf("truncation dropped the filename: %q", got)
	}
}

// tests that dynamic .toml config path resolution follows proper
// precendence/priority flow (ie: 1: user override, 2: pending state, 3: last/previous apply)
func TestResolveConfigPathPriority(t *testing.T) {
	status := &core.Status{
		HasPending: true,
		Pending:    &commit.PendingState{ConfigPath: "/etc/nfty/pending.toml"},
		LastApply:  &commit.LastApply{ConfigPath: "/etc/nfty/last.toml"},
	}

	// user-passed arg always preferred
	if path, source := resolveConfigPath("/tmp/override.toml", status); path != "/tmp/override.toml" || source != "argument" {
		t.Fatalf("override ignored: %q (%s)", path, source)
	}

	// otherwise, a pending state is the smartest option
	if path, source := resolveConfigPath("", status); path != "/etc/nfty/pending.toml" || source != "pending apply" {
		t.Fatalf("pending path not chosen: %q (%s)", path, source)
	}

	// if no pending state, the last/previous confirmed apply
	status.HasPending = false
	status.Pending = nil
	if path, source := resolveConfigPath("", status); path != "/etc/nfty/last.toml" || source != "last apply" {
		t.Fatalf("last-apply path not chosen: %q (%s)", path, source)
	}
}

// tests that drift-detection fires only when both checksums are known and differ
func TestDriftedNeedsBothChecksums(t *testing.T) {
	status := &core.Status{LastApply: &commit.LastApply{Checksum: "aaaa1111"}}

	if !drifted(configState{Checksum: "bbbb2222"}, status) {
		t.Fatal("differing checksums should read as drift")
	}
	if drifted(configState{Checksum: "aaaa1111"}, status) {
		t.Fatal("matching checksums should not read as drift")
	}
	// an unknown checksum doesnt mean anything and should be caught
	if drifted(configState{}, status) {
		t.Fatal("unrendered config should not read as drift")
	}
	if drifted(configState{Checksum: "bbbb2222"}, &core.Status{}) {
		t.Fatal("missing applied checksum should not read as drift")
	}
}

// test that the tui badge/top right field tracks current state properly
func TestBadgeTracksLifecycle(t *testing.T) {
	m := confirmedModel()
	if badge, _ := m.badge(); badge != "✓ CONFIRMED" {
		t.Fatalf("clean state badge: %q", badge)
	}

	m.status.HasPending = true
	if badge, _ := m.badge(); badge != "▲ PENDING" {
		t.Fatalf("pending badge: %q", badge)
	}

	m.err = errStub{}
	if badge, _ := m.badge(); badge != "✕ UNREADABLE" {
		t.Fatalf("error badge: %q", badge)
	}
}

type errStub struct{}

func (errStub) Error() string { return "nft unavailable" }

// test that apply key remains disabled until a diff/drift is detected
func TestApplyHintFollowsDrift(t *testing.T) {
	m := confirmedModel()
	for _, h := range m.keyHints() {
		if h.key == "x" && h.on {
			t.Fatal("apply hint lit with no drift")
		}
	}

	m.cfg.Checksum = "7d10b4ff"
	var lit bool
	for _, h := range m.keyHints() {
		if h.key == "x" {
			lit = h.on
		}
	}
	if !lit {
		t.Fatal("apply hint dark despite drift")
	}

	// ensure apply hint stays disabled while confirm is pending
	m.status.HasPending = true
	for _, h := range m.keyHints() {
		if h.key == "x" && h.on {
			t.Fatal("apply hint lit during a pending confirm window")
		}
	}
}

// test thatkeys properly navigate panes
func TestPaneKeysSelectAndCycle(t *testing.T) {
	m := confirmedModel()

	// num-key testing
	next, _ := updateKeys(keyPress("3"), m)
	if got := next.(model).pane; got != paneLists {
		t.Fatalf("number key selected pane %d, want %d", got, paneLists)
	}

	// tab cycling must wrap
	m.pane = paneLog
	next, _ = updateKeys(keyPress("tab"), m)
	if got := next.(model).pane; got != paneStatus {
		t.Fatalf("tab from the last pane landed on %d, want %d", got, paneStatus)
	}

	m.pane = paneStatus
	next, _ = updateKeys(keyPress("shift+tab"), m)
	if got := next.(model).pane; got != paneLog {
		t.Fatalf("shift+tab from the first pane landed on %d, want %d", got, paneLog)
	}
}

// test that empty path-editor input clears path override
func TestEditorClearsOverrideOnEmptyInput(t *testing.T) {
	m := confirmedModel()
	m.pathOverride = "/tmp/scratch.toml"
	m.editing = true
	m.editBuf = "   "

	next, _ := updateEditor(keyPress("enter"), m)
	got := next.(model)
	if got.editing {
		t.Fatal("editor stayed open after enter")
	}
	if got.pathOverride != "" {
		t.Fatalf("override survived an empty field: %q", got.pathOverride)
	}
}

// test that pane shortcuts/navigation does not fire while
// editing the config path via the editor
func TestEditorSwallowsPaneKeys(t *testing.T) {
	m := confirmedModel()
	m.editing = true

	for _, key := range []string{"3", "a", "q"} {
		next, _ := updateEditor(keyPress(key), m)
		m = next.(model)
	}
	if m.pane != paneStatus || m.quitting {
		t.Fatalf("editor leaked keys: pane %d, quitting %v", m.pane, m.quitting)
	}
	if m.editBuf != "3aq" {
		t.Fatalf("editor buffer is %q, want %q", m.editBuf, "3aq")
	}
}

// test that the status pane properly reports config drift
func TestStatusPaneReportsDrift(t *testing.T) {
	m := confirmedModel()

	// in sync
	if body := statusPane(m); !strings.Contains(body, "matches the applied ruleset") {
		t.Fatalf("in-sync config not reported:\n%s", body)
	}

	// drifted, with line counts available
	m.cfg.Checksum = "7d10b4ff"
	m.diff = diffStat{forHash: m.cfg.fileHash, forApplied: "a3f91c2e", adds: 14, removes: 6, ok: true}
	body := statusPane(m)
	for _, want := range []string{
		"changed on disk since last apply",
		"+14",
		"-6",
		"a3f91c2e → 7d10b4ff",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("drift report missing %q:\n%s", want, body)
		}
	}
}

// test that the status pane drops stale diffs
// either the config raw bytes or the ruleset itself changing
// must result in the current diff being rejected
func TestStatusPaneDropsStaleDiffStat(t *testing.T) {
	// the config was edited again after the counts were computed
	m := confirmedModel()
	m.cfg.Checksum = "7d10b4ff"
	m.diff = diffStat{forHash: "an-older-hash", forApplied: "a3f91c2e", adds: 99, removes: 99, ok: true}

	if body := statusPane(m); strings.Contains(body, "+99") {
		t.Fatalf("counts for a superseded config rendered:\n%s", body)
	}

	// if a change is applied from another shell, the counts must be considered stale
	m = confirmedModel()
	m.cfg.Checksum = "7d10b4ff"
	m.status.LastApply.Checksum = "cc33dd44"
	m.diff = diffStat{forHash: m.cfg.fileHash, forApplied: "a3f91c2e", adds: 99, removes: 99, ok: true}

	if body := statusPane(m); strings.Contains(body, "+99") {
		t.Fatalf("counts for a superseded ruleset rendered:\n%s", body)
	}
}

// the update loop has to notice the same two cases and schedule a fresh diff
func TestConfigMsgRecomputesWhenEitherKeyMoves(t *testing.T) {
	base := confirmedModel()
	base.cfg.Checksum = "7d10b4ff"
	base.diff = diffStat{forHash: base.cfg.fileHash, forApplied: "a3f91c2e", adds: 14, removes: 6, ok: true}

	// nothing changed, so no re-diff is fired and the counts survive
	next, cmd := update(configMsg{cfg: base.cfg}, base)
	if cmd != nil {
		t.Fatal("unchanged config scheduled a redundant diff")
	}
	if got := next.(model).diff; !got.ok || got.adds != 14 {
		t.Fatalf("settled counts were discarded: %+v", got)
	}

	// applied checksum changed, counts must be dropped and recomputed
	moved := base
	moved.status = &core.Status{
		LastApply:  &commit.LastApply{Checksum: "cc33dd44"},
		StateFiles: base.status.StateFiles,
		Ruleset:    base.status.Ruleset,
	}
	next, cmd = update(configMsg{cfg: moved.cfg}, moved)
	if cmd == nil {
		t.Fatal("a moved applied checksum did not schedule a recompute")
	}
	got := next.(model).diff
	if got.ok {
		t.Fatalf("stale counts survived the recompute trigger: %+v", got)
	}
	if got.forApplied != "cc33dd44" {
		t.Fatalf("in-flight marker keyed to %q, want the new applied checksum", got.forApplied)
	}
}

// once config is back in-step with the live ruleset, alert must clear
func TestConfigMsgClearsCountsWhenDriftResolves(t *testing.T) {
	m := confirmedModel()
	m.diff = diffStat{forHash: m.cfg.fileHash, forApplied: "a3f91c2e", adds: 14, removes: 6, ok: true}

	// cfg.Checksum already matches LastApply.Checksum in confirmedModel
	next, cmd := update(configMsg{cfg: m.cfg}, m)
	if cmd != nil {
		t.Fatal("an in-sync config scheduled a diff")
	}
	if got := next.(model).diff; got.ok || got.forHash != "" {
		t.Fatalf("counts survived drift resolving: %+v", got)
	}
}

// pending.json holds the deadline, the tui only reports off it
func TestPendingCountdownReadsTheDeadline(t *testing.T) {
	m := confirmedModel()
	m.status.HasPending = true
	m.status.Pending = &commit.PendingState{
		ConfigPath: "/etc/nfty/public.toml",
		AppliedBy:  "root@100.10.1.1",
		AppliedAt:  time.Now(),
		Deadline:   time.Now().Add(47 * time.Second),
		Checksum:   "a3f91c2e",
	}
	m.status.LastApply = nil

	body := statusPane(m)
	if !strings.Contains(body, "47s remaining") {
		t.Fatalf("countdown missing:\n%s", body)
	}
	if !strings.Contains(body, "systemd timer") {
		t.Fatalf("timer ownership not stated:\n%s", body)
	}
}

// confirm has to stay reachable with an unreadable pending.json, must alert
// rather than rendering blank
func TestUnreadablePendingStateStillPrompts(t *testing.T) {
	m := confirmedModel()
	m.status.HasPending = true
	m.status.Pending = nil

	body := statusPane(m)
	if !strings.Contains(body, "unreadable") || !strings.Contains(body, "nfty confirm") {
		t.Fatalf("unreadable pending state not explained:\n%s", body)
	}
}

// bubbletea renders once before the first WindowSizeMsg, so the very first
// View() runs against a zero width and musn't panic
// had resulted in the tui crashing with a rollback still armed
func TestViewSurvivesEveryTerminalWidth(t *testing.T) {
	states := map[string]func(m model) model{
		"unsized":  func(m model) model { m.status = nil; return m },
		"loading":  func(m model) model { m.status = nil; return m },
		"errored":  func(m model) model { m.status = nil; m.err = errStub{}; return m },
		"clean":    func(m model) model { return m },
		"drifted":  func(m model) model { m.cfg.Checksum = "7d10b4ff"; return m },
		"help":     func(m model) model { m.showHelp = true; return m },
		"editing":  func(m model) model { m.editing = true; m.editBuf = "/etc/nfty/x.toml"; return m },
		"noconfig": func(m model) model { m.cfg = configState{}; return m },
		"notice":   func(m model) model { m.notice = strings.Repeat("long ", 40); return m },
	}

	// 0 is the pre-size render
	for _, width := range []int{0, 1, 2, 20, 40, 59, 60, 61, 80, 100, 200} {
		for name, mutate := range states {
			for p := pane(0); p < paneCount; p++ {
				m := mutate(confirmedModel())
				m.width = width
				m.pane = p

				func() {
					defer func() {
						if r := recover(); r != nil {
							t.Fatalf("View panicked at width %d, state %q, pane %d: %v",
								width, name, p, r)
						}
					}()
					m.View()
				}()
			}
		}
	}
}

// test that the clamp keeps every downstream width calculation positive
func TestEdgeStaysWithinClamps(t *testing.T) {
	for _, width := range []int{0, 1, 40, 80, 500} {
		m := model{width: width}
		if edge := contentEdge(m); edge < minWidth || edge > maxWidth {
			t.Fatalf("width %d produced edge %d, want %d..%d", width, edge, minWidth, maxWidth)
		}
	}
}

// the layouts must tolerate garbage/nonsense widths
func TestLayoutsTolerateGarbageWidths(t *testing.T) {
	for _, width := range []int{-10, -1, 0, 1, 2} {
		fit("value", width)
		truncate("value", width)
		truncatePath("/etc/nfty/public.toml", width)
		divider(width)
	}
}

// test that frame rows fit within the terminal max width
func TestFrameRowsFitTheContentWidth(t *testing.T) {
	states := map[string]func(m model) model{
		"confirmed": func(m model) model { return m },
		"drifted": func(m model) model {
			m.cfg.Checksum = "7d10b4ff"
			// forApplied has to match or the counts get dropped
			// causing the widest row to never renders
			m.diff = diffStat{forHash: m.cfg.fileHash, forApplied: "a3f91c2e", adds: 14, removes: 6, ok: true}
			return m
		},
		"pending": func(m model) model {
			m.status.HasPending = true
			m.status.Pending = &commit.PendingState{
				ConfigPath: "/etc/nfty/public.toml",
				AppliedBy:  "root@100.10.1.1",
				AppliedAt:  time.Now(),
				Deadline:   time.Now().Add(108 * time.Second),
				Checksum:   "7d10b4ff",
			}
			return m
		},
		"unreadable pending": func(m model) model {
			m.status.HasPending = true
			m.status.Pending = nil
			return m
		},
		"long path": func(m model) model {
			m.cfg.Path = "/home/agriffin/nfty/toml-templates/very/deep/nested/internal-host.toml"
			m.cfg.Source = "pending apply"
			return m
		},
		"no config": func(m model) model { m.cfg = configState{}; return m },
	}

	for _, width := range []int{80, 81, 96, 120, 200} {
		for name, mutate := range states {
			m := mutate(confirmedModel())
			m.width = width
			edge := contentEdge(m)

			lines := append(strings.Split(statusPane(m), "\n"),
				m.header(), m.tabs(), m.footer(), divider(edge))
			lines = append(lines, strings.Split(m.help(), "\n")...)
			for p := pane(0); p < paneCount; p++ {
				m.pane = p
				lines = append(lines, strings.Split(body(m), "\n")...)
			}

			for _, line := range lines {
				if n := utf8.RuneCountInString(line); n > edge {
					t.Fatalf("width %d, state %q: row is %d cols, edge is %d: %q",
						width, name, n, edge, line)
				}
			}
		}
	}
}

// test that file paths don't collide with the (source) inform
func TestConfigPathNeverCollidesWithSource(t *testing.T) {
	for _, source := range []string{"argument", "pending apply", "last apply", "default path"} {
		m := confirmedModel()
		m.cfg.Path = "/home/agriffin/nfty/toml-templates/very/deep/nested/internal-host.toml"
		m.cfg.Source = source

		var b strings.Builder
		m.renderConfig(&b)

		for _, line := range strings.Split(b.String(), "\n") {
			if !strings.Contains(line, ".toml") {
				continue
			}
			if n := utf8.RuneCountInString(line); n > contentEdge(m) {
				t.Fatalf("source %q overflowed: %d cols vs edge %d: %q", source, n, contentEdge(m), line)
			}
			// the suffix must be readable as its own token, not glued to the path
			if !strings.Contains(line, "  ("+source+")") {
				t.Fatalf("source %q has no gap before it: %q", source, line)
			}
		}
	}
}

// wrapped text has to survive/fit arbitrary column widths
func TestWrapTextFitsTheColumn(t *testing.T) {
	text := "Every apply arms a rollback before the new rules go in, and that timer " +
		"is a systemd unit rather than part of nfty."

	for _, width := range []int{10, 20, 40, 78} {
		for _, line := range wrapText(text, width) {
			if n := utf8.RuneCountInString(line); n > width {
				t.Fatalf("width %d produced a %d-col line: %q", width, n, line)
			}
		}
	}

	// cut words that cannot break, rather than overhanging them
	for _, line := range wrapText("supercalifragilistic", 8) {
		if n := utf8.RuneCountInString(line); n > 8 {
			t.Fatalf("unbreakable word overhung the column: %q", line)
		}
	}

	if got := wrapText("anything", 0); got != nil {
		t.Fatalf("zero width should wrap to nothing, got %q", got)
	}
}

// test that text-wrapper handles linebreaks properly
func TestWrapTextHonoursExplicitBreaks(t *testing.T) {
	// a single \n starts a new line without a gap
	got := wrapText("first line\nsecond line", 40)
	if len(got) != 2 || got[0] != "first line" || got[1] != "second line" {
		t.Fatalf("single break should give two lines, got %q", got)
	}

	// leading spaces after the break get swallowed
	if got := wrapText("first\n second", 40); got[1] != "second" {
		t.Fatalf("break should not carry leading whitespace, got %q", got[1])
	}

	// a doubled break emits a blank line between paragraphs
	got = wrapText("para one\n\npara two", 40)
	if len(got) != 3 || got[1] != "" {
		t.Fatalf("doubled break should leave a blank line, got %q", got)
	}

	// each segment must still wrap on its own
	for _, line := range wrapText("aaa bbb ccc ddd\neee fff ggg hhh", 7) {
		if utf8.RuneCountInString(line) > 7 {
			t.Fatalf("segment overflowed the column: %q", line)
		}
	}
}

// pages with more content than fits in the frame can be scrolled to
// but must advertise as such as to not get missed
func TestClipLinesMarksHiddenContent(t *testing.T) {
	lines := []string{"a", "b", "c", "d", "e", "f"}

	// unknown height means the size is not known yet, nothing gets clipped
	if got := strings.Count(clipLines(lines, 0, 0), "\n"); got != len(lines) {
		t.Fatalf("unclipped render produced %d lines, want %d", got, len(lines))
	}

	// clipped from the top, showing the window plus a marker row
	out := clipLines(lines, 4, 0)
	if n := strings.Count(out, "\n"); n != 4 {
		t.Fatalf("clipped render produced %d lines, want 4", n)
	}
	if !strings.Contains(out, "↓ 3 more") || strings.Contains(out, "↑") {
		t.Fatalf("marker should report 3 below and nothing above:\n%s", out)
	}

	// scrolling into the middle reports more in both directions
	if out := clipLines(lines, 4, 2); !strings.Contains(out, "↑ 2 more") || !strings.Contains(out, "↓ 1 more") {
		t.Fatalf("marker should report both directions:\n%s", out)
	}

	// a scroll past the end clamps
	if out := clipLines(lines, 4, 99); !strings.Contains(out, "f") {
		t.Fatalf("over-scroll should clamp to the last line:\n%s", out)
	}
}

// vertical scolling ends at the last line of content and musnt scroll into dead space (good game)
func TestHelpScrollClampsToContent(t *testing.T) {
	m := confirmedModel()
	m.height = 24

	max := helpScrollMax(m)
	if max <= 0 {
		t.Fatalf("help should overflow a 24-row terminal, got max scroll %d", max)
	}

	// pressing s/down past the end must not advance
	m.showHelp = true
	m.helpScroll = max
	next, _ := updateKeys(keyPress("s"), m)
	if got := next.(model).helpScroll; got != max {
		t.Fatalf("scroll ran past the end: %d, want %d", got, max)
	}

	// and w stops at the top
	m.helpScroll = 0
	next, _ = updateKeys(keyPress("w"), m)
	if got := next.(model).helpScroll; got != 0 {
		t.Fatalf("scroll ran above the first line: %d", got)
	}

	// closing help should rewind, so that reopening doesn't land mid-paragraph
	m.helpScroll = max
	next, _ = updateKeys(keyPress("?"), m)
	if got := next.(model).helpScroll; got != 0 {
		t.Fatalf("help kept its scroll position across a close: %d", got)
	}
}

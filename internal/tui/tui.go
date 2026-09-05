// tui.go
// interactive terminal interface
// only the tui package depends on the bubbletea library to keep rest of program wholly independent
package tui

import (
	"fmt"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	tea "charm.land/bubbletea/v2"
	"golang.org/x/term"

	"github.com/adrian-griffin/nfty/internal/colour"
	"github.com/adrian-griffin/nfty/internal/core"
	"github.com/adrian-griffin/nfty/internal/nft"
)

const (
	// clock interval redraws tui to update countdown
	// poll interval checks for changes to live ruleset & state files
	clockInterval = time.Second
	pollInterval  = 5 * time.Second
)

// defines bubbletea Tick types
type (
	clockTickMsg time.Time
	pollTickMsg  time.Time
)

type statusMsg struct {
	status *core.Status
	err    error
}

// wraps the configState so bubbletea can pass it thru Update()
type configMsg struct{ cfg configState }

// counts up stats of diff between the live and rendered nft ruleset
type diffStatMsg struct {
	forHash    string
	forApplied string
	adds       int
	removes    int
	err        error
}

// tui state, bubbletea calls Update() and View() on this repeatedly
type model struct {
	// terminal
	width    int
	height   int
	hostname string
	now      time.Time

	// data, all re-collected from disk every pollInterval
	status *core.Status
	err    error
	cfg    configState
	diff   diffStat

	// allows .toml path override from tui
	pathOverride string

	// tui state
	pane       pane
	showHelp   bool
	helpScroll int // first visible help line, help is taller than most terminals
	editing    bool
	editBuf    string
	notice     string
	quitting   bool
}

// determines how tall the body pane can be, given what is left after the frame's chrome
// (ie: header, dividers, the nav bar, footer, notice message, etc)
// returns 0 before the first WindowSizeMsg
func bodyHeight(m model) int {
	if m.height == 0 {
		return 0
	}
	chrome := 7
	if m.editing {
		chrome++
	}
	if m.notice != "" {
		chrome++
	}
	return m.height - chrome
}

// bubbletea's Model interface requires receivers
func (m model) Init() tea.Cmd                           { return initCmds(m) }
func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) { return update(msg, m) }
func (m model) View() tea.View                          { return view(m) }

// limits right-side of tui table to a max in order to keep it
// readable and properly-sized (too long makes it tough to follow rows)
// the lower clamp is crucial here, as layout widths are all calculated from here
// and a negative one panics strings.Repeat
func contentEdge(m model) int {
	edge := m.width - indent
	if edge > maxWidth {
		edge = maxWidth
	}
	if edge < minWidth {
		edge = minWidth
	}
	return edge
}

// fetches a new snapshot of current nft state
func fetchStatus() tea.Msg {
	status, err := core.GatherStatus()
	return statusMsg{status: status, err: err}
}

// creates and returns command which reads the target .toml and converts it to a configState
// this outer body runs inside the core trui update loop and cannot block or perform disk operations
// the command it returns does touch disk, but within bubbletea's own goroutine
func fetchConfig(m model) tea.Cmd {
	// everything the .toml read depends on is built/resolved here, but is not executed
	// as to keep the update loop moving, prevent tui hiccup, etc.
	path, source := resolveConfigPath(m.pathOverride, m.status)

	// holds the previous configfile hash and render, allowing pollConfig
	// to skip re-parsing the file if it hasn't changed
	prev := m.cfg

	// the command itself, run later and out of the main tui update loop, this is the only
	// part that touches the disk and reads the .toml file
	poll := func() tea.Msg {
		cfg := pollConfig(path, source, prev)
		return configMsg{cfg: cfg}
	}

	return poll
}

// diffs nfty rendered/converted nftables config against what lives in the system's live ruleset
// returns diffStatMsg for bubbletea with counts of the lines added and removed
// somewhat heavy and only worth running when the file has actually changed, so is a separate
// cmd rather than part of the main poll
func diffStatCmd(cfg configState, applied string) tea.Cmd {
	hash, table, script := cfg.fileHash, cfg.Table, cfg.Script
	return func() tea.Msg {
		adds, removes, err := nft.DiffStat(table, script)
		return diffStatMsg{
			forHash: hash, forApplied: applied,
			adds: adds, removes: removes, err: err,
		}
	}
}

// builds cmd that ticks the tui clock, keeps the countdown moving
// bubbletea runs the timer off the update loop and delivers a clockTickMsg back
// into it when it fires, so each tick has to re-arm the next one
func clockTick() tea.Cmd {
	return tea.Tick(clockInterval, func(t time.Time) tea.Msg { return clockTickMsg(t) })
}

// builds cmd that ticks the tui polling of statefiles and config
// keeps the live ruleset and state files up to date, same re-arming as clockTick
func pollTick() tea.Cmd {
	return tea.Tick(pollInterval, func(t time.Time) tea.Msg { return pollTickMsg(t) })
}

// bubbletea calls this once on start, kicks off the first fetches and starts both
// tickers that keep the update loop running from then on
func initCmds(m model) tea.Cmd {
	return tea.Batch(fetchStatus, fetchConfig(m), clockTick(), pollTick())
}

// main tui update loop, bubbletea calls this repeatedly with events and current model
// handles tui interaction events and returns updated model + any user-supplied cmds to run
func update(msg tea.Msg, m model) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {

	// sets terminal size, is checked on every update cycle to adjust as terminal is resized
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil
	// parse when the user presses a key (while tui is open, all keys are captured)
	case tea.KeyPressMsg:
		// if path editor is open, all keypresses go to it
		if m.editing {
			return updateEditor(msg, m)
		}
		// otherwise, return to main tui keypress handler
		return updateKeys(msg, m)

	// clock updates only, doesnt touch disk
	case clockTickMsg:
		m.now = time.Time(msg)
		return m, clockTick()

	// poll nft config and nfty statefiles every pollInterval
	case pollTickMsg:
		return m, tea.Batch(fetchStatus, fetchConfig(m), pollTick())

	// a finished status read coming back from fetchStatus
	case statusMsg:
		// set model's status or error
		// then re-resolve the config path
		m.status = msg.status
		m.err = msg.err
		// by default the path comes from state files
		// re-resolves the config path immediately if the state files changed
		if path, _ := resolveConfigPath(m.pathOverride, m.status); path != m.cfg.Path {
			return m, fetchConfig(m)
		}
		return m, nil

	// if config file changed, re-render to nftables script and diff against the live ruleset
	case configMsg:
		// set model's configState to what is passed from pollConfig
		// which is the result of reading and rendering the .toml file
		m.cfg = msg.cfg
		applied := appliedChecksum(m.status)

		// a config matching what is applied has nothing to count against
		if !drifted(m.cfg, m.status) {
			m.diff = diffStat{}
			return m, nil
		}

		// recompute hash if either the raw config bytes or the applied ruleset changes
		// the zeroed value is an in-flight marker, so that a re-poll that happens to
		// land mid-computation doesn't fire a second diff
		if !diffMatches(m.diff, m.cfg, applied) {
			m.diff = diffStat{forHash: m.cfg.fileHash, forApplied: applied}
			return m, diffStatCmd(m.cfg, applied)
		}
		return m, nil

	// diffStatMsg is only sent when the config file changed and the diffStatCmd was run
	case diffStatMsg:
		// drop results computed from a stale config or ruleset
		if msg.forHash != m.cfg.fileHash || msg.forApplied != appliedChecksum(m.status) {
			return m, nil
		}
		// update the model with the new diffStat
		// the zeroed marker is left in place so that diffMatches remains True
		// and no retries fire
		if msg.err == nil {
			m.diff = diffStat{
				forHash: msg.forHash, forApplied: msg.forApplied,
				adds: msg.adds, removes: msg.removes, ok: true,
			}
		}
		return m, nil
	}

	return m, nil
}

// if the main update loop catches a keypress, parse it and act accordingly
// returns the updated model and any commands to run
func updateKeys(msg tea.KeyPressMsg, m model) (tea.Model, tea.Cmd) {
	key := msg.String()

	// clears previous notice
	// notice is used to display messages to the user, such as errors or help text
	m.notice = ""

	switch key {
	// exiting tui
	case "q", "esc", "ctrl+c":
		m.quitting = true
		return m, tea.Quit
	// toggles help, always reopening at the top
	case "?":
		m.showHelp = !m.showHelp
		m.helpScroll = 0
		return m, nil

	// scroll vertically if the body is too long for the view
	// currently scoped to the help window only
	case "w", "up":
		if m.showHelp && m.helpScroll > 0 {
			m.helpScroll--
		}
		return m, nil
	case "s", "down":
		if m.showHelp && m.helpScroll < helpScrollMax(m) {
			m.helpScroll++
		}
		return m, nil
	// refreshes status and config
	case "r":
		return m, tea.Batch(fetchStatus, fetchConfig(m))
	// opens the config path editor
	case "/":
		m.editing = true
		m.editBuf = m.cfg.Path
		return m, nil
	// switches forward between panes
	case "tab":
		m.pane = (m.pane + 1) % paneCount
		m.showHelp = false
		return m, nil
	// switches backward between panes
	case "shift+tab":
		m.pane = (m.pane + paneCount - 1) % paneCount
		m.showHelp = false
		return m, nil
	// switches forward between panes
	case "d":
		m.pane = (m.pane + 1) % paneCount
		m.showHelp = false
		return m, nil
	// switches backward between panes
	case "a":
		m.pane = (m.pane + paneCount - 1) % paneCount
		m.showHelp = false
		return m, nil
	// apply target config
	// if there is a pending apply, reject and warn
	case "x":
		// wip here instead just spit out the command to run
		if m.status != nil && m.status.HasPending {
			m.notice = "an apply window is already open - confirm or rollback first"
			return m, nil
		}
		if m.cfg.Path == "" {
			m.notice = "no valid config path - press [/] to set one"
			return m, nil
		}
		m.notice = "tui apply still wip, instead run: nfty apply " + m.cfg.Path
		return m, nil
	}

	// number keys jump straight to said pane
	// only if the key is a single digit and within the range of available panes
	if len(key) == 1 && key[0] >= '1' && key[0] <= '0'+byte(paneCount) {
		// jump to the pane # pressed, starts at 1 rather than 0 for obvious reasons
		m.pane = pane(key[0] - '1')
		m.showHelp = false
	}
	return m, nil
}

// tui path editor
func updateEditor(msg tea.KeyPressMsg, m model) (tea.Model, tea.Cmd) {
	// eats all keys while active
	switch key := msg.String(); key {

	// exit editor without saving text, returns to tui
	case "esc":
		m.editing = false
		m.editBuf = "" // wipe editor buffer
		return m, nil

	// fully quits tui from editor
	case "ctrl+c":
		m.quitting = true
		return m, tea.Quit

	// save editor text and return to tui
	case "enter":
		path := strings.TrimSpace(m.editBuf)
		m.editing = false
		m.editBuf = "" // wipe editor buffer

		// if nothing is passed when enter is pressed, assume resolve from statefile intent/cancel
		if path == "" {
			m.pathOverride = ""
		} else { // otherwise set config toml path to user-supplied
			m.pathOverride = path
		}
		// drop the old diff, it belongs to the config being watched before
		// a fresh one is computed immediately
		m.diff = diffStat{}
		return m, fetchConfig(m)

	// allows backspace
	case "backspace":
		if runes := []rune(m.editBuf); len(runes) > 0 {
			m.editBuf = string(runes[:len(runes)-1])
		}
		return m, nil

	case "ctrl+u":
		m.editBuf = ""
		return m, nil

	case "space":
		m.editBuf += " "
		return m, nil

	// TODO: add case for pasting

	default:
		// printable single runes only, anything else is a key name and not input
		if utf8.RuneCountInString(key) == 1 {
			m.editBuf += key
		}
		return m, nil
	}
}

// wraps rendered content in a frame, sets alt screen (fullscreen) and window title
func frame(content string) tea.View {
	view := tea.NewView(content)
	view.AltScreen = true
	view.WindowTitle = "nfty tui"
	return view
}

func view(m model) tea.View {
	// last frame before quitting, drawn without AltScreen so that it lands
	// in the true terminal displaying nothing
	// this is cosmetic only, the terminal itself is restored by bubbletea
	// as its Run() exits, and its panic handler if anything goes south
	if m.quitting {
		return tea.NewView("")
	}

	// terminal width/details are not known until first WindowSizeMsg
	if m.width == 0 {
		return frame("")
	}

	// alert if the terminal width shrinks beyond the min limit
	if m.width < minWidth {
		return frame(fmt.Sprintf("\n  nfty tui needs at least %d columns of terminal width\n  this terminal is %d\n",
			minWidth, m.width))
	}

	var b strings.Builder
	// determine cap/limit for right-side edge
	edge := contentEdge(m)

	// writes to terminal view
	// always display header, tabs, and top dividers
	b.WriteString("\n")
	b.WriteString(m.header() + "\n")
	b.WriteString(divider(edge) + "\n")
	b.WriteString(m.tabs() + "\n")
	b.WriteString(divider(edge) + "\n")

	// if help screen toggled
	switch {
	case m.showHelp:
		b.WriteString(m.help())

	// if unable to read nftables ruleset, report with the error itself
	case m.err != nil:
		b.WriteString(newRow().write("could not read the live nftables ruleset", boldRed).String() + "\n")
		b.WriteString(newRow().pad(indent+2).write(m.err.Error(), colour.Red).String() + "\n")

	// if no status this loop, show loading message
	case m.status == nil:
		b.WriteString(newRow().write("reading state files…", colour.DarkGrey).String() + "\n")

	// otherwise print main body (currently just status..)
	default:
		b.WriteString(body(m))
	}

	b.WriteString(divider(edge) + "\n")

	// editor replaces footer while open
	if m.editing {
		b.WriteString(newRow().
			// editor text field
			write("config path: ", colour.Grey).
			// ensure the tail of long paths is always visibile
			write(truncatePath(m.editBuf, edge-indent-14), colour.Bold).
			// text field end visual
			write("|", colour.Cyan).String() + "\n")
		b.WriteString(newRow().
			write(truncate("enter accept · esc cancel · ctrl+u clear · empty to resolve from statefile",
				edge-indent), colour.DarkGrey).String() + "\n")
		return frame(b.String())
	}

	// otherwise, write footer with default help notes
	b.WriteString(m.footer() + "\n")

	// if any notice message needs advertising, write it below the footer
	// this remains in the frame, breadcrumb() prints after the tui closes
	if m.notice != "" {
		b.WriteString(newRow().write(truncate(m.notice, edge-indent), colour.Yellow).String() + "\n")
	}

	return frame(b.String())
}

// entry point for the tui
// args can be supplied following `nfty tui` (optional config path only, really)
func Run(args []string) {
	// prevent tui from getting piped around
	// fail loudly rather than emitting into receiver

	// check if terminal is interactive and reject if not
	if !term.IsTerminal(int(os.Stdout.Fd())) {
		fmt.Fprintln(os.Stderr, "ERROR: nfty tui requires an interactive terminal - use nfty status instead")
		os.Exit(1)
	}

	// parse additional tui args, basic checking for now at [0] for path
	// TODO: needs more robust parsing
	var override string
	if len(args) > 0 {
		override = args[0]
	}

	// TODO: needs path validation, sanitizing hostname (ya never know bro..)
	start := model{
		hostname:     hostname(),
		now:          time.Now(),
		pathOverride: override,
	}

	// create new bubbletea program with start model
	program := tea.NewProgram(start)

	// run bubbletea program/tui, capture returnModel on tui end
	final, err := program.Run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: tui exited: %v\n", err)
		os.Exit(1)
	}

	// leave breadcrumbs/hints for nfty rollback if tui exited while timer is counting
	if m, ok := final.(model); ok {
		breadcrumb(m)
	}
}

// prints the reminder hints into user's true terminal on tui exit
func breadcrumb(m model) {
	// so long as status is empty or no pending job, return silently
	if m.status == nil || !m.status.HasPending || m.status.Pending == nil {
		return
	}
	// otherwise, calculate remaining job time
	remaining := time.Until(m.status.Pending.Deadline).Round(time.Second)
	if remaining <= 0 {
		// possibly TODO: as this branch should neve really be getting hit
		// if so, may want to warn
		return
	}

	// print remainder timer and hints to terminal
	fmt.Printf("%s\n", colour.Yellow(fmt.Sprintf(
		"a nfty apply is still pending, %s left \nrun: nfty confirm or nfty rollback", remaining)))
}

// grab system hostname for tui display
func hostname() string {
	name, err := os.Hostname()
	if err != nil {
		return "unknown-host"
	}
	return name
}

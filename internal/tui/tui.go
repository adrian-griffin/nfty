// tui.go
// interactive terminal interface
// only the tui package depends on the bubbletea library to keep rest of program wholly independent
package tui

import (
	"fmt"
	"os"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"golang.org/x/term"

	"github.com/adrian-griffin/nfty/internal/colour"
	"github.com/adrian-griffin/nfty/internal/core"
	"github.com/adrian-griffin/nfty/internal/meta"
)

const refreshInterval = time.Second

type tickMsg time.Time

type statusMsg struct {
	status *core.Status
	err    error
}

// tui state, bubbletea calls Update() and View() on this repeatedly
type model struct {
	status      *core.Status
	err         error
	lastRefresh time.Time
	width       int
	quitting    bool
}

// fetches a new snapshot of current nft state
func fetchStatus() tea.Msg {
	status, err := core.GatherStatus()
	return statusMsg{status: status, err: err}
}

// refreshes the tui every refreshInterval
func tick() tea.Cmd {
	return tea.Tick(refreshInterval, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

// init on tui call, returns cmds for fetchStatus and tick
func (m model) Init() tea.Cmd {
	return tea.Batch(fetchStatus, tick())
}

// handles tui events, returns updated model and any cmds to run
func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {

	// bubbletea sends a WindowSizeMsg on start so the tui can size correctly
	case tea.WindowSizeMsg:
		m.width = msg.Width
		return m, nil

	// the main tui loop
	// handle keypresses, refreshes
	case tea.KeyPressMsg:
		switch msg.String() {
		case "q", "esc", "ctrl+c": // quit
			m.quitting = true
			return m, tea.Quit
		case "r": // manual refresh
			return m, fetchStatus
		}
		return m, nil

	// fetch new status and refresh the tui on interval
	case tickMsg:
		return m, tea.Batch(fetchStatus, tick())

	// update the tui with a new snapshot of the nfty state
	case statusMsg:
		m.status = msg.status
		m.err = msg.err
		m.lastRefresh = time.Now()
		return m, nil
	}

	return m, nil
}

// wraps rendered content in a frame, sets alt screen (fullscreen) and window title
func frame(content string) tea.View {
	view := tea.NewView(content)
	view.AltScreen = true
	view.WindowTitle = "nfty tui"
	return view // return the view
}

func (m model) View() tea.View {
	// detaching from the alt screen restores main terminal
	if m.quitting {
		return tea.NewView("")
	}

	// build the tui frame as a whole in a strings.Builder, then wrap it in a tea.View
	var built strings.Builder

	// header
	fmt.Fprintf(&built, "  %s - %s\n\n",
		colour.Bold("nfty"), colour.DarkGrey(meta.Version))

	// if err, emit and return early
	if m.err != nil {
		fmt.Fprintf(&built, "  %s %v\n", colour.Red("error:"), m.err)
		// write footer so user knows how to quit the tui (aint vim lol)
		built.WriteString(footer())
		return frame(built.String())
	}

	// if still fetching or no status available, emit a pending response and return early
	if m.status == nil {
		built.WriteString(colour.Grey("  reading statefile...\n"))
		return frame(built.String())
	}

	// the same functions `nfty status` renders with, cli separates via dividers
	// tui currently separating via newlines
	core.RenderPending(&built, m.status)
	built.WriteString("\n")
	core.RenderStateFiles(&built, m.status)
	built.WriteString("\n")
	core.RenderRulesetInfo(&built, m.status)
	built.WriteString(footer())

	// return fully built view
	return frame(built.String())
}

// footer with hints, always at the bottom
func footer() string {
	return "\n  " + colour.DarkGrey("r refresh · q quit") + "\n"
}

// entry point for the tui
func Run() {
	// prevent tui from getting piped around
	// fail loudly rather than emitting into receiver

	// check if terminal is interactive and reject if not
	if !term.IsTerminal(int(os.Stdout.Fd())) {
		fmt.Fprintln(os.Stderr, "ERROR: nfty tui requires an interactive terminal - use nfty status instead")
		os.Exit(1)
	}

	// bubbletea tui program, runs until user quits or an error occurs
	program := tea.NewProgram(model{})
	if _, err := program.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: tui exited: %v\n", err)
		os.Exit(1)
	}
}

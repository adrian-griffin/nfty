// layout.go
// builds column-row layout for use in every pane
// ansi escape sequences make len() useless for alignment, so each write records
// the number of visible columns it consumed and all padding works off that count
package tui

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/adrian-griffin/nfty/internal/colour"
)

const (
	indent     = 2  // left margin shared by all rows
	labelWidth = 17 // grey left-hand label column
	minWidth   = 80 // the layout is built for 80, below it rows wrap and shear the frame
	maxWidth   = 96 // plates are 78-86 wide, higher and it gets hard to track

	// defines indent location for every value column
	valueCol = indent + 2 + labelWidth
)

// defines a paint function type, any ansi colour wrapper matches it (colour.Grey etc)
type paint func(string) string

// combines two paints, eg. boldGreen = combine(colour.Bold, colour.Green)
func combine(outer, inner paint) paint {
	return func(s string) string { return outer(inner(s)) }
}

var (
	boldGreen  = combine(colour.Bold, colour.Green)
	boldYellow = combine(colour.Bold, colour.Yellow)
	boldRed    = combine(colour.Bold, colour.Red)
	boldCyan   = combine(colour.Bold, colour.Cyan)
	tabActive  = combine(colour.Bold, combine(colour.Underline, colour.Cyan))
)

// one fully rendered line, built left to right
type row struct {
	b   strings.Builder
	col int // count of visible columns written so far
}

// always starts a row past left indent margin
func newRow() *row {
	r := &row{}
	r.pad(indent)
	return r
}

// writes text in the given colour, nil paint writes it plain
func (r *row) write(text string, p paint) *row {
	if p != nil {
		r.b.WriteString(p(text))
	} else {
		r.b.WriteString(text)
	}
	r.col += utf8.RuneCountInString(text)
	return r
}

// advances forward a column
// a row already past the requested column cannot go back or delete data
// so instead, alignment takes the hit here, rather than risking text vanishing
func (r *row) pad(to int) *row {
	if to > r.col {
		r.b.WriteString(strings.Repeat(" ", to-r.col))
		r.col = to
	}
	return r
}

// writes a grey label and leaves the cursor at the value/right column
func (r *row) label(name string) *row {
	return r.write(fit(name, labelWidth), colour.Grey)
}

// writes text such that it ends flush against the right edge
func (r *row) right(edge int, text string, p paint) *row {
	return r.pad(edge-utf8.RuneCountInString(text)).write(text, p)
}

// returns the text stored in row's strings.builder as a string
func (r *row) String() string { return r.b.String() }

// the widths below all are arithmetic off the terminal edge, and a negative
// count panics strings.Repeat, leaving the shell a mess with rollback still counting
// so everything is clamped

// pads or truncates to the given width
func fit(s string, width int) string {
	if width <= 0 {
		return ""
	}
	n := utf8.RuneCountInString(s)
	// if longer than the width, truncate text
	if n > width {
		return truncate(s, width)
	}
	// fill with blank space to full width
	return s + strings.Repeat(" ", width-n)
}

// truncate a string with a trailing ellipsis, counts runes rather than raw bytes
func truncate(s string, width int) string {
	if width <= 0 {
		return ""
	}
	if utf8.RuneCountInString(s) <= width {
		return s
	}
	if width == 1 {
		return "…"
	}
	return string([]rune(s)[:width-1]) + "…"
}

// visual section dividers
func divider(edge int) string {
	if edge <= indent {
		return ""
	}
	return newRow().write(strings.Repeat("─", edge-indent), colour.DarkGrey).String()
}

// wraps text onto a column width, splitting on spaces
// returns one string per line so that the caller can clip or scroll them
func wrapText(s string, width int) []string {
	if width <= 0 {
		return nil
	}

	var lines []string
	for _, para := range strings.Split(s, "\n") {
		wrapped := wrapParagraph(para, width)
		// nothing to wrap means newline
		if len(wrapped) == 0 {
			lines = append(lines, "")
			continue
		}
		lines = append(lines, wrapped...)
	}
	return lines
}

// wraps a single paragraph in the terminal (no line breaks)
func wrapParagraph(s string, width int) []string {
	var lines []string
	var line strings.Builder
	col := 0

	for _, word := range strings.Fields(s) {
		// a word wider than the column must be cut
		if utf8.RuneCountInString(word) > width {
			word = truncate(word, width)
		}
		n := utf8.RuneCountInString(word)

		switch {
		// first word on a line goes down
		case col == 0:
			line.WriteString(word)
			col = n
		// fits with the leading space
		case col+1+n <= width:
			line.WriteByte(' ')
			line.WriteString(word)
			col += 1 + n
		// if it doesn't fit, break line and start the next with it
		default:
			lines = append(lines, line.String())
			line.Reset()
			line.WriteString(word)
			col = n
		}
	}
	if col > 0 {
		lines = append(lines, line.String())
	}
	return lines
}

// renders a window of lines + a marker when some are off screen
// bubbletea alt screens silently swallow anything past final row, so a pane with
// more content than fits the display has to say so or the user will never know it exists
// height <= 0 means the terminal size is not known yet, so nothing is clipped
func clipLines(lines []string, height, scroll int) string {
	var b strings.Builder

	if height <= 0 || len(lines) <= height {
		for _, ln := range lines {
			writeLine(&b, ln)
		}
		return b.String()
	}

	// the marker itself consumes a row
	window := height - 1
	if scroll > len(lines)-window {
		scroll = len(lines) - window
	}
	if scroll < 0 {
		scroll = 0
	}

	for _, ln := range lines[scroll : scroll+window] {
		writeLine(&b, ln)
	}

	above, below := scroll, len(lines)-window-scroll
	marker := newRow()
	if above > 0 {
		marker.write(fmt.Sprintf("↑ %d more ", above), colour.Cyan)
	}
	if below > 0 {
		marker.write(fmt.Sprintf("↓ %d more ", below), colour.Cyan)
	}
	marker.write("· w/s to scroll", colour.DarkGrey)
	writeRow(&b, marker)

	return b.String()
}

// writes a finished row and its line break
func writeRow(b *strings.Builder, r *row) {
	b.WriteString(r.String())
	b.WriteByte('\n')
}

// same, for a line that is already rendered
func writeLine(b *strings.Builder, s string) {
	b.WriteString(s)
	b.WriteByte('\n')
}

// watch tail of filepaths
// chop off left to always keep filename in view, rather than truncating right
func truncatePath(path string, width int) string {
	if width <= 0 {
		return ""
	}
	if utf8.RuneCountInString(path) <= width {
		return path
	}
	if width == 1 {
		return "…"
	}
	runes := []rune(path)
	return "…" + string(runes[len(runes)-(width-1):])
}

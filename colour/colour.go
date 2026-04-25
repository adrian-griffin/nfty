package colour

import (
	"fmt"
	"os"

	"golang.org/x/term"
)

// checks whether stdout is interactive shell or not
// if not (ie piping, et all cuz i cant think of other examples), all colour function becomes disabled
var isTTY = term.IsTerminal(int(os.Stdout.Fd()))

// NoColour can be set by a --no-colour or eventual env NFTY_NO_COLOUR (TODO:)
var NoColour bool

func enabled() bool {
	// only if interactive tty + colour enabled
	return isTTY && !NoColour
}

// colours
const (
	reset = "\033[0m"
	bold  = "\033[1m"

	fgRed    = "\033[31m"
	fgGreen  = "\033[32m"
	fgYellow = "\033[33m"
	fgBlue   = "\033[34m"
	fgCyan   = "\033[36m"
	fgWhite  = "\033[37m"
	fgGrey   = "\033[90m"
)

func wrap(code, s string) string {
	if !enabled() {
		return s
	}
	return code + s + reset
}

// colour wrappers
func Bold(s string) string   { return wrap(bold, s) }
func Red(s string) string    { return wrap(fgRed, s) }
func Green(s string) string  { return wrap(fgGreen, s) }
func Blue(s string) string   { return wrap(fgBlue, s) }
func Yellow(s string) string { return wrap(fgYellow, s) }
func Cyan(s string) string   { return wrap(fgCyan, s) }
func Grey(s string) string   { return wrap(fgGrey, s) }

// strf formatters
func Boldf(format string, a ...any) string   { return Bold(fmt.Sprintf(format, a...)) }
func Greenf(format string, a ...any) string  { return Green(fmt.Sprintf(format, a...)) }
func Yellowf(format string, a ...any) string { return Yellow(fmt.Sprintf(format, a...)) }

package nft

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/adrian-griffin/nfty/internal/colour"
	"github.com/adrian-griffin/nfty/internal/config"
)

// writes section divier
func divider() {
	fmt.Println(colour.Grey("  " + strings.Repeat("─", 52)))
}

// reorders flag args to allow dynamic flag inputs from user
func sortFlags(args []string) []string {
	var flags, positional []string
	for _, arg := range args {
		if strings.HasPrefix(arg, "-") {
			flags = append(flags, arg)
		} else {
			positional = append(positional, arg)
		}
	}
	return append(flags, positional...)
}

// normalizes counter values for diffing
var counterRegex = regexp.MustCompile(`counter packets \d+ bytes \d+`)

// for normalizing nftables ~64char line maximums for diffing
// replaces comma followed by newline + leading whitespace -> `,`
var elemContinuation = regexp.MustCompile(`(?m),\s*\n\s+`)

func collapseElements(script string) string {
	return elemContinuation.ReplaceAllString(script, ", ")
}

// ~~ strippers (heh)
func stripCounters(script string) string {
	return counterRegex.ReplaceAllString(script, "counter")
}

// strip file preamble & shebang for diff purposes
func stripPreamble(script string) string {
	var lines []string
	// walk through file, if shebang or other prefix, skip line
	for _, line := range strings.Split(script, "\n") {
		// skip shebang, blank lines before first table, and atomic cleanup
		if strings.HasPrefix(line, "#!/") ||
			strings.HasPrefix(line, "delete table") ||
			// bare "table ip X" without a "{" is the create-before-delete line
			(strings.HasPrefix(line, "table ") && !strings.HasSuffix(line, "{")) {
			continue
		}
		lines = append(lines, line)
	}
	// trim leading blank lines left by removed preamble
	result := strings.TrimLeft(strings.Join(lines, "\n"), "\n")
	return result
}

// format and ansi colourize diff
func colourizeDiff(diff string) string {
	var out strings.Builder
	for _, line := range strings.Split(diff, "\n") {
		switch {
		case strings.HasPrefix(line, "+++") || strings.HasPrefix(line, "---"):
			out.WriteString(colour.Bold(line))
		case strings.HasPrefix(line, "+"):
			out.WriteString(colour.Green(line))
		case strings.HasPrefix(line, "-"):
			out.WriteString(colour.Red(line))
		case strings.HasPrefix(line, "@@"):
			out.WriteString(colour.Cyan(line))
		default:
			out.WriteString(line)
		}
		out.WriteString("\n")
	}
	return out.String()
}

// diffs two configs by shelling out
func diffScripts(oldLabel, newLabel, oldScript, newScript string) (string, bool, error) {
	// strip counter values
	oldScript = stripCounters(oldScript)
	newScript = stripCounters(newScript)

	// normalize ~64char-per-line-max nft formatting
	oldScript = collapseElements(oldScript)
	newScript = collapseElements(newScript)

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

// is called by `nfty diff <.toml>`, compares against current NFTables output
func RunDiff(args []string) {
	args = sortFlags(args)
	fs := flag.NewFlagSet("diff", flag.ExitOnError)
	fs.Parse(args)

	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "usage: nfty diff <config.toml>")
		os.Exit(1)
	}

	configPath := fs.Arg(0)

	// hostname for the header line
	hostname, _ := os.Hostname()
	now := time.Now().Format("2006-01-02 15:04:05")

	fmt.Printf("  %s %s%s%s\n",
		colour.Grey("nfty"),
		colour.Bold("diff"),
		strings.Repeat(" ", 15),
		colour.DarkGrey(hostname+" · "+now),
	)
	fmt.Println()

	divider()

	// load and generate the proposed config
	cfg, err := config.Load(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  config error: %v\n", err)
		os.Exit(1)
	}

	// generate nftables from nfty
	proposed, err := Generate(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  rule generation failed: %v\n", err)
		os.Exit(1)
	}

	// validate nftables syntax before diff
	if err := ValidateScript(proposed); err != nil {
		fmt.Fprintf(os.Stderr, "  nft syntax validation failed: %v\n", err)
		os.Exit(1)
	}

	proposedChecksum := ScriptChecksum(proposed)

	// check against last-apply checksum (should be the same always lol)
	// maybe will re-activate later, but disabled for debug purposes
	//
	//if last, err := commit.LoadLastApply(); err == nil {
	//	if proposedChecksum == last.Checksum {
	//		fmt.Printf("  %s\n", colour.Green("✓ config matches current confirmed ruleset — no changes"))
	//		fmt.Printf("  %s %s\n", colour.Grey("checksum:"), colour.DarkGrey(proposedChecksum))
	//		return
	//	}
	//}

	// get current NFTables live ruleset
	// nfty IP Tables only
	ipTable, err := ListTable("ip", cfg.Core.Table)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  could not read live table ip %s: %v\n", cfg.Core.Table, err)
		os.Exit(1)
	}
	ip6Table, err := ListTable("ip6", cfg.Core.Table)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  could not read live table ip6 %s: %v\n", cfg.Core.Table, err)
		os.Exit(1)
	}

	current := string(ipTable) + "\n" + string(ip6Table)

	fmt.Printf("  %s %s %s\n", colour.Grey("config:"), cfg.Core.Name, colour.DarkGrey(cfg.Core.Description))
	fmt.Printf("  %s %s\n", colour.Grey("checksum:"), colour.DarkGrey(proposedChecksum))

	divider()

	// run the diff
	diffOutput, changed, err := diffScripts(
		"current ruleset",
		"proposed ruleset",
		current,
		stripPreamble(proposed),
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  diff failed: %v\n", err)
		os.Exit(1)
	}

	if !changed {
		fmt.Printf("  %s\n", colour.Green("✓ no differences, proposed nfty config matches live ruleset"))
		return
	}

	// counts # of adds/rems for summary
	adds, removes := 0, 0
	for _, line := range strings.Split(diffOutput, "\n") {
		switch {
		case strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "+++"):
			adds++
		case strings.HasPrefix(line, "-") && !strings.HasPrefix(line, "---"):
			removes++
		}
	}

	fmt.Printf("  %s  %s\n",
		colour.Green(fmt.Sprintf("+%d lines", adds)),
		colour.Red(fmt.Sprintf("-%d lines", removes)),
	)
	fmt.Println()

	// colourize that ish
	fmt.Print(colourizeDiff(diffOutput))
}

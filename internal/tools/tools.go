package tools

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/adrian-griffin/nfty/internal/colour"
)

// max length left-column for labels
const LabelWidth = 18

// reorders flag args to allow dynamic flag inputs from user
func SortFlags(args []string) []string {
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

// return grey for left-column labels
func Label(s string) string {
	return colour.Grey(fmt.Sprintf("%-*s", LabelWidth, s))
}

// writes section divier
func Divider() {
	fmt.Println(colour.Grey("  " + strings.Repeat("─", 52)))
}

// gathers file path & last-edited time
func FileInfo(path string) string {
	info, err := os.Stat(path)
	if err != nil {
		return ""
	}

	// make that shit human readable tho
	size := info.Size()
	var sizeStr string
	switch {
	// if < 1048576b (1MB)
	case size >= 1<<20:
		sizeStr = fmt.Sprintf("%.1fMB", float64(size)/float64(1<<20))
		// if < 1024 (1KB)
	case size >= 1<<10:
		sizeStr = fmt.Sprintf("%.1fKB", float64(size)/float64(1<<10))
	default:
		sizeStr = fmt.Sprintf("%dB", size)
	}

	// convert time into HR
	age := time.Since(info.ModTime()).Round(time.Second)
	var ageStr string
	switch {
	case age < time.Minute:
		ageStr = fmt.Sprintf("%ds ago", int(age.Seconds()))
	case age < time.Hour:
		ageStr = fmt.Sprintf("%dm ago", int(age.Minutes()))
	case age < 24*time.Hour:
		ageStr = fmt.Sprintf("%dh ago", int(age.Hours()))
	default:
		ageStr = fmt.Sprintf("%dh ago", int(age.Hours()))
	}

	return fmt.Sprintf("%s, %s", sizeStr, ageStr)
}

// cuts string to maxLen, adds "..."
func Truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// performs a rough count of tables, chains, and rules from raw nft
func CountNftObjects(ruleset string) (tables, chains, rules int) {
	for _, line := range strings.Split(ruleset, "\n") {
		trimmed := strings.TrimSpace(line)
		// every hit of 'table' is probably a table
		if strings.HasPrefix(trimmed, "table ") {
			tables++
			// likewise with chain
		} else if strings.HasPrefix(trimmed, "chain ") {
			chains++
		} else if trimmed != "" &&
			// everything else, so long as it doesnt include these
			// keywords, is probably a rule
			!strings.HasPrefix(trimmed, "}") &&
			!strings.HasPrefix(trimmed, "type ") &&
			!strings.HasPrefix(trimmed, "set ") &&
			!strings.HasPrefix(trimmed, "elements") &&
			!strings.HasPrefix(trimmed, "flags ") &&
			!strings.HasPrefix(trimmed, "auto-merge") &&
			!strings.HasPrefix(trimmed, "comment ") &&
			!strings.HasPrefix(trimmed, "table ") &&
			!strings.HasPrefix(trimmed, "chain ") {
			rules++
		}
	}
	return
}

// strips port off IPs "10.0.0.1:12345" or "[::1]:12345".
func StripIPPorts(addr string) net.IP {
	if strings.HasPrefix(addr, "[") {
		end := strings.Index(addr, "]")
		if end < 0 {
			return nil
		}
		return net.ParseIP(addr[1:end])
	}
	lastColon := strings.LastIndex(addr, ":")
	if lastColon < 0 {
		return nil
	}
	return net.ParseIP(addr[:lastColon])
}

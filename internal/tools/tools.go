// tools.go
// nfty internal tooling
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

// struct for stderr alerts/warns/errs
type Issue struct {
	Severity Severity
	Category string
	RuleRef  string
	Message  string
	Hint     string
}

type Severity int

const (
	SeverityWarn Severity = iota
	SeverityError
)

func (s Severity) String() string {
	if s == SeverityError {
		return "ERROR"
	}
	return "WARNING"
}

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

func CommandExecuteHeader(subcommand string) {
	// hostname for the header line
	hostname, _ := os.Hostname()
	now := time.Now().Format("2006-01-02 15:04:05")

	fmt.Printf("\n  %s %s%s%s\n",
		colour.Grey("nfty"),
		colour.Bold(subcommand),
		strings.Repeat(" ", 15),
		colour.DarkGrey(hostname+" · "+now),
	)
	Divider()
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
	case age < 48*time.Hour:
		ageStr = fmt.Sprintf("%dh ago", int(age.Hours()))
	case age > 48*time.Hour:
		ageStr = fmt.Sprintf("%dd ago", int(age.Hours()/24))
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

// detects if host has a globally routable ip6 address
func HasGlobalIPv6() bool {
	ifaces, err := net.Interfaces()
	if err != nil {
		return false
	}
	for _, iface := range ifaces {
		// skip down and loopback interfaces
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		// pull ips
		addys, err := iface.Addrs()
		if err != nil {
			continue
		}
		// iterate, parse for v6 global-only
		for _, addr := range addys {
			ip, _, err := net.ParseCIDR(addr.String())
			if err != nil {
				continue
			}
			// not v4, not link-local (fe80::/10), not loopback (::1)
			if ip.To4() == nil && !ip.IsLinkLocalUnicast() && !ip.IsLoopback() {
				return true
			}
		}
	}
	return false
}

// validate cidr, ip family concious
func ValidateFamilyCIDR(entry, family string) error {
	if err := ValidateCIDR(entry); err != nil {
		return err
	}
	ip := net.ParseIP(strings.SplitN(entry, "/", 2)[0])
	if ip == nil {
		return nil
	}
	if family == "ipv4" && ip.To4() == nil {
		return fmt.Errorf("IPv6 address %q in IPv4 list", entry)
	}
	if family == "ipv6" && ip.To4() != nil {
		return fmt.Errorf("IPv4 address %q in IPv6 list", entry)
	}
	return nil
}

// validate whether passed IP string is valid cidr or single-ip notation (ip4, ip6)
func ValidateCIDR(s string) error {
	// try as CIDR first
	if _, _, err := net.ParseCIDR(s); err == nil {
		return nil
	}
	// try as plain IP
	if net.ParseIP(s) != nil {
		return nil
	}
	return fmt.Errorf("not a valid IP or CIDR: %q", s)
}

// writes notifications to stderr
// returns number of alerts
func PrintIssues(issues []Issue) int {
	if len(issues) == 0 {
		return 0
	}

	errCount := 0
	Divider()
	for _, i := range issues {
		var marker string
		switch i.Severity {
		case SeverityError:
			marker = colour.Red("  ✗ ERROR  ")
		case SeverityWarn:
			marker = colour.Yellow("  ⚠ WARN   ")
		}

		errCount++
		// print rule reference
		ref := ""
		if i.RuleRef != "" {
			ref = colour.DarkGrey(fmt.Sprintf("  [%s]", i.RuleRef))
		}
		fmt.Fprintf(os.Stderr, "%s%s%s\n", marker, i.Message, ref)

		// hint/subtext
		if i.Hint != "" {
			fmt.Fprintf(os.Stderr, "    %s\n", colour.Grey(i.Hint))
		}
		Divider()
	}
	Divider()
	return errCount
}

// safety.go
// firewall logic and safety
package config

import (
	"fmt"
	"os"

	"github.com/adrian-griffin/nfty/internal/colour"
	"github.com/adrian-griffin/nfty/internal/tools"
)

func srcRestrictionCheck(rule *Rule) {
	if rule.Disabled {
		return
	}

	// warn when a rule does not have any src-ip or in-interface matching (ie: open to all)
	if len(rule.SrcIPs) == 0 && rule.SrcList == "" && rule.IIF == "" && rule.IIFName == "" {

		if len(rule.DPort) > 0 {
			tools.Divider()
			fmt.Fprintf(os.Stderr, colour.Yellowf("  ⚠ WARNING: Rule %q has dst_port but no source restriction (src_list, src_ips, iifname, etc)\n", rule.Comment))
			fmt.Fprintf(os.Stderr, colour.Grey("    Leaving the socket open from all addresses and interfaces\n"))
			tools.Divider()
		}
	}
}

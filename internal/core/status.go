// status.go
// called by `nfty status` cli flag, parse subflags, call render function
// status gathered by statusmodel.go
// status rendered in statusview.go
package core

import (
	"flag"
	"fmt"
	"os"

	"github.com/adrian-griffin/nfty/internal/colour"
	"github.com/adrian-griffin/nfty/internal/tools"
)

// build status output
func RunStatus() {
	args := tools.SortFlags(os.Args[2:]) // sort flags
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	listRuleset := fs.Bool("list-ruleset", false, "show full nftables ruleset")
	fs.Parse(args)

	// print header output
	tools.CommandExecuteHeader("status")

	// gather first, render second - the tui reads the same snapshot
	status, err := GatherStatus()
	if err != nil {
		fmt.Fprintf(os.Stderr, "  %s %v\n", colour.Red("error:"), err)
		os.Exit(1)
	}

	RenderStatus(os.Stdout, status, StatusOpts{ListRuleset: *listRuleset})
}

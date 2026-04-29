package main

import (
	"fmt"
	"os"

	"github.com/adrian-griffin/nfty/internal/commit"
	"github.com/adrian-griffin/nfty/internal/core"
	"github.com/adrian-griffin/nfty/internal/meta"
	"github.com/adrian-griffin/nfty/internal/nft"
)

func main() {

	// handle version flagging before any checks
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version":
			fmt.Printf("nfty  ~  version: %s\n", meta.Version)
			fmt.Printf("  %s\n", meta.MOTD)
			os.Exit(0)
		}
	}

	// validate running as root
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "please run nfty with sudo or as the root user")
		fmt.Fprintln(os.Stderr, "this is required for interacting with system networking")
		fmt.Fprintln(os.Stderr, "for details and security considerations, see the GitHub README <3")
		os.Exit(1)
	}

	// before continuing, check nft binary
	if err := nft.CheckBinary(); err != nil {
		fmt.Fprintf(os.Stderr, "nfty startup failed: %v\n", err)
		os.Exit(1)
	}

	// subcommand routing
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "apply":
		commit.RunApply(os.Args[2:])
	case "status":
		core.RunStatus()
	case "confirm":
		commit.RunConfirm()
	case "rollback":
		commit.RunRollback()
	case "rollback-if-pending":
		commit.RunRollbackIfPending()
	case "restore":
		commit.RunRestore()
	case "counters":
		core.RunCounters()
	case "diff":
		nft.RunDiff(os.Args[2:])
	case "check":
		core.RunCheck(os.Args[2:])
		os.Exit(0)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Printf("nfty  ~  version: %s\n", meta.Version)
	fmt.Println("usage: nfty <command> [options]")
	fmt.Println()
	fmt.Println("commands:")
	fmt.Println("  version                          show version info")
	fmt.Println("  check <config.toml>              validate config")
	fmt.Println("      --list-ruleset                 list target's NFT ruleset output")
	fmt.Println("  status                           show current status")
	fmt.Println("      --list-ruleset                 list current NFT ruleset output")
	fmt.Println("  diff <config.toml>               show changes against current ruleset")
	fmt.Println("  apply <config.toml>              apply target config")
	fmt.Println("      --commit-confirm <seconds>     set rollback timer (default: 30)")
	fmt.Println("      --skip-confirm                 skip rollback timer (dangerous)")
	fmt.Println("  confirm                          confirm pending config")
	fmt.Println("  rollback                         revert to previous rule snapshot")
	fmt.Println("  counters                         display counters/statistics")

}

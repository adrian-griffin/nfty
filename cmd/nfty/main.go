package main

import (
	"fmt"
	"os"

	"github.com/adrian-griffin/nfty/meta"
	"github.com/adrian-griffin/nfty/nft"
)

func main() {

	// handle version flagging before any checks
	if len(os.Args) > 1 && os.Args[1] == "version" {
		fmt.Printf("nfty  ~  version:%s\n", meta.Version)
		os.Exit(0)
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
		runApply(os.Args[2:])
	case "check":
		runCheck(os.Args[2:])
	case "status":
		runStatus()
	case "confirm":
		runConfirm()
	case "rollback":
		runRollback()
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
	fmt.Println("  apply <config.toml>              apply config with safety checks")
	fmt.Println("      --dry-run                      show diffs, no changes")
	fmt.Println("      --commit-confirm <seconds>     set rollback timer (default: 30)")
	fmt.Println("      --skip-confirm                 skip rollback timer (dangerous)")
	fmt.Println("  check <config.toml>              validate config, no changes")
	fmt.Println("  status                           show current ruleset")
	fmt.Println("  confirm                          confirm applied config")
	fmt.Println("  rollback                         revert to previous rule snapshot")
	fmt.Println("  version                          show version info")
}

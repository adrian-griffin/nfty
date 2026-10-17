// rollback_netns_test.go
// applies rulesets and operates rollbacks against the real kernel in dedicated, throwaway namespaces
//
// must be run under a dedicated namespace or will be skipped on go test:
//	unshare -rn env PATH="$PATH:/usr/sbin" NFTY_NETNS_TEST=1 go test ./internal/commit -run NetNS -count=1
//
// these tests refuse to run anywhere but a fresh namespace
package commit

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/adrian-griffin/nfty/internal/config"
	"github.com/adrian-griffin/nfty/internal/nft"
)

// fake docker tables, of which nfty should never touch
const fakeDocker = `table ip nat {
	chain PREROUTING {
		type nat hook prerouting priority dstnat; policy accept;
		tcp dport 8080 dnat to 172.17.0.2:80
	}
}
table ip filter {
	chain DOCKER-USER {
		return
	}
}
`
// fake nfty config table A
const netnsConfA = `
[core]
name = "a"
table = "nfty"
default_rules = false

[[chains.ipv4.input]]
comment = "allow ssh"
protocol = "tcp"
dport = 22
action = "accept"
`

// fake nfty config table B, A + new rule
const netnsConfB = netnsConfA + `
[[chains.ipv4.input]]
comment = "allow https"
protocol = "tcp"
dport = 443
action = "accept"
`

// table A with [core] table rename
var netnsConfRenamed = strings.Replace(netnsConfA, `table = "nfty"`, `table = "nfty-renamed"`, 1)

// only run tests if in a fresh namespace, yell about it if not
func requireNetNS(t *testing.T) {
	t.Helper()
	if os.Getenv("NFTY_NETNS_TEST") != "1" {
		t.Skip("set NFTY_NETNS_TEST=1 and run under unshare -rn")
	}
	// a fresh network namespace should have a loopback and nothing else
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatalf("listing interfaces: %v", err)
	}
	if len(ifaces) != 1 || ifaces[0].Name != "lo" {
		t.Fatal("reject run: not a fresh network namespace (expected only lo)")
	}
	if got := liveRuleset(t); strings.TrimSpace(got) != "" {
		t.Fatalf("reject run: ruleset is not empty:\n%s", got)
	}
	t.Cleanup(func() {
		if err := nft.ApplyScript("flush ruleset\n"); err != nil {
			t.Errorf("cleanup flush: %v", err)
		}
	})
}

// check the live ruleset (within namespace)
func liveRuleset(t *testing.T) string {
	t.Helper()
	out, err := nft.ListRulesetScript()
	if err != nil {
		t.Fatalf("listing ruleset: %v", err)
	}
	return string(out)
}

// render a config (exactly as a true apply would)
func renderConf(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "nfty.toml")
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("loading config: %v", err)
	}
	script, err := nft.Generate(cfg)
	if err != nil {
		t.Fatalf("rendering config: %v", err)
	}
	return script
}

func mustApply(t *testing.T, script string) {
	t.Helper()
	if err := nft.ApplyScript(script); err != nil {
		t.Fatalf("applying script: %v\n%s", err, script)
	}
}

// list one table, "" if dne
func tableListing(t *testing.T, family, name string) string {
	t.Helper()
	out, err := nft.ListTable(family, name)
	if err != nil {
		return ""
	}
	return string(out)
}

// both families of a nfty table, returns as 1 string
func nftyTables(t *testing.T, name string) string {
	return tableListing(t, "ip", name) + tableListing(t, "ip6", name)
}

// load mock docker tables and return their listing
// an empty result would make every "docker unchanged" check pass
func applyFakeDocker(t *testing.T) string {
	t.Helper()
	mustApply(t, fakeDocker)
	docker := dockerTables(t)
	if !strings.Contains(docker, "dnat to") {
		t.Fatalf("fake docker tables not listed back:\n%s", docker)
	}
	return docker
}

func dockerTables(t *testing.T) string {
	return tableListing(t, "ip", "nat") + tableListing(t, "ip", "filter")
}

func tableNames(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("nft", "list", "tables").Output()
	if err != nil {
		t.Fatalf("listing tables: %v", err)
	}
	return string(out)
}

// test that rollback/undo of a pending apply restores the previously confirmed ruleset, and leaves docker tables alone
func TestNetNSRollbackRestoresConfirmedAndLeavesDockerAlone(t *testing.T) {
	requireNetNS(t)
	docker := applyFakeDocker(t)

	confirmed := renderConf(t, netnsConfA)
	mustApply(t, confirmed)
	want := nftyTables(t, "nfty")

	// pending apply, same table name
	mustApply(t, renderConf(t, netnsConfB))
	if nftyTables(t, "nfty") == want {
		t.Fatal("pending apply did not change the nfty tables, test proves nothing")
	}

	mustApply(t, buildRollbackScript(confirmed, true, "nfty", "nfty"))

	if got := nftyTables(t, "nfty"); got != want {
		t.Errorf("rollback did not restore the confirmed tables\nwant:\n%s\ngot:\n%s", want, got)
	}
	if got := dockerTables(t); got != docker {
		t.Errorf("rollback changed docker's tables\nbefore:\n%s\nafter:\n%s", docker, got)
	}
}

// renaming [core] table + apply must remove the old tables, and rollback removes the new ones
func TestNetNSRenamedTableNeverLeavesBothLive(t *testing.T) {
	requireNetNS(t)
	docker := applyFakeDocker(t)

	confirmed := renderConf(t, netnsConfA)
	mustApply(t, confirmed)
	want := nftyTables(t, "nfty")

	mustApply(t, nft.DeleteTables("nfty")+renderConf(t, netnsConfRenamed))
	if got := nftyTables(t, "nfty"); got != "" {
		t.Errorf("old tables still live after a renamed apply:\n%s", got)
	}
	if nftyTables(t, "nfty-renamed") == "" {
		t.Fatal("renamed tables missing after apply")
	}

	mustApply(t, buildRollbackScript(confirmed, true, "nfty-renamed", "nfty"))

	if got := nftyTables(t, "nfty-renamed"); got != "" {
		t.Errorf("renamed tables still live after rollback:\n%s", got)
	}
	if got := nftyTables(t, "nfty"); got != want {
		t.Errorf("rollback did not restore the confirmed tables\nwant:\n%s\ngot:\n%s", want, got)
	}
	if got := dockerTables(t); got != docker {
		t.Errorf("docker's tables changed\nbefore:\n%s\nafter:\n%s", docker, got)
	}
}

// nothing previously confirmed (fresh nfty setup), so rollback should removes nfty tables
func TestNetNSRollbackWithoutConfirmedRemovesTables(t *testing.T) {
	requireNetNS(t)
	docker := applyFakeDocker(t)

	mustApply(t, renderConf(t, netnsConfA))
	mustApply(t, buildRollbackScript("", false, "nfty", ""))

	if strings.Contains(tableNames(t), "nfty") {
		t.Errorf("nfty tables still live:\n%s", tableNames(t))
	}
	if got := dockerTables(t); got != docker {
		t.Errorf("docker's tables changed\nbefore:\n%s\nafter:\n%s", docker, got)
	}
}

// emergency table WIPE must succeed, whether both named tables exist or not
func TestNetNSDeleteScriptToleratesMissingTables(t *testing.T) {
	requireNetNS(t)
	docker := applyFakeDocker(t)

	mustApply(t, renderConf(t, netnsConfA))
	mustApply(t, buildDeleteScript("nfty", "nfty-never-existed"))

	if strings.Contains(tableNames(t), "nfty") {
		t.Errorf("nfty tables still live:\n%s", tableNames(t))
	}
	if got := dockerTables(t); got != docker {
		t.Errorf("docker's tables changed\nbefore:\n%s\nafter:\n%s", docker, got)
	}
}

// a failed/rejected script apply must leave the live ruleset exactly as it was
func TestNetNSRejectedScriptChangesNothing(t *testing.T) {
	requireNetNS(t)
	mustApply(t, fakeDocker)
	mustApply(t, renderConf(t, netnsConfB))
	before := liveRuleset(t)

	broken := nft.DeleteTables("nfty") + "table ip nfty {\n\tchain input {\n\t\tthis is not nft\n\t}\n}\n"
	if err := nft.ApplyScript(broken); err == nil {
		t.Fatal("broken script was accepted")
	}

	if got := liveRuleset(t); got != before {
		t.Errorf("rejected script changed the ruleset\nbefore:\n%s\nafter:\n%s", before, got)
	}
}

// manual rollback with nothing pending re-applies confirmed.nft
func TestNetNSReapplyingConfirmedIsIdempotent(t *testing.T) {
	requireNetNS(t)
	confirmed := renderConf(t, netnsConfA)
	mustApply(t, confirmed)
	want := liveRuleset(t)

	mustApply(t, confirmed)

	if got := liveRuleset(t); got != want {
		t.Errorf("re-applying confirmed changed the ruleset\nwant:\n%s\ngot:\n%s", want, got)
	}
}

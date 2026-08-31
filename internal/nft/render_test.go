// render_test.go
// tests for nfty toml -> nft script conversions
package nft

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/adrian-griffin/nfty/internal/config"
)

// writes body to temp .toml and runs it through the full render logic
// returns the rendered script or the error that stopped it
func render(t *testing.T, body string) (string, error) {
	t.Helper()
	// create temp test toml file and write supplied body to it
	path := filepath.Join(t.TempDir(), "probe.toml")
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatalf("writing probe config: %v", err)
	}
	// run config-load and render logic on temp file
	cfg, err := config.Load(path)
	if err != nil {
		return "", err
	}
	// if no err, generate full nft script and return it
	return Generate(cfg)
}

// define base/core test toml
const base = `
[core]
name = "probe"
table = "nfty"
default_rules = false

[[chains.ipv4.input]]
comment = "allow ssh"
protocol = "tcp"
dport = 22
action = "accept"
`

// ensure that a *minimal* config renders the correct rules
func TestRenderBaseline(t *testing.T) {
	// run base through render and nft script generate
	script, err := render(t, base)
	if err != nil {
		t.Fatalf("minimal config rejected: %v", err)
	}
	// check that the expected base rule (allow 22/tcp ssh) is present in the nftables output
	if !strings.Contains(script, `tcp dport 22 counter accept comment "nfty: allow ssh"`) {
		t.Errorf("expected ssh rule in output, got:\n%s", script)
	}
}

// address lists with no entries must not render (eg: `elements = {  }`) as nft rejects
// an empty set itself is legal and stays declared.
func TestEmptyUnreferencedList(t *testing.T) {
	script, err := render(t, base+`
[lists.ipv4.dead]
entries = []
`)
	// if render err, empty and unreferenced list not allowed
	if err != nil {
		t.Fatalf("empty unreferenced list rejected: %v", err)
	}
	// if completed render with "elements = {  }", fail
	// nft itself rejects empty sets
	if strings.Contains(script, "elements = {  }") {
		t.Errorf("empty list rendered an empty elements line:\n%s", script)
	}
	// if completed render with no mention of dead list, fail
	if !strings.Contains(script, "set dead {") {
		t.Errorf("empty list dropped from output entirely:\n%s", script)
	}
}

// test for comment escaping
func TestHashInTableName(t *testing.T) {
	script, err := render(t, `
[core]
name = "probe"
table = "nf#ty"
default_rules = false

[[chains.ipv4.input]]
comment = "allow ssh"
protocol = "tcp"
dport = 22
action = "accept"
`)
	if err == nil {
		t.Errorf("'#' accepted in table name, rendered:\n%s", script)
	}
}

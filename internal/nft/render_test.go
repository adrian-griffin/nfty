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

// test for comment escaping in tale names
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

// test for comment escaping in list names
func TestHashInListName(t *testing.T) {
	script, err := render(t, base+`
[lists.ipv4."ad#min"]
entries = ["10.0.0.1"]
`)
	if err == nil {
		t.Errorf("'#' accepted in list name, rendered:\n%s", script)
	}
}

// test against space/whitespace in table names leading to splits in output nft script
func TestSpaceInTableName(t *testing.T) {
	script, err := render(t, `
[core]
name = "probe"
table = "nfty evil"
default_rules = false

[[chains.ipv4.input]]
comment = "allow ssh"
protocol = "tcp"
dport = 22
action = "accept"
`)
	// if allowed, fail test
	if err == nil {
		t.Errorf("space accepted in table name, rendered:\n%s", script)
	}
}

// test normalization of ct_state casing
func TestCtStateCaseNormalized(t *testing.T) {
	script, err := render(t, `
[core]
name = "probe"
table = "nfty"
default_rules = false

[[chains.ipv4.input]]
comment = "established"
ct_state = ["ESTABLISHED", "RELATED"]
action = "accept"
`)
	// if render errors, fail
	if err != nil {
		t.Fatalf("uppercase ct_state rejected: %v", err)
	}
	// if emitted script still has uppercase ESTABLISHED, fail
	if strings.Contains(script, "ESTABLISHED") {
		t.Errorf("ct_state not normalized to lowercase:\n%s", script)
	}
	// if emitted script does not have normalized est,rel nft script
	if !strings.Contains(script, "ct state established,related") {
		t.Errorf("expected lowercased ct_state in output:\n%s", script)
	}
}

// Atoi accepts a leading +/- sign, negative rates need rejected
func TestNegativeRateLimit(t *testing.T) {
	script, err := render(t, `
[core]
name = "probe"
table = "nfty"
default_rules = false

[[chains.ipv4.input]]
comment = "allow ssh"
protocol = "tcp"
dport = 22
action = "accept"
rate_limit = { rate = "-5/second" }
`)
	// if render accepted a negative rate, fail
	if err == nil {
		t.Errorf("negative rate accepted, rendered:\n%s", script)
	}
}

// a '+' signed positive rate is legal, but it must reach nft without any sign
func TestSignedRateLimitNormalized(t *testing.T) {
	script, err := render(t, `
[core]
name = "probe"
table = "nfty"
default_rules = false

[[chains.ipv4.input]]
comment = "allow ssh"
protocol = "tcp"
dport = 22
action = "accept"
rate_limit = { rate = "+5/second" }
`)
	if err != nil {
		t.Fatalf("signed rate rejected: %v", err)
	}
	// if + sign survives normalization, fail
	if strings.Contains(script, "+5/second") {
		t.Errorf("rate sign survived normalization:\n%s", script)
	}
}

// over_limit is only read by renderer when attached to a rate_limit
// if present otherwise, it must be rejected
func TestOverLimitCheckedWithoutRateLimit(t *testing.T) {
	script, err := render(t, `
[core]
name = "probe"
table = "nfty"
default_rules = false

[[chains.ipv4.input]]
comment = "allow ssh"
protocol = "tcp"
dport = 22
action = "accept"
over_limit = "drop; something else"
`)
	// if renderer does not err with erroneous over_limit, fail
	if err == nil {
		t.Errorf("unvalidated over_limit accepted, rendered:\n%s", script)
	}
}

// duplicate comment/name check is scoped per IP family
// so same-name rules in v4 and v6 must be accepted
func TestSameCommentAcrossFamilies(t *testing.T) {
	_, err := render(t, `
[core]
name = "probe"
table = "nfty"
default_rules = false

[[chains.ipv4.input]]
comment = "allow ssh"
protocol = "tcp"
dport = 22
action = "accept"

[[chains.ipv6.input]]
comment = "allow ssh"
protocol = "tcp"
dport = 22
action = "accept"
`)
	if err != nil {
		t.Errorf("same comment in ipv4 and ipv6 rejected: %v", err)
	}
}

// within the same IP-family, dupes must be rejected (even on different chains)
func TestDuplicateCommentWithinFamily(t *testing.T) {
	script, err := render(t, `
[core]
name = "probe"
table = "nfty"
default_rules = false

[[chains.ipv4.input]]
comment = "allow ssh"
protocol = "tcp"
dport = 22
action = "accept"

[[chains.ipv4.forward]]
comment = "allow ssh"
protocol = "tcp"
dport = 22
action = "accept"
`)
	if err == nil {
		t.Errorf("duplicate comment within ipv4 accepted, rendered:\n%s", script)
	}
}

// interface names are interpolated inside quotes, so a space is contained
// even though validateNFTString permits it
func TestSpaceInInterfaceNameStaysQuoted(t *testing.T) {
	script, err := render(t, `
[core]
name = "probe"
table = "nfty"
default_rules = false

[[chains.ipv4.input]]
comment = "allow ssh"
iifname = "eth0 accept"
protocol = "tcp"
dport = 22
action = "accept"
`)
	if err != nil {
		t.Logf("rejected at load: %v", err)
		return
	}
	// if string does not contain the quoted and spaced interface name, fail
	if !strings.Contains(script, `iifname "eth0 accept"`) {
		t.Errorf("spaced interface name escaped its quotes:\n%s", script)
	}
}

// validate that src-port-only rules render correctly
func TestSportOnlyRule(t *testing.T) {
	script, err := render(t, `
[core]
name = "probe"
table = "nfty"
default_rules = false

[[chains.ipv4.input]]
comment = "allow ntp replies"
protocol = "udp"
sport = [123]
action = "accept"
`)
	if err != nil {
		t.Fatalf("sport-only rule rejected: %v", err)
	}
	// check if renderer emits proper src-port nft
	if !strings.Contains(script, `udp sport 123 counter accept comment "nfty: allow ntp replies"`) {
		t.Errorf("expected sport-only rule in output:\n%s", script)
	}
	// check if renderer emits dst-port rule erroneously
	if strings.Contains(script, "dport") {
		t.Errorf("sport-only rule invented a dport:\n%s", script)
	}
}

// ensure that tcp/udp rules with no port number defined are rejected
func TestProtocolWithNoPorts(t *testing.T) {
	script, err := render(t, `
[core]
name = "probe"
table = "nfty"
default_rules = false

[[chains.ipv4.input]]
comment = "portless tcp"
protocol = "tcp"
action = "accept"
`)
	// if renderer accepts, fail test
	if err == nil {
		t.Errorf("tcp rule with no ports accepted, rendered:\n%s", script)
	}
}

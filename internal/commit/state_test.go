// state_test.go
// tests the confirmed/pending state files, as well as the scripts that rollback builds from them
package commit

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/adrian-griffin/nfty/internal/nft"
)

// rollback leaves confirmed.nft untouched when table NAME is the same
func TestRollbackScriptSameTableIsConfirmedVerbatim(t *testing.T) {
	//                           ruleset    prev?  new     prev
	got := buildRollbackScript("CONFIRMED", true, "nfty", "nfty")
	if got != "CONFIRMED" {
		t.Errorf("expected confirmed script verbatim, got:\n%s", got)
	}
}

// a pending apply that renames [core] table must have its own tables removed,
// confirmed.nft only clears the confirmed name
func TestRollbackScriptRenamedTableDeletesPendingTables(t *testing.T) {
	got := buildRollbackScript("CONFIRMED", true, "nfty-new", "nfty")
	want := nft.DeleteTables("nfty-new") + "CONFIRMED"
	if got != want {
		t.Errorf("expected pending tables deleted before restore\nwant:\n%s\ngot:\n%s", want, got)
	}
}

// nothing confirmed previously, so 'undoing the pending apply' means just removing its tables
func TestRollbackScriptWithoutConfirmedDeletesPendingTables(t *testing.T) {
	got := buildRollbackScript("", false, "nfty", "")
	if got != nft.DeleteTables("nfty") {
		t.Errorf("expected only the pending tables deleted, got:\n%s", got)
	}
}

// the emergency/last resort case must delete every known nfty table, and skip unknown ones
func TestDeleteScriptDedupesAndSkipsEmpty(t *testing.T) {
	got := buildDeleteScript("nfty", "", "nfty", "nfty-new")
	want := nft.DeleteTables("nfty") + nft.DeleteTables("nfty-new")
	if got != want {
		t.Errorf("want:\n%s\ngot:\n%s", want, got)
	}
	if buildDeleteScript("", "") != "" {
		t.Errorf("expected empty script when no table names are known")
	}
}

// test that confirm promotes the pending config exactly, byte for byte
func TestPromoteScriptCopiesPendingExactly(t *testing.T) {
	dir := t.TempDir()
	pending := filepath.Join(dir, "pending.nft")
	confirmed := filepath.Join(dir, "confirmed.nft")
	script := "#!/usr/sbin/nft -f\ntable ip nfty {\n}\n"
	if err := os.WriteFile(pending, []byte(script), 0600); err != nil {
		t.Fatal(err)
	}

	// promote pending script
	if err := promoteScript(pending, confirmed, nft.ScriptChecksum(script)); err != nil {
		t.Fatalf("promote failed: %v", err)
	}
	// read the newly confirmed file
	got, err := os.ReadFile(confirmed)
	if err != nil {
		t.Fatal(err)
	}
	// newly confirmed must match previously-pending exactly
	if string(got) != script {
		t.Errorf("confirmed script differs from pending\nwant:\n%s\ngot:\n%s", script, got)
	}
	// confirmed file exists?
	info, err := os.Stat(confirmed)
	if err != nil {
		t.Fatal(err)
	}
	// vet perms
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("confirmed script has mode %o, want 600", perm)
	}
}


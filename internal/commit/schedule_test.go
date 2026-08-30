// schedule_test.go
package commit

import (
	"strings"
	"testing"
)

// a rollback window that's shorter than an nftables apply to the system takes leads to reverting mid-apply, clears pending,
// and still leave the new ruleset live afterwards
func TestScheduleRollbackRejectsShortWindow(t *testing.T) {
	// walk -1s, 0s, 1s, and 1s less than MinConfirmSeconds
	// schedule rolback logic against these values
	for _, seconds := range []int{-1, 0, 1, MinConfirmSeconds - 1} {
		err := ScheduleRollback(seconds, "/usr/local/bin/nfty")
		if err == nil {
			t.Errorf("ScheduleRollback(%d) accepted a duration lower than the %ds minimum",
				seconds, MinConfirmSeconds)
			continue
		}
		if !strings.Contains(err.Error(), "minimum") {
			t.Errorf("ScheduleRollback(%d) error %q does not mention the minimum", seconds, err)
		}
	}
}

// prompt_test.go
package tools

import (
	"bufio"
	"errors"
	"strings"
	"testing"
)

// test confirmYesNo functionality with various inputs
func TestConfirmYesNo(t *testing.T) {
	// declare test inputs struct
	cases := []struct {
		name    string
		input   string
		want    bool
		wantErr error
	}{
		{"yes", "y\n", true, nil},
		{"yes spelled out", "yes\n", true, nil},
		{"uppercase", "Y\n", true, nil},
		{"surrounding whitespace", "  y  \n", true, nil},
		{"no", "n\n", false, nil},
		{"no spelled out", "no\n", false, nil},
		{"retries past garbage", "maybe\nsure\ny\n", true, nil},

		// empty stdin was a hole that caused infinite loop
		// testing from here on
		{"empty stdin", "", false, ErrNoInput},
		{"garbage then newline", "maybe\n", false, ErrNoInput},
		{"answer without trailing newline", "y", true, nil},
		{"no answer, no newline", "maybe", false, ErrNoInput},
	}

	// iterate cases and test
	for _, testCases := range cases {
		t.Run(testCases.name, func(t *testing.T) {
			// thru bufio.NewReader to simulate stdin
			result, err := confirmYesNo(bufio.NewReader(strings.NewReader(testCases.input)), "")
			// check if result's err matches err we want, if not then fail test
			if !errors.Is(err, testCases.wantErr) {
				t.Fatalf("err = %v, want %v", err, testCases.wantErr)
			}
			// check if result matches what we want, if not then fail test
			if result != testCases.want {
				t.Errorf("result %v, want %v", result, testCases.want)
			}
		})
	}
}

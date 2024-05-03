package autheliacfg

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestStandardizeDurationString(t *testing.T) {
	tcs := []struct {
		input    string
		expected string
	}{
		{input: "1s", expected: "1s"},
		{input: "3h", expected: "3h"},
		{input: "1d", expected: "24h"},
		{input: "2w", expected: "336h"},   // 24 * 7 * 2
		{input: "4M", expected: "2880h"},  // 24 * 30 * 4
		{input: "5y", expected: "43800h"}, // 24 * 365 * 5
	}
	for _, tt := range tcs {
		t.Run(tt.input, func(t *testing.T) {
			actual, err := StandardizeDurationString(tt.input)
			require.NoError(t, err)
			require.Equal(t, tt.expected, actual)
		})
	}
}

package token

import (
	"testing"
)

func TestAccountForAKID(t *testing.T) {
	testcases := []struct {
		name     string
		akid     string
		expected string
		wantErr  error
	}{
		{
			name:     "empty akid",
			akid:     "",
			expected: "",
		},
		{
			name:     "akid with account",
			akid:     "ASIAR2TG44V5PDTTBZRR",
			expected: "125843596666",
		},
		{
			name:     "account starting with a 0",
			akid:     "ASIAQNZGKIQY56JQ7WML",
			expected: "029608264753",
		},
		{
			name:     "non base32 encoded akid",
			akid:     "ASIAc29tZXRoaW5nCg==",
			expected: "",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			actual := accountForAKID(tc.akid)
			if actual != tc.expected {
				t.Errorf("expected %s, got %s", tc.expected, actual)
			}
		})
	}
}

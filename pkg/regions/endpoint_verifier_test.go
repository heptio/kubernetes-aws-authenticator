package regions

import (
	"context"
	"testing"
)

type testDiscoverer struct {
	resp map[string]bool
	err  error
}

func (t *testDiscoverer) Find(context.Context) (map[string]bool, error) {
	return t.resp, t.err
}

var _ Discoverer = &testDiscoverer{}

func TestEndpointVerifier(t *testing.T) {
	verifier, err := NewEndpointVerifier(
		&testDiscoverer{
			resp: map[string]bool{"us-east-1": true},
			err:  nil,
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	if !verifier.Verify("us-east-1") {
		t.Fatal("expected true")
	}

	if verifier.Verify("us-east-2") {
		t.Fatal("expected false")
	}

	err = verifier.Stop()
	if err != nil {
		t.Fatal(err)
	}
}

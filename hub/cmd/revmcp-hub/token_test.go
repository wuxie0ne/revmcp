package main

import (
	"bytes"
	"strings"
	"testing"

	hubauth "github.com/revmcp/revmcp/hub/internal/auth"
)

func TestTokenGenLegacyOutput(t *testing.T) {
	const secret = "test-signing-secret-for-enrollment"
	var stdout bytes.Buffer
	if err := runTokenGen([]string{"--secret", secret, "--target", "remote-99"}, &stdout); err != nil {
		t.Fatal(err)
	}
	signer, err := hubauth.NewEnrollmentSigner(secret)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := signer.Verify(strings.TrimSpace(stdout.String())); err != nil {
		t.Fatalf("expected stdout to contain only the enrollment token: %v", err)
	}
}

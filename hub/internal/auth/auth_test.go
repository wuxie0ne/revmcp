package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	sdkauth "github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/revmcp/revmcp/hub/internal/config"
	"github.com/revmcp/revmcp/proto"
)

func TestEnrollmentTokenSignAndVerify(t *testing.T) {
	t.Parallel()

	signer, err := NewEnrollmentSigner("super-secret-signing-key-123456")
	if err != nil {
		t.Fatalf("NewEnrollmentSigner failed: %v", err)
	}

	tok, issued, err := signer.Issue("prod-web-01", proto.ModeRestricted, time.Hour)
	if err != nil {
		t.Fatalf("Issue failed: %v", err)
	}

	claims, err := signer.Verify(tok)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if claims.TargetID != "prod-web-01" || claims.MaxMode != proto.ModeRestricted || claims.JTI != issued.JTI {
		t.Fatalf("claims mismatch: got %+v, want %+v", claims, issued)
	}

	// Tampering with token must fail closed.
	if _, err := signer.Verify(tok + "x"); !errors.Is(err, ErrInvalidEnrollmentToken) {
		t.Fatalf("expected ErrInvalidEnrollmentToken on tamper, got: %v", err)
	}

	// Revoked JTI must fail closed immediately.
	signer.Revoke(issued.JTI)
	if !signer.IsRevoked(issued.JTI) {
		t.Fatal("expected IsRevoked to return true")
	}
	if _, err := signer.Verify(tok); !errors.Is(err, ErrInvalidEnrollmentToken) {
		t.Fatalf("expected ErrInvalidEnrollmentToken on revoked jti, got: %v", err)
	}

	// Expired token must fail closed.
	tok2, _, err := signer.Issue("prod-web-02", proto.ModeReadOnly, time.Hour)
	if err != nil {
		t.Fatalf("Issue tok2 failed: %v", err)
	}
	now := time.Now()
	signer.now = func() time.Time { return now.Add(2 * time.Hour) }
	if _, err := signer.Verify(tok2); !errors.Is(err, ErrInvalidEnrollmentToken) {
		t.Fatalf("expected ErrInvalidEnrollmentToken on expiry, got: %v", err)
	}
}

func TestStaticBearerVerifier(t *testing.T) {
	t.Parallel()

	rawToken := "revmcp-secret-api-key"
	sum := sha256.Sum256([]byte(rawToken))

	verifier, err := NewStaticBearerVerifier([]config.ClientConfig{
		{
			Name:           "ops-alice",
			TokenSHA256:    hex.EncodeToString(sum[:]),
			Scopes:         []string{"read", "exec:restricted"},
			AllowedTargets: []string{"prod-*"},
		},
	})
	if err != nil {
		t.Fatalf("NewStaticBearerVerifier failed: %v", err)
	}

	info, err := verifier(context.Background(), rawToken, nil)
	if err != nil {
		t.Fatalf("valid token rejected: %v", err)
	}
	if info.UserID != "ops-alice" {
		t.Fatalf("unexpected UserID: %q", info.UserID)
	}
	if targets := AllowedTargetsFromToken(info); len(targets) != 1 || targets[0] != "prod-*" {
		t.Fatalf("unexpected allowed targets: %v", targets)
	}

	if _, err := verifier(context.Background(), "wrong-token", nil); !errors.Is(err, sdkauth.ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken for wrong token, got: %v", err)
	}
}

package auth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"net/http"

	sdkauth "github.com/modelcontextprotocol/go-sdk/auth"
)

const ExtraKeyAllowedTargets = "allowed_targets"

// NewAdminBearerVerifier authenticates the single operator credential for management routes.
func NewAdminBearerVerifier(tokenSHA256 string) (sdkauth.TokenVerifier, error) {
	digest, err := hex.DecodeString(tokenSHA256)
	if err != nil || len(digest) != sha256.Size {
		return nil, fmt.Errorf("auth: invalid administrator SHA-256 digest")
	}
	return func(_ context.Context, token string, _ *http.Request) (*sdkauth.TokenInfo, error) {
		sum := sha256.Sum256([]byte(token))
		if token == "" || subtle.ConstantTimeCompare(sum[:], digest) != 1 {
			return nil, sdkauth.ErrInvalidToken
		}
		return &sdkauth.TokenInfo{UserID: "token-admin", Scopes: []string{"admin"}}, nil
	}, nil
}

// AllowedTargetsFromToken extracts allowed target glob patterns from an authenticated TokenInfo.
func AllowedTargetsFromToken(info *sdkauth.TokenInfo) []string {
	if info == nil || info.Extra == nil {
		return nil
	}
	raw, ok := info.Extra[ExtraKeyAllowedTargets]
	if !ok {
		return nil
	}
	patterns, ok := raw.([]string)
	if !ok {
		return nil
	}
	return patterns
}

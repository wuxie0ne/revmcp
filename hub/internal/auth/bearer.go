package auth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"net/http"

	sdkauth "github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/revmcp/revmcp/hub/internal/config"
)

const ExtraKeyAllowedTargets = "allowed_targets"

type hashedClient struct {
	name           string
	digest         []byte
	scopes         []string
	allowedTargets []string
}

// NewStaticBearerVerifier constructs a northbound TokenVerifier backed by SHA-256 hashed
// API keys from Hub configuration. Comparisons are constant-time and raw tokens are never logged.
func NewStaticBearerVerifier(clients []config.ClientConfig) (sdkauth.TokenVerifier, error) {
	entries := make([]hashedClient, 0, len(clients))
	for _, cl := range clients {
		digest, err := hex.DecodeString(cl.TokenSHA256)
		if err != nil || len(digest) != sha256.Size {
			return nil, fmt.Errorf("auth: invalid sha256 digest for client %q", cl.Name)
		}
		entries = append(entries, hashedClient{
			name:           cl.Name,
			digest:         digest,
			scopes:         append([]string(nil), cl.Scopes...),
			allowedTargets: append([]string(nil), cl.AllowedTargets...),
		})
	}

	return func(_ context.Context, token string, _ *http.Request) (*sdkauth.TokenInfo, error) {
		if token == "" {
			return nil, sdkauth.ErrInvalidToken
		}
		sum := sha256.Sum256([]byte(token))

		matchedIdx := -1
		for i := range entries {
			if subtle.ConstantTimeCompare(sum[:], entries[i].digest) == 1 {
				matchedIdx = i
			}
		}
		if matchedIdx < 0 {
			return nil, sdkauth.ErrInvalidToken
		}

		c := entries[matchedIdx]
		return &sdkauth.TokenInfo{
			UserID: c.name,
			Scopes: append([]string(nil), c.scopes...),
			Extra: map[string]any{
				ExtraKeyAllowedTargets: append([]string(nil), c.allowedTargets...),
			},
		}, nil
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

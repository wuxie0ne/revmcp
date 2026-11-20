package auth

import (
	"context"
	"net/http"
	"slices"

	sdkauth "github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/revmcp/revmcp/hub/internal/channel"
)

const extraKeyChannelID = "channel_id"

func ChannelID(info *sdkauth.TokenInfo) string {
	if info == nil {
		return ""
	}
	id, _ := info.Extra[extraKeyChannelID].(string)
	return id
}

// WithChannelBearer preserves legacy static authentication in its own target namespace.
func WithChannelBearer(store *channel.Store, static sdkauth.TokenVerifier) sdkauth.TokenVerifier {
	return func(ctx context.Context, token string, req *http.Request) (*sdkauth.TokenInfo, error) {
		if !channel.Managed(token) {
			return static(ctx, token, req)
		}
		record, expiry, err := store.Verify(token, channel.MCP)
		if err != nil {
			return nil, sdkauth.ErrInvalidToken
		}
		return &sdkauth.TokenInfo{
			UserID: record.Name, Expiration: expiry, Scopes: slices.Clone(record.Policy.MCPScopes),
			Extra: map[string]any{
				extraKeyChannelID:      record.ID,
				ExtraKeyAllowedTargets: []string{record.Policy.Target},
			},
		}, nil
	}
}

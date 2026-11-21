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

// NewChannelBearerVerifier accepts only current MCP channel credentials.
func NewChannelBearerVerifier(store *channel.Store) sdkauth.TokenVerifier {
	return func(_ context.Context, token string, _ *http.Request) (*sdkauth.TokenInfo, error) {
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

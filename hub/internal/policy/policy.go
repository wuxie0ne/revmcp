package policy

import (
	"fmt"
	"path"
	"slices"
	"strings"

	sdkauth "github.com/modelcontextprotocol/go-sdk/auth"
	hubauth "github.com/revmcp/revmcp/hub/internal/auth"
)

const (
	ScopeRead           = "read"
	ScopeExecRestricted = "exec:restricted"
	ScopeExecFull       = "exec:full"
	ScopeExecSession    = "exec:session"
	ScopeAdmin          = "admin"
)

// Authorize verifies that tokenInfo carries requiredScope and (when targetID is non-empty)
// is permitted to access targetID via glob matching. Fails closed when TokenInfo is nil.
func Authorize(info *sdkauth.TokenInfo, requiredScope, targetID string) error {
	if info == nil {
		return fmt.Errorf("missing authentication context")
	}
	if requiredScope != "" && !HasScope(info.Scopes, requiredScope) {
		return fmt.Errorf("missing required scope %q", requiredScope)
	}
	if targetID != "" && !TargetAllowed(hubauth.AllowedTargetsFromToken(info), targetID) {
		return fmt.Errorf("target %q is not in caller allowed_targets", targetID)
	}
	return nil
}

// HasScope checks whether scopes grants requiredScope (exec:full implies exec:restricted).
func HasScope(scopes []string, required string) bool {
	if slices.Contains(scopes, required) {
		return true
	}
	if required == ScopeExecRestricted && slices.Contains(scopes, ScopeExecFull) {
		return true
	}
	return false
}

// TargetAllowed returns true if targetID matches any configured glob pattern.
func TargetAllowed(patterns []string, targetID string) bool {
	for _, pattern := range patterns {
		if pattern == "*" {
			return true
		}
		matched, err := path.Match(pattern, targetID)
		if err == nil && matched {
			return true
		}
	}
	return false
}

// WrapRemoteOutput wraps untrusted remote target output inside clear prompt-injection boundary tags.
func WrapRemoteOutput(targetID string, exitCode int, truncated bool, content string) string {
	// Sanitize any literal closing boundary tag inside untrusted data so it cannot break out.
	safeContent := strings.ReplaceAll(content, "</remote_output>", "</remote_output_escaped>")
	return fmt.Sprintf(
		"<remote_output target=%q exit_code=\"%d\" truncated=\"%t\">\n%s\n</remote_output>",
		targetID, exitCode, truncated, safeContent,
	)
}

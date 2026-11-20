package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/revmcp/revmcp/proto"
)

var (
	// ErrInvalidEnrollmentToken indicates a malformed, forged, or expired enrollment token.
	ErrInvalidEnrollmentToken = errors.New("auth: invalid enrollment token")
)

// EnrollmentClaims are the signed claims embedded in a southbound Agent enrollment token.
type EnrollmentClaims struct {
	TargetID string     `json:"target_id"`
	MaxMode  proto.Mode `json:"max_mode"`
	Exp      int64      `json:"exp"`
	JTI      string     `json:"jti"`
}

// EnrollmentSigner signs and verifies HMAC-SHA256 short-lived enrollment tokens.
type EnrollmentSigner struct {
	secret []byte
	now    func() time.Time
}

// NewEnrollmentSigner creates an EnrollmentSigner from a shared secret.
func NewEnrollmentSigner(secret string) (*EnrollmentSigner, error) {
	if len(strings.TrimSpace(secret)) < 16 {
		return nil, fmt.Errorf("auth: signing secret must be at least 16 bytes")
	}
	return &EnrollmentSigner{
		secret: []byte(secret),
		now:    time.Now,
	}, nil
}

// Issue generates a signed short-lived enrollment token for targetID and maxMode.
func (s *EnrollmentSigner) Issue(targetID string, maxMode proto.Mode, ttl time.Duration) (string, *EnrollmentClaims, error) {
	if strings.TrimSpace(targetID) == "" {
		return "", nil, fmt.Errorf("auth: target_id is required")
	}
	mode, err := proto.ParseMode(string(maxMode))
	if err != nil {
		return "", nil, err
	}
	if ttl <= 0 {
		return "", nil, fmt.Errorf("auth: ttl must be positive")
	}

	jtiBytes := make([]byte, 8)
	if _, err := rand.Read(jtiBytes); err != nil {
		return "", nil, fmt.Errorf("auth: generate jti: %w", err)
	}

	claims := &EnrollmentClaims{
		TargetID: targetID,
		MaxMode:  mode,
		Exp:      s.now().Add(ttl).Unix(),
		JTI:      hex.EncodeToString(jtiBytes),
	}

	payload, err := json.Marshal(claims)
	if err != nil {
		return "", nil, fmt.Errorf("auth: marshal claims: %w", err)
	}

	encodedPayload := base64.RawURLEncoding.EncodeToString(payload)
	mac := s.sign(encodedPayload)
	encodedMAC := base64.RawURLEncoding.EncodeToString(mac)
	return encodedPayload + "." + encodedMAC, claims, nil
}

// Verify validates signature, expiration, target_id, and max_mode, failing closed on any error.
func (s *EnrollmentSigner) Verify(token string) (*EnrollmentClaims, error) {
	encodedPayload, encodedMAC, ok := strings.Cut(strings.TrimSpace(token), ".")
	if !ok || encodedPayload == "" || encodedMAC == "" {
		return nil, fmt.Errorf("%w: malformed token", ErrInvalidEnrollmentToken)
	}

	providedMAC, err := base64.RawURLEncoding.DecodeString(encodedMAC)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid signature encoding", ErrInvalidEnrollmentToken)
	}
	expectedMAC := s.sign(encodedPayload)
	if !hmac.Equal(providedMAC, expectedMAC) {
		return nil, fmt.Errorf("%w: signature mismatch", ErrInvalidEnrollmentToken)
	}

	rawPayload, err := base64.RawURLEncoding.DecodeString(encodedPayload)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid payload encoding", ErrInvalidEnrollmentToken)
	}

	var claims EnrollmentClaims
	if err := json.Unmarshal(rawPayload, &claims); err != nil {
		return nil, fmt.Errorf("%w: invalid claims json", ErrInvalidEnrollmentToken)
	}
	if strings.TrimSpace(claims.TargetID) == "" {
		return nil, fmt.Errorf("%w: missing target_id", ErrInvalidEnrollmentToken)
	}
	if _, err := proto.ParseMode(string(claims.MaxMode)); err != nil {
		return nil, fmt.Errorf("%w: invalid max_mode", ErrInvalidEnrollmentToken)
	}
	if claims.Exp <= s.now().Unix() {
		return nil, fmt.Errorf("%w: token expired", ErrInvalidEnrollmentToken)
	}

	return &claims, nil
}

func (s *EnrollmentSigner) sign(encodedPayload string) []byte {
	mac := hmac.New(sha256.New, s.secret)
	_, _ = mac.Write([]byte(encodedPayload))
	return mac.Sum(nil)
}

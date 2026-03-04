package jwtassertion

import (
	"context"
	"crypto/rsa"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

const (
	clientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
)

// Config holds the settings required to obtain OAuth tokens using
// the private_key_jwt client authentication method.
type Config struct {
	// OAuth2 config containing ClientID, TokenURL, and Scopes.
	OAuth2 *oauth2.Config

	// PrivKey is the RSA private key used to sign JWT assertions.
	PrivKey *rsa.PrivateKey

	// KeyID is the optional "kid" header included in the JWT.
	KeyID string

	// SigningMethod is the JWT signing algorithm. Defaults to RS256 if nil.
	SigningMethod jwt.SigningMethod
}

// CustomClaims extends jwt.RegisteredClaims with an OAuth scope list.
type CustomClaims struct {
	Scope []string `json:"scope"`
	jwt.RegisteredClaims
}

// Client returns an *http.Client whose requests are automatically
// authorized with a Bearer token obtained via client_credentials +
// private_key_jwt assertion. Tokens are cached and refreshed automatically.
func (c *Config) Client(ctx context.Context) *http.Client {
	ts := oauth2.ReuseTokenSource(nil, &jwtTokenSource{
		ctx:    ctx,
		config: c,
	})
	return oauth2.NewClient(ctx, ts)
}

// jwtTokenSource implements oauth2.TokenSource. Each call to Token()
// performs a client_credentials grant using a freshly signed JWT assertion.
type jwtTokenSource struct {
	// ctx is stored to satisfy oauth2.TokenSource, which does not
	// accept a context parameter. Use Config.Client to control lifetime.
	ctx    context.Context
	config *Config
}

// Token fetches a new access token from the token endpoint.
func (s *jwtTokenSource) Token() (*oauth2.Token, error) {
	assertion, err := buildAssertion(s.config)
	if err != nil {
		return nil, fmt.Errorf("building JWT assertion: %w", err)
	}

	return s.config.OAuth2.Exchange(s.ctx, "",
		oauth2.SetAuthURLParam("grant_type", "client_credentials"),
		oauth2.SetAuthURLParam("client_assertion_type", clientAssertionType),
		oauth2.SetAuthURLParam("client_assertion", assertion),
	)
}

// buildAssertion creates and signs the JWT client assertion.
func buildAssertion(c *Config) (string, error) {
	now := time.Now()
	claims := CustomClaims{
		Scope: c.OAuth2.Scopes,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			Issuer:    c.OAuth2.ClientID,
			Audience:  jwt.ClaimStrings{c.OAuth2.Endpoint.TokenURL},
			IssuedAt:  jwt.NewNumericDate(now),
			Subject:   c.OAuth2.ClientID,
			ID:        fmt.Sprintf("%d", now.UnixNano()),
		},
	}

	signingMethod := c.SigningMethod
	if signingMethod == nil {
		signingMethod = jwt.SigningMethodRS256
	}

	token := jwt.NewWithClaims(c.SigningMethod, claims)
	if c.KeyID != "" {
		token.Header["kid"] = c.KeyID
	}

	return token.SignedString(c.PrivKey)
}

// LoadPrivateKey parses an RSA private key from PEM-encoded bytes.
func LoadPrivateKey(pemData []byte) (*rsa.PrivateKey, error) {
	return jwt.ParseRSAPrivateKeyFromPEM(pemData)
}

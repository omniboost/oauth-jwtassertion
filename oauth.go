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
	//Create the Claims
	claims := CustomClaims{
		[]string{"rest_webservices"},
		jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute * 60)),
			Issuer:    c.OAuth2.ClientID,
			Audience:  jwt.ClaimStrings{c.OAuth2.Endpoint.TokenURL},
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodPS256, claims)
	if c.KeyID != "" {
		token.Header["kid"] = c.KeyID
	}

	return token.SignedString(c.PrivKey)
}

// LoadPrivateKey parses an RSA private key from PEM-encoded bytes.
func LoadPrivateKey(pemData []byte) (*rsa.PrivateKey, error) {
	return jwt.ParseRSAPrivateKeyFromPEM(pemData)
}

// Data for the custom claims
type CustomClaims struct {
	Scope []string `json:"scope"`
	jwt.RegisteredClaims
}

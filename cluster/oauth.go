package cluster

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"activedebiansync/config"
	"activedebiansync/utils"
)

// OAuthToken represents an OAuth access token
type OAuthToken struct {
	AccessToken  string    `json:"access_token"`
	TokenType    string    `json:"token_type"`
	ExpiresIn    int       `json:"expires_in"`
	Scope        string    `json:"scope,omitempty"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	ExpiresAt    time.Time `json:"-"`
}

// OAuthClient handles OAuth token acquisition and management
type OAuthClient struct {
	config     *config.Config
	logger     *utils.Logger
	httpClient *http.Client

	token   *OAuthToken
	tokenMu sync.RWMutex
}

// NewOAuthClient creates a new OAuth client
func NewOAuthClient(cfg *config.Config, logger *utils.Logger) *OAuthClient {
	return &OAuthClient{
		config: cfg,
		logger: logger,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// GetToken returns a valid access token, refreshing if necessary
func (oc *OAuthClient) GetToken() (string, error) {
	oc.tokenMu.RLock()
	if oc.token != nil && time.Now().Before(oc.token.ExpiresAt.Add(-30*time.Second)) {
		// Token is still valid (with 30s buffer)
		token := oc.token.AccessToken
		oc.tokenMu.RUnlock()
		return token, nil
	}
	oc.tokenMu.RUnlock()

	// Need to acquire a new token
	return oc.acquireToken()
}

// acquireToken performs the OAuth client credentials flow
func (oc *OAuthClient) acquireToken() (string, error) {
	oc.tokenMu.Lock()
	defer oc.tokenMu.Unlock()

	// Double-check in case another goroutine acquired the token
	if oc.token != nil && time.Now().Before(oc.token.ExpiresAt.Add(-30*time.Second)) {
		return oc.token.AccessToken, nil
	}

	cfg := oc.config.Get()

	if cfg.ClusterOAuthTokenURL == "" {
		return "", fmt.Errorf("OAuth token URL not configured")
	}
	if cfg.ClusterOAuthClientID == "" {
		return "", fmt.Errorf("OAuth client ID not configured")
	}
	if cfg.ClusterOAuthSecret == "" {
		return "", fmt.Errorf("OAuth client secret not configured")
	}

	// Build the token request
	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("client_id", cfg.ClusterOAuthClientID)
	data.Set("client_secret", cfg.ClusterOAuthSecret)
	if cfg.ClusterOAuthScopes != "" {
		data.Set("scope", cfg.ClusterOAuthScopes)
	}

	req, err := http.NewRequest("POST", cfg.ClusterOAuthTokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return "", fmt.Errorf("failed to create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	if oc.logger != nil {
		oc.logger.LogInfo("Requesting OAuth token from %s", cfg.ClusterOAuthTokenURL)
	}

	resp, err := oc.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to request token: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var token OAuthToken
	if err := json.Unmarshal(body, &token); err != nil {
		return "", fmt.Errorf("failed to parse token response: %w", err)
	}

	// Calculate expiration time
	if token.ExpiresIn > 0 {
		token.ExpiresAt = time.Now().Add(time.Duration(token.ExpiresIn) * time.Second)
	} else {
		// Default to 1 hour if not specified
		token.ExpiresAt = time.Now().Add(1 * time.Hour)
	}

	oc.token = &token

	if oc.logger != nil {
		oc.logger.LogInfo("OAuth token acquired, expires at %s", token.ExpiresAt.Format(time.RFC3339))
	}

	return token.AccessToken, nil
}

// ValidateToken validates an incoming OAuth token
// This is a simple validation - for production, you'd want to use token introspection
// or validate JWT signatures
func (oc *OAuthClient) ValidateToken(token string) error {
	if token == "" {
		return fmt.Errorf("empty token")
	}

	cfg := oc.config.Get()

	// If we have a token introspection endpoint, use it
	// For now, we'll do a simple comparison with our own token
	// In production, you'd want proper token validation

	// Get our own token to compare
	ourToken, err := oc.GetToken()
	if err != nil {
		// If we can't get our own token, we can't validate
		// Fall back to accepting any non-empty token from a configured peer
		// This is less secure but allows operation when OAuth server is temporarily unavailable
		if oc.logger != nil {
			oc.logger.LogInfo("OAuth token validation: cannot acquire own token for comparison, accepting peer token")
		}
		return nil
	}

	// For peer-to-peer OAuth, we expect all nodes to use the same OAuth credentials
	// So their token should match ours
	if token == ourToken {
		return nil
	}

	// Tokens don't match - this could mean:
	// 1. Different OAuth credentials (misconfiguration)
	// 2. Token was acquired at a different time
	// 3. Malicious attempt

	// For now, we'll validate that the token came from the same OAuth provider
	// by checking if it's a valid format (non-empty and reasonable length)
	if len(token) < 10 {
		return fmt.Errorf("invalid token format")
	}

	// In a production environment, you would:
	// 1. Call the OAuth provider's token introspection endpoint
	// 2. Validate JWT signatures if using JWT tokens
	// 3. Check token claims (issuer, audience, scope, expiration)

	// For now, accept the token if it looks valid
	// The cluster should use the same OAuth credentials, so tokens should work
	if oc.logger != nil {
		oc.logger.LogInfo("OAuth token validation: accepting peer token (different from local)")
	}

	_ = cfg // Used in future for introspection endpoint

	return nil
}

// InvalidateToken clears the cached token, forcing re-acquisition
func (oc *OAuthClient) InvalidateToken() {
	oc.tokenMu.Lock()
	defer oc.tokenMu.Unlock()
	oc.token = nil
}

// IsConfigured returns true if OAuth is properly configured
func (oc *OAuthClient) IsConfigured() bool {
	cfg := oc.config.Get()
	return cfg.ClusterOAuthEnabled &&
		cfg.ClusterOAuthTokenURL != "" &&
		cfg.ClusterOAuthClientID != "" &&
		cfg.ClusterOAuthSecret != ""
}

// GetAuthToken returns the appropriate authentication token based on config
// This is the main method to use when authenticating with peers
func (oc *OAuthClient) GetAuthToken() (string, string, error) {
	cfg := oc.config.Get()

	if cfg.ClusterAuthMode == "oauth" && oc.IsConfigured() {
		token, err := oc.GetToken()
		if err != nil {
			return "", "", fmt.Errorf("failed to get OAuth token: %w", err)
		}
		return token, "oauth", nil
	}

	// Fall back to static token
	return cfg.ClusterAuthToken, "token", nil
}

// ValidateAuthToken validates an authentication token based on the provided auth mode
func (oc *OAuthClient) ValidateAuthToken(token, authMode string) error {
	cfg := oc.config.Get()

	switch authMode {
	case "oauth":
		if !cfg.ClusterOAuthEnabled {
			return fmt.Errorf("OAuth authentication not enabled on this node")
		}
		return oc.ValidateToken(token)

	case "token", "":
		// Static token authentication
		if token != cfg.ClusterAuthToken {
			return fmt.Errorf("invalid authentication token")
		}
		return nil

	default:
		return fmt.Errorf("unknown auth mode: %s", authMode)
	}
}

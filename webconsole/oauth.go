package webconsole

import (
	"crypto/rand"
	"encoding/base64"
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

// OAuthState stores OAuth flow state for CSRF protection
type OAuthState struct {
	State     string
	CreatedAt time.Time
	ReturnURL string
}

// OAuthUserInfo represents user information from the OAuth provider
type OAuthUserInfo struct {
	Sub               string   `json:"sub"`
	Name              string   `json:"name"`
	PreferredUsername string   `json:"preferred_username"`
	Email             string   `json:"email"`
	EmailVerified     bool     `json:"email_verified"`
	Groups            []string `json:"groups"`
	Roles             []string `json:"roles"`
	// Additional fields for different providers
	Login    string `json:"login"`    // GitHub
	Username string `json:"username"` // Generic
}

// OAuthTokenResponse represents the OAuth token endpoint response
type OAuthTokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	Scope        string `json:"scope"`
	Error        string `json:"error"`
	ErrorDesc    string `json:"error_description"`
}

// ConsoleOAuthHandler handles OAuth authentication for the web console
type ConsoleOAuthHandler struct {
	config     *config.Config
	logger     *utils.Logger
	httpClient *http.Client

	// State storage for CSRF protection
	states   map[string]*OAuthState
	statesMu sync.RWMutex
}

// NewConsoleOAuthHandler creates a new OAuth handler
func NewConsoleOAuthHandler(cfg *config.Config, logger *utils.Logger) *ConsoleOAuthHandler {
	handler := &ConsoleOAuthHandler{
		config: cfg,
		logger: logger,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		states: make(map[string]*OAuthState),
	}

	// Start state cleanup goroutine
	go handler.cleanupStates()

	return handler
}

// cleanupStates removes expired OAuth states
func (h *ConsoleOAuthHandler) cleanupStates() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		h.statesMu.Lock()
		now := time.Now()
		for state, data := range h.states {
			// States expire after 10 minutes
			if now.Sub(data.CreatedAt) > 10*time.Minute {
				delete(h.states, state)
			}
		}
		h.statesMu.Unlock()
	}
}

// generateState creates a random state for CSRF protection
func (h *ConsoleOAuthHandler) generateState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// IsEnabled returns true if OAuth is enabled and configured
func (h *ConsoleOAuthHandler) IsEnabled() bool {
	cfg := h.config.Get()
	return cfg.WebConsoleOAuthEnabled &&
		cfg.WebConsoleOAuthClientID != "" &&
		cfg.WebConsoleOAuthAuthURL != "" &&
		cfg.WebConsoleOAuthTokenURL != ""
}

// GetAuthorizationURL returns the OAuth authorization URL
func (h *ConsoleOAuthHandler) GetAuthorizationURL(returnURL string) (string, error) {
	cfg := h.config.Get()

	if !h.IsEnabled() {
		return "", fmt.Errorf("OAuth is not enabled or not configured")
	}

	// Generate state for CSRF protection
	state, err := h.generateState()
	if err != nil {
		return "", fmt.Errorf("failed to generate state: %w", err)
	}

	// Store state
	h.statesMu.Lock()
	h.states[state] = &OAuthState{
		State:     state,
		CreatedAt: time.Now(),
		ReturnURL: returnURL,
	}
	h.statesMu.Unlock()

	// Build redirect URL
	redirectURL := cfg.WebConsoleOAuthRedirectURL
	if redirectURL == "" {
		// Auto-generate based on console URL
		scheme := "http"
		if cfg.WebConsoleHTTPSEnabled || cfg.WebConsoleSecureCookies {
			scheme = "https"
		}
		redirectURL = fmt.Sprintf("%s://%s:%d%s/oauth/callback",
			scheme, cfg.WebConsoleListenAddr, cfg.WebConsolePort, cfg.WebConsoleBasePath)
	}

	// Build authorization URL
	params := url.Values{}
	params.Set("client_id", cfg.WebConsoleOAuthClientID)
	params.Set("response_type", "code")
	params.Set("redirect_uri", redirectURL)
	params.Set("scope", cfg.WebConsoleOAuthScopes)
	params.Set("state", state)

	authURL := cfg.WebConsoleOAuthAuthURL
	if strings.Contains(authURL, "?") {
		authURL += "&" + params.Encode()
	} else {
		authURL += "?" + params.Encode()
	}

	return authURL, nil
}

// OAuthCallbackResult contains the result of an OAuth callback
type OAuthCallbackResult struct {
	Username    string
	IsAdmin     bool
	AccessToken string
	ReturnURL   string
}

// HandleCallback handles the OAuth callback and returns user info
func (h *ConsoleOAuthHandler) HandleCallback(code, state string) (*OAuthCallbackResult, error) {
	cfg := h.config.Get()

	// Verify state
	h.statesMu.Lock()
	stateData, exists := h.states[state]
	if exists {
		delete(h.states, state)
	}
	h.statesMu.Unlock()

	if !exists {
		return nil, fmt.Errorf("invalid or expired state")
	}

	// Exchange code for token
	token, err := h.exchangeCode(code)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code: %w", err)
	}

	// Get user info
	userInfo, err := h.getUserInfo(token.AccessToken)
	if err != nil {
		h.logger.LogError("Failed to get user info: %v", err)
		// Continue with limited info from token
	}

	// Determine username
	username := h.determineUsername(userInfo)
	if username == "" {
		return nil, fmt.Errorf("could not determine username from OAuth response")
	}

	// Determine if user is admin
	isAdmin := h.isUserAdmin(userInfo, cfg.WebConsoleOAuthAdminGroup)

	h.logger.LogInfo("OAuth callback successful for user: %s (admin: %v)", username, isAdmin)

	return &OAuthCallbackResult{
		Username:    username,
		IsAdmin:     isAdmin,
		AccessToken: token.AccessToken,
		ReturnURL:   stateData.ReturnURL,
	}, nil
}

// exchangeCode exchanges the authorization code for tokens
func (h *ConsoleOAuthHandler) exchangeCode(code string) (*OAuthTokenResponse, error) {
	cfg := h.config.Get()

	// Build redirect URL (must match the one used in authorization)
	redirectURL := cfg.WebConsoleOAuthRedirectURL
	if redirectURL == "" {
		scheme := "http"
		if cfg.WebConsoleHTTPSEnabled || cfg.WebConsoleSecureCookies {
			scheme = "https"
		}
		redirectURL = fmt.Sprintf("%s://%s:%d%s/oauth/callback",
			scheme, cfg.WebConsoleListenAddr, cfg.WebConsolePort, cfg.WebConsoleBasePath)
	}

	// Build token request
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", redirectURL)
	data.Set("client_id", cfg.WebConsoleOAuthClientID)
	data.Set("client_secret", cfg.WebConsoleOAuthClientSecret)

	req, err := http.NewRequest("POST", cfg.WebConsoleOAuthTokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var tokenResp OAuthTokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	if tokenResp.Error != "" {
		return nil, fmt.Errorf("OAuth error: %s - %s", tokenResp.Error, tokenResp.ErrorDesc)
	}

	if tokenResp.AccessToken == "" {
		return nil, fmt.Errorf("no access token in response")
	}

	return &tokenResp, nil
}

// getUserInfo fetches user information from the OAuth provider
func (h *ConsoleOAuthHandler) getUserInfo(accessToken string) (*OAuthUserInfo, error) {
	cfg := h.config.Get()

	// If no userinfo URL, return nil (not an error)
	if cfg.WebConsoleOAuthUserInfoURL == "" {
		return nil, nil
	}

	req, err := http.NewRequest("GET", cfg.WebConsoleOAuthUserInfoURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("userinfo request failed with status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var userInfo OAuthUserInfo
	if err := json.Unmarshal(body, &userInfo); err != nil {
		return nil, fmt.Errorf("failed to parse userinfo response: %w", err)
	}

	return &userInfo, nil
}

// determineUsername extracts username from user info
func (h *ConsoleOAuthHandler) determineUsername(userInfo *OAuthUserInfo) string {
	if userInfo == nil {
		return ""
	}

	// Try different fields in order of preference
	if userInfo.PreferredUsername != "" {
		return userInfo.PreferredUsername
	}
	if userInfo.Username != "" {
		return userInfo.Username
	}
	if userInfo.Login != "" {
		return userInfo.Login
	}
	if userInfo.Email != "" {
		return userInfo.Email
	}
	if userInfo.Name != "" {
		return userInfo.Name
	}
	if userInfo.Sub != "" {
		return userInfo.Sub
	}

	return ""
}

// isUserAdmin checks if the user has admin privileges
func (h *ConsoleOAuthHandler) isUserAdmin(userInfo *OAuthUserInfo, adminGroup string) bool {
	if userInfo == nil || adminGroup == "" {
		return false
	}

	// Check groups
	for _, group := range userInfo.Groups {
		if strings.EqualFold(group, adminGroup) {
			return true
		}
	}

	// Check roles
	for _, role := range userInfo.Roles {
		if strings.EqualFold(role, adminGroup) {
			return true
		}
	}

	return false
}

// GetProviderName returns the configured provider name or a default
func (h *ConsoleOAuthHandler) GetProviderName() string {
	cfg := h.config.Get()
	if cfg.WebConsoleOAuthProvider != "" {
		return cfg.WebConsoleOAuthProvider
	}
	return "OAuth Provider"
}

// AllowsLocalLogin returns true if local login is allowed alongside OAuth
func (h *ConsoleOAuthHandler) AllowsLocalLogin() bool {
	cfg := h.config.Get()
	return cfg.WebConsoleOAuthAllowLocal || !h.IsEnabled()
}

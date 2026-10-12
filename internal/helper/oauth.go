package helper

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/group-project/authentication/internal/config"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type OAuthUser struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	VerifiedEmail bool   `json:"verified_email"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
}

type OAuthProvider interface {
	GetAuthURL(state string) (string, error)
	ExchangeCode(ctx context.Context, code string) (*OAuthUser, error)
	IsConfigured() bool
}

type GoogleOAuthProvider struct {
	oauthConfig *oauth2.Config
}

func NewGoogleOAuthProvider(cfg config.GoogleOAuthConfig) *GoogleOAuthProvider {
	if cfg.ClientID == "" || cfg.ClientSecret == "" {
		return &GoogleOAuthProvider{oauthConfig: nil}
	}

	return &GoogleOAuthProvider{
		oauthConfig: &oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURL,
			Scopes: []string{
				"https://www.googleapis.com/auth/userinfo.email",
				"https://www.googleapis.com/auth/userinfo.profile",
			},
			Endpoint: google.Endpoint,
		},
	}
}

func (g *GoogleOAuthProvider) IsConfigured() bool {
	return g.oauthConfig != nil
}

func (g *GoogleOAuthProvider) GetAuthURL(state string) (string, error) {
	if !g.IsConfigured() {
		return "", errors.New("google oauth is not configured")
	}
	return g.oauthConfig.AuthCodeURL(state, oauth2.AccessTypeOffline), nil
}

func (g *GoogleOAuthProvider) ExchangeCode(ctx context.Context, code string) (*OAuthUser, error) {
	if !g.IsConfigured() {
		return nil, errors.New("google oauth is not configured")
	}

	token, err := g.oauthConfig.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code with google: %w", err)
	}

	client := g.oauthConfig.Client(ctx, token)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
	if err != nil {
		return nil, fmt.Errorf("failed to fetch user info from google: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("google userinfo returned status: %d", resp.StatusCode)
	}

	var user OAuthUser
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return nil, fmt.Errorf("failed to parse google userinfo: %w", err)
	}

	if user.Email == "" || user.ID == "" {
		return nil, errors.New("google userinfo missing email or id")
	}

	return &user, nil
}

// GenerateOAuthState creates a cryptographically secure random state string to mitigate CSRF.
func GenerateOAuthState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

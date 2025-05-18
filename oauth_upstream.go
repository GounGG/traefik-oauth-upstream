// Package traefik_oauth_upstream - Traefik plugin to manage upstream OAuth.
package traefik_oauth_upstream //nolint:stylecheck,revive

import (
	"context"
	"encoding/json"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
	"net/url"
	"log"

	"golang.org/x/oauth2"
)

const CALLBACK_PATH = "/_oauth" //nolint:revive,stylecheck

// Config - the plugin configuration.
type Config struct {
	ClientID     string   `json:"clientId"`
	ClientSecret string   `json:"clientSecret"`
	AuthURL      string   `json:"authUrl"`
	TokenURL     string   `json:"tokenUrl"`
	Scopes       []string `json:"scopes"`
	AllowedEmails []string `json:"allowedEmails"`
	// AllowedEmailDomains allows all emails with these domain suffixes (e.g. "garena.com")
	AllowedEmailDomains []string `json:"allowedEmailDomains"`
}

// CreateConfig - creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		Scopes: []string{},
	}
}

// OauthUpstream - information about upstream OAuth.
type OauthUpstream struct {
	next       http.Handler
	config     *oauth2.Config
	name       string
	allowedEmails []string
	allowedEmailDomains []string
}

// New created a new Demo plugin.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if config.ClientID == "" || config.ClientSecret == "" || config.AuthURL == "" || config.TokenURL == "" || len(config.Scopes) == 0 {
		return nil, fmt.Errorf("error loading traefik_oauth_upstream plugin: All of the following config must be defined: clientId, clientSecret, authUrl, tokenUrl, scopes")
	}

	return &OauthUpstream{
		config: &oauth2.Config{
			ClientID:     config.ClientID,
			ClientSecret: config.ClientSecret,
			Scopes:       config.Scopes,
			Endpoint: oauth2.Endpoint{
				AuthURL:  config.AuthURL,
				TokenURL: config.TokenURL,
			},
		},
		next:       next,
		name:       name,
		allowedEmails: config.AllowedEmails,
		allowedEmailDomains: config.AllowedEmailDomains,
	}, nil
}

// UserInfo represents the user information from Google
// Only the email field is used here

type UserInfo struct {
	Email string `json:"email"`
}

func (a *OauthUpstream) getUserEmail(token *oauth2.Token) (string, error) {
	req, err := http.NewRequest("GET", "https://www.googleapis.com/oauth2/v2/userinfo", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	// Debug: print status and body
	bodyBytes, _ := io.ReadAll(resp.Body)
	// log.Printf("[DEBUG] userinfo status: %d", resp.StatusCode)
	// log.Printf("[DEBUG] userinfo body: %s", string(bodyBytes))
	// Try to decode
	var userInfo UserInfo
	if err := json.Unmarshal(bodyBytes, &userInfo); err != nil {
		return "", err
	}
	return userInfo.Email, nil
}

func (a *OauthUpstream) isEmailAllowed(email string) bool {
	// If neither list is configured, allow all emails
	if len(a.allowedEmails) == 0 && len(a.allowedEmailDomains) == 0 {
		return true
	}
	// Exact match
	for _, allowed := range a.allowedEmails {
		if email == allowed {
			return true
		}
	}
	// Suffix match (domain)
	for _, domain := range a.allowedEmailDomains {
		if strings.HasSuffix(strings.ToLower(email), "@"+strings.ToLower(domain)) {
			return true
		}
	}
	return false
}

// Helper: encode token to base64 JSON
func encodeToken(token *oauth2.Token) (string, error) {
	b, err := json.Marshal(token)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// Helper: decode token from base64 JSON
func decodeToken(s string) (*oauth2.Token, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	var token oauth2.Token
	if err := json.Unmarshal(b, &token); err != nil {
		return nil, err
	}
	return &token, nil
}

func (a *OauthUpstream) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	// log.Printf("[DEBUG] Serving request: %s", req.URL.Path)
	if strings.HasPrefix(req.URL.Path, CALLBACK_PATH) {
		// Handle token exchange
		callbackCode := req.URL.Query().Get("code")
		state := req.URL.Query().Get("state") // original URL
		if state == "" {
			state = "/"
		} else {
			if decoded, err := url.QueryUnescape(state); err == nil {
				state = decoded
			} else {
				log.Printf("[DEBUG] state decode error: %v", err)
			}
		}
		//nolint:contextcheck // false positive
		token, err := a.config.Exchange(context.Background(), callbackCode)
		if err != nil {
			http.Error(rw, "Failed to exchange auth code: "+err.Error(), http.StatusInternalServerError)
			return
		}
		tokenStr, err := encodeToken(token)
		if err != nil {
			http.Error(rw, "Failed to encode token: "+err.Error(), http.StatusInternalServerError)
			return
		}
		// Get email and write to cookie
		email := ""
		if len(a.allowedEmails) > 0 || len(a.allowedEmailDomains) > 0 {
			email, err = a.getUserEmail(token)
			if err != nil {
				http.Error(rw, "Failed to get userinfo: "+err.Error(), http.StatusInternalServerError)
				return
			}
			http.SetCookie(rw, &http.Cookie{
				Name:     "oauth_email",
				Value:    url.QueryEscape(email),
				Path:     "/",
				HttpOnly: true,
				Secure:   true,
				Expires:  token.Expiry,
			})
		}
		http.SetCookie(rw, &http.Cookie{
			Name:     "oauth_token",
			Value:    tokenStr,
			Path:     "/",
			HttpOnly: true,
			Secure:   true,
			Expires:  token.Expiry,
		})
		http.Redirect(rw, req, state, http.StatusFound)
		return
	}

	// Check for oauth_token cookie
	cookie, err := req.Cookie("oauth_token")
	if err != nil || cookie.Value == "" {
		// No token, redirect to Google login
		a.config.RedirectURL = fmt.Sprintf("https://%s%s", req.Host, CALLBACK_PATH)
		state := url.QueryEscape(req.URL.RequestURI())
		url := a.config.AuthCodeURL(state, oauth2.AccessTypeOffline)
		http.Redirect(rw, req, url, http.StatusFound)
		return
	}
	token, err := decodeToken(cookie.Value)
	if err != nil {
		// Invalid token, force re-login
		a.config.RedirectURL = fmt.Sprintf("https://%s%s", req.Host, CALLBACK_PATH)
		state := url.QueryEscape(req.URL.RequestURI())
		url := a.config.AuthCodeURL(state, oauth2.AccessTypeOffline)
		http.Redirect(rw, req, url, http.StatusFound)
		return
	}
	// Optionally refresh token if expired
	if token.Expiry.Before(time.Now()) {
		// Token expired, force re-login
		a.config.RedirectURL = fmt.Sprintf("https://%s%s", req.Host, CALLBACK_PATH)
		state := url.QueryEscape(req.URL.RequestURI())
		url := a.config.AuthCodeURL(state, oauth2.AccessTypeOffline)
		http.Redirect(rw, req, url, http.StatusFound)
		return
	}
	// Validate email
	if len(a.allowedEmails) > 0 || len(a.allowedEmailDomains) > 0 {
		email := ""
		emailCookie, err := req.Cookie("oauth_email")
		if err == nil && emailCookie.Value != "" {
			email, _ = url.QueryUnescape(emailCookie.Value)
		}
		if email == "" {
			// No cached email, fetch from Google and write to cookie
			email, err = a.getUserEmail(token)
			if err != nil {
				// Token invalid, force re-login
				a.config.RedirectURL = fmt.Sprintf("https://%s%s", req.Host, CALLBACK_PATH)
				state := url.QueryEscape(req.URL.RequestURI())
				url := a.config.AuthCodeURL(state, oauth2.AccessTypeOffline)
				http.Redirect(rw, req, url, http.StatusFound)
				return
			}
			http.SetCookie(rw, &http.Cookie{
				Name:     "oauth_email",
				Value:    url.QueryEscape(email),
				Path:     "/",
				HttpOnly: true,
				Secure:   true,
				Expires:  token.Expiry,
			})
		}
		if !a.isEmailAllowed(email) {
			log.Printf("[DEBUG] Access denied for email: %s", email)
			http.Error(rw, "Access denied: Your email ("+email+") is not authorized to access this resource", http.StatusForbidden)
			return
		}
		// Optionally pass email to downstream
		req.Header.Set("X-User-Email", email)
	}
	// pass down the middleware chain
	a.next.ServeHTTP(rw, req)
}
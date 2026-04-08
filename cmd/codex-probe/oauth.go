package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	codexOAuthClientID     = "app_EMoamEEZ73f0CkXaXp7hrann"
	codexOAuthAuthorizeURL = "https://auth.openai.com/oauth/authorize"
	codexOAuthTokenURL     = "https://auth.openai.com/oauth/token"
	codexOAuthRedirectURI  = "http://localhost:1455/auth/callback"
	codexOAuthScope        = "openid profile email offline_access"
	codexJWTClaimPath      = "https://api.openai.com/auth"
	oauthCallbackTimeout   = 30 * time.Minute
)

type oauthFlow struct {
	State     string
	Verifier  string
	Challenge string
	AuthURL   string
}

func createOAuthFlow() (*oauthFlow, error) {
	state, err := createStateHex(16)
	if err != nil {
		return nil, err
	}
	verifier, challenge, err := generatePKCEPair()
	if err != nil {
		return nil, err
	}
	authURL, err := buildAuthorizeURL(state, challenge)
	if err != nil {
		return nil, err
	}
	return &oauthFlow{
		State:     state,
		Verifier:  verifier,
		Challenge: challenge,
		AuthURL:   authURL,
	}, nil
}

func buildAuthorizeURL(state, challenge string) (string, error) {
	u, err := url.Parse(codexOAuthAuthorizeURL)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", codexOAuthClientID)
	q.Set("redirect_uri", codexOAuthRedirectURI)
	q.Set("scope", codexOAuthScope)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	q.Set("state", state)
	q.Set("id_token_add_organizations", "true")
	q.Set("codex_cli_simplified_flow", "true")
	q.Set("originator", "codex_cli_rs")
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func createStateHex(nBytes int) (string, error) {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", b), nil
}

func generatePKCEPair() (verifier, challenge string, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	verifier = base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	return verifier, challenge, nil
}

// waitForCallback starts a local HTTP server on :1455 and waits for the OAuth callback.
// Returns the code and state extracted from the redirect.
func waitForCallback(ctx context.Context, expectedState string) (code string, state string, err error) {
	type result struct {
		code  string
		state string
		err   error
	}
	ch := make(chan result, 1)

	mux := http.NewServeMux()
	srv := &http.Server{Addr: ":1455", Handler: mux}

	mux.HandleFunc("/auth/callback", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		c := strings.TrimSpace(q.Get("code"))
		s := strings.TrimSpace(q.Get("state"))

		if c == "" {
			errMsg := q.Get("error_description")
			if errMsg == "" {
				errMsg = q.Get("error")
			}
			if errMsg == "" {
				errMsg = "missing code in callback"
			}
			http.Error(w, "Authorization failed: "+errMsg, http.StatusBadRequest)
			ch <- result{err: fmt.Errorf("callback error: %s", errMsg)}
			return
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<!DOCTYPE html><html><body style="font-family:sans-serif;text-align:center;padding:60px">
<h2 style="color:#16a34a">&#10003; 授权成功</h2>
<p>可以关闭此标签页，返回终端继续操作。</p>
</body></html>`)
		ch <- result{code: c, state: s}
	})

	go func() {
		if listenErr := srv.ListenAndServe(); listenErr != nil && listenErr != http.ErrServerClosed {
			select {
			case ch <- result{err: fmt.Errorf("callback server: %w", listenErr)}:
			default:
			}
		}
	}()

	defer func() {
		shutCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()

	select {
	case res := <-ch:
		return res.code, res.state, res.err
	case <-ctx.Done():
		return "", "", fmt.Errorf("timed out waiting for OAuth callback")
	}
}

type tokenResult struct {
	AccessToken  string
	RefreshToken string
	ExpiresAt    time.Time
}

// exchangeAuthCode exchanges an authorization code for tokens using PKCE verifier.
func exchangeAuthCode(ctx context.Context, client *http.Client, code, verifier string) (*tokenResult, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("client_id", codexOAuthClientID)
	form.Set("code", strings.TrimSpace(code))
	form.Set("code_verifier", strings.TrimSpace(verifier))
	form.Set("redirect_uri", codexOAuthRedirectURI)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, codexOAuthTokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var payload struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
		Error        string `json:"error"`
		ErrorDesc    string `json:"error_description"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("decode token response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg := payload.ErrorDesc
		if msg == "" {
			msg = payload.Error
		}
		if msg == "" {
			msg = fmt.Sprintf("status %d", resp.StatusCode)
		}
		return nil, fmt.Errorf("token exchange failed: %s", msg)
	}
	if payload.AccessToken == "" || payload.RefreshToken == "" {
		return nil, fmt.Errorf("token response missing access_token or refresh_token")
	}
	return &tokenResult{
		AccessToken:  strings.TrimSpace(payload.AccessToken),
		RefreshToken: strings.TrimSpace(payload.RefreshToken),
		ExpiresAt:    time.Now().Add(time.Duration(payload.ExpiresIn) * time.Second),
	}, nil
}

// refreshToken uses a refresh_token to obtain a new access_token.
func refreshToken(ctx context.Context, client *http.Client, refreshTokenStr string) (*tokenResult, error) {
	return refreshTokenWithURL(ctx, client, refreshTokenStr, codexOAuthTokenURL)
}

func refreshTokenWithURL(ctx context.Context, client *http.Client, refreshTokenStr string, tokenURL string) (*tokenResult, error) {
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", strings.TrimSpace(refreshTokenStr))
	form.Set("client_id", codexOAuthClientID)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var payload struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
		Error        string `json:"error"`
		ErrorDesc    string `json:"error_description"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("decode refresh response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg := payload.ErrorDesc
		if msg == "" {
			msg = payload.Error
		}
		return nil, fmt.Errorf("token refresh failed: %s (status %d)", msg, resp.StatusCode)
	}
	if payload.AccessToken == "" || payload.RefreshToken == "" {
		return nil, fmt.Errorf("refresh response missing tokens")
	}
	return &tokenResult{
		AccessToken:  strings.TrimSpace(payload.AccessToken),
		RefreshToken: strings.TrimSpace(payload.RefreshToken),
		ExpiresAt:    time.Now().Add(time.Duration(payload.ExpiresIn) * time.Second),
	}, nil
}

// --- JWT helpers (mirrors service/codex_oauth.go) ---

func extractAccountIDFromJWT(token string) (string, bool) {
	claims, ok := decodeJWTClaims(token)
	if !ok {
		return "", false
	}
	raw, ok := claims[codexJWTClaimPath]
	if !ok {
		return "", false
	}
	obj, ok := raw.(map[string]any)
	if !ok {
		return "", false
	}
	v, ok := obj["chatgpt_account_id"]
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	if !ok || strings.TrimSpace(s) == "" {
		return "", false
	}
	return strings.TrimSpace(s), true
}

func extractEmailFromJWT(token string) (string, bool) {
	claims, ok := decodeJWTClaims(token)
	if !ok {
		return "", false
	}
	v, ok := claims["email"]
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	if !ok || strings.TrimSpace(s) == "" {
		return "", false
	}
	return strings.TrimSpace(s), true
}

func decodeJWTClaims(token string) (map[string]any, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, false
	}
	payloadRaw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, false
	}
	var claims map[string]any
	if err := json.Unmarshal(payloadRaw, &claims); err != nil {
		return nil, false
	}
	return claims, true
}

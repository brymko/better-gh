// Package oauth implements GitHub's OAuth device flow so the proxy can obtain its own
// upstream GitHub token interactively (bgh-proxy login) instead of the operator pasting
// a personal access token. The resulting user-to-server token is the proxy's upstream
// credential; the proxy then hands out narrowly-scoped proxy tokens to clients.
package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const defaultBaseURL = "https://github.com"

// sleep is indirected so tests can run the poll loop without real delays.
var sleep = time.Sleep

type Config struct {
	ClientID string
	Scopes   string // space-separated, e.g. "repo read:org"
	BaseURL  string // default https://github.com; overridden in tests
	Client   *http.Client
	Out      io.Writer // device-flow instructions are written here (stderr)
	// OnCode, if set, is called once with the user code and verification URI as soon as the
	// device code is obtained — before polling begins. The proxy uses it to surface the code
	// to the operator while DeviceFlow keeps polling for authorization in the background.
	OnCode func(userCode, verificationURI string)
}

type deviceCode struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
	Error           string `json:"error"`
	ErrorDesc       string `json:"error_description"`
}

type tokenResult struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	Scope       string `json:"scope"`
	Interval    int    `json:"interval"`
	Error       string `json:"error"`
	ErrorDesc   string `json:"error_description"`
}

// DeviceFlow runs the full device flow and returns the access token. It prints the
// verification URI and user code to cfg.Out, then polls until the user authorizes,
// the code expires, or the context is cancelled.
func DeviceFlow(ctx context.Context, cfg Config) (string, error) {
	if cfg.ClientID == "" {
		return "", fmt.Errorf("no OAuth client id (set oauth_client_id, BGH_OAUTH_CLIENT_ID, or --client-id)")
	}
	base := cfg.BaseURL
	if base == "" {
		base = defaultBaseURL
	}
	client := cfg.Client
	if client == nil {
		client = http.DefaultClient
	}
	out := cfg.Out
	if out == nil {
		out = io.Discard
	}

	dc, err := requestDeviceCode(ctx, client, base, cfg.ClientID, cfg.Scopes)
	if err != nil {
		return "", err
	}

	fmt.Fprintf(out, "\n  First copy your one-time code: %s\n  Then open: %s\n\n  Waiting for authorization...\n",
		dc.UserCode, dc.VerificationURI)
	if cfg.OnCode != nil {
		cfg.OnCode(dc.UserCode, dc.VerificationURI)
	}

	interval := dc.Interval
	if interval <= 0 {
		interval = 5
	}
	deadline := time.Now().Add(time.Duration(maxInt(dc.ExpiresIn, 60)) * time.Second)

	for {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		if time.Now().After(deadline) {
			return "", fmt.Errorf("device code expired before authorization; run login again")
		}

		// Poll first, then wait the interval before the next poll — and never poll faster than
		// the server-advertised interval (raised on slow_down). Polling faster trips GitHub's
		// slow_down, which then withholds the token until the caller backs off.
		tok, err := pollToken(ctx, client, base, cfg.ClientID, dc.DeviceCode)
		if err == nil {
			switch tok.Error {
			case "":
				if tok.AccessToken == "" {
					return "", fmt.Errorf("authorization succeeded but no access token was returned")
				}
				return tok.AccessToken, nil
			case "authorization_pending":
				// keep waiting
			case "slow_down":
				if tok.Interval > 0 {
					interval = tok.Interval
				} else {
					interval += 5
				}
			case "expired_token":
				return "", fmt.Errorf("device code expired before authorization; run login again")
			case "access_denied":
				return "", fmt.Errorf("authorization was denied")
			default:
				return "", fmt.Errorf("oauth error: %s (%s)", tok.Error, tok.ErrorDesc)
			}
		}
		// A transient transport/decoding fault is not fatal: keep polling until the deadline.
		sleep(time.Duration(interval) * time.Second)
	}
}

func requestDeviceCode(ctx context.Context, client *http.Client, base, clientID, scopes string) (*deviceCode, error) {
	form := url.Values{"client_id": {clientID}}
	if strings.TrimSpace(scopes) != "" {
		form.Set("scope", scopes)
	}
	var dc deviceCode
	if err := postForm(ctx, client, base+"/login/device/code", form, &dc); err != nil {
		return nil, err
	}
	if dc.Error != "" {
		return nil, fmt.Errorf("requesting device code: %s (%s)", dc.Error, dc.ErrorDesc)
	}
	if dc.DeviceCode == "" || dc.UserCode == "" {
		return nil, fmt.Errorf("malformed device code response")
	}
	if dc.VerificationURI == "" {
		dc.VerificationURI = "https://github.com/login/device"
	}
	return &dc, nil
}

func pollToken(ctx context.Context, client *http.Client, base, clientID, deviceCode string) (*tokenResult, error) {
	form := url.Values{
		"client_id":   {clientID},
		"device_code": {deviceCode},
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
	}
	var tok tokenResult
	if err := postForm(ctx, client, base+"/login/oauth/access_token", form, &tok); err != nil {
		return nil, err
	}
	return &tok, nil
}

// postForm POSTs form-encoded values and decodes the JSON response into out. The
// Accept header is required or GitHub returns a form-encoded body instead of JSON.
func postForm(ctx context.Context, client *http.Client, endpoint string, form url.Values, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "bgh-proxy")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 500 {
		return fmt.Errorf("github returned %d for %s", resp.StatusCode, endpoint)
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("decoding response from %s: %w", endpoint, err)
	}
	return nil
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

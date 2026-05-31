package oauth

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// noSleep removes the poll delay for the duration of a test.
func noSleep(t *testing.T) {
	t.Helper()
	orig := sleep
	sleep = func(time.Duration) {}
	t.Cleanup(func() { sleep = orig })
}

// deviceServer mocks GitHub's two device-flow endpoints. tokenResponses are returned
// in order, one per poll, so a test can stage authorization_pending then success.
func deviceServer(t *testing.T, deviceBody string, tokenResponses []string) (*httptest.Server, *int32) {
	t.Helper()
	var polls int32
	mux := http.NewServeMux()
	mux.HandleFunc("/login/device/code", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept") != "application/json" {
			t.Errorf("device/code missing Accept: application/json")
		}
		_ = r.ParseForm()
		if r.Form.Get("client_id") == "" {
			t.Errorf("device/code missing client_id")
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, deviceBody)
	})
	mux.HandleFunc("/login/oauth/access_token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:device_code" {
			t.Errorf("token poll wrong grant_type: %q", r.Form.Get("grant_type"))
		}
		n := atomic.AddInt32(&polls, 1)
		idx := int(n) - 1
		if idx >= len(tokenResponses) {
			idx = len(tokenResponses) - 1
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, tokenResponses[idx])
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, &polls
}

func TestDeviceFlowSuccessAfterPending(t *testing.T) {
	noSleep(t)

	srv, polls := deviceServer(t,
		`{"device_code":"DC","user_code":"WXYZ-1234","verification_uri":"https://github.com/login/device","expires_in":900,"interval":0}`,
		[]string{
			`{"error":"authorization_pending"}`,
			`{"error":"slow_down","interval":0}`,
			`{"access_token":"gho_realtoken","token_type":"bearer","scope":"repo,read:org"}`,
		},
	)

	var out strings.Builder
	tok, err := DeviceFlow(context.Background(), Config{
		ClientID: "cid", Scopes: "repo read:org", BaseURL: srv.URL, Client: srv.Client(), Out: &out,
	})
	if err != nil {
		t.Fatal(err)
	}
	if tok != "gho_realtoken" {
		t.Fatalf("got token %q", tok)
	}
	if atomic.LoadInt32(polls) != 3 {
		t.Fatalf("expected 3 polls, got %d", *polls)
	}
	if !strings.Contains(out.String(), "WXYZ-1234") {
		t.Fatalf("instructions should show the user code, got: %s", out.String())
	}
}

func TestDeviceFlowAccessDenied(t *testing.T) {
	noSleep(t)
	srv, _ := deviceServer(t,
		`{"device_code":"DC","user_code":"X","verification_uri":"u","expires_in":900,"interval":0}`,
		[]string{`{"error":"access_denied","error_description":"user denied"}`},
	)
	_, err := DeviceFlow(context.Background(), Config{ClientID: "cid", BaseURL: srv.URL, Client: srv.Client()})
	if err == nil || !strings.Contains(err.Error(), "denied") {
		t.Fatalf("expected access denied error, got %v", err)
	}
}

func TestDeviceFlowExpired(t *testing.T) {
	noSleep(t)
	srv, _ := deviceServer(t,
		`{"device_code":"DC","user_code":"X","verification_uri":"u","expires_in":900,"interval":0}`,
		[]string{`{"error":"expired_token"}`},
	)
	_, err := DeviceFlow(context.Background(), Config{ClientID: "cid", BaseURL: srv.URL, Client: srv.Client()})
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expected expired error, got %v", err)
	}
}

func TestDeviceFlowDeviceCodeError(t *testing.T) {
	noSleep(t)
	srv, _ := deviceServer(t, `{"error":"unauthorized_client","error_description":"device flow not enabled"}`, []string{`{}`})
	_, err := DeviceFlow(context.Background(), Config{ClientID: "cid", BaseURL: srv.URL, Client: srv.Client()})
	if err == nil || !strings.Contains(err.Error(), "device flow not enabled") {
		t.Fatalf("expected device code error, got %v", err)
	}
}

func TestDeviceFlowNoClientID(t *testing.T) {
	_, err := DeviceFlow(context.Background(), Config{})
	if err == nil || !strings.Contains(err.Error(), "client id") {
		t.Fatalf("expected client id error, got %v", err)
	}
}

func TestDeviceFlowContextCancel(t *testing.T) {
	noSleep(t)
	srv, _ := deviceServer(t,
		`{"device_code":"DC","user_code":"X","verification_uri":"u","expires_in":900,"interval":0}`,
		[]string{`{"error":"authorization_pending"}`},
	)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := DeviceFlow(ctx, Config{ClientID: "cid", BaseURL: srv.URL, Client: srv.Client()})
	if err == nil {
		t.Fatalf("expected context cancellation error")
	}
}

// sanity: device/code form encodes scopes
func TestRequestDeviceCodeSendsScope(t *testing.T) {
	var gotScope string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotScope = r.Form.Get("scope")
		io.WriteString(w, `{"device_code":"d","user_code":"u","verification_uri":"v","interval":0,"expires_in":900}`)
	}))
	defer srv.Close()
	_, err := requestDeviceCode(context.Background(), srv.Client(), srv.URL, "cid", "repo read:org")
	if err != nil {
		t.Fatal(err)
	}
	if gotScope != "repo read:org" {
		t.Fatalf("scope = %q", gotScope)
	}
}

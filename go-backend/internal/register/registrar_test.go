package register

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
)

func TestReplaceRegisterSessionUsesIndependentDeviceCookie(t *testing.T) {
	originalDeviceID := "original-device-id"
	originalClient, err := registerHTTPClient("", 0, originalDeviceID)
	if err != nil {
		t.Fatalf("registerHTTPClient original error: %v", err)
	}
	worker := &registerWorker{
		config:   map[string]any{"proxy": ""},
		client:   originalClient,
		deviceID: originalDeviceID,
	}

	loginDeviceID := "login-device-id"
	loginClient, err := worker.replaceRegisterSession(loginDeviceID)
	if err != nil {
		t.Fatalf("replaceRegisterSession error: %v", err)
	}
	defer loginClient.CloseIdleConnections()

	if worker.client == originalClient {
		t.Fatalf("worker client was not replaced")
	}
	if worker.client != loginClient {
		t.Fatalf("worker client does not point to login client")
	}
	if worker.deviceID != loginDeviceID {
		t.Fatalf("worker deviceID = %q, want %q", worker.deviceID, loginDeviceID)
	}

	authURL, err := url.Parse(registerAuthBase)
	if err != nil {
		t.Fatalf("parse auth url: %v", err)
	}
	got := ""
	for _, cookie := range worker.client.Jar.Cookies(authURL) {
		if cookie.Name == "oai-did" {
			got = cookie.Value
			break
		}
	}
	if got != loginDeviceID {
		t.Fatalf("login oai-did cookie = %q, want %q", got, loginDeviceID)
	}
}

func TestRegisterHTTPClientAcceptsSocksProxyConfig(t *testing.T) {
	client, err := registerHTTPClient("socks5://127.0.0.1:7890", 0, "device-id")
	if err != nil {
		t.Fatalf("registerHTTPClient socks proxy error: %v", err)
	}
	defer client.CloseIdleConnections()

	if client.Jar == nil {
		t.Fatalf("registerHTTPClient did not attach cookie jar")
	}
}

func TestRegisterMailConfigForWorkerUsesTopLevelProxy(t *testing.T) {
	config := map[string]any{
		"proxy": "http://127.0.0.1:7890",
		"mail": map[string]any{
			"request_timeout": 10,
			"proxy":           "http://127.0.0.1:8080",
		},
	}

	mail := registerMailConfigForWorker(config)
	if got := clean(mail["proxy"]); got != "http://127.0.0.1:7890" {
		t.Fatalf("worker mail proxy = %q", got)
	}
	if clean(asMap(config["mail"])["proxy"]) != "http://127.0.0.1:8080" {
		t.Fatalf("registerMailConfigForWorker mutated original mail config")
	}
}

func TestRegisterMailConfigForWorkerKeepsMailProxyWithoutTopLevelProxy(t *testing.T) {
	config := map[string]any{
		"proxy": "",
		"mail":  map[string]any{"proxy": "http://127.0.0.1:8080"},
	}

	mail := registerMailConfigForWorker(config)
	if got := clean(mail["proxy"]); got != "http://127.0.0.1:8080" {
		t.Fatalf("worker mail proxy = %q", got)
	}
}

func TestRequestDetailedWithFinalURLReturnsRedirectCallbackCode(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/start":
			http.Redirect(w, r, "/callback?code=oauth-code&state=state-1", http.StatusFound)
		case "/callback":
			http.Redirect(w, r, "/done", http.StatusFound)
		case "/done":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"ok":true}`))
		default:
			t.Fatalf("unexpected path: %s", r.URL.String())
		}
	}))
	defer server.Close()

	worker := &registerWorker{client: server.Client()}
	status, payload, _, finalURL, err := worker.requestDetailedWithFinalURL(context.Background(), http.MethodGet, server.URL+"/start", nil, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if status != http.StatusOK {
		t.Fatalf("status = %d payload=%#v", status, payload)
	}
	if code := oauthCode(finalURL); code != "oauth-code" {
		t.Fatalf("finalURL = %q, code = %q", finalURL, code)
	}
}

func TestAuthorizeErrorDetailSummarizesCloudflareChallenge(t *testing.T) {
	payload := map[string]any{
		"body": `<!DOCTYPE html><html><head><title>Just a moment...</title></head><script src="https://challenges.cloudflare.com/turnstile/v0/api.js"></script></html>`,
	}

	if got := authorizeErrorDetail(payload); got != ": cloudflare_challenge" {
		t.Fatalf("authorizeErrorDetail = %q", got)
	}
}

func TestResponseDetailSummarizesCloudflareChallenge(t *testing.T) {
	payload := map[string]any{
		"body": `<!DOCTYPE html><html><head><title>Just a moment...</title></head><body>Cloudflare</body></html>`,
	}

	got := responseDetail(payload)
	want := `, detail={"error":"cloudflare_challenge","message":"upstream returned Cloudflare challenge page"}`
	if got != want {
		t.Fatalf("responseDetail = %q, want %q", got, want)
	}
}

func TestCloudflareChallengePayloadRecognizesAdditionalMarkers(t *testing.T) {
	cases := []string{
		`<title>Attention Required! | Cloudflare</title>`,
		`<script>window.__cf_chl_opt={}</script>`,
		`<div id="cf-chl-widget"></div>`,
	}
	for _, body := range cases {
		if !isCloudflareChallengePayload(map[string]any{"body": body}) {
			t.Fatalf("expected challenge marker in %q", body)
		}
	}
}

func TestSentinelHelperPathUsesConfiguredFile(t *testing.T) {
	helper := filepath.Join(t.TempDir(), "sentinel_token_helper.mjs")
	if err := os.WriteFile(helper, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CHATGPT2API_SENTINEL_HELPER", helper)

	got, err := sentinelHelperPath()
	if err != nil {
		t.Fatal(err)
	}
	if got != helper {
		t.Fatalf("sentinelHelperPath = %q, want %q", got, helper)
	}
}

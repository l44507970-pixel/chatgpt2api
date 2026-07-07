package register

import (
	"context"
	"encoding/json"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestYydsSelectDomainExploreAndReputation(t *testing.T) {
	store := newDomainReputationStore(t.TempDir() + "/mail_domain_reputation.json")
	store.RecordSuccess("yyds_mail", "winner.example")
	store.RecordFailure("yyds_mail", "disabled.example", "unsupported_email")

	provider := &yydsMailProvider{
		baseMailProvider: baseMailProvider{entry: map[string]any{
			"domain":              []string{"disabled.example", "winner.example"},
			"domain_learning":     true,
			"domain_explore_rate": 0,
		}},
		reputation: store,
	}

	resetMailDomainSeq()
	if got := provider.selectDomain(); got != "winner.example" {
		t.Fatalf("selectDomain() = %q", got)
	}

	provider.entry["domain_explore_rate"] = 1
	rand.Seed(1)
	if got := provider.selectDomain(); got != "" {
		t.Fatalf("explore selectDomain() = %q, want empty domain", got)
	}
}

func TestYydsSelectDomainRotatesConfiguredDomainsWithReputation(t *testing.T) {
	store := newDomainReputationStore(t.TempDir() + "/mail_domain_reputation.json")
	store.RecordSuccess("yyds_mail", "winner.example")

	provider := &yydsMailProvider{
		baseMailProvider: baseMailProvider{entry: map[string]any{
			"domain":              []string{"fresh.example", "winner.example", "other.example"},
			"domain_learning":     true,
			"domain_explore_rate": 0,
		}},
		reputation: store,
	}

	resetMailDomainSeq()
	got := []string{provider.selectDomain(), provider.selectDomain(), provider.selectDomain()}
	want := []string{"winner.example", "fresh.example", "other.example"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("rotated domains = %#v, want %#v", got, want)
		}
	}
}

func TestYydsSelectDomainReturnsEmptyWhenAllCandidatesDisabled(t *testing.T) {
	store := newDomainReputationStore(t.TempDir() + "/mail_domain_reputation.json")
	store.RecordFailure("yyds_mail", "disabled.example", "account_creation_failed")

	provider := &yydsMailProvider{
		baseMailProvider: baseMailProvider{entry: map[string]any{
			"domain":              []string{"disabled.example"},
			"domain_learning":     true,
			"domain_explore_rate": 0,
		}},
		reputation: store,
	}

	if got := provider.selectDomain(); got != "" {
		t.Fatalf("selectDomain() = %q, want empty domain when all candidates are disabled", got)
	}
}

func TestYydsCreateMailboxTokenFieldsAndWildcard(t *testing.T) {
	for _, tokenField := range []string{"token", "temp_token", "tempToken", "access_token"} {
		t.Run(tokenField, func(t *testing.T) {
			var gotPath string
			var gotAPIKey string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotPath = r.URL.Path
				gotAPIKey = r.Header.Get("X-API-Key")
				payload := map[string]any{}
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					t.Fatalf("decode payload: %v", err)
				}
				if payload["localPart"] != "alice" || payload["domain"] != "mail.example" {
					t.Fatalf("payload = %#v", payload)
				}
				_ = json.NewEncoder(w).Encode(map[string]any{
					"data": map[string]any{
						"address":     "alice@mail.example",
						tokenField:    "mail-token",
						"id":          "account-id",
						"ignored_key": "ignored",
					},
				})
			}))
			defer server.Close()

			provider := &yydsMailProvider{baseMailProvider: baseMailProvider{
				client: server.Client(),
				conf:   mailSettings{RequestTimeout: time.Second, UserAgent: "test-agent"},
				entry: map[string]any{
					"api_base":            server.URL,
					"api_key":             "secret-key",
					"wildcard":            true,
					"domain":              []string{"mail.example"},
					"domain_learning":     false,
					"domain_explore_rate": 0,
					"provider_ref":        "yyds_mail#1",
				},
			}}

			mailbox, err := provider.CreateMailbox(context.Background(), "alice")
			if err != nil {
				t.Fatal(err)
			}
			if gotPath != "/accounts/wildcard" || gotAPIKey != "secret-key" {
				t.Fatalf("path=%q apiKey=%q", gotPath, gotAPIKey)
			}
			if mailbox["address"] != "alice@mail.example" || mailbox["token"] != "mail-token" || mailbox["domain"] != "mail.example" {
				t.Fatalf("mailbox = %#v", mailbox)
			}
		})
	}
}

func TestGptMailCreateMailboxStoresDomain(t *testing.T) {
	var gotPath string
	var gotAPIKey string
	var gotPayload map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAPIKey = r.Header.Get("X-API-Key")
		if err := json.NewDecoder(r.Body).Decode(&gotPayload); err != nil {
			t.Fatalf("decode payload: %v", err)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": true,
			"data":    map[string]any{"email": "alice@mail.example"},
		})
	}))
	defer server.Close()

	provider := &gptMailProvider{baseMailProvider: baseMailProvider{
		client: rewriteHostClient(server.URL),
		conf:   mailSettings{RequestTimeout: time.Second, UserAgent: "test-agent"},
		entry: map[string]any{
			"api_key":        "secret-key",
			"default_domain": "mail.example",
			"provider_ref":   "gptmail#1",
		},
	}}
	mailbox, err := provider.CreateMailbox(context.Background(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	if gotPath != "/api/generate-email" || gotAPIKey != "secret-key" || gotPayload["prefix"] != "alice" || gotPayload["domain"] != "mail.example" {
		t.Fatalf("path=%q apiKey=%q payload=%#v", gotPath, gotAPIKey, gotPayload)
	}
	if mailbox["address"] != "alice@mail.example" || mailbox["domain"] != "mail.example" {
		t.Fatalf("mailbox = %#v", mailbox)
	}
}

func TestGptMailEmailsSupportsDocumentedShapes(t *testing.T) {
	cases := []any{
		map[string]any{"success": true, "data": map[string]any{"emails": []any{map[string]any{"id": "nested"}}}},
		map[string]any{"success": true, "data": []any{map[string]any{"id": "list"}}},
		map[string]any{"emails": []any{map[string]any{"id": "plain"}}},
	}
	for _, item := range cases {
		items := gptMailEmails(item)
		if len(items) != 1 || clean(items[0]["id"]) == "" {
			t.Fatalf("emails from %#v = %#v", item, items)
		}
	}
}

func TestYydsMailItemsSupportsKnownShapes(t *testing.T) {
	shapes := []map[string]any{
		{"items": []any{map[string]any{"id": "items-id"}}},
		{"messages": []any{map[string]any{"id": "messages-id"}}},
		{"data": []any{map[string]any{"id": "data-id"}}},
		{"list": []any{map[string]any{"id": "list-id"}}},
	}
	for _, shape := range shapes {
		items := yydsMailItems(shape)
		if len(items) != 1 || clean(items[0]["id"]) == "" {
			t.Fatalf("items from %#v = %#v", shape, items)
		}
	}
}

func TestExtractUnseenMailCodeDeduplicatesByMessageRef(t *testing.T) {
	mailbox := map[string]any{}
	message := map[string]any{
		"provider":     "yyds_mail",
		"mailbox":      "alice@example.com",
		"message_id":   "message-1",
		"text_content": "Your verification code is 123456",
	}

	if got := extractUnseenMailCode(mailbox, message); got != "123456" {
		t.Fatalf("first code = %q", got)
	}
	if got := extractUnseenMailCode(mailbox, message); got != "" {
		t.Fatalf("duplicate code = %q, want empty", got)
	}

	next := copyMap(message)
	next["message_id"] = "message-2"
	if got := extractUnseenMailCode(mailbox, next); got != "123456" {
		t.Fatalf("new message code = %q", got)
	}
}

func TestYydsRequestRetriesTransientStatus(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 3 {
			http.Error(w, "rate limited", http.StatusTooManyRequests)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"ok": true}})
	}))
	defer server.Close()

	provider := &yydsMailProvider{baseMailProvider: baseMailProvider{
		client: server.Client(),
		conf:   mailSettings{RequestTimeout: time.Second, UserAgent: "test-agent"},
		entry:  map[string]any{"api_base": server.URL, "api_key": "secret-key"},
	}}

	got, err := provider.request(context.Background(), http.MethodGet, "/messages", "mail-token", nil, nil, http.StatusOK)
	if err != nil {
		t.Fatal(err)
	}
	if attempts != 3 {
		t.Fatalf("attempts = %d", attempts)
	}
	if asMap(got)["ok"] != true {
		t.Fatalf("response = %#v", got)
	}
}

func resetMailDomainSeq() {
	mailDomainMu.Lock()
	defer mailDomainMu.Unlock()
	mailDomainSeq = 0
}

func rewriteHostClient(baseURL string) *http.Client {
	base, _ := url.Parse(baseURL)
	return &http.Client{Transport: rewriteHostTransport{base: base, inner: http.DefaultTransport}}
}

type rewriteHostTransport struct {
	base  *url.URL
	inner http.RoundTripper
}

func (t rewriteHostTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.URL.Scheme = t.base.Scheme
	req.URL.Host = t.base.Host
	return t.inner.RoundTrip(req)
}

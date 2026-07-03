package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"chatgpt2api-go-backend/internal/account"
	"chatgpt2api-go-backend/internal/auth"
	"chatgpt2api-go-backend/internal/config"
	"chatgpt2api-go-backend/internal/protocol"
	"chatgpt2api-go-backend/internal/proxy"
	"chatgpt2api-go-backend/internal/storage"
	"chatgpt2api-go-backend/internal/upstream"
)

func TestAccountsRequireAdminAndHideToken(t *testing.T) {
	app, accounts := newTestApp(t)
	accounts.AddAccounts([]string{"token-alpha-1234567890"})

	unauthorized := httptest.NewRecorder()
	app.ServeHTTP(unauthorized, httptest.NewRequest(http.MethodGet, "/api/accounts", nil))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized status = %d", unauthorized.Code)
	}

	authorized := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/accounts", nil)
	req.Header.Set("Authorization", "Bearer admin-key")
	app.ServeHTTP(authorized, req)
	if authorized.Code != http.StatusOK {
		t.Fatalf("authorized status = %d body=%s", authorized.Code, authorized.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(authorized.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	items := body["items"].([]any)
	first := items[0].(map[string]any)
	if _, ok := first["access_token"]; ok {
		t.Fatalf("account leaked access_token: %#v", first)
	}
}

func TestUpdateAndDeleteByAccountID(t *testing.T) {
	app, accounts := newTestApp(t)
	accounts.AddAccounts([]string{"token-alpha-1234567890"})
	id := accounts.ListAccounts()[0]["id"].(string)

	updateBody := []byte(`{"account_id":"` + id + `","status":"禁用"}`)
	update := httptest.NewRecorder()
	updateReq := httptest.NewRequest(http.MethodPost, "/api/accounts/update", bytes.NewReader(updateBody))
	updateReq.Header.Set("Authorization", "Bearer admin-key")
	app.ServeHTTP(update, updateReq)
	if update.Code != http.StatusOK {
		t.Fatalf("update status = %d body=%s", update.Code, update.Body.String())
	}

	deleteBody := []byte(`{"account_ids":["` + id + `"]}`)
	deleteResp := httptest.NewRecorder()
	deleteReq := httptest.NewRequest(http.MethodDelete, "/api/accounts", bytes.NewReader(deleteBody))
	deleteReq.Header.Set("Authorization", "Bearer admin-key")
	app.ServeHTTP(deleteResp, deleteReq)
	if deleteResp.Code != http.StatusOK {
		t.Fatalf("delete status = %d body=%s", deleteResp.Code, deleteResp.Body.String())
	}
	if len(accounts.ListAccounts()) != 0 {
		t.Fatalf("accounts not deleted: %#v", accounts.ListAccounts())
	}
}

func TestCreateAccountReportsRefreshNotImplemented(t *testing.T) {
	app, _ := newTestApp(t)
	resp := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/accounts", bytes.NewReader([]byte(`{"tokens":["token-alpha-1234567890"]}`)))
	req.Header.Set("Authorization", "Bearer admin-key")
	app.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", resp.Code, resp.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["refreshed"].(float64) != 0 {
		t.Fatalf("refreshed = %#v", body["refreshed"])
	}
	if len(body["errors"].([]any)) != 1 {
		t.Fatalf("errors = %#v", body["errors"])
	}
}

func TestAccountRefreshWithMissingAccountIDsDoesNotRefreshAll(t *testing.T) {
	app, accounts := newTestApp(t)
	refresher := &fakeAccountRefresher{
		info: map[string]any{"quota": 99, "type": "Team", "status": "正常"},
	}
	accounts.SetRemoteRefresher(refresher)

	resp := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/accounts/refresh", bytes.NewReader([]byte(`{"account_ids":["missing-account-id"]}`)))
	req.Header.Set("Authorization", "Bearer admin-key")
	app.ServeHTTP(resp, req)
	if resp.Code != http.StatusNotFound {
		t.Fatalf("refresh status = %d body=%s", resp.Code, resp.Body.String())
	}
	if refresher.calls != 0 {
		t.Fatalf("missing account id should not call refresher, calls = %d", refresher.calls)
	}

	items := accounts.ListAccounts()
	if len(items) != 1 {
		t.Fatalf("items = %#v", items)
	}
	if items[0]["quota"] != 5 || items[0]["type"] != "Plus" {
		t.Fatalf("missing account id should not refresh existing accounts, item = %#v", items[0])
	}
}

func TestAccountRefreshWritesSystemLog(t *testing.T) {
	app, _ := newTestApp(t)
	resp := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/accounts/refresh", bytes.NewReader([]byte(`{}`)))
	req.Header.Set("Authorization", "Bearer admin-key")
	app.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("refresh status = %d body=%s", resp.Code, resp.Body.String())
	}

	logs := httptest.NewRecorder()
	logsReq := httptest.NewRequest(http.MethodGet, "/api/logs?type=account", nil)
	logsReq.Header.Set("Authorization", "Bearer admin-key")
	app.ServeHTTP(logs, logsReq)
	if logs.Code != http.StatusOK {
		t.Fatalf("logs status = %d body=%s", logs.Code, logs.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(logs.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	items := body["items"].([]any)
	if len(items) == 0 || items[0].(map[string]any)["summary"] != "刷新账号" {
		t.Fatalf("logs = %#v", body)
	}
}

func TestAccountRefreshAsyncJobPollsUntilComplete(t *testing.T) {
	app, accounts := newTestApp(t)
	refresher := &fakeAccountRefresher{
		info: map[string]any{"quota": 42, "type": "Team", "status": "正常", "email": "async@example.test"},
	}
	accounts.SetRemoteRefresher(refresher)
	id := accounts.ListAccounts()[0]["id"].(string)

	submit := httptest.NewRecorder()
	submitReq := httptest.NewRequest(http.MethodPost, "/api/accounts/refresh", bytes.NewReader([]byte(`{"account_ids":["`+id+`"],"async":true}`)))
	submitReq.Header.Set("Authorization", "Bearer admin-key")
	app.ServeHTTP(submit, submitReq)
	if submit.Code != http.StatusAccepted {
		t.Fatalf("submit status = %d body=%s", submit.Code, submit.Body.String())
	}
	var submitBody map[string]any
	if err := json.Unmarshal(submit.Body.Bytes(), &submitBody); err != nil {
		t.Fatal(err)
	}
	job := submitBody["job"].(map[string]any)
	jobID := job["id"].(string)
	if jobID == "" || job["requested"] != float64(1) {
		t.Fatalf("job = %#v", job)
	}

	var pollBody map[string]any
	for i := 0; i < 20; i++ {
		poll := httptest.NewRecorder()
		pollReq := httptest.NewRequest(http.MethodGet, "/api/accounts/refresh/jobs/"+jobID, nil)
		pollReq.Header.Set("Authorization", "Bearer admin-key")
		app.ServeHTTP(poll, pollReq)
		if poll.Code != http.StatusOK {
			t.Fatalf("poll status = %d body=%s", poll.Code, poll.Body.String())
		}
		if err := json.Unmarshal(poll.Body.Bytes(), &pollBody); err != nil {
			t.Fatal(err)
		}
		current := pollBody["job"].(map[string]any)
		if current["status"] == account.RefreshJobSuccess {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	current := pollBody["job"].(map[string]any)
	if current["status"] != account.RefreshJobSuccess {
		t.Fatalf("job did not finish: %#v", current)
	}
	if current["completed"] != float64(1) || current["refreshed"] != float64(1) || current["failed"] != float64(0) {
		t.Fatalf("job counters = %#v", current)
	}
	items := pollBody["items"].([]any)
	item := items[0].(map[string]any)
	if item["quota"] != float64(42) || item["type"] != "Team" || item["email"] != "async@example.test" {
		t.Fatalf("items = %#v", items)
	}
}

func TestAccountReloginJobPollsUntilComplete(t *testing.T) {
	app, accounts := newTestApp(t)
	const oldToken = "token-alpha-1234567890"
	const newToken = "token-relogin-1234567890"
	accounts.UpdateAccount(oldToken, map[string]any{
		"email":    "user@example.test",
		"password": "secret-password",
		"status":   "异常",
		"quota":    0,
	})
	accounts.SetPasswordReloginProvider(&fakePasswordRelogin{
		tokens: map[string]any{"access_token": newToken, "refresh_token": "refresh-new"},
	})
	id := account.AccountID(oldToken)

	submit := httptest.NewRecorder()
	submitReq := httptest.NewRequest(http.MethodPost, "/api/accounts/re-login", bytes.NewReader([]byte(`{"account_ids":["`+id+`"]}`)))
	submitReq.Header.Set("Authorization", "Bearer admin-key")
	app.ServeHTTP(submit, submitReq)
	if submit.Code != http.StatusOK {
		t.Fatalf("submit status = %d body=%s", submit.Code, submit.Body.String())
	}
	var submitted map[string]any
	if err := json.Unmarshal(submit.Body.Bytes(), &submitted); err != nil {
		t.Fatal(err)
	}
	jobID := submitted["progress_id"].(string)
	if jobID == "" {
		t.Fatalf("submitted = %#v", submitted)
	}

	var polled map[string]any
	for i := 0; i < 20; i++ {
		poll := httptest.NewRecorder()
		pollReq := httptest.NewRequest(http.MethodGet, "/api/accounts/re-login/jobs/"+jobID, nil)
		pollReq.Header.Set("Authorization", "Bearer admin-key")
		app.ServeHTTP(poll, pollReq)
		if poll.Code != http.StatusOK {
			t.Fatalf("poll status = %d body=%s", poll.Code, poll.Body.String())
		}
		if err := json.Unmarshal(poll.Body.Bytes(), &polled); err != nil {
			t.Fatal(err)
		}
		job := polled["job"].(map[string]any)
		if job["status"] == account.RefreshJobSuccess {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	job := polled["job"].(map[string]any)
	if job["status"] != account.RefreshJobSuccess || job["refreshed"] != float64(1) {
		t.Fatalf("job = %#v", job)
	}
	items := accounts.ListAccounts()
	if items[0]["id"] != account.AccountID(newToken) || items[0]["status"] != "正常" || items[0]["has_password"] != true {
		t.Fatalf("items = %#v", items)
	}
}

func TestAccountRefreshLargeRequestAutoStartsAsyncJob(t *testing.T) {
	app, accounts := newTestApp(t)
	tokens := make([]string, 0, accountRefreshAutoAsyncThreshold+1)
	for i := 0; i < accountRefreshAutoAsyncThreshold; i++ {
		tokens = append(tokens, "token-large-"+strings.Repeat("x", 20)+fmt.Sprint(i))
	}
	accounts.AddAccounts(tokens)

	resp := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/accounts/refresh", bytes.NewReader([]byte(`{}`)))
	req.Header.Set("Authorization", "Bearer admin-key")
	app.ServeHTTP(resp, req)
	if resp.Code != http.StatusAccepted {
		t.Fatalf("refresh status = %d body=%s", resp.Code, resp.Body.String())
	}

	var body map[string]any
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["async"] != true {
		t.Fatalf("async flag = %#v body=%#v", body["async"], body)
	}
	job := body["job"].(map[string]any)
	if job["id"] == "" || job["requested"] != float64(accountRefreshAutoAsyncThreshold+1) {
		t.Fatalf("job = %#v", job)
	}
	if body["refreshed"] != float64(0) || len(body["errors"].([]any)) != 0 {
		t.Fatalf("compat fields = refreshed:%#v errors:%#v", body["refreshed"], body["errors"])
	}

	logs := httptest.NewRecorder()
	logsReq := httptest.NewRequest(http.MethodGet, "/api/logs?type=account", nil)
	logsReq.Header.Set("Authorization", "Bearer admin-key")
	app.ServeHTTP(logs, logsReq)
	if logs.Code != http.StatusOK {
		t.Fatalf("logs status = %d body=%s", logs.Code, logs.Body.String())
	}
	var logBody map[string]any
	if err := json.Unmarshal(logs.Body.Bytes(), &logBody); err != nil {
		t.Fatal(err)
	}
	items := logBody["items"].([]any)
	if len(items) == 0 || items[0].(map[string]any)["summary"] != "提交账号刷新任务" {
		t.Fatalf("logs = %#v", logBody)
	}
}

func TestFetchRemoteInfoDoesNotBootstrapHomepage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			t.Fatalf("should not request homepage during account refresh")
		case "/backend-api/me":
			_ = json.NewEncoder(w).Encode(map[string]any{"email": "test@example.com", "id": "user-1"})
		case "/backend-api/conversation/init":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"default_model_slug": "gpt-5",
				"limits_progress": []map[string]any{{
					"feature_name": "image_gen",
					"remaining":    2,
					"reset_after":  "2026-06-01T00:00:00Z",
				}},
				"workspace": map[string]any{"plan_type": "plus"},
			})
		default:
			t.Fatalf("unexpected path: %s", r.URL.String())
		}
	}))
	defer server.Close()

	service := upstream.NewService(nil, proxy.NewService(""))
	service.BaseURL = server.URL
	client := service.NewClient("test-token")
	client.HTTPClient = server.Client()
	info, err := client.FetchRemoteInfo(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if info["quota"] != 2 || info["status"] != "正常" {
		t.Fatalf("info = %#v", info)
	}
}

func TestImagesListServesStaticFilesAndUsesShanghaiTime(t *testing.T) {
	app, _ := newTestApp(t)
	rel := filepath.ToSlash(filepath.Join("2026", "05", "31", "sample.png"))
	imagePath := filepath.Join(app.local.DataDir, "images", filepath.FromSlash(rel))
	thumbnailPath := filepath.Join(app.local.DataDir, "image_thumbnails", filepath.FromSlash(rel)+".png")
	if err := os.MkdirAll(filepath.Dir(imagePath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(thumbnailPath), 0o755); err != nil {
		t.Fatal(err)
	}
	imageBytes := []byte("image-bytes")
	thumbBytes := []byte("thumb-bytes")
	if err := os.WriteFile(imagePath, imageBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(thumbnailPath, thumbBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	modTime := time.Date(2026, 5, 31, 16, 0, 0, 0, time.UTC)
	if err := os.Chtimes(imagePath, modTime, modTime); err != nil {
		t.Fatal(err)
	}

	listResp := httptest.NewRecorder()
	listReq := httptest.NewRequest(http.MethodGet, "/api/images", nil)
	listReq.Header.Set("Authorization", "Bearer admin-key")
	app.ServeHTTP(listResp, listReq)
	if listResp.Code != http.StatusOK {
		t.Fatalf("images status = %d body=%s", listResp.Code, listResp.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(listResp.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	items := body["items"].([]any)
	if len(items) != 1 {
		t.Fatalf("items = %#v", body["items"])
	}
	item := items[0].(map[string]any)
	if got := item["created_at"]; got != "2026-06-01 00:00:00" {
		t.Fatalf("created_at = %#v", got)
	}
	if got := item["date"]; got != "2026-06-01" {
		t.Fatalf("date = %#v", got)
	}
	if got := item["url"].(string); !strings.Contains(got, "/images/"+rel) {
		t.Fatalf("url = %s", got)
	}
	if got := item["thumbnail_url"].(string); !strings.Contains(got, "/image-thumbnails/"+rel) {
		t.Fatalf("thumbnail_url = %s", got)
	}

	imageResp := httptest.NewRecorder()
	imageReq := httptest.NewRequest(http.MethodGet, "/images/"+rel, nil)
	app.ServeHTTP(imageResp, imageReq)
	if imageResp.Code != http.StatusOK {
		t.Fatalf("image route status = %d body=%s", imageResp.Code, imageResp.Body.String())
	}
	if imageResp.Body.String() != string(imageBytes) {
		t.Fatalf("image route body = %q", imageResp.Body.String())
	}

	thumbResp := httptest.NewRecorder()
	thumbReq := httptest.NewRequest(http.MethodGet, "/image-thumbnails/"+rel, nil)
	app.ServeHTTP(thumbResp, thumbReq)
	if thumbResp.Code != http.StatusOK {
		t.Fatalf("thumbnail route status = %d body=%s", thumbResp.Code, thumbResp.Body.String())
	}
	if thumbResp.Body.String() != string(thumbBytes) {
		t.Fatalf("thumbnail route body = %q", thumbResp.Body.String())
	}
}

func TestRegisterProviderEnableStatePersists(t *testing.T) {
	app, _ := newTestApp(t)
	body := []byte(`{
		"mail": {
			"request_timeout": 30,
			"wait_timeout": 30,
			"wait_interval": 2,
			"providers": [
				{"enable": false, "type": "gptmail", "api_key": "sk-gptmail", "default_domain": ""},
				{"enable": true, "type": "yyds_mail", "api_base": "https://maliapi.215.im/v1", "api_key": "sk-yyds", "domain": [], "subdomain": "", "wildcard": false}
			]
		},
		"proxy": "",
		"total": 1,
		"threads": 1,
		"mode": "total",
		"target_quota": 1,
		"target_available": 1,
		"check_interval": 5
	}`)
	save := httptest.NewRecorder()
	saveReq := httptest.NewRequest(http.MethodPost, "/api/register", bytes.NewReader(body))
	saveReq.Header.Set("Authorization", "Bearer admin-key")
	app.ServeHTTP(save, saveReq)
	if save.Code != http.StatusOK {
		t.Fatalf("save register status = %d body=%s", save.Code, save.Body.String())
	}

	getResp := httptest.NewRecorder()
	getReq := httptest.NewRequest(http.MethodGet, "/api/register", nil)
	getReq.Header.Set("Authorization", "Bearer admin-key")
	app.ServeHTTP(getResp, getReq)
	if getResp.Code != http.StatusOK {
		t.Fatalf("get register status = %d body=%s", getResp.Code, getResp.Body.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(getResp.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	register := payload["register"].(map[string]any)
	mail := register["mail"].(map[string]any)
	providers := mail["providers"].([]any)
	if len(providers) != 2 {
		t.Fatalf("providers = %#v", providers)
	}
	first := providers[0].(map[string]any)
	second := providers[1].(map[string]any)
	if first["type"] != "gptmail" || first["enable"] != false {
		t.Fatalf("first provider = %#v", first)
	}
	if second["type"] != "yyds_mail" || second["enable"] != true {
		t.Fatalf("second provider = %#v", second)
	}
}

func TestRegisterStatsReflectAccountPoolMetrics(t *testing.T) {
	app, accounts := newTestApp(t)
	accounts.AddAccounts([]string{"token-beta-1234567890", "token-gamma-1234567890"})
	if item := accounts.UpdateAccount("token-beta-1234567890", map[string]any{"quota": 7, "status": "正常"}); item == nil {
		t.Fatal("failed to update beta")
	}
	if item := accounts.UpdateAccount("token-gamma-1234567890", map[string]any{"quota": 9, "status": "限流"}); item == nil {
		t.Fatal("failed to update gamma")
	}

	resp := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/register", nil)
	req.Header.Set("Authorization", "Bearer admin-key")
	app.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("register status = %d body=%s", resp.Code, resp.Body.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	register := payload["register"].(map[string]any)
	stats := register["stats"].(map[string]any)
	if stats["current_available"] != float64(2) {
		t.Fatalf("current_available = %#v stats=%#v", stats["current_available"], stats)
	}
	if stats["current_quota"] != float64(12) {
		t.Fatalf("current_quota = %#v stats=%#v", stats["current_quota"], stats)
	}
}

func TestModelsRequireAuthAndUseLister(t *testing.T) {
	app, _ := newTestAppWithModels(t, fakeModelLister{})
	unauthorized := httptest.NewRecorder()
	app.ServeHTTP(unauthorized, httptest.NewRequest(http.MethodGet, "/v1/models", nil))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized status = %d", unauthorized.Code)
	}

	authorized := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	req.Header.Set("Authorization", "Bearer admin-key")
	app.ServeHTTP(authorized, req)
	if authorized.Code != http.StatusOK {
		t.Fatalf("authorized status = %d body=%s", authorized.Code, authorized.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(authorized.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["object"] != "list" {
		t.Fatalf("body = %#v", body)
	}
}

func newTestApp(t *testing.T) (*App, *account.Service) {
	return newTestAppWithModels(t, nil)
}

func newTestAppWithModels(t *testing.T, models ModelLister) (*App, *account.Service) {
	t.Helper()
	protocol.ClearTextChatCacheForTest()
	root := t.TempDir()
	dataDir := filepath.Join(root, "data")
	if err := os.WriteFile(filepath.Join(root, "config.json"), []byte(`{"auth-key":"admin-key"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	store := storage.NewJSONStore(dataDir)
	accounts, err := account.NewService(store, 3)
	if err != nil {
		t.Fatal(err)
	}
	accounts.AddAccounts([]string{"token-alpha-1234567890"})
	if item := accounts.UpdateAccount("token-alpha-1234567890", map[string]any{"quota": 5, "type": "Plus", "status": "正常"}); item == nil {
		t.Fatal("failed to seed test account")
	}
	cfg := &config.Config{
		ProjectRoot:             root,
		ConfigFile:              filepath.Join(root, "config.json"),
		AuthKey:                 "admin-key",
		Version:                 "test-version",
		DataDir:                 filepath.Dir(store.AccountsPath),
		ImageAccountConcurrency: 3,
		ImageRetentionDays:      3,
		ImagePollTimeoutSecs:    1,
		Raw:                     map[string]any{"auth-key": "admin-key"},
	}
	return New(cfg, accounts, auth.NewService(store, cfg.AuthKey), models), accounts
}

func TestBackupRunAppearsInListAndDetail(t *testing.T) {
	app, _ := newTestApp(t)

	run := httptest.NewRecorder()
	runReq := httptest.NewRequest(http.MethodPost, "/api/backups/run", bytes.NewReader([]byte(`{}`)))
	runReq.Header.Set("Authorization", "Bearer admin-key")
	app.ServeHTTP(run, runReq)
	if run.Code != http.StatusOK {
		t.Fatalf("backup run status = %d body=%s", run.Code, run.Body.String())
	}

	list := httptest.NewRecorder()
	listReq := httptest.NewRequest(http.MethodGet, "/api/backups", nil)
	listReq.Header.Set("Authorization", "Bearer admin-key")
	app.ServeHTTP(list, listReq)
	if list.Code != http.StatusOK {
		t.Fatalf("backup list status = %d body=%s", list.Code, list.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(list.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	items := body["items"].([]any)
	if len(items) != 1 {
		t.Fatalf("items = %#v", body["items"])
	}
	key := items[0].(map[string]any)["key"].(string)

	detail := httptest.NewRecorder()
	detailReq := httptest.NewRequest(http.MethodGet, "/api/backups/detail?key="+key, nil)
	detailReq.Header.Set("Authorization", "Bearer admin-key")
	app.ServeHTTP(detail, detailReq)
	if detail.Code != http.StatusOK {
		t.Fatalf("backup detail status = %d body=%s", detail.Code, detail.Body.String())
	}
}

type fakeModelLister struct{}

func (fakeModelLister) ListModels(context.Context) (map[string]any, error) {
	return map[string]any{"object": "list", "data": []any{}}, nil
}

type fakeAccountRefresher struct {
	calls int
	info  map[string]any
	err   error
}

func (f *fakeAccountRefresher) FetchRemoteInfo(context.Context, string) (map[string]any, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	if f.info != nil {
		return f.info, nil
	}
	return map[string]any{"quota": 1, "type": "Free", "status": "正常"}, nil
}

type fakePasswordRelogin struct {
	tokens map[string]any
	err    error
}

func (f *fakePasswordRelogin) LoginWithPassword(context.Context, string, string, map[string]any) (map[string]any, error) {
	if f.err != nil {
		return nil, f.err
	}
	out := make(map[string]any, len(f.tokens))
	for key, value := range f.tokens {
		out[key] = value
	}
	return out, nil
}

func TestChatCompletionsUsesAccountPool(t *testing.T) {
	app, accounts := newTestAppWithModels(t, fakeChatBackend{})
	accounts.AddAccounts([]string{"token-alpha-1234567890"})

	resp := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader([]byte(`{
		"model": "auto",
		"messages": [{"role": "user", "content": "ping"}]
	}`)))
	req.Header.Set("Authorization", "Bearer admin-key")
	app.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", resp.Code, resp.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	choices := body["choices"].([]any)
	message := choices[0].(map[string]any)["message"].(map[string]any)
	if message["content"] != "你好，世界" {
		t.Fatalf("body = %#v", body)
	}
}

func TestChatCompletion401MarksAccountAbnormal(t *testing.T) {
	app, accounts := newTestAppWithModels(t, failingChatBackend{
		err: fmt.Errorf("/backend-api/conversation failed: HTTP 401, body={\"error\":{\"code\":\"token_invalidated\"}}"),
	})

	resp := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader([]byte(`{
		"model": "auto",
		"messages": [{"role": "user", "content": "ping"}]
	}`)))
	req.Header.Set("Authorization", "Bearer admin-key")
	app.ServeHTTP(resp, req)
	if resp.Code != http.StatusBadGateway {
		t.Fatalf("status = %d body=%s", resp.Code, resp.Body.String())
	}
	items := accounts.ListAccounts()
	if items[0]["status"] != "异常" || items[0]["quota"] != 0 {
		t.Fatalf("401 account should be abnormal, item = %#v", items[0])
	}
}

func TestSettingsAutoRemoveInvalidAccountAffectsRuntimeCalls(t *testing.T) {
	app, accounts := newTestAppWithModels(t, failingChatBackend{
		err: fmt.Errorf("/backend-api/conversation failed: HTTP 401, body={\"error\":{\"code\":\"token_invalidated\"}}"),
	})

	settings := httptest.NewRecorder()
	settingsReq := httptest.NewRequest(http.MethodPost, "/api/settings", bytes.NewReader([]byte(`{
		"auto_remove_invalid_accounts": true
	}`)))
	settingsReq.Header.Set("Authorization", "Bearer admin-key")
	app.ServeHTTP(settings, settingsReq)
	if settings.Code != http.StatusOK {
		t.Fatalf("settings status = %d body=%s", settings.Code, settings.Body.String())
	}

	resp := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader([]byte(`{
		"model": "auto",
		"messages": [{"role": "user", "content": "ping"}]
	}`)))
	req.Header.Set("Authorization", "Bearer admin-key")
	app.ServeHTTP(resp, req)
	if resp.Code != http.StatusBadGateway {
		t.Fatalf("status = %d body=%s", resp.Code, resp.Body.String())
	}
	if got := len(accounts.ListAccounts()); got != 0 {
		t.Fatalf("invalid account should be removed, remaining=%d items=%#v", got, accounts.ListAccounts())
	}
}

func TestChatCompletionsGPT55UsesSearch(t *testing.T) {
	backend := &fakeSearchBackend{}
	app, _ := newTestAppWithModels(t, backend)

	resp := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader([]byte(`{
		"model": "gpt-5-5",
		"messages": [{"role": "user", "content": "查一下今天的消息"}]
	}`)))
	req.Header.Set("Authorization", "Bearer admin-key")
	app.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", resp.Code, resp.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	choices := body["choices"].([]any)
	message := choices[0].(map[string]any)["message"].(map[string]any)
	if message["content"] != "搜索答案" {
		t.Fatalf("body = %#v", body)
	}
	if backend.searches != 1 || backend.streams != 0 {
		t.Fatalf("searches=%d streams=%d", backend.searches, backend.streams)
	}
	if backend.prompt != "查一下今天的消息" {
		t.Fatalf("prompt = %q", backend.prompt)
	}
}

func TestSearchEndpointUsesAccountPool(t *testing.T) {
	backend := &fakeSearchBackend{}
	app, accounts := newTestAppWithModels(t, backend)
	accounts.UpdateAccount("token-alpha-1234567890", map[string]any{"email": "user@example.test"})

	resp := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/search", bytes.NewReader([]byte(`{"prompt":"查一下今天的消息"}`)))
	req.Header.Set("Authorization", "Bearer admin-key")
	app.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", resp.Code, resp.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["answer"] != "搜索答案" || body["_account_email"] != "user@example.test" {
		t.Fatalf("body = %#v", body)
	}
	if backend.token != "token-alpha-1234567890" || backend.model != protocol.SearchModel {
		t.Fatalf("token=%q model=%q", backend.token, backend.model)
	}
}

type fakeChatBackend struct {
	fakeModelLister
}

func (fakeChatBackend) StreamConversation(ctx context.Context, accessToken string, messages []map[string]any, model, prompt string) (<-chan string, <-chan error) {
	out := make(chan string, 3)
	errCh := make(chan error, 1)
	out <- `{"message":{"author":{"role":"assistant"},"content":{"parts":["你好"]}}}`
	out <- `{"p":"/message/content/parts/0","o":"append","v":"，世界"}`
	out <- "[DONE]"
	close(out)
	errCh <- nil
	close(errCh)
	return out, errCh
}

type fakeSearchBackend struct {
	fakeModelLister
	searches int
	streams  int
	token    string
	model    string
	prompt   string
}

func (f *fakeSearchBackend) StreamConversation(ctx context.Context, accessToken string, messages []map[string]any, model, prompt string) (<-chan string, <-chan error) {
	f.streams++
	return fakeChatBackend{}.StreamConversation(ctx, accessToken, messages, model, prompt)
}

func (f *fakeSearchBackend) Search(ctx context.Context, accessToken, prompt, model string) (map[string]any, error) {
	f.searches++
	f.token = accessToken
	f.model = model
	f.prompt = prompt
	return map[string]any{"answer": "搜索答案", "conversation_id": "conv-search", "sources": []map[string]string{}}, nil
}

type failingChatBackend struct {
	fakeModelLister
	err error
}

func (f failingChatBackend) StreamConversation(ctx context.Context, accessToken string, messages []map[string]any, model, prompt string) (<-chan string, <-chan error) {
	out := make(chan string)
	errCh := make(chan error, 1)
	close(out)
	errCh <- f.err
	close(errCh)
	return out, errCh
}

func TestImageTaskGenerationSubmitsAndPolls(t *testing.T) {
	app, _ := newTestAppWithModels(t, fakeImageBackend{})

	submit := httptest.NewRecorder()
	submitReq := httptest.NewRequest(http.MethodPost, "/api/image-tasks/generations", bytes.NewReader([]byte(`{
		"client_task_id": "task-1",
		"prompt": "一只小猫",
		"model": "gpt-image-2",
		"size": "1:1"
	}`)))
	submitReq.Header.Set("Authorization", "Bearer admin-key")
	app.ServeHTTP(submit, submitReq)
	if submit.Code != http.StatusOK {
		t.Fatalf("submit status = %d body=%s", submit.Code, submit.Body.String())
	}

	var listed map[string]any
	for i := 0; i < 20; i++ {
		resp := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/image-tasks?ids=task-1,missing", nil)
		req.Header.Set("Authorization", "Bearer admin-key")
		app.ServeHTTP(resp, req)
		if resp.Code != http.StatusOK {
			t.Fatalf("list status = %d body=%s", resp.Code, resp.Body.String())
		}
		if err := json.Unmarshal(resp.Body.Bytes(), &listed); err != nil {
			t.Fatal(err)
		}
		items := listed["items"].([]any)
		if len(items) == 1 && items[0].(map[string]any)["status"] == "success" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	items := listed["items"].([]any)
	task := items[0].(map[string]any)
	if task["status"] != "success" {
		t.Fatalf("task did not finish: %#v", task)
	}
	missing := listed["missing_ids"].([]any)
	if len(missing) != 1 || missing[0] != "missing" {
		t.Fatalf("missing_ids = %#v", missing)
	}
	data := task["data"].([]any)
	if data[0].(map[string]any)["b64_json"] != "Y2F0" {
		t.Fatalf("data = %#v", data)
	}
}

func TestDirectImageGenerationSupportsB64JSON(t *testing.T) {
	app, _ := newTestAppWithModels(t, fakeImageBackend{})

	resp := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/images/generations", bytes.NewReader([]byte(`{
		"prompt": "一只小猫",
		"model": "gpt-image-2",
		"response_format": "b64_json"
	}`)))
	req.Header.Set("Authorization", "Bearer admin-key")
	app.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", resp.Code, resp.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	items := body["data"].([]any)
	if len(items) != 1 || items[0].(map[string]any)["b64_json"] != "Y2F0" {
		t.Fatalf("data = %#v", body["data"])
	}
	usage := body["usage"].(map[string]any)
	if usage["completion_tokens"] != float64(1056) || usage["output_tokens"] != float64(1056) {
		t.Fatalf("usage output tokens = %#v", usage)
	}
	if usage["prompt_tokens"].(float64) <= 0 || usage["input_tokens"].(float64) <= 0 {
		t.Fatalf("usage input tokens = %#v", usage)
	}
	if usage["total_tokens"] != usage["prompt_tokens"].(float64)+usage["completion_tokens"].(float64) {
		t.Fatalf("usage total tokens = %#v", usage)
	}
}

func TestDirectImageGenerationUploadsToImgbedWhenEnabled(t *testing.T) {
	uploadCount := 0
	imgbed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		uploadCount++
		if r.URL.Path != "/upload" {
			t.Errorf("upload path = %s", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Errorf("upload method = %s", r.Method)
		}
		if r.Header.Get("Authorization") != "Bearer upload-token" {
			t.Errorf("authorization = %q", r.Header.Get("Authorization"))
		}
		if r.URL.Query().Get("uploadFolder") == "" || r.URL.Query().Get("returnFormat") != "full" {
			t.Errorf("upload query = %s", r.URL.RawQuery)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]map[string]string{{"src": "/uploads/cat.png"}})
	}))
	defer imgbed.Close()

	app, _ := newTestAppWithModels(t, fakeImageBackend{})
	app.config.Raw = map[string]any{
		"imgbed": map[string]any{
			"enabled":           true,
			"base_url":          imgbed.URL,
			"api_token":         "upload-token",
			"folder_prefix":     "chatgpt2api",
			"timeout_seconds":   2,
			"fallback_to_local": true,
		},
	}

	resp := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/images/generations", bytes.NewReader([]byte(`{
		"prompt": "一只小猫",
		"model": "gpt-image-2",
		"response_format": "url"
	}`)))
	req.Header.Set("Authorization", "Bearer admin-key")
	app.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", resp.Code, resp.Body.String())
	}
	if uploadCount != 1 {
		t.Fatalf("upload count = %d", uploadCount)
	}
	var body map[string]any
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	items := body["data"].([]any)
	first := items[0].(map[string]any)
	if first["url"] != imgbed.URL+"/uploads/cat.png" {
		t.Fatalf("url = %#v", first["url"])
	}
	if _, ok := first["b64_json"]; ok {
		t.Fatalf("url response should not include b64_json: %#v", first)
	}
}

func TestDirectImageGenerationDefaultsToB64JSON(t *testing.T) {
	app, _ := newTestAppWithModels(t, fakeImageBackend{})

	resp := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/images/generations", bytes.NewReader([]byte(`{
		"prompt": "一只小猫",
		"model": "gpt-image-2"
	}`)))
	req.Header.Set("Authorization", "Bearer admin-key")
	app.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", resp.Code, resp.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	items := body["data"].([]any)
	if len(items) != 1 || items[0].(map[string]any)["b64_json"] != "Y2F0" {
		t.Fatalf("data = %#v", body["data"])
	}
}

func TestDirectImageGenerationSkipsInvalidAccountAndRetries(t *testing.T) {
	backend := &retryingImageBackend{
		err: fmt.Errorf("/backend-api/conversation failed: HTTP 401, body={\"error\":{\"code\":\"token_invalidated\"}}"),
		failTokens: map[string]bool{
			"token-alpha-1234567890": true,
		},
	}
	app, accounts := newTestAppWithModels(t, backend)
	addImageAccount(t, accounts, "token-beta-1234567890", 5)

	resp := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/images/generations", bytes.NewReader([]byte(`{
		"prompt": "一只小猫",
		"model": "gpt-image-2",
		"response_format": "b64_json"
	}`)))
	req.Header.Set("Authorization", "Bearer admin-key")
	app.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", resp.Code, resp.Body.String())
	}
	if strings.Join(backend.generateTokens, ",") != "token-alpha-1234567890,token-beta-1234567890" {
		t.Fatalf("generate tokens = %#v", backend.generateTokens)
	}
	items := accounts.ListAccounts()
	if items[0]["status"] != "异常" || items[0]["quota"] != 0 {
		t.Fatalf("invalid account should be abnormal, item = %#v", items[0])
	}
	if items[1]["status"] != "正常" || items[1]["quota"] != 4 {
		t.Fatalf("retry account should be used successfully, item = %#v", items[1])
	}
	var body map[string]any
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	data := body["data"].([]any)
	if len(data) != 1 || data[0].(map[string]any)["b64_json"] != "Y2F0" {
		t.Fatalf("data = %#v", body["data"])
	}
}

func TestDirectImageGenerationRunsMultipleImagesInParallel(t *testing.T) {
	backend := &concurrentImageBackend{delay: 50 * time.Millisecond}
	app, _ := newTestAppWithModels(t, backend)

	resp := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/images/generations", bytes.NewReader([]byte(`{
		"prompt": "一只小猫",
		"model": "gpt-image-2",
		"n": 2,
		"response_format": "b64_json"
	}`)))
	req.Header.Set("Authorization", "Bearer admin-key")
	app.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", resp.Code, resp.Body.String())
	}
	if backend.maxActiveCount() < 2 {
		t.Fatalf("expected parallel image generation, max active = %d", backend.maxActiveCount())
	}
	var body map[string]any
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	data := body["data"].([]any)
	if len(data) != 2 {
		t.Fatalf("data = %#v", body["data"])
	}
}

func TestDirectImageGenerationUsesRedundancyMultiplier(t *testing.T) {
	backend := &retryingImageBackend{}
	app, accounts := newTestAppWithModels(t, backend)
	app.config.ImageRedundancyMultiplier = 2

	resp := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/images/generations", bytes.NewReader([]byte(`{
		"prompt": "一只小猫",
		"model": "gpt-image-2",
		"n": 2,
		"response_format": "b64_json"
	}`)))
	req.Header.Set("Authorization", "Bearer admin-key")
	app.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", resp.Code, resp.Body.String())
	}
	if len(backend.generateTokens) != 4 {
		t.Fatalf("generate attempts = %d tokens=%#v", len(backend.generateTokens), backend.generateTokens)
	}
	var body map[string]any
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	data := body["data"].([]any)
	if len(data) != 2 {
		t.Fatalf("response should return requested count only: %#v", data)
	}
	items := accounts.ListAccounts()
	if items[0]["quota"] != 1 {
		t.Fatalf("quota should include redundant attempts, item = %#v", items[0])
	}
}

func TestDirectImageGenerationReturnsPartialSuccess(t *testing.T) {
	backend := &retryingImageBackend{
		err: fmt.Errorf("temporary upstream image failure"),
		failTokens: map[string]bool{
			"token-alpha-1234567890": true,
		},
	}
	app, accounts := newTestAppWithModels(t, backend)
	addImageAccount(t, accounts, "token-beta-1234567890", 5)

	resp := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/images/generations", bytes.NewReader([]byte(`{
		"prompt": "一只小猫",
		"model": "gpt-image-2",
		"n": 2,
		"response_format": "b64_json"
	}`)))
	req.Header.Set("Authorization", "Bearer admin-key")
	app.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", resp.Code, resp.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	data := body["data"].([]any)
	if len(data) != 1 || data[0].(map[string]any)["b64_json"] != "Y2F0" {
		t.Fatalf("data = %#v", body["data"])
	}
	items := accounts.ListAccounts()
	if items[0]["fail"] != 1 || items[1]["quota"] != 4 {
		t.Fatalf("accounts = %#v", items)
	}
}

func TestImageEditEndpointsValidateMultipart(t *testing.T) {
	app, _ := newTestAppWithModels(t, fakeImageBackend{})

	taskResp := httptest.NewRecorder()
	taskReq := httptest.NewRequest(http.MethodPost, "/api/image-tasks/edits", bytes.NewReader([]byte("not multipart")))
	taskReq.Header.Set("Authorization", "Bearer admin-key")
	app.ServeHTTP(taskResp, taskReq)
	if taskResp.Code != http.StatusBadRequest {
		t.Fatalf("task edit status = %d body=%s", taskResp.Code, taskResp.Body.String())
	}

	openAIResp := httptest.NewRecorder()
	openAIReq := httptest.NewRequest(http.MethodPost, "/v1/images/edits", bytes.NewReader([]byte("not multipart")))
	openAIReq.Header.Set("Authorization", "Bearer admin-key")
	app.ServeHTTP(openAIResp, openAIReq)
	if openAIResp.Code != http.StatusBadRequest {
		t.Fatalf("openai edit status = %d body=%s", openAIResp.Code, openAIResp.Body.String())
	}
}

func TestImageEditEndpointsSupportMultipart(t *testing.T) {
	app, _ := newTestAppWithModels(t, fakeImageBackend{})
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	_ = writer.WriteField("client_task_id", "edit-task-1")
	_ = writer.WriteField("prompt", "把这张图改成复古海报")
	_ = writer.WriteField("model", "gpt-image-2")
	_ = writer.WriteField("size", "1:1")
	part, err := writer.CreateFormFile("image", "first.png")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = part.Write([]byte("fake-image-bytes"))
	_ = writer.Close()

	taskResp := httptest.NewRecorder()
	taskReq := httptest.NewRequest(http.MethodPost, "/api/image-tasks/edits", bytes.NewReader(body.Bytes()))
	taskReq.Header.Set("Authorization", "Bearer admin-key")
	taskReq.Header.Set("Content-Type", writer.FormDataContentType())
	app.ServeHTTP(taskResp, taskReq)
	if taskResp.Code != http.StatusOK {
		t.Fatalf("task edit status = %d body=%s", taskResp.Code, taskResp.Body.String())
	}

	var listed map[string]any
	for i := 0; i < 20; i++ {
		resp := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/image-tasks?ids=edit-task-1", nil)
		req.Header.Set("Authorization", "Bearer admin-key")
		app.ServeHTTP(resp, req)
		if resp.Code != http.StatusOK {
			t.Fatalf("list status = %d body=%s", resp.Code, resp.Body.String())
		}
		if err := json.Unmarshal(resp.Body.Bytes(), &listed); err != nil {
			t.Fatal(err)
		}
		items := listed["items"].([]any)
		if len(items) == 1 && items[0].(map[string]any)["status"] == "success" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	items := listed["items"].([]any)
	task := items[0].(map[string]any)
	if task["status"] != "success" {
		t.Fatalf("edit task did not finish: %#v", task)
	}
	data := task["data"].([]any)
	if data[0].(map[string]any)["b64_json"] != "Y2F0" {
		t.Fatalf("task data = %#v", data)
	}

	openAIBody := &bytes.Buffer{}
	openAIWriter := multipart.NewWriter(openAIBody)
	_ = openAIWriter.WriteField("prompt", "把这张图改成复古海报")
	_ = openAIWriter.WriteField("model", "gpt-image-2")
	_ = openAIWriter.WriteField("response_format", "b64_json")
	part, err = openAIWriter.CreateFormFile("image", "first.png")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = part.Write([]byte("fake-image-bytes"))
	_ = openAIWriter.Close()

	openAIResp := httptest.NewRecorder()
	openAIReq := httptest.NewRequest(http.MethodPost, "/v1/images/edits", bytes.NewReader(openAIBody.Bytes()))
	openAIReq.Header.Set("Authorization", "Bearer admin-key")
	openAIReq.Header.Set("Content-Type", openAIWriter.FormDataContentType())
	app.ServeHTTP(openAIResp, openAIReq)
	if openAIResp.Code != http.StatusOK {
		t.Fatalf("openai edit status = %d body=%s", openAIResp.Code, openAIResp.Body.String())
	}
	var imageBody map[string]any
	if err := json.Unmarshal(openAIResp.Body.Bytes(), &imageBody); err != nil {
		t.Fatal(err)
	}
	data = imageBody["data"].([]any)
	if len(data) != 1 || data[0].(map[string]any)["b64_json"] != "Y2F0" {
		t.Fatalf("openai edit body = %#v", imageBody)
	}
	usage := imageBody["usage"].(map[string]any)
	if usage["completion_tokens"] != float64(1056) || usage["output_tokens"] != float64(1056) {
		t.Fatalf("openai edit usage output tokens = %#v", usage)
	}
	if usage["prompt_tokens"].(float64) <= 0 || usage["input_tokens"].(float64) <= 0 {
		t.Fatalf("openai edit usage input tokens = %#v", usage)
	}
}

func TestDirectImageEditSkipsInvalidAccountAndRetries(t *testing.T) {
	backend := &retryingImageBackend{
		err: fmt.Errorf("/backend-api/conversation failed: HTTP 401, body={\"error\":{\"code\":\"token_invalidated\"}}"),
		failTokens: map[string]bool{
			"token-alpha-1234567890": true,
		},
	}
	app, accounts := newTestAppWithModels(t, backend)
	addImageAccount(t, accounts, "token-beta-1234567890", 5)

	openAIBody := &bytes.Buffer{}
	openAIWriter := multipart.NewWriter(openAIBody)
	_ = openAIWriter.WriteField("prompt", "把这张图改成复古海报")
	_ = openAIWriter.WriteField("model", "gpt-image-2")
	_ = openAIWriter.WriteField("response_format", "b64_json")
	part, err := openAIWriter.CreateFormFile("image", "first.png")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = part.Write([]byte("fake-image-bytes"))
	_ = openAIWriter.Close()

	resp := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/images/edits", bytes.NewReader(openAIBody.Bytes()))
	req.Header.Set("Authorization", "Bearer admin-key")
	req.Header.Set("Content-Type", openAIWriter.FormDataContentType())
	app.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", resp.Code, resp.Body.String())
	}
	if strings.Join(backend.editTokens, ",") != "token-alpha-1234567890,token-beta-1234567890" {
		t.Fatalf("edit tokens = %#v", backend.editTokens)
	}
	items := accounts.ListAccounts()
	if items[0]["status"] != "异常" || items[0]["quota"] != 0 {
		t.Fatalf("invalid account should be abnormal, item = %#v", items[0])
	}
	if items[1]["status"] != "正常" || items[1]["quota"] != 4 {
		t.Fatalf("retry account should be used successfully, item = %#v", items[1])
	}
}

func TestResponsesAndMessagesCompat(t *testing.T) {
	app, _ := newTestAppWithModels(t, fakeImageBackend{})

	resp := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/responses", bytes.NewReader([]byte(`{
		"model": "auto",
		"input": [{"role":"user","content":[{"type":"input_text","text":"你好"}]}]
	}`)))
	req.Header.Set("Authorization", "Bearer admin-key")
	app.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("responses status = %d body=%s", resp.Code, resp.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["object"] != "response" || body["status"] != "completed" {
		t.Fatalf("responses body = %#v", body)
	}

	msgResp := httptest.NewRecorder()
	msgReq := httptest.NewRequest(http.MethodPost, "/v1/messages", bytes.NewReader([]byte(`{
		"model": "auto",
		"messages": [{"role":"user","content":"你好"}]
	}`)))
	msgReq.Header.Set("x-api-key", "admin-key")
	msgReq.Header.Set("anthropic-version", "2023-06-01")
	app.ServeHTTP(msgResp, msgReq)
	if msgResp.Code != http.StatusOK {
		t.Fatalf("messages status = %d body=%s", msgResp.Code, msgResp.Body.String())
	}
	var msgBody map[string]any
	if err := json.Unmarshal(msgResp.Body.Bytes(), &msgBody); err != nil {
		t.Fatal(err)
	}
	if msgBody["type"] != "message" {
		t.Fatalf("messages body = %#v", msgBody)
	}
}

func TestResponsesImageToolSkipsInvalidAccountAndRetries(t *testing.T) {
	backend := &retryingImageBackend{
		err: fmt.Errorf("/backend-api/conversation failed: HTTP 401, body={\"error\":{\"code\":\"token_invalidated\"}}"),
		failTokens: map[string]bool{
			"token-alpha-1234567890": true,
		},
	}
	app, accounts := newTestAppWithModels(t, backend)
	addImageAccount(t, accounts, "token-beta-1234567890", 5)

	resp := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/responses", bytes.NewReader([]byte(`{
		"model": "gpt-image-2",
		"input": "画一只小猫",
		"tools": [{"type": "image_generation"}]
	}`)))
	req.Header.Set("Authorization", "Bearer admin-key")
	app.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("responses status = %d body=%s", resp.Code, resp.Body.String())
	}
	if strings.Join(backend.generateTokens, ",") != "token-alpha-1234567890,token-beta-1234567890" {
		t.Fatalf("generate tokens = %#v", backend.generateTokens)
	}
	items := accounts.ListAccounts()
	if items[0]["status"] != "异常" || items[0]["quota"] != 0 {
		t.Fatalf("invalid account should be abnormal, item = %#v", items[0])
	}
}

func TestResponsesImageToolPassesSizeAndQuality(t *testing.T) {
	backend := &capturingImageBackend{}
	app, _ := newTestAppWithModels(t, backend)

	resp := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/responses", bytes.NewReader([]byte(`{
		"model": "gpt-image-2",
		"input": "画一张产品海报",
		"tools": [{
			"type": "image_generation",
			"size": "2:3",
			"quality": "high"
		}]
	}`)))
	req.Header.Set("Authorization", "Bearer admin-key")
	app.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("responses status = %d body=%s", resp.Code, resp.Body.String())
	}
	if backend.size != "2:3" {
		t.Fatalf("size = %q", backend.size)
	}
	if !strings.Contains(backend.prompt, "输出图片质量为 high。") {
		t.Fatalf("prompt = %q", backend.prompt)
	}
}

func TestResponses401MarksAccountAbnormal(t *testing.T) {
	app, accounts := newTestAppWithModels(t, failingChatBackend{
		err: fmt.Errorf("/backend-api/conversation failed: HTTP 401, body={\"error\":{\"code\":\"token_invalidated\"}}"),
	})

	resp := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/responses", bytes.NewReader([]byte(`{
		"model": "auto",
		"input": "你好"
	}`)))
	req.Header.Set("Authorization", "Bearer admin-key")
	app.ServeHTTP(resp, req)
	if resp.Code != http.StatusBadGateway {
		t.Fatalf("responses status = %d body=%s", resp.Code, resp.Body.String())
	}
	items := accounts.ListAccounts()
	if items[0]["status"] != "异常" || items[0]["quota"] != 0 {
		t.Fatalf("401 account should be abnormal, item = %#v", items[0])
	}
}

func TestCreationTaskAliasesWork(t *testing.T) {
	app, _ := newTestAppWithModels(t, fakeImageBackend{})

	submit := httptest.NewRecorder()
	submitReq := httptest.NewRequest(http.MethodPost, "/api/creation-tasks/image-generations", bytes.NewReader([]byte(`{
		"client_task_id": "task-creation-1",
		"prompt": "一只小猫",
		"model": "gpt-image-2",
		"size": "1:1"
	}`)))
	submitReq.Header.Set("Authorization", "Bearer admin-key")
	app.ServeHTTP(submit, submitReq)
	if submit.Code != http.StatusOK {
		t.Fatalf("submit status = %d body=%s", submit.Code, submit.Body.String())
	}

	list := httptest.NewRecorder()
	listReq := httptest.NewRequest(http.MethodGet, "/api/creation-tasks?ids=task-creation-1", nil)
	listReq.Header.Set("Authorization", "Bearer admin-key")
	var listed map[string]any
	for i := 0; i < 20; i++ {
		list = httptest.NewRecorder()
		app.ServeHTTP(list, listReq)
		if list.Code != http.StatusOK {
			t.Fatalf("list status = %d body=%s", list.Code, list.Body.String())
		}
		if err := json.Unmarshal(list.Body.Bytes(), &listed); err != nil {
			t.Fatal(err)
		}
		items := listed["items"].([]any)
		if len(items) == 1 && items[0].(map[string]any)["status"] == "success" {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("creation task alias did not finish: %#v", listed)
}

func TestImageGeneration401MarksAccountAbnormal(t *testing.T) {
	app, accounts := newTestAppWithModels(t, failingImageBackend{
		err: fmt.Errorf("/backend-api/conversation failed: HTTP 401, body={\"error\":{\"code\":\"token_invalidated\"}}"),
	})

	resp := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/images/generations", bytes.NewReader([]byte(`{
		"prompt": "一只小猫",
		"model": "gpt-image-2",
		"n": 1
	}`)))
	req.Header.Set("Authorization", "Bearer admin-key")
	app.ServeHTTP(resp, req)
	if resp.Code != http.StatusBadGateway {
		t.Fatalf("status = %d body=%s", resp.Code, resp.Body.String())
	}
	items := accounts.ListAccounts()
	if items[0]["status"] != "异常" || items[0]["quota"] != 0 {
		t.Fatalf("401 account should be abnormal, item = %#v", items[0])
	}
}

func TestImageGenerationRuntimeFailureDoesNotMarkAccountAbnormal(t *testing.T) {
	app, accounts := newTestAppWithModels(t, failingImageBackend{
		err: fmt.Errorf("ChatGPT 生图超时（已等待 120 秒），可能是账号被限流或生图队列拥堵"),
	})

	resp := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/images/generations", bytes.NewReader([]byte(`{
		"prompt": "一只小猫",
		"model": "gpt-image-2",
		"n": 1
	}`)))
	req.Header.Set("Authorization", "Bearer admin-key")
	app.ServeHTTP(resp, req)
	if resp.Code != http.StatusBadGateway {
		t.Fatalf("status = %d body=%s", resp.Code, resp.Body.String())
	}
	items := accounts.ListAccounts()
	if items[0]["status"] != "正常" || items[0]["quota"] != 5 || items[0]["fail"] != 1 {
		t.Fatalf("runtime failure should only count failure, item = %#v", items[0])
	}
}

func TestSettingsAutoRemoveInvalidAccountAffectsImage401(t *testing.T) {
	app, accounts := newTestAppWithModels(t, failingImageBackend{
		err: fmt.Errorf("/backend-api/conversation failed: HTTP 401, body={\"error\":{\"code\":\"token_invalidated\"}}"),
	})

	settings := httptest.NewRecorder()
	settingsReq := httptest.NewRequest(http.MethodPost, "/api/settings", bytes.NewReader([]byte(`{
		"auto_remove_invalid_accounts": true
	}`)))
	settingsReq.Header.Set("Authorization", "Bearer admin-key")
	app.ServeHTTP(settings, settingsReq)
	if settings.Code != http.StatusOK {
		t.Fatalf("settings status = %d body=%s", settings.Code, settings.Body.String())
	}

	resp := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/images/generations", bytes.NewReader([]byte(`{
		"prompt": "一只小猫",
		"model": "gpt-image-2",
		"n": 1
	}`)))
	req.Header.Set("Authorization", "Bearer admin-key")
	app.ServeHTTP(resp, req)
	if resp.Code != http.StatusBadGateway {
		t.Fatalf("status = %d body=%s", resp.Code, resp.Body.String())
	}
	if got := len(accounts.ListAccounts()); got != 0 {
		t.Fatalf("401 account should be removed, remaining=%d items=%#v", got, accounts.ListAccounts())
	}
}

func TestSettingsAutoRemoveInvalidAccountDoesNotRemoveImageTimeout(t *testing.T) {
	app, accounts := newTestAppWithModels(t, failingImageBackend{
		err: fmt.Errorf("ChatGPT 生图超时（已等待 120 秒），可能是账号被限流或生图队列拥堵"),
	})

	settings := httptest.NewRecorder()
	settingsReq := httptest.NewRequest(http.MethodPost, "/api/settings", bytes.NewReader([]byte(`{
		"auto_remove_invalid_accounts": true
	}`)))
	settingsReq.Header.Set("Authorization", "Bearer admin-key")
	app.ServeHTTP(settings, settingsReq)
	if settings.Code != http.StatusOK {
		t.Fatalf("settings status = %d body=%s", settings.Code, settings.Body.String())
	}

	resp := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/images/generations", bytes.NewReader([]byte(`{
		"prompt": "一只小猫",
		"model": "gpt-image-2",
		"n": 1
	}`)))
	req.Header.Set("Authorization", "Bearer admin-key")
	app.ServeHTTP(resp, req)
	if resp.Code != http.StatusBadGateway {
		t.Fatalf("status = %d body=%s", resp.Code, resp.Body.String())
	}
	items := accounts.ListAccounts()
	if len(items) != 1 || items[0]["status"] != "正常" || items[0]["fail"] != 1 {
		t.Fatalf("timeout should not remove account, items=%#v", items)
	}
}

func addImageAccount(t *testing.T, accounts *account.Service, token string, quota int) {
	t.Helper()
	accounts.AddAccounts([]string{token})
	if item := accounts.UpdateAccount(token, map[string]any{"quota": quota, "type": "Plus", "status": "正常"}); item == nil {
		t.Fatalf("failed to seed account %s", token)
	}
}

type fakeImageBackend struct {
	fakeChatBackend
}

func (fakeImageBackend) GenerateImage(ctx context.Context, accessToken, prompt, model, size, responseFormat string) ([]map[string]any, error) {
	item := map[string]any{"url": "https://example.test/cat.png", "revised_prompt": prompt}
	if strings.EqualFold(strings.TrimSpace(responseFormat), "b64_json") {
		item["b64_json"] = "Y2F0"
	}
	return []map[string]any{item}, nil
}

type retryingImageBackend struct {
	fakeModelLister
	mu             sync.Mutex
	err            error
	failTokens     map[string]bool
	generateTokens []string
	editTokens     []string
}

func (f *retryingImageBackend) GenerateImage(ctx context.Context, accessToken, prompt, model, size, responseFormat string) ([]map[string]any, error) {
	f.mu.Lock()
	f.generateTokens = append(f.generateTokens, accessToken)
	f.mu.Unlock()
	if f.failTokens[accessToken] {
		return nil, f.err
	}
	return fakeImageBackend{}.GenerateImage(ctx, accessToken, prompt, model, size, responseFormat)
}

func (f *retryingImageBackend) EditImage(ctx context.Context, accessToken, prompt, model, size, responseFormat string, images []protocol.ImageInput) ([]map[string]any, error) {
	f.mu.Lock()
	f.editTokens = append(f.editTokens, accessToken)
	f.mu.Unlock()
	if f.failTokens[accessToken] {
		return nil, f.err
	}
	return fakeImageBackend{}.EditImage(ctx, accessToken, prompt, model, size, responseFormat, images)
}

type concurrentImageBackend struct {
	fakeModelLister
	mu        sync.Mutex
	active    int
	maxActive int
	delay     time.Duration
}

func (f *concurrentImageBackend) GenerateImage(ctx context.Context, accessToken, prompt, model, size, responseFormat string) ([]map[string]any, error) {
	f.mu.Lock()
	f.active++
	if f.active > f.maxActive {
		f.maxActive = f.active
	}
	f.mu.Unlock()

	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
		}
	}

	f.mu.Lock()
	f.active--
	f.mu.Unlock()
	return fakeImageBackend{}.GenerateImage(ctx, accessToken, prompt, model, size, responseFormat)
}

func (f *concurrentImageBackend) EditImage(ctx context.Context, accessToken, prompt, model, size, responseFormat string, images []protocol.ImageInput) ([]map[string]any, error) {
	return fakeImageBackend{}.EditImage(ctx, accessToken, prompt, model, size, responseFormat, images)
}

func (f *concurrentImageBackend) maxActiveCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.maxActive
}

type capturingImageBackend struct {
	fakeModelLister
	prompt string
	size   string
}

func (f *capturingImageBackend) GenerateImage(ctx context.Context, accessToken, prompt, model, size, responseFormat string) ([]map[string]any, error) {
	f.prompt = prompt
	f.size = size
	return fakeImageBackend{}.GenerateImage(ctx, accessToken, prompt, model, size, responseFormat)
}

func (f *capturingImageBackend) EditImage(ctx context.Context, accessToken, prompt, model, size, responseFormat string, images []protocol.ImageInput) ([]map[string]any, error) {
	return fakeImageBackend{}.EditImage(ctx, accessToken, prompt, model, size, responseFormat, images)
}

type failingImageBackend struct {
	fakeModelLister
	err error
}

func (f failingImageBackend) GenerateImage(ctx context.Context, accessToken, prompt, model, size, responseFormat string) ([]map[string]any, error) {
	return nil, f.err
}

func (f failingImageBackend) EditImage(ctx context.Context, accessToken, prompt, model, size, responseFormat string, images []protocol.ImageInput) ([]map[string]any, error) {
	return nil, f.err
}

func (fakeImageBackend) EditImage(ctx context.Context, accessToken, prompt, model, size, responseFormat string, images []protocol.ImageInput) ([]map[string]any, error) {
	item := map[string]any{"url": "https://example.test/edit.png", "revised_prompt": prompt}
	if strings.EqualFold(strings.TrimSpace(responseFormat), "b64_json") {
		item["b64_json"] = "Y2F0"
	}
	return []map[string]any{item}, nil
}

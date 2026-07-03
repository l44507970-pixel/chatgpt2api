package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"chatgpt2api-go-backend/internal/account"
	"chatgpt2api-go-backend/internal/auth"
	"chatgpt2api-go-backend/internal/config"
	"chatgpt2api-go-backend/internal/imagetask"
	"chatgpt2api-go-backend/internal/localdata"
	"chatgpt2api-go-backend/internal/protocol"
	"chatgpt2api-go-backend/internal/register"
)

type App struct {
	config   *config.Config
	accounts *account.Service
	auth     *auth.Service
	models   ModelLister
	chat     ConversationStreamer
	search   Searcher
	image    ImageGenerator
	tasks    *imagetask.Service
	local    *localdata.Services
	register *register.Service
	mux      *http.ServeMux
	started  time.Time
}

type ModelLister interface {
	ListModels(ctx context.Context) (map[string]any, error)
}

type ConversationStreamer interface {
	StreamConversation(ctx context.Context, accessToken string, messages []map[string]any, model, prompt string) (<-chan string, <-chan error)
}

type Searcher interface {
	Search(ctx context.Context, accessToken, prompt, model string) (map[string]any, error)
}

type ImageGenerator interface {
	GenerateImage(ctx context.Context, accessToken, prompt, model, size, responseFormat string) ([]map[string]any, error)
	EditImage(ctx context.Context, accessToken, prompt, model, size, responseFormat string, images []protocol.ImageInput) ([]map[string]any, error)
}

const accountRefreshAutoAsyncThreshold = 10

func New(cfg *config.Config, accounts *account.Service, authService *auth.Service, models ModelLister) *App {
	app := &App{
		config:   cfg,
		accounts: accounts,
		auth:     authService,
		models:   models,
		local:    localdata.NewServices(cfg, cfg.ProjectRoot, cfg.DataDir, accounts),
		register: register.NewService(filepath.Join(cfg.DataDir, "register.json"), filepath.Join(cfg.DataDir, "mail_domain_reputation.json"), accounts),
		mux:      http.NewServeMux(),
		started:  time.Now(),
	}
	accounts.SetPasswordReloginProvider(app.register)
	accounts.SetAutoRemoveOptions(cfg.AutoRemoveInvalidAccounts, cfg.AutoRemoveRateLimitedAccounts)
	if chat, ok := models.(ConversationStreamer); ok {
		app.chat = chat
	}
	if searcher, ok := models.(Searcher); ok {
		app.search = searcher
	}
	if imageGenerator, ok := models.(ImageGenerator); ok {
		app.image = imageGenerator
		if tasks, err := imagetask.NewService(
			filepath.Join(cfg.DataDir, "image_tasks.json"),
			accounts,
			imageGenerator,
			cfg.ImageRetentionDays,
			time.Duration(cfg.ImagePollTimeoutSecs+60)*time.Second,
		); err == nil {
			app.tasks = tasks
			app.tasks.SetHistoryRecorder(app.local.Images())
		}
	}
	app.routes()
	return app
}

func (a *App) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.mux.ServeHTTP(w, r)
}

func (a *App) routes() {
	a.mux.HandleFunc("/health", a.handleHealth)
	a.mux.HandleFunc("/version", a.handleVersion)
	a.mux.HandleFunc("/auth/login", a.handleLogin)
	a.mux.HandleFunc("/api/settings", a.handleSettings)
	a.mux.HandleFunc("/api/storage/info", a.handleStorageInfo)
	a.mux.HandleFunc("/api/proxy", a.handleProxy)
	a.mux.HandleFunc("/api/proxy/test", a.handleProxyTest)
	a.mux.HandleFunc("/api/accounts", a.handleAccounts)
	a.mux.HandleFunc("/api/accounts/refresh", a.handleAccountsRefresh)
	a.mux.HandleFunc("/api/accounts/refresh/jobs/", a.handleAccountRefreshJob)
	a.mux.HandleFunc("/api/accounts/re-login/progress/", a.handleAccountReloginJob)
	a.mux.HandleFunc("/api/accounts/re-login/jobs/", a.handleAccountReloginJob)
	a.mux.HandleFunc("/api/accounts/re-login", a.handleAccountsRelogin)
	a.mux.HandleFunc("/api/accounts/update", a.handleAccountsUpdate)
	a.mux.HandleFunc("/api/auth/users/", a.handleUserKeyItem)
	a.mux.HandleFunc("/api/auth/users", a.handleUserKeys)
	a.mux.HandleFunc("/api/logs/delete", a.handleLogsDelete)
	a.mux.HandleFunc("/api/logs", a.handleLogs)
	a.mux.HandleFunc("/api/images/download/", a.handleImageDownloadSingle)
	a.mux.HandleFunc("/api/images/download", a.handleImagesDownload)
	a.mux.HandleFunc("/api/images/delete", a.handleImagesDelete)
	a.mux.HandleFunc("/api/images/tags/", a.handleImageTagItem)
	a.mux.HandleFunc("/api/images/tags", a.handleImageTags)
	a.mux.HandleFunc("/api/images", a.handleImages)
	a.mux.HandleFunc("/images/", a.handleStaticImage)
	a.mux.HandleFunc("/image-thumbnails/", a.handleStaticImageThumbnail)
	a.mux.HandleFunc("/api/image-history/delete", a.handleImageHistoryDelete)
	a.mux.HandleFunc("/api/image-history/", a.handleImageHistoryImage)
	a.mux.HandleFunc("/api/image-history", a.handleImageHistory)
	a.mux.HandleFunc("/api/backups/run", a.handleBackupsRun)
	a.mux.HandleFunc("/api/backups/delete", a.handleBackupsDelete)
	a.mux.HandleFunc("/api/backups/detail", a.handleBackupsDetail)
	a.mux.HandleFunc("/api/backups/download", a.handleBackupsDownload)
	a.mux.HandleFunc("/api/backups", a.handleBackups)
	a.mux.HandleFunc("/api/backup/test", a.handleBackupTest)
	a.mux.HandleFunc("/api/imgbed/test", a.handleImgbedTest)
	a.mux.HandleFunc("/api/register/events", a.handleRegisterEvents)
	a.mux.HandleFunc("/api/register/start", a.handleRegisterStart)
	a.mux.HandleFunc("/api/register/stop", a.handleRegisterStop)
	a.mux.HandleFunc("/api/register/reset", a.handleRegisterReset)
	a.mux.HandleFunc("/api/register", a.handleRegister)
	a.mux.HandleFunc("/api/cpa/pools/", a.handleCPAPoolItem)
	a.mux.HandleFunc("/api/cpa/pools", a.handleCPAPools)
	a.mux.HandleFunc("/api/sub2api/servers/", a.handleSub2APIServerItem)
	a.mux.HandleFunc("/api/sub2api/servers", a.handleSub2APIServers)
	a.mux.HandleFunc("/api/image-tasks", a.handleImageTasks)
	a.mux.HandleFunc("/api/image-tasks/generations", a.handleImageTaskGenerations)
	a.mux.HandleFunc("/api/image-tasks/edits", a.handleImageTaskEdits)
	a.mux.HandleFunc("/api/creation-tasks", a.handleImageTasks)
	a.mux.HandleFunc("/api/creation-tasks/image-generations", a.handleImageTaskGenerations)
	a.mux.HandleFunc("/api/creation-tasks/image-edits", a.handleImageTaskEdits)
	a.mux.HandleFunc("/v1/models", a.handleModels)
	a.mux.HandleFunc("/v1/chat/completions", a.handleChatCompletions)
	a.mux.HandleFunc("/v1/search", a.handleSearch)
	a.mux.HandleFunc("/v1/responses", a.handleResponses)
	a.mux.HandleFunc("/v1/messages", a.handleMessages)
	a.mux.HandleFunc("/v1/images/generations", a.handleImagesGenerations)
	a.mux.HandleFunc("/v1/images/edits", a.handleImagesEdits)
}

func (a *App) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":         true,
		"backend":    "go",
		"version":    a.config.Version,
		"uptime_sec": int(time.Since(a.started).Seconds()),
	})
}

func (a *App) handleVersion(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"version": a.config.Version})
}

func (a *App) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w)
		return
	}
	identity, ok := a.requireIdentity(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":         true,
		"version":    a.config.Version,
		"role":       identity.Role,
		"subject_id": identity.ID,
		"name":       identity.Name,
	})
}

func (a *App) handleAccounts(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.requireAdmin(w, r); !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{"items": a.accounts.ListAccounts()})
	case http.MethodPost:
		var body struct {
			Tokens []string `json:"tokens"`
		}
		if !decodeJSONBody(w, r, &body) {
			return
		}
		tokens := cleanStrings(body.Tokens)
		if len(tokens) == 0 {
			writeDetailError(w, http.StatusBadRequest, "tokens is required")
			return
		}
		result := a.accounts.AddAccounts(tokens)
		refreshResult := a.accounts.RefreshAccounts(r.Context(), tokens)
		result["refreshed"] = refreshResult["refreshed"]
		result["errors"] = refreshResult["errors"]
		if items, ok := refreshResult["items"]; ok {
			result["items"] = items
		}
		a.logEvent("account", "新增账号并刷新", map[string]any{
			"added":     result["added"],
			"skipped":   result["skipped"],
			"refreshed": refreshResult["refreshed"],
			"errors":    len(anySlice(refreshResult["errors"])),
		})
		writeJSON(w, http.StatusOK, result)
	case http.MethodDelete:
		var body struct {
			Tokens     []string `json:"tokens"`
			AccountIDs []string `json:"account_ids"`
		}
		if !decodeJSONBody(w, r, &body) {
			return
		}
		tokens := cleanStrings(body.Tokens)
		accountIDs := cleanStrings(body.AccountIDs)
		if len(tokens) > 0 {
			writeJSON(w, http.StatusOK, a.accounts.DeleteAccounts(tokens))
			return
		}
		if len(accountIDs) == 0 {
			writeDetailError(w, http.StatusBadRequest, "tokens or account_ids is required")
			return
		}
		if len(a.accounts.ListTokensByIDs(accountIDs)) == 0 {
			writeDetailError(w, http.StatusNotFound, "accounts not found")
			return
		}
		writeJSON(w, http.StatusOK, a.accounts.DeleteAccountsByIDs(accountIDs))
	default:
		writeMethodNotAllowed(w)
	}
}

func (a *App) handleAccountsRefresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w)
		return
	}
	if _, ok := a.requireAdmin(w, r); !ok {
		return
	}
	var body struct {
		AccessTokens []string `json:"access_tokens"`
		AccountIDs   []string `json:"account_ids"`
		Async        bool     `json:"async"`
	}
	if !decodeJSONBody(w, r, &body) {
		return
	}
	tokens := cleanStrings(body.AccessTokens)
	accountIDs := cleanStrings(body.AccountIDs)
	if len(tokens) == 0 && len(accountIDs) > 0 {
		tokens = a.accounts.ListTokensByIDs(accountIDs)
		if len(tokens) == 0 {
			writeDetailError(w, http.StatusNotFound, "accounts not found")
			return
		}
	}
	if len(tokens) == 0 {
		tokens = a.accounts.ListTokens()
	}
	if len(tokens) == 0 {
		writeDetailError(w, http.StatusBadRequest, "access_tokens or account_ids is required")
		return
	}
	autoAsync := len(tokens) > accountRefreshAutoAsyncThreshold
	if body.Async || autoAsync {
		job, err := a.accounts.StartRefreshJob(tokens)
		if err != nil {
			writeDetailError(w, http.StatusBadRequest, err.Error())
			return
		}
		a.logEvent("account", "提交账号刷新任务", map[string]any{
			"requested":  len(tokens),
			"job_id":     job["id"],
			"auto_async": autoAsync,
		})
		writeJSON(w, http.StatusAccepted, map[string]any{
			"job":       job,
			"items":     a.accounts.ListAccounts(),
			"refreshed": 0,
			"errors":    []map[string]string{},
			"async":     true,
		})
		return
	}
	result := a.accounts.RefreshAccounts(r.Context(), tokens)
	a.logEvent("account", "刷新账号", map[string]any{
		"requested": len(tokens),
		"refreshed": result["refreshed"],
		"errors":    len(anySlice(result["errors"])),
	})
	writeJSON(w, http.StatusOK, result)
}

func (a *App) handleAccountRefreshJob(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w)
		return
	}
	if _, ok := a.requireAdmin(w, r); !ok {
		return
	}
	id := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/accounts/refresh/jobs/"), "/")
	if id == "" {
		writeDetailError(w, http.StatusBadRequest, "job id is required")
		return
	}
	job := a.accounts.GetRefreshJob(id)
	if job == nil {
		writeDetailError(w, http.StatusNotFound, "refresh job not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"job": job, "items": a.accounts.ListAccounts()})
}

func (a *App) handleAccountsRelogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w)
		return
	}
	if _, ok := a.requireAdmin(w, r); !ok {
		return
	}
	var body struct {
		AccessTokens []string `json:"access_tokens"`
		AccountIDs   []string `json:"account_ids"`
	}
	if !decodeJSONBody(w, r, &body) {
		return
	}
	tokens := cleanStrings(body.AccessTokens)
	if len(tokens) == 0 {
		tokens = a.accounts.ListTokensByIDs(cleanStrings(body.AccountIDs))
	}
	if len(tokens) == 0 {
		writeDetailError(w, http.StatusBadRequest, "access_tokens or account_ids is required")
		return
	}
	job, err := a.accounts.StartReloginJob(tokens)
	if err != nil {
		writeDetailError(w, http.StatusBadRequest, err.Error())
		return
	}
	a.logEvent("account", "开始账号密码重登", map[string]any{"requested": job["requested"], "job_id": job["id"]})
	writeJSON(w, http.StatusOK, map[string]any{"job": job, "progress_id": job["id"], "items": a.accounts.ListAccounts()})
}

func (a *App) handleAccountReloginJob(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w)
		return
	}
	if _, ok := a.requireAdmin(w, r); !ok {
		return
	}
	id := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/accounts/re-login/jobs/"), "/")
	if strings.HasPrefix(r.URL.Path, "/api/accounts/re-login/progress/") {
		id = strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/accounts/re-login/progress/"), "/")
	}
	if id == "" {
		writeDetailError(w, http.StatusBadRequest, "job id is required")
		return
	}
	job := a.accounts.GetReloginJob(id)
	if job == nil {
		writeDetailError(w, http.StatusNotFound, "job not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"job": job, "items": a.accounts.ListAccounts()})
}

func (a *App) handleAccountsUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w)
		return
	}
	if _, ok := a.requireAdmin(w, r); !ok {
		return
	}
	var body struct {
		AccessToken  string  `json:"access_token"`
		AccountID    string  `json:"account_id"`
		Type         *string `json:"type"`
		Status       *string `json:"status"`
		Quota        *int    `json:"quota"`
		Email        *string `json:"email"`
		Password     *string `json:"password"`
		RefreshToken *string `json:"refresh_token"`
		SourceType   *string `json:"source_type"`
	}
	if !decodeJSONBody(w, r, &body) {
		return
	}
	accessToken := strings.TrimSpace(body.AccessToken)
	accountID := strings.TrimSpace(body.AccountID)
	if accessToken == "" && accountID == "" {
		writeDetailError(w, http.StatusBadRequest, "access_token or account_id is required")
		return
	}
	updates := map[string]any{}
	if body.Type != nil {
		updates["type"] = *body.Type
	}
	if body.Status != nil {
		updates["status"] = *body.Status
	}
	if body.Quota != nil {
		updates["quota"] = *body.Quota
	}
	if body.Email != nil {
		updates["email"] = *body.Email
	}
	if body.Password != nil {
		updates["password"] = *body.Password
	}
	if body.RefreshToken != nil {
		updates["refresh_token"] = *body.RefreshToken
	}
	if body.SourceType != nil {
		updates["source_type"] = *body.SourceType
	}
	if len(updates) == 0 {
		writeDetailError(w, http.StatusBadRequest, "还没有检测到改动，请修改后再保存")
		return
	}
	var item map[string]any
	if accessToken != "" {
		item = a.accounts.UpdateAccount(accessToken, updates)
	} else {
		item = a.accounts.UpdateAccountByID(accountID, updates)
	}
	if item == nil {
		writeDetailError(w, http.StatusNotFound, "account not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"item": item, "items": a.accounts.ListAccounts()})
}

func (a *App) handleModels(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w)
		return
	}
	if _, ok := a.requireIdentity(w, r); !ok {
		return
	}
	if a.models == nil {
		writeDetailError(w, http.StatusNotImplemented, "models upstream is not configured")
		return
	}
	result, err := a.models.ListModels(r.Context())
	if err != nil {
		writeDetailError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (a *App) handleChatCompletions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w)
		return
	}
	if _, ok := a.requireIdentity(w, r); !ok {
		return
	}
	if a.chat == nil {
		writeOpenAIError(w, http.StatusNotImplemented, "server_error", "chat completions upstream is not configured")
		return
	}
	var body map[string]any
	if !decodeJSONBody(w, r, &body) {
		return
	}
	token, err := a.accounts.GetAvailableAccessTokenFor(r.Context(), nil)
	if err != nil {
		writeOpenAIError(w, http.StatusServiceUnavailable, "no_available_account", err.Error())
		return
	}
	if protocol.IsStream(body) {
		a.streamChatCompletion(w, r, token, body)
		return
	}
	result, err := protocol.ChatCompletion(r.Context(), a.chat, token, body)
	if err != nil {
		if account.IsInvalidTokenError(err) {
			a.accounts.MarkInvalidToken(token)
		}
		writeOpenAIError(w, http.StatusBadGateway, "upstream_error", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (a *App) handleSearch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w)
		return
	}
	if _, ok := a.requireIdentity(w, r); !ok {
		return
	}
	if a.search == nil {
		writeOpenAIError(w, http.StatusNotImplemented, "server_error", "search upstream is not configured")
		return
	}
	var body struct {
		Prompt string `json:"prompt"`
		Model  string `json:"model"`
	}
	if !decodeJSONBody(w, r, &body) {
		return
	}
	prompt := strings.TrimSpace(body.Prompt)
	if prompt == "" {
		writeOpenAIError(w, http.StatusBadRequest, "invalid_request_error", "prompt is required")
		return
	}
	model := strings.TrimSpace(body.Model)
	if model == "" {
		model = protocol.SearchModel
	}
	token, err := a.accounts.GetAvailableAccessTokenFor(r.Context(), nil)
	if err != nil {
		writeOpenAIError(w, http.StatusServiceUnavailable, "no_available_account", err.Error())
		return
	}
	accountInfo := a.accounts.GetAccount(token)
	result, err := a.search.Search(r.Context(), token, prompt, model)
	if err != nil {
		if account.IsInvalidTokenError(err) {
			a.accounts.MarkInvalidToken(token)
		}
		writeOpenAIError(w, http.StatusBadGateway, "upstream_error", err.Error())
		return
	}
	if result == nil {
		result = map[string]any{}
	}
	if email := cleanResponseString(accountInfo["email"]); email != "" {
		result["_account_email"] = email
	}
	a.logEvent("call", "搜索成功", map[string]any{"model": model})
	writeJSON(w, http.StatusOK, result)
}

func (a *App) handleImageTasks(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w)
		return
	}
	identity, ok := a.requireIdentity(w, r)
	if !ok {
		return
	}
	if a.tasks == nil {
		writeDetailError(w, http.StatusNotImplemented, "image task upstream is not configured")
		return
	}
	writeJSON(w, http.StatusOK, a.tasks.ListTasks(identity, splitComma(r.URL.Query().Get("ids"))))
}

func (a *App) handleImageTaskGenerations(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w)
		return
	}
	identity, ok := a.requireIdentity(w, r)
	if !ok {
		return
	}
	if a.tasks == nil {
		writeDetailError(w, http.StatusNotImplemented, "image task upstream is not configured")
		return
	}
	var body struct {
		ClientTaskID string `json:"client_task_id"`
		Prompt       string `json:"prompt"`
		Model        string `json:"model"`
		Size         string `json:"size"`
	}
	if !decodeJSONBody(w, r, &body) {
		return
	}
	task, err := a.tasks.SubmitGeneration(identity, imagetask.SubmitGenerationRequest{
		ClientTaskID: body.ClientTaskID,
		Prompt:       body.Prompt,
		Model:        body.Model,
		Size:         body.Size,
	})
	if err != nil {
		writeDetailError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, task)
}

func (a *App) handleImageTaskEdits(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w)
		return
	}
	identity, ok := a.requireIdentity(w, r)
	if !ok {
		return
	}
	prompt, model, size, _, _, images, masks, err := parseImageEditRequest(r)
	if err != nil {
		writeDetailError(w, http.StatusBadRequest, err.Error())
		return
	}
	images, err = compositeEditMasks(images, masks)
	if err != nil {
		writeDetailError(w, http.StatusBadRequest, err.Error())
		return
	}
	if a.tasks == nil {
		writeDetailError(w, http.StatusNotImplemented, "image task upstream is not configured")
		return
	}
	task, err := a.tasks.SubmitEdit(identity, imagetask.SubmitEditRequest{
		ClientTaskID: firstFormValue(r, "client_task_id"),
		Prompt:       prompt,
		Model:        model,
		Size:         size,
		Images:       toProtocolImages(images),
	})
	if err != nil {
		writeDetailError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, task)
}

func (a *App) handleImagesGenerations(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w)
		return
	}
	if _, ok := a.requireIdentity(w, r); !ok {
		return
	}
	if a.image == nil {
		writeOpenAIError(w, http.StatusNotImplemented, "server_error", "image generation upstream is not configured")
		return
	}
	var body struct {
		Prompt         string `json:"prompt"`
		Model          string `json:"model"`
		Size           string `json:"size"`
		N              int    `json:"n"`
		ResponseFormat string `json:"response_format"`
	}
	if !decodeJSONBody(w, r, &body) {
		return
	}
	if strings.TrimSpace(body.Prompt) == "" {
		writeOpenAIError(w, http.StatusBadRequest, "invalid_request_error", "prompt is required")
		return
	}
	if body.N == 0 {
		body.N = 1
	}
	if body.N < 1 || body.N > 4 {
		writeOpenAIError(w, http.StatusBadRequest, "invalid_request_error", "n must be between 1 and 4")
		return
	}
	if strings.TrimSpace(body.ResponseFormat) == "" {
		body.ResponseFormat = "b64_json"
	}
	responseFormat := normalizeImageResponseFormat(body.ResponseFormat)
	requestedCount := body.N
	attemptCount := a.imageGenerationAttemptCount(requestedCount)
	data, errorsOut := a.generateImagesWithPool(r.Context(), body.Prompt, body.Model, body.Size, "b64_json", attemptCount)
	if len(data) == 0 && len(errorsOut) > 0 {
		err := errorsOut[0]
		if isNoAvailableImageAccountError(err) {
			a.logEvent("call", "图片生成失败：无可用账号", map[string]any{"model": body.Model, "size": body.Size, "error": err.Error()})
			writeOpenAIError(w, http.StatusServiceUnavailable, "no_available_account", err.Error())
			return
		}
		a.logEvent("call", "图片生成失败", map[string]any{"model": body.Model, "size": body.Size, "error": err.Error()})
		writeOpenAIError(w, http.StatusBadGateway, "upstream_error", err.Error())
		return
	}
	if len(data) == 0 {
		a.logEvent("call", "图片生成失败", map[string]any{"model": body.Model, "size": body.Size, "error": "image generation failed"})
		writeOpenAIError(w, http.StatusBadGateway, "upstream_error", "image generation failed")
		return
	}
	if len(errorsOut) > 0 {
		a.logEvent("call", "图片生成部分失败", map[string]any{
			"model":     body.Model,
			"size":      body.Size,
			"count":     len(data),
			"requested": requestedCount,
			"attempts":  attemptCount,
			"errors":    errorMessages(errorsOut),
		})
	}
	if len(data) > requestedCount {
		data = data[:requestedCount]
	}
	data, err := a.local.Images().PrepareResultData(data, resolveBaseURL(a.config.BaseURL, r))
	if err != nil {
		a.logEvent("call", "图片生成保存失败", map[string]any{"model": body.Model, "size": body.Size, "error": err.Error()})
		writeOpenAIError(w, http.StatusBadGateway, "upstream_error", err.Error())
		return
	}
	usage := protocol.ImageUsage(body.Prompt, len(data))
	a.local.Images().SaveHistoryRecord("/v1/images/generations", "generate", body.Model, body.Prompt, data, usage)
	a.logEvent("call", "图片生成成功", map[string]any{"model": body.Model, "size": body.Size, "count": len(data)})
	writeJSON(w, http.StatusOK, map[string]any{
		"created": time.Now().Unix(),
		"data":    imageResponseData(data, responseFormat),
		"usage":   usage,
	})
}

func (a *App) imageGenerationAttemptCount(requested int) int {
	if requested < 1 {
		requested = 1
	}
	multiplier := 1.0
	if a.config != nil && a.config.ImageRedundancyMultiplier >= 1.0 {
		multiplier = a.config.ImageRedundancyMultiplier
	}
	attempts := int(math.Round(float64(requested) * multiplier))
	if attempts < requested {
		attempts = requested
	}
	if attempts > 8 {
		attempts = 8
	}
	return attempts
}

type imageGenerationAttempt struct {
	Index int
	Data  []map[string]any
	Err   error
}

func (a *App) generateImagesWithPool(ctx context.Context, prompt, model, size, responseFormat string, count int) ([]map[string]any, []error) {
	if count <= 1 {
		data, err := protocol.GenerateImageWithPool(ctx, a.image, a.accounts, prompt, model, size, responseFormat)
		if err != nil {
			return nil, []error{err}
		}
		return data, nil
	}
	results := make(chan imageGenerationAttempt, count)
	for index := 0; index < count; index++ {
		go func(index int) {
			data, err := protocol.GenerateImageWithPool(ctx, a.image, a.accounts, prompt, model, size, responseFormat)
			results <- imageGenerationAttempt{Index: index, Data: data, Err: err}
		}(index)
	}

	ordered := make([]imageGenerationAttempt, count)
	for index := 0; index < count; index++ {
		result := <-results
		ordered[result.Index] = result
	}

	data := make([]map[string]any, 0, count)
	errorsOut := []error{}
	for _, result := range ordered {
		if result.Err != nil {
			errorsOut = append(errorsOut, result.Err)
			continue
		}
		data = append(data, result.Data...)
	}
	return data, errorsOut
}

func (a *App) handleImagesEdits(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w)
		return
	}
	if _, ok := a.requireIdentity(w, r); !ok {
		return
	}
	prompt, model, size, responseFormat, stream, images, masks, err := parseImageEditRequest(r)
	if err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid_request_error", err.Error())
		return
	}
	images, err = compositeEditMasks(images, masks)
	if err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid_request_error", err.Error())
		return
	}
	if a.image == nil {
		writeOpenAIError(w, http.StatusNotImplemented, "server_error", "image edit upstream is not configured")
		return
	}
	_ = responseFormat
	_ = stream
	var inputs []protocol.ImageInput
	for _, item := range images {
		inputs = append(inputs, protocol.ImageInput{
			Data:     item.Data,
			FileName: item.FileName,
			MimeType: item.MimeType,
		})
	}
	responseFormat = normalizeImageResponseFormat(responseFormat)
	data, err := protocol.EditImageWithPool(r.Context(), a.image, a.accounts, prompt, model, size, "b64_json", inputs)
	if err != nil {
		if isNoAvailableImageAccountError(err) {
			a.logEvent("call", "图片编辑失败：无可用账号", map[string]any{"model": model, "size": size, "error": err.Error()})
			writeOpenAIError(w, http.StatusServiceUnavailable, "no_available_account", err.Error())
			return
		}
		a.logEvent("call", "图片编辑失败", map[string]any{"model": model, "size": size, "image_count": len(inputs), "error": err.Error()})
		writeOpenAIError(w, http.StatusBadGateway, "upstream_error", err.Error())
		return
	}
	data, err = a.local.Images().PrepareResultData(data, resolveBaseURL(a.config.BaseURL, r))
	if err != nil {
		a.logEvent("call", "图片编辑保存失败", map[string]any{"model": model, "size": size, "image_count": len(inputs), "error": err.Error()})
		writeOpenAIError(w, http.StatusBadGateway, "upstream_error", err.Error())
		return
	}
	usage := protocol.ImageUsage(prompt, len(data))
	a.local.Images().SaveHistoryRecord("/v1/images/edits", "edit", model, prompt, data, usage)
	a.logEvent("call", "图片编辑成功", map[string]any{"model": model, "size": size, "image_count": len(inputs), "count": len(data)})
	writeJSON(w, http.StatusOK, map[string]any{
		"created": time.Now().Unix(),
		"data":    imageResponseData(data, responseFormat),
		"usage":   usage,
	})
}

func (a *App) handleResponses(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w)
		return
	}
	if _, ok := a.requireIdentity(w, r); !ok {
		return
	}
	var body map[string]any
	if !decodeJSONBody(w, r, &body) {
		return
	}
	if protocol.IsStream(body) {
		result, err := protocol.Response(body, a.chat, a.image, a.accounts)
		if err != nil {
			writeOpenAIError(w, http.StatusBadGateway, "upstream_error", err.Error())
			return
		}
		w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)
		writeSSEJSON(w, map[string]any{"type": "response.created", "response": map[string]any{
			"id":         result["id"],
			"object":     "response",
			"created_at": result["created_at"],
			"status":     "in_progress",
			"model":      result["model"],
			"output":     []any{},
		}})
		writeSSEJSON(w, map[string]any{"type": "response.completed", "response": result})
		_, _ = fmt.Fprint(w, "data: [DONE]\n\n")
		return
	}
	result, err := protocol.Response(body, a.chat, a.image, a.accounts)
	if err != nil {
		writeOpenAIError(w, http.StatusBadGateway, "upstream_error", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (a *App) handleMessages(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w)
		return
	}
	authHeader := strings.TrimSpace(r.Header.Get("Authorization"))
	if authHeader == "" {
		if apiKey := strings.TrimSpace(r.Header.Get("x-api-key")); apiKey != "" {
			authHeader = "Bearer " + apiKey
		}
	}
	if _, ok := a.requireIdentityWithHeader(w, r, authHeader); !ok {
		return
	}
	var body map[string]any
	if !decodeJSONBody(w, r, &body) {
		return
	}
	result, err := protocol.AnthropicMessage(body, a.chat, a.accounts)
	if err != nil {
		writeDetailError(w, http.StatusBadGateway, err.Error())
		return
	}
	if protocol.IsStream(body) {
		w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("data: [DONE]\n\n"))
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (a *App) streamChatCompletion(w http.ResponseWriter, r *http.Request, accessToken string, body map[string]any) {
	chunks, errCh, err := protocol.StreamChatCompletion(r.Context(), a.chat, accessToken, body)
	if err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid_request_error", err.Error())
		return
	}
	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)
	for chunk := range chunks {
		writeSSEJSON(w, chunk)
		if flusher != nil {
			flusher.Flush()
		}
	}
	if err := <-errCh; err != nil {
		if account.IsInvalidTokenError(err) {
			a.accounts.MarkInvalidToken(accessToken)
		}
		writeSSEJSON(w, openAIErrorPayload("upstream_error", err.Error()))
		if flusher != nil {
			flusher.Flush()
		}
		return
	}
	_, _ = fmt.Fprint(w, "data: [DONE]\n\n")
	if flusher != nil {
		flusher.Flush()
	}
}

func (a *App) requireIdentity(w http.ResponseWriter, r *http.Request) (*auth.Identity, bool) {
	identity := a.auth.AuthenticateBearer(r.Header.Get("Authorization"))
	if identity == nil {
		writeDetailError(w, http.StatusUnauthorized, "密钥无效或已失效，请重新登录")
		return nil, false
	}
	return identity, true
}

func (a *App) requireIdentityWithHeader(w http.ResponseWriter, r *http.Request, authorization string) (*auth.Identity, bool) {
	identity := a.auth.AuthenticateBearer(authorization)
	if identity == nil {
		writeDetailError(w, http.StatusUnauthorized, "密钥无效或已失效，请重新登录")
		return nil, false
	}
	return identity, true
}

func (a *App) requireAdmin(w http.ResponseWriter, r *http.Request) (*auth.Identity, bool) {
	identity, ok := a.requireIdentity(w, r)
	if !ok {
		return nil, false
	}
	if identity.Role != "admin" {
		writeDetailError(w, http.StatusForbidden, "需要管理员权限才能执行这个操作")
		return nil, false
	}
	return identity, true
}

func decodeJSONBody(w http.ResponseWriter, r *http.Request, target any) bool {
	defer r.Body.Close()
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2<<20))
	if err := decoder.Decode(target); err != nil {
		writeDetailError(w, http.StatusBadRequest, "invalid json body")
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeDetailError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]any{"detail": map[string]any{"error": message}})
}

func writeOpenAIError(w http.ResponseWriter, status int, errorType, message string) {
	writeJSON(w, status, openAIErrorPayload(errorType, message))
}

func isNoAvailableImageAccountError(err error) bool {
	if err == nil {
		return false
	}
	text := strings.ToLower(err.Error())
	return strings.Contains(text, "no available image quota") || strings.Contains(text, "no available account")
}

func errorMessages(errorsOut []error) []string {
	messages := make([]string, 0, len(errorsOut))
	for _, err := range errorsOut {
		if err != nil {
			messages = append(messages, err.Error())
		}
	}
	return messages
}

func normalizeImageResponseFormat(value string) string {
	if strings.EqualFold(strings.TrimSpace(value), "url") {
		return "url"
	}
	return "b64_json"
}

func imageResponseData(data []map[string]any, responseFormat string) []map[string]any {
	out := make([]map[string]any, 0, len(data))
	for _, item := range data {
		next := map[string]any{}
		if revisedPrompt := cleanResponseString(item["revised_prompt"]); revisedPrompt != "" {
			next["revised_prompt"] = revisedPrompt
		}
		if url := cleanResponseString(item["url"]); url != "" {
			next["url"] = url
		}
		if responseFormat == "b64_json" {
			if b64 := cleanResponseString(item["b64_json"]); b64 != "" {
				next["b64_json"] = b64
			}
		}
		out = append(out, next)
	}
	return out
}

func cleanResponseString(value any) string {
	if value == nil {
		return ""
	}
	return strings.TrimSpace(fmt.Sprint(value))
}

func openAIErrorPayload(errorType, message string) map[string]any {
	if strings.TrimSpace(errorType) == "" {
		errorType = "server_error"
	}
	return map[string]any{"error": map[string]any{"message": message, "type": errorType, "param": nil, "code": errorType}}
}

func writeSSEJSON(w http.ResponseWriter, payload any) {
	data, _ := json.Marshal(payload)
	_, _ = fmt.Fprintf(w, "data: %s\n\n", data)
}

func writeMethodNotAllowed(w http.ResponseWriter) {
	writeDetailError(w, http.StatusMethodNotAllowed, "method not allowed")
}

func cleanStrings(values []string) []string {
	out := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func splitComma(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return cleanStrings(strings.Split(value, ","))
}

func (a *App) logEvent(logType, summary string, detail map[string]any) {
	if a == nil || a.local == nil {
		return
	}
	a.local.Logs().Add(logType, summary, detail)
	log.Printf("[go-api] %s %s %s", logType, summary, compactLogDetail(detail))
}

func compactLogDetail(detail map[string]any) string {
	if len(detail) == 0 {
		return "{}"
	}
	data, err := json.Marshal(detail)
	if err != nil {
		return "{}"
	}
	return string(data)
}

func anySlice(value any) []any {
	switch items := value.(type) {
	case []any:
		return items
	case []map[string]string:
		out := make([]any, 0, len(items))
		for _, item := range items {
			out = append(out, item)
		}
		return out
	case []map[string]any:
		out := make([]any, 0, len(items))
		for _, item := range items {
			out = append(out, item)
		}
		return out
	default:
		return nil
	}
}

var ErrNotImplemented = errors.New("not implemented")

package register

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	mathrand "math/rand"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	browserproxy "chatgpt2api-go-backend/internal/proxy"
)

const (
	registerAuthBase                 = "https://auth.openai.com"
	registerPlatformBase             = "https://platform.openai.com"
	registerPlatformOAuthClientID    = "app_2SKx67EdpoN0G6j64rFvigXD"
	registerPlatformOAuthRedirectURI = registerPlatformBase + "/auth/callback"
	registerPlatformOAuthAudience    = "https://api.openai.com/v1"
	registerPlatformAuth0Client      = "eyJuYW1lIjoiYXV0aDAtc3BhLWpzIiwidmVyc2lvbiI6IjEuMjEuMCJ9"
	registerUserAgent                = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36"
	registerSecCHUA                  = `"Google Chrome";v="145", "Not?A_Brand";v="8", "Chromium";v="145"`
	registerSecCHUAFullVersionList   = `"Chromium";v="145.0.0.0", "Not:A-Brand";v="99.0.0.0", "Google Chrome";v="145.0.0.0"`
	registerSentinelBase             = "https://sentinel.openai.com"
	registerSentinelSDKLoader        = registerSentinelBase + "/backend-api/sentinel/sdk.js"
	registerSentinelSDK              = registerSentinelBase + "/sentinel/20260124ceb8/sdk.js"
	registerSentinelMaxAttempts      = 500000
	registerSentinelErrorPrefix      = "wQ8Lk5FbGpA2NcR9dShT6gYjU7VxZ4D"
)

var registerFirstNames = []string{"James", "Robert", "John", "Michael", "David", "Mary", "Emma", "Olivia"}
var registerLastNames = []string{"Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller"}

type attemptError struct {
	Reason  string
	Mailbox map[string]any
}

func (e *attemptError) Error() string {
	return e.Reason
}

func (e *attemptError) Provider() string {
	return clean(e.Mailbox["provider"])
}

func (e *attemptError) Domain() string {
	if domain := normalizeDomain(clean(e.Mailbox["domain"])); domain != "" {
		return domain
	}
	return normalizeDomain(clean(e.Mailbox["address"]))
}

type registerWorker struct {
	service  *Service
	index    int
	config   map[string]any
	mail     map[string]any
	factory  *mailProviderFactory
	client   *http.Client
	deviceID string
}

type sentinelTokens struct {
	token   string
	soToken string
}

type sentinelSDKHelperResult struct {
	Token      string `json:"token"`
	SOToken    string `json:"so_token"`
	SDKURL     string `json:"sdk_url"`
	SDKVersion string `json:"sdk_version"`
	TokenLen   int    `json:"token_len"`
	SOTokenLen int    `json:"so_token_len"`
	HasSOToken bool   `json:"has_so_token"`
}

type sentinelTokenGenerator struct {
	deviceID  string
	userAgent string
	sid       string
}

func newRegisterWorker(service *Service, index int, config map[string]any) (*registerWorker, error) {
	deviceID := newUUID()
	client, err := registerHTTPClient(clean(config["proxy"]), 60*time.Second, deviceID)
	if err != nil {
		return nil, err
	}
	return &registerWorker{
		service:  service,
		index:    index,
		config:   config,
		mail:     registerMailConfigForWorker(config),
		factory:  service.mail,
		client:   client,
		deviceID: deviceID,
	}, nil
}

func registerMailConfigForWorker(config map[string]any) map[string]any {
	mail := cloneMap(asMap(config["mail"]))
	if proxy := clean(config["proxy"]); proxy != "" {
		mail["proxy"] = proxy
	}
	return mail
}

func registerHTTPClient(proxy string, timeout time.Duration, deviceID string) (*http.Client, error) {
	base := browserproxy.NewService(proxy).BrowserHTTPClientWithProfile("chrome/windows", timeout)
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	base.Jar = jar
	authURL, _ := url.Parse(registerAuthBase)
	if authURL != nil {
		jar.SetCookies(authURL, []*http.Cookie{
			{Name: "oai-did", Value: deviceID, Domain: ".auth.openai.com", Path: "/"},
			{Name: "oai-did", Value: deviceID, Domain: "auth.openai.com", Path: "/"},
		})
	}
	return base, nil
}

func (w *registerWorker) close() {
	if w.client != nil {
		w.client.CloseIdleConnections()
	}
}

func (w *registerWorker) run(ctx context.Context) (map[string]any, error) {
	mailbox := map[string]any{}
	w.step("开始创建邮箱")
	mailbox, err := w.factory.CreateMailbox(ctx, w.mail, "")
	if err != nil {
		return nil, err
	}
	email := clean(mailbox["address"])
	if email == "" {
		return nil, &attemptError{Reason: "邮箱服务未返回 address", Mailbox: mailbox}
	}
	w.step("邮箱创建完成: " + email)
	password := randomPassword(16)
	firstName, lastName := randomName()
	if err := w.platformAuthorize(ctx, email); err != nil {
		return nil, &attemptError{Reason: err.Error(), Mailbox: mailbox}
	}
	if err := w.submitRegisterEmail(ctx, email); err != nil {
		return nil, &attemptError{Reason: err.Error(), Mailbox: mailbox}
	}
	if err := w.registerUser(ctx, email, password); err != nil {
		return nil, &attemptError{Reason: err.Error(), Mailbox: mailbox}
	}
	if err := w.sendOTP(ctx); err != nil {
		return nil, &attemptError{Reason: err.Error(), Mailbox: mailbox}
	}
	w.step("开始等待注册验证码")
	code, err := w.factory.WaitForCode(ctx, w.mail, mailbox)
	if err != nil {
		return nil, &attemptError{Reason: err.Error(), Mailbox: mailbox}
	}
	if code == "" {
		return nil, &attemptError{Reason: "等待注册验证码超时", Mailbox: mailbox}
	}
	w.step("收到注册验证码: " + code)
	if err := w.validateOTP(ctx, code); err != nil {
		return nil, &attemptError{Reason: err.Error(), Mailbox: mailbox}
	}
	if err := w.createAccount(ctx, firstName+" "+lastName, randomBirthdate()); err != nil {
		return nil, &attemptError{Reason: err.Error(), Mailbox: mailbox}
	}
	tokens, err := w.loginAndExchangeTokens(ctx, email, password, mailbox)
	if err != nil {
		return nil, &attemptError{Reason: err.Error(), Mailbox: mailbox}
	}
	return map[string]any{
		"email":             email,
		"password":          password,
		"access_token":      clean(tokens["access_token"]),
		"refresh_token":     clean(tokens["refresh_token"]),
		"id_token":          clean(tokens["id_token"]),
		"mail_provider":     clean(mailbox["provider"]),
		"mail_provider_ref": clean(mailbox["provider_ref"]),
		"mail_domain":       firstNonEmpty(normalizeDomain(clean(mailbox["domain"])), normalizeDomain(email)),
		"created_at":        nowISO(),
	}, nil
}

func (w *registerWorker) platformAuthorize(ctx context.Context, email string) error {
	w.step("开始 platform authorize")
	values := authorizeParams(email, w.deviceID, randomToken(24), randomToken(24), pkceChallenge())
	status, payload, err := w.request(ctx, http.MethodGet, registerAuthBase+"/api/accounts/authorize?"+values.Encode(), nil, w.navigateHeaders(registerPlatformBase+"/"), true)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("platform_authorize_http_%d%s", status, authorizeErrorDetail(payload))
	}
	w.step("platform authorize 完成")
	return nil
}

func (w *registerWorker) registerUser(ctx context.Context, email, password string) error {
	w.step("开始提交注册密码")
	headers := w.jsonHeaders(registerAuthBase + "/create-account/password")
	tokens, err := w.buildSentinelToken(ctx, "username_password_create")
	if err != nil {
		return err
	}
	headers["OpenAI-Sentinel-Token"] = tokens.token
	status, payload, err := w.request(ctx, http.MethodPost, registerAuthBase+"/api/accounts/user/register", map[string]any{
		"username": email,
		"password": password,
	}, headers, true)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		if failedToCreateAccount(payload) {
			w.step("注册失败提示: 邮箱域名很可能因滥用被封禁，请更换邮箱域名")
		}
		return fmt.Errorf("user_register_http_%d%s", status, responseDetail(payload))
	}
	w.step("提交注册密码完成")
	return nil
}

func (w *registerWorker) submitRegisterEmail(ctx context.Context, email string) error {
	w.step("开始提交注册邮箱")
	var lastPayload map[string]any
	for attempt := 0; attempt < 2; attempt++ {
		headers := w.jsonHeaders(registerAuthBase + "/log-in?usernameKind=email")
		tokens, err := w.buildSentinelToken(ctx, "authorize_continue")
		if err != nil {
			return err
		}
		headers["OpenAI-Sentinel-Token"] = tokens.token
		status, payload, err := w.request(ctx, http.MethodPost, registerAuthBase+"/api/accounts/authorize/continue", map[string]any{
			"username": map[string]any{"kind": "email", "value": email},
		}, headers, false)
		if err != nil {
			return err
		}
		if status == http.StatusConflict && attempt == 0 {
			lastPayload = payload
			w.step("注册邮箱提交 invalid_state，重新 authorize 后重试")
			if err := w.platformAuthorize(ctx, email); err != nil {
				return err
			}
			continue
		}
		if status != http.StatusOK {
			if len(payload) == 0 {
				payload = lastPayload
			}
			return fmt.Errorf("register_email_submit_http_%d%s", status, responseDetail(payload))
		}
		w.step("注册邮箱提交完成")
		return nil
	}
	return fmt.Errorf("register_email_submit_failed")
}

func (w *registerWorker) sendOTP(ctx context.Context) error {
	w.step("开始发送验证码")
	status, _, err := w.request(ctx, http.MethodGet, registerAuthBase+"/api/accounts/email-otp/send", nil, w.navigateHeaders(registerAuthBase+"/create-account/password"), true)
	if err != nil {
		return err
	}
	if status != http.StatusOK && status != http.StatusFound {
		return fmt.Errorf("send_otp_http_%d", status)
	}
	w.step("发送验证码完成")
	return nil
}

func (w *registerWorker) validateOTP(ctx context.Context, code string) error {
	w.step("开始校验验证码 " + code)
	if _, err := w.validateOTPCode(ctx, code); err != nil {
		return err
	}
	w.step("验证码校验完成")
	return nil
}

func (w *registerWorker) createAccount(ctx context.Context, name, birthdate string) error {
	w.step("开始创建账号资料")
	headers := w.jsonHeaders(registerAuthBase + "/about-you")
	tokens, err := w.buildSentinelToken(ctx, "oauth_create_account")
	if err != nil {
		return err
	}
	headers["OpenAI-Sentinel-Token"] = tokens.token
	if tokens.soToken != "" {
		headers["OpenAI-Sentinel-SO-Token"] = tokens.soToken
	} else {
		return fmt.Errorf("create_account_missing_sentinel_so_token")
	}
	w.service.appendLog(
		fmt.Sprintf("[任务%d] create_account 携带 Sentinel 双 token: sentinel_len=%d, so_len=%d",
			w.index, len(tokens.token), len(tokens.soToken)),
		"info",
	)
	status, payload, err := w.request(ctx, http.MethodPost, registerAuthBase+"/api/accounts/create_account", map[string]any{
		"name":      name,
		"birthdate": birthdate,
	}, headers, true)
	if err != nil {
		return err
	}
	if status != http.StatusOK && status != http.StatusFound {
		if failedToCreateAccount(payload) {
			w.step("创建账号失败提示: 邮箱域名很可能因滥用被封禁，请更换邮箱域名")
		} else if registrationDisallowed(payload) {
			w.step("创建账号失败提示: 上游拒绝这组注册信息，通常与邮箱域名、代理 IP 或注册频率风控有关")
		}
		return fmt.Errorf("create_account_http_%d%s", status, responseDetail(payload))
	}
	w.step("创建账号资料完成")
	return nil
}

func (w *registerWorker) loginAndExchangeTokens(ctx context.Context, email, password string, mailbox map[string]any) (map[string]any, error) {
	w.step("开始独立登录换 token")
	originalClient := w.client
	originalDeviceID := w.deviceID
	loginDeviceID := newUUID()
	loginClient, err := w.replaceRegisterSession(loginDeviceID)
	if err != nil {
		return nil, err
	}
	defer func() {
		if loginClient != nil {
			loginClient.CloseIdleConnections()
		}
		w.client = originalClient
		w.deviceID = originalDeviceID
	}()
	codeVerifier, codeChallenge := generatePKCE()
	values := authorizeParams(email, loginDeviceID, randomToken(24), randomToken(24), codeChallenge)
	authorizeLogin := func() (string, error) {
		status, _, _, finalURL, err := w.requestDetailedWithFinalURL(ctx, http.MethodGet, registerAuthBase+"/api/accounts/authorize?"+values.Encode(), nil, w.navigateHeaders(registerPlatformBase+"/"), true)
		if err != nil {
			return "", err
		}
		if code := oauthCode(finalURL); code != "" {
			return code, nil
		}
		if status != http.StatusOK {
			return "", fmt.Errorf("platform_login_authorize_http_%d", status)
		}
		return "", nil
	}
	callbackCode, err := authorizeLogin()
	if err != nil {
		return nil, err
	}
	w.step("登录 authorize 完成")
	if callbackCode != "" {
		if tokens, tokenErr := w.exchangeOAuthCode(ctx, codeVerifier, callbackCode); tokenErr == nil {
			w.step("authorize 已返回 OAuth code，跳过密码校验")
			return tokens, nil
		} else {
			w.step("authorize 已返回 OAuth code，但 token 换取失败，继续尝试密码校验")
		}
	}
	status, payload, err := w.submitLoginEmail(ctx, email)
	if err != nil {
		return nil, err
	}
	if status == http.StatusConflict {
		w.step("邮箱提交 invalid_state，重建登录会话后重试")
		loginClient.CloseIdleConnections()
		loginClient, err = w.replaceRegisterSession(loginDeviceID)
		if err != nil {
			return nil, err
		}
		callbackCode, err = authorizeLogin()
		if err != nil {
			return nil, err
		}
		if callbackCode != "" {
			return w.exchangeOAuthCode(ctx, codeVerifier, callbackCode)
		}
		status, payload, err = w.submitLoginEmail(ctx, email)
		if err != nil {
			return nil, err
		}
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("email_submit_http_%d%s", status, responseDetail(payload))
	}
	w.step("邮箱提交完成")
	headers := w.jsonHeaders(registerAuthBase + "/log-in/password")
	st, err := w.buildSentinelToken(ctx, "password_verify")
	if err != nil {
		return nil, err
	}
	headers["OpenAI-Sentinel-Token"] = st.token
	status, payload, err = w.request(ctx, http.MethodPost, registerAuthBase+"/api/accounts/password/verify", map[string]any{
		"password": password,
	}, headers, false)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("password_verify_http_%d", status)
	}
	w.step("密码校验完成")
	continueURL := clean(payload["continue_url"])
	page := asMap(payload["page"])
	if clean(page["type"]) == "email_otp_verification" || strings.Contains(continueURL, "email-verification") || strings.Contains(continueURL, "email-otp") {
		w.step("独立登录需要邮箱验证码")
		code, waitErr := w.factory.WaitForCode(ctx, w.mail, mailbox)
		if waitErr != nil {
			return nil, waitErr
		}
		if code == "" {
			return nil, fmt.Errorf("独立登录等待验证码超时")
		}
		otpPayload, otpErr := w.validateOTPCode(ctx, code)
		if otpErr != nil {
			return nil, otpErr
		}
		if next := clean(otpPayload["continue_url"]); next != "" {
			continueURL = next
		}
		w.step("独立登录验证码校验完成")
	}
	if continueURL == "" {
		continueURL = registerAuthBase + "/sign-in-with-chatgpt/codex/consent"
	}
	code, err := w.followConsentForCode(ctx, continueURL)
	if err != nil {
		return nil, err
	}
	if code == "" {
		return nil, fmt.Errorf("token exchange callback code not found")
	}
	tokens, err := w.exchangeOAuthCode(ctx, codeVerifier, code)
	if err != nil {
		return nil, err
	}
	w.step("token 换取完成")
	return tokens, nil
}

func (w *registerWorker) exchangeOAuthCode(ctx context.Context, codeVerifier, code string) (map[string]any, error) {
	status, tokenPayload, err := w.requestForm(ctx, registerAuthBase+"/oauth/token", url.Values{
		"grant_type":    []string{"authorization_code"},
		"code":          []string{code},
		"redirect_uri":  []string{registerPlatformOAuthRedirectURI},
		"client_id":     []string{registerPlatformOAuthClientID},
		"code_verifier": []string{codeVerifier},
	})
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("oauth_token_http_%d", status)
	}
	accessToken := clean(tokenPayload["access_token"])
	refreshToken := clean(tokenPayload["refresh_token"])
	idToken := clean(tokenPayload["id_token"])
	if accessToken == "" || refreshToken == "" || idToken == "" {
		return nil, fmt.Errorf("token exchange response missing access_token, refresh_token, or id_token")
	}
	return map[string]any{"access_token": accessToken, "refresh_token": refreshToken, "id_token": idToken}, nil
}

func (w *registerWorker) replaceRegisterSession(deviceID string) (*http.Client, error) {
	client, err := registerHTTPClient(clean(w.config["proxy"]), 60*time.Second, deviceID)
	if err != nil {
		return nil, err
	}
	w.client = client
	w.deviceID = deviceID
	return client, nil
}

func (w *registerWorker) submitLoginEmail(ctx context.Context, email string) (int, map[string]any, error) {
	w.step("开始提交邮箱")
	headers := w.jsonHeaders(registerAuthBase + "/log-in?usernameKind=email")
	tokens, err := w.buildSentinelToken(ctx, "authorize_continue")
	if err != nil {
		return 0, nil, err
	}
	headers["OpenAI-Sentinel-Token"] = tokens.token
	return w.request(ctx, http.MethodPost, registerAuthBase+"/api/accounts/authorize/continue", map[string]any{
		"username": map[string]any{"kind": "email", "value": email},
	}, headers, false)
}

func (w *registerWorker) followConsentForCode(ctx context.Context, continueURL string) (string, error) {
	current := continueURL
	if strings.HasPrefix(current, "/") {
		current = registerAuthBase + current
	}
	noRedirect := *w.client
	noRedirect.CheckRedirect = func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }
	for i := 0; i < 10; i++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, current, nil)
		if err != nil {
			return "", err
		}
		for key, value := range w.navigateHeaders(current) {
			req.Header.Set(key, value)
		}
		resp, err := noRedirect.Do(req)
		if err != nil {
			return "", err
		}
		_ = resp.Body.Close()
		if code := oauthCode(resp.Request.URL.String()); code != "" {
			return code, nil
		}
		location := strings.TrimSpace(resp.Header.Get("Location"))
		if code := oauthCode(location); code != "" {
			return code, nil
		}
		if location == "" || (resp.StatusCode < 300 || resp.StatusCode >= 400) {
			break
		}
		next, err := resolveLocation(current, location)
		if err != nil {
			return "", err
		}
		current = next
	}
	return w.selectWorkspaceForConsentCode(ctx, continueURL)
}

func (w *registerWorker) validateOTPCode(ctx context.Context, code string) (map[string]any, error) {
	status, payload, err := w.request(ctx, http.MethodPost, registerAuthBase+"/api/accounts/email-otp/validate", map[string]any{"code": code}, w.jsonHeaders(registerAuthBase+"/email-verification"), true)
	if err != nil {
		return nil, err
	}
	if status == http.StatusOK {
		return payload, nil
	}
	headers := w.jsonHeaders(registerAuthBase + "/email-verification")
	tokens, tokenErr := w.buildSentinelToken(ctx, "authorize_continue")
	if tokenErr != nil {
		return nil, fmt.Errorf("validate_otp_http_%d; sentinel fallback failed: %w", status, tokenErr)
	}
	headers["OpenAI-Sentinel-Token"] = tokens.token
	status, payload, err = w.request(ctx, http.MethodPost, registerAuthBase+"/api/accounts/email-otp/validate", map[string]any{"code": code}, headers, true)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("validate_otp_http_%d", status)
	}
	return payload, nil
}

func (w *registerWorker) selectWorkspaceForConsentCode(ctx context.Context, consentURL string) (string, error) {
	workspaceID := w.authSessionWorkspaceID()
	if workspaceID == "" {
		return "", nil
	}
	if strings.HasPrefix(consentURL, "/") {
		consentURL = registerAuthBase + consentURL
	}
	headers := w.jsonHeaders(consentURL)
	status, wsPayload, wsHeaders, err := w.requestDetailed(ctx, http.MethodPost, registerAuthBase+"/api/accounts/workspace/select", map[string]any{"workspace_id": workspaceID}, headers, false)
	if err != nil {
		return "", err
	}
	if code := oauthCode(wsHeaders.Get("Location")); code != "" {
		return code, nil
	}
	if code := oauthCode(clean(wsPayload["continue_url"])); code != "" {
		return code, nil
	}
	if status < 200 || status >= 400 {
		return "", fmt.Errorf("workspace_select_http_%d", status)
	}
	data := asMap(wsPayload["data"])
	orgs := asMapSlice(data["orgs"])
	if len(orgs) == 0 {
		return "", nil
	}
	orgID := clean(orgs[0]["id"])
	if orgID == "" {
		return "", nil
	}
	orgBody := map[string]any{"org_id": orgID}
	if projects := asMapSlice(orgs[0]["projects"]); len(projects) > 0 {
		if projectID := clean(projects[0]["id"]); projectID != "" {
			orgBody["project_id"] = projectID
		}
	}
	orgReferer := firstNonEmpty(clean(wsPayload["continue_url"]), consentURL)
	status, orgPayload, orgHeaders, err := w.requestDetailed(ctx, http.MethodPost, registerAuthBase+"/api/accounts/organization/select", orgBody, w.jsonHeaders(orgReferer), false)
	if err != nil {
		return "", err
	}
	if code := oauthCode(orgHeaders.Get("Location")); code != "" {
		return code, nil
	}
	if code := oauthCode(clean(orgPayload["continue_url"])); code != "" {
		return code, nil
	}
	if status < 200 || status >= 400 {
		return "", fmt.Errorf("organization_select_http_%d", status)
	}
	return "", nil
}

func (w *registerWorker) authSessionWorkspaceID() string {
	if w.client == nil || w.client.Jar == nil {
		return ""
	}
	authURL, err := url.Parse(registerAuthBase)
	if err != nil {
		return ""
	}
	raw := ""
	for _, cookie := range w.client.Jar.Cookies(authURL) {
		if cookie.Name == "oai-client-auth-session" {
			raw = cookie.Value
			break
		}
	}
	if raw == "" {
		return ""
	}
	firstPart := strings.Split(raw, ".")[0]
	if padding := len(firstPart) % 4; padding != 0 {
		firstPart += strings.Repeat("=", 4-padding)
	}
	data, err := base64.URLEncoding.DecodeString(firstPart)
	if err != nil {
		return ""
	}
	var payload map[string]any
	if json.Unmarshal(data, &payload) != nil {
		return ""
	}
	workspaces := asMapSlice(payload["workspaces"])
	if len(workspaces) == 0 {
		return ""
	}
	return clean(workspaces[0]["id"])
}

func (w *registerWorker) buildSentinelToken(ctx context.Context, flow string) (*sentinelTokens, error) {
	tokens, err := w.buildSentinelTokenWithSDK(ctx, flow)
	if err == nil {
		return tokens, nil
	}
	if os.Getenv("CHATGPT2API_ALLOW_LEGACY_SENTINEL") == "1" {
		w.service.appendLog(
			fmt.Sprintf("[任务%d] Sentinel SDK helper 失败，按环境变量回退旧逻辑: %v", w.index, err),
			"yellow",
		)
		return w.buildLegacySentinelToken(ctx, flow)
	}
	return nil, err
}

func (w *registerWorker) buildSentinelTokenWithSDK(ctx context.Context, flow string) (*sentinelTokens, error) {
	nodePath := strings.TrimSpace(os.Getenv("NODE_BINARY"))
	var err error
	if nodePath == "" {
		nodePath, err = exec.LookPath("node")
		if err != nil {
			return nil, fmt.Errorf("sentinel_sdk_helper_node_missing")
		}
	}
	helperPath, err := sentinelHelperPath()
	if err != nil {
		return nil, err
	}
	needSO := flow == "oauth_create_account"
	payload := map[string]any{
		"flow":       flow,
		"device_id":  w.deviceID,
		"need_so":    needSO,
		"user_agent": registerUserAgent,
		"sec_ch_ua":  registerSecCHUA,
		"loader_url": registerSentinelSDKLoader,
		"proxy":      clean(w.config["proxy"]),
	}
	body, err := compactJSONBytes(payload)
	if err != nil {
		return nil, err
	}
	timeout := 45 * time.Second
	if needSO {
		timeout = 80 * time.Second
	}
	cmdCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(cmdCtx, nodePath, helperPath)
	cmd.Stdin = bytes.NewReader(body)
	env := os.Environ()
	if proxy := clean(w.config["proxy"]); proxy != "" {
		env = append(env, "HTTPS_PROXY="+proxy, "HTTP_PROXY="+proxy)
	}
	cmd.Env = env
	output, err := cmd.CombinedOutput()
	if cmdCtx.Err() == context.DeadlineExceeded {
		return nil, fmt.Errorf("sentinel_sdk_helper_timeout")
	}
	if err != nil {
		detail := strings.TrimSpace(string(output))
		if len(detail) > 500 {
			detail = detail[:500]
		}
		if detail != "" {
			return nil, fmt.Errorf("sentinel_sdk_helper_failed: %s", detail)
		}
		return nil, fmt.Errorf("sentinel_sdk_helper_failed: %w", err)
	}
	var result sentinelSDKHelperResult
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, fmt.Errorf("sentinel_sdk_helper_invalid_json: %w", err)
	}
	result.Token = strings.TrimSpace(result.Token)
	result.SOToken = strings.TrimSpace(result.SOToken)
	if result.Token == "" {
		return nil, fmt.Errorf("sentinel_sdk_helper_empty_token")
	}
	if needSO {
		w.service.appendLog(
			fmt.Sprintf("[任务%d] Sentinel SDK token 已生成: flow=%s, sdk=%s, sentinel_len=%d, so_len=%d, has_so=%v",
				w.index, flow, firstNonEmpty(result.SDKVersion, "unknown"), len(result.Token), len(result.SOToken), result.SOToken != ""),
			"info",
		)
	}
	return &sentinelTokens{token: result.Token, soToken: result.SOToken}, nil
}

func sentinelHelperPath() (string, error) {
	candidates := []string{}
	if configured := strings.TrimSpace(os.Getenv("CHATGPT2API_SENTINEL_HELPER")); configured != "" {
		candidates = append(candidates, configured)
	}
	candidates = append(candidates,
		"scripts/sentinel_token_helper.mjs",
		"./scripts/sentinel_token_helper.mjs",
		"/app/scripts/sentinel_token_helper.mjs",
	)
	for _, candidate := range candidates {
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("sentinel_sdk_helper_missing")
}

func (w *registerWorker) buildLegacySentinelToken(ctx context.Context, flow string) (*sentinelTokens, error) {
	generator := newSentinelTokenGenerator(w.deviceID, registerUserAgent)
	reqsToken := generator.generateRequirementsToken()
	reqPayload := map[string]any{"p": reqsToken, "id": w.deviceID, "flow": flow}
	body, err := compactJSONBytes(reqPayload)
	if err != nil {
		return nil, err
	}
	status, payload, err := w.requestRawJSON(ctx, http.MethodPost, registerSentinelBase+"/backend-api/sentinel/req", body, sentinelHeaders())
	if err != nil {
		return nil, err
	}
	challengeToken := clean(payload["token"])
	if status != http.StatusOK || challengeToken == "" {
		return nil, fmt.Errorf("sentinel_req_failed_%d", status)
	}
	proof := asMap(payload["proofofwork"])
	pValue := generator.generateRequirementsToken()
	if boolValue(proof["required"], false) && clean(proof["seed"]) != "" {
		pValue = generator.generateToken(clean(proof["seed"]), firstNonEmpty(clean(proof["difficulty"]), "0"))
	}
	tokenPayload := map[string]any{"p": pValue, "t": "", "c": challengeToken, "id": w.deviceID, "flow": flow}
	data, err := compactJSONBytes(tokenPayload)
	if err != nil {
		return nil, err
	}

	// 生成 SO token（Sentinel Observer），仅在 oauth_create_account 阶段需要
	var soToken string
	if flow == "oauth_create_account" {
		keys := make([]string, 0, len(payload))
		for k := range payload {
			keys = append(keys, k)
		}
		w.service.appendLog(
			fmt.Sprintf("[任务%d] Sentinel legacy resp keys=%v, has_so=%v",
				w.index, keys, payload["so"] != nil),
			"info",
		)
		soData := asMap(payload["so"])
		collectorDX := clean(soData["collector_dx"])
		if boolValue(soData["required"], false) && collectorDX != "" {
			// 按官方前端逻辑等待 5000ms 采集 observer 数据
			time.Sleep(5000 * time.Millisecond)
			soToken = generateSOTokenFromCollectorDX(collectorDX, reqsToken)
			w.service.appendLog(
				fmt.Sprintf("[任务%d] Sentinel legacy SO token 已生成: collector_dx_len=%d, so_len=%d, has_snapshot=%v",
					w.index, len(collectorDX), len(soToken), clean(soData["snapshot_dx"]) != ""),
				"info",
			)
		} else {
			w.service.appendLog(
				fmt.Sprintf("[任务%d] Sentinel so 字段无有效的 collector_dx（required=%v, has_collector=%v）", w.index, soData["required"], collectorDX != ""),
				"info",
			)
		}
	}
	return &sentinelTokens{token: string(data), soToken: soToken}, nil
}

func (w *registerWorker) requestRawJSON(ctx context.Context, method, target string, body []byte, headers map[string]string) (int, map[string]any, error) {
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		req, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(body))
		if err != nil {
			return 0, nil, err
		}
		for key, value := range headers {
			if strings.TrimSpace(value) != "" {
				req.Header.Set(key, value)
			}
		}
		resp, err := w.client.Do(req)
		if err != nil {
			lastErr = err
			if attempt < 2 {
				time.Sleep(time.Second)
				continue
			}
			return 0, nil, err
		}
		defer resp.Body.Close()
		payload := map[string]any{}
		decoder := json.NewDecoder(resp.Body)
		decoder.UseNumber()
		_ = decoder.Decode(&payload)
		return resp.StatusCode, payload, nil
	}
	if lastErr != nil {
		return 0, nil, lastErr
	}
	return 0, nil, fmt.Errorf("raw request failed")
}

func (w *registerWorker) request(ctx context.Context, method, target string, payload any, headers map[string]string, followRedirects bool) (int, map[string]any, error) {
	status, payloadMap, _, err := w.requestDetailed(ctx, method, target, payload, headers, followRedirects)
	return status, payloadMap, err
}

func (w *registerWorker) requestDetailed(ctx context.Context, method, target string, payload any, headers map[string]string, followRedirects bool) (int, map[string]any, http.Header, error) {
	status, payloadMap, responseHeaders, _, err := w.requestDetailedWithFinalURL(ctx, method, target, payload, headers, followRedirects)
	return status, payloadMap, responseHeaders, err
}

func (w *registerWorker) requestDetailedWithFinalURL(ctx context.Context, method, target string, payload any, headers map[string]string, followRedirects bool) (int, map[string]any, http.Header, string, error) {
	var bodyData []byte
	if payload != nil {
		data, err := json.Marshal(payload)
		if err != nil {
			return 0, nil, nil, "", err
		}
		bodyData = data
	}
	client := w.client
	if !followRedirects {
		noRedirect := *w.client
		noRedirect.CheckRedirect = func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }
		client = &noRedirect
	}
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		redirectCodeURL := ""
		if followRedirects {
			withRedirectHistory := *w.client
			previousCheckRedirect := withRedirectHistory.CheckRedirect
			withRedirectHistory.CheckRedirect = func(req *http.Request, via []*http.Request) error {
				if redirectCodeURL == "" {
					if oauthCode(req.URL.String()) != "" {
						redirectCodeURL = req.URL.String()
					}
				}
				if previousCheckRedirect != nil {
					return previousCheckRedirect(req, via)
				}
				if len(via) >= 10 {
					return fmt.Errorf("stopped after 10 redirects")
				}
				return nil
			}
			client = &withRedirectHistory
		}
		var body io.Reader
		if payload != nil {
			body = bytes.NewReader(bodyData)
		}
		req, err := http.NewRequestWithContext(ctx, method, target, body)
		if err != nil {
			return 0, nil, nil, "", err
		}
		for key, value := range headers {
			if strings.TrimSpace(value) != "" {
				req.Header.Set(key, value)
			}
		}
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			if attempt < 2 {
				time.Sleep(time.Second)
				continue
			}
			return 0, nil, nil, "", err
		}
		defer resp.Body.Close()
		payloadMap := map[string]any{}
		if strings.Contains(resp.Header.Get("Content-Type"), "application/json") {
			decoder := json.NewDecoder(resp.Body)
			decoder.UseNumber()
			_ = decoder.Decode(&payloadMap)
		} else {
			data, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
			if len(data) > 0 {
				payloadMap["body"] = string(data)
			}
		}
		finalURL := ""
		if resp.Request != nil && resp.Request.URL != nil {
			finalURL = resp.Request.URL.String()
		}
		if redirectCodeURL != "" {
			finalURL = redirectCodeURL
		}
		return resp.StatusCode, payloadMap, resp.Header.Clone(), finalURL, nil
	}
	if lastErr != nil {
		return 0, nil, nil, "", lastErr
	}
	return 0, nil, nil, "", fmt.Errorf("request failed")
}

func (w *registerWorker) requestForm(ctx context.Context, target string, form url.Values) (int, map[string]any, error) {
	body := []byte(form.Encode())
	headers := map[string]string{"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json", "User-Agent": registerUserAgent}
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
		if err != nil {
			return 0, nil, err
		}
		for key, value := range headers {
			req.Header.Set(key, value)
		}
		resp, err := w.client.Do(req)
		if err != nil {
			lastErr = err
			if attempt < 2 {
				time.Sleep(time.Second)
				continue
			}
			return 0, nil, err
		}
		defer resp.Body.Close()
		payload := map[string]any{}
		decoder := json.NewDecoder(resp.Body)
		decoder.UseNumber()
		_ = decoder.Decode(&payload)
		return resp.StatusCode, payload, nil
	}
	if lastErr != nil {
		return 0, nil, lastErr
	}
	return 0, nil, fmt.Errorf("form request failed")
}

func (w *registerWorker) navigateHeaders(referer string) map[string]string {
	headers := map[string]string{
		"Accept":                      "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
		"Accept-Language":             "en-US,en;q=0.9",
		"Upgrade-Insecure-Requests":   "1",
		"User-Agent":                  registerUserAgent,
		"sec-ch-ua":                   registerSecCHUA,
		"sec-ch-ua-arch":              `"x86_64"`,
		"sec-ch-ua-bitness":           `"64"`,
		"sec-ch-ua-full-version-list": registerSecCHUAFullVersionList,
		"sec-ch-ua-mobile":            "?0",
		"sec-ch-ua-model":             `""`,
		"sec-ch-ua-platform":          `"Windows"`,
		"sec-ch-ua-platform-version":  `"10.0.0"`,
		"sec-fetch-dest":              "document",
		"sec-fetch-mode":              "navigate",
		"sec-fetch-site":              "same-origin",
		"sec-fetch-user":              "?1",
	}
	if referer != "" {
		headers["Referer"] = referer
	}
	return headers
}

func (w *registerWorker) jsonHeaders(referer string) map[string]string {
	headers := map[string]string{
		"Accept":                      "application/json",
		"Accept-Language":             "en-US,en;q=0.9",
		"Content-Type":                "application/json",
		"Origin":                      registerAuthBase,
		"priority":                    "u=1, i",
		"User-Agent":                  registerUserAgent,
		"oai-device-id":               w.deviceID,
		"sec-ch-ua":                   registerSecCHUA,
		"sec-ch-ua-arch":              `"x86_64"`,
		"sec-ch-ua-bitness":           `"64"`,
		"sec-ch-ua-full-version-list": registerSecCHUAFullVersionList,
		"sec-ch-ua-mobile":            "?0",
		"sec-ch-ua-model":             `""`,
		"sec-ch-ua-platform":          `"Windows"`,
		"sec-ch-ua-platform-version":  `"10.0.0"`,
		"sec-fetch-dest":              "empty",
		"sec-fetch-mode":              "cors",
		"sec-fetch-site":              "same-origin",
	}
	for key, value := range traceHeaders() {
		headers[key] = value
	}
	if referer != "" {
		headers["Referer"] = referer
	}
	return headers
}

func (w *registerWorker) step(text string) {
	w.service.appendLog(fmt.Sprintf("[任务%d] %s", w.index, text), "info")
}

func authorizeErrorDetail(payload map[string]any) string {
	if isCloudflareChallengePayload(payload) {
		return ": cloudflare_challenge"
	}
	errPayload := asMap(payload["error"])
	if len(errPayload) == 0 {
		return responseDetail(payload)
	}
	parts := []string{}
	if code := clean(errPayload["code"]); code != "" {
		parts = append(parts, code)
	}
	if message := clean(errPayload["message"]); message != "" {
		parts = append(parts, message)
	}
	if len(parts) == 0 {
		return responseDetail(payload)
	}
	return ": " + strings.Join(parts, " - ")
}

func responseDetail(payload map[string]any) string {
	if len(payload) == 0 {
		return ""
	}
	if isCloudflareChallengePayload(payload) {
		return `, detail={"error":"cloudflare_challenge","message":"upstream returned Cloudflare challenge page"}`
	}
	data, err := json.Marshal(payload)
	if err != nil || len(data) == 0 {
		return ""
	}
	return ", detail=" + string(data)
}

func isCloudflareChallengePayload(payload map[string]any) bool {
	body := strings.ToLower(clean(payload["body"]))
	return strings.Contains(body, "challenges.cloudflare.com") ||
		strings.Contains(body, "<title>just a moment") ||
		strings.Contains(body, "<title>attention required! | cloudflare") ||
		strings.Contains(body, "cf-chl-") ||
		strings.Contains(body, "__cf_chl_") ||
		strings.Contains(body, "cf-browser-verification")
}

func failedToCreateAccount(payload map[string]any) bool {
	return clean(payload["message"]) == "Failed to create account. Please try again."
}

func registrationDisallowed(payload map[string]any) bool {
	errPayload := asMap(payload["error"])
	return clean(errPayload["code"]) == "registration_disallowed"
}

func randomPassword(length int) string {
	if length < 8 {
		length = 8
	}
	upper := "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	lower := "abcdefghijklmnopqrstuvwxyz"
	digits := "0123456789"
	special := "!@#$%"
	all := upper + lower + digits + special
	value := []byte{upper[mathrand.Intn(len(upper))], lower[mathrand.Intn(len(lower))], digits[mathrand.Intn(len(digits))], special[mathrand.Intn(len(special))]}
	for len(value) < length {
		value = append(value, all[mathrand.Intn(len(all))])
	}
	mathrand.Shuffle(len(value), func(i, j int) { value[i], value[j] = value[j], value[i] })
	return string(value)
}

func randomName() (string, string) {
	return registerFirstNames[mathrand.Intn(len(registerFirstNames))], registerLastNames[mathrand.Intn(len(registerLastNames))]
}

func randomBirthdate() string {
	year := 1996 + mathrand.Intn(11)
	month := 1 + mathrand.Intn(12)
	day := 1 + mathrand.Intn(28)
	return fmt.Sprintf("%04d-%02d-%02d", year, month, day)
}

func randomToken(bytesLen int) string {
	if bytesLen < 1 {
		bytesLen = 24
	}
	raw := make([]byte, bytesLen)
	_, _ = rand.Read(raw)
	return base64.RawURLEncoding.EncodeToString(raw)
}

func pkceChallenge() string {
	_, challenge := generatePKCE()
	return challenge
}

func generatePKCE() (string, string) {
	buf := make([]byte, 64)
	_, _ = rand.Read(buf)
	verifier := base64.RawURLEncoding.EncodeToString(buf)
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	return verifier, challenge
}

func authorizeParams(email, deviceID, state, nonce, codeChallenge string) url.Values {
	values := url.Values{}
	values.Set("issuer", registerAuthBase)
	values.Set("client_id", registerPlatformOAuthClientID)
	values.Set("audience", registerPlatformOAuthAudience)
	values.Set("redirect_uri", registerPlatformOAuthRedirectURI)
	values.Set("device_id", deviceID)
	values.Set("screen_hint", "login_or_signup")
	values.Set("max_age", "0")
	values.Set("login_hint", email)
	values.Set("scope", "openid profile email offline_access")
	values.Set("response_type", "code")
	values.Set("response_mode", "query")
	values.Set("state", state)
	values.Set("nonce", nonce)
	values.Set("code_challenge", codeChallenge)
	values.Set("code_challenge_method", "S256")
	values.Set("auth0Client", registerPlatformAuth0Client)
	return values
}

func oauthCode(target string) string {
	if strings.TrimSpace(target) == "" {
		return ""
	}
	parsed, err := url.Parse(target)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(parsed.Query().Get("code"))
}

func resolveLocation(baseURL, location string) (string, error) {
	base, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}
	next, err := url.Parse(location)
	if err != nil {
		return "", err
	}
	return base.ResolveReference(next).String(), nil
}

func newSentinelTokenGenerator(deviceID, userAgent string) *sentinelTokenGenerator {
	return &sentinelTokenGenerator{deviceID: deviceID, userAgent: userAgent, sid: newUUID()}
}

func (g *sentinelTokenGenerator) config() []any {
	perfNow := 1000 + mathrand.Float64()*49000
	timeOrigin := float64(time.Now().UnixMilli()) - perfNow
	searchParams := fmt.Sprintf("device_id=%s,flow=,screen_hint=login_or_signup", g.deviceID)
	return []any{
		"1920x1080",
		time.Now().UTC().Format("Mon Jan 02 2006 15:04:05 GMT+0000 (Coordinated Universal Time)"),
		int64(4294705152),
		mathrand.Float64(),
		g.userAgent,
		registerSentinelSDK,
		"",
		"en-US",
		"en-US,en,es-US,es",
		mathrand.Float64(),
		randomChoice([]string{"vendorSub-undefined", "plugins-undefined", "mimeTypes-undefined", "hardwareConcurrency-undefined"}),
		randomChoice([]string{"location", "implementation", "URL", "documentURI", "compatMode"}),
		randomChoice([]string{"Object", "Function", "Array", "Number", "parseFloat", "undefined"}),
		perfNow,
		g.sid,
		searchParams,
		randomChoiceInt([]int{4, 8, 12, 16}),
		timeOrigin,
	}
}

// soConfig 生成 SO (Sentinel Observer) 专用配置，与普通 config 的主要区别：
// - 模拟 5000ms 的浏览器采集期
// - 使用不同的 navigator/document key 集合
func (g *sentinelTokenGenerator) soConfig() []any {
	observerPerfNow := 5000 + mathrand.Float64()*500
	timeOrigin := float64(time.Now().UnixMilli()) - observerPerfNow
	searchParams := fmt.Sprintf("device_id=%s,flow=,screen_hint=login_or_signup", g.deviceID)
	return []any{
		"1920x1080",
		time.Now().UTC().Format("Mon Jan 02 2006 15:04:05 GMT+0000 (Coordinated Universal Time)"),
		int64(4294705152),
		mathrand.Float64(),
		g.userAgent,
		registerSentinelSDK,
		"",
		"en-US",
		"en-US,en,es-US,es",
		mathrand.Float64(),
		randomChoice([]string{"hardwareConcurrency-undefined", "deviceMemory-undefined", "jsHeapSizeLimit-undefined", "totalJSHeapSize-undefined"}),
		randomChoice([]string{"cookieEnabled", "doNotTrack", "onLine", "pdfViewerEnabled"}),
		randomChoice([]string{"Intl", "ArrayBuffer", "Uint8Array", "Float64Array", "BigInt64Array"}),
		observerPerfNow,
		g.sid,
		searchParams,
		randomChoiceInt([]int{4, 8, 12, 16}),
		timeOrigin,
	}
}

func (g *sentinelTokenGenerator) generateRequirementsToken() string {
	data := g.config()
	data[3] = 1
	data[9] = round1(5 + mathrand.Float64()*45)
	return "gAAAAAC" + base64JSON(data)
}

func (g *sentinelTokenGenerator) generateToken(seed, difficulty string) string {
	start := time.Now()
	data := g.config()
	if difficulty == "" {
		difficulty = "0"
	}
	for i := 0; i < registerSentinelMaxAttempts; i++ {
		data[3] = i
		data[9] = round1(float64(time.Since(start).Milliseconds()))
		payload := base64JSON(data)
		hash := fnv1a32(seed + payload)
		prefixLen := minInt(len(difficulty), len(hash))
		if hash[:prefixLen] <= difficulty[:prefixLen] {
			return "gAAAAAB" + payload + "~S"
		}
	}
	return "gAAAAAB" + registerSentinelErrorPrefix + base64JSON("None")
}

// generateSOToken 生成 SO (Sentinel Observer) token。
// 与 generateToken 的区别：
// 1. 使用 soConfig 而非 config（模拟 5000ms 采集周期）
// 2. 在生成前已等待 observerDuration（由调用方控制）
func (g *sentinelTokenGenerator) generateSOToken(seed, difficulty string) string {
	start := time.Now()
	data := g.soConfig()
	if difficulty == "" {
		difficulty = "0"
	}
	for i := 0; i < registerSentinelMaxAttempts; i++ {
		data[3] = i
		data[9] = round1(float64(time.Since(start).Milliseconds()))
		payload := base64JSON(data)
		hash := fnv1a32(seed + payload)
		prefixLen := minInt(len(difficulty), len(hash))
		if hash[:prefixLen] <= difficulty[:prefixLen] {
			return "gAAAAAB" + payload + "~S"
		}
	}
	return "gAAAAAB" + registerSentinelErrorPrefix + base64JSON("so_none")
}

func base64JSON(value any) string {
	data, err := compactJSONBytes(value)
	if err != nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(data)
}

func compactJSONBytes(value any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(value); err != nil {
		return nil, err
	}
	return bytes.TrimSpace(buf.Bytes()), nil
}

func fnv1a32(text string) string {
	hash := uint32(2166136261)
	for _, ch := range text {
		hash ^= uint32(ch)
		hash *= 16777619
	}
	hash ^= hash >> 16
	hash *= 2246822507
	hash ^= hash >> 13
	hash *= 3266489909
	hash ^= hash >> 16
	return fmt.Sprintf("%08x", hash)
}

func sentinelHeaders() map[string]string {
	return map[string]string{
		"Content-Type":       "text/plain;charset=UTF-8",
		"Referer":            registerSentinelBase + "/backend-api/sentinel/frame.html",
		"Origin":             registerSentinelBase,
		"User-Agent":         registerUserAgent,
		"sec-ch-ua":          registerSecCHUA,
		"sec-ch-ua-mobile":   "?0",
		"sec-ch-ua-platform": `"Windows"`,
		"sec-fetch-dest":     "empty",
		"sec-fetch-mode":     "cors",
		"sec-fetch-site":     "same-origin",
	}
}

func traceHeaders() map[string]string {
	traceID := newHex(32)
	parentID := randomUint64()
	parentHex := fmt.Sprintf("%016x", parentID)
	parentText := strconv.FormatUint(parentID, 10)
	return map[string]string{
		"traceparent":                 "00-" + traceID + "-" + parentHex + "-01",
		"tracestate":                  "dd=s:1;o:rum",
		"x-datadog-origin":            "rum",
		"x-datadog-parent-id":         parentText,
		"x-datadog-sampling-priority": "1",
		"x-datadog-trace-id":          strconv.FormatUint(randomUint64(), 10),
	}
}

func randomUint64() uint64 {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return uint64(mathrand.Int63())
	}
	var value uint64
	for _, b := range buf {
		value = (value << 8) | uint64(b)
	}
	return value
}

func randomChoice(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[mathrand.Intn(len(values))]
}

func randomChoiceInt(values []int) int {
	if len(values) == 0 {
		return 0
	}
	return values[mathrand.Intn(len(values))]
}

// ── Sentinel Observer VM ──────────────────────────────────
func xorDecrypt(data, key string) string {
	var buf strings.Builder
	kl := len(key)
	if kl == 0 {
		return data
	}
	for i := 0; i < len(data); i++ {
		buf.WriteByte(data[i] ^ key[i%kl])
	}
	return buf.String()
}

type sentinelObsVM struct {
	regs     map[string]any
	queue    []any
	counter  int
	finished bool
}

func newSentinelObsVM() *sentinelObsVM {
	vm := &sentinelObsVM{regs: map[string]any{}}
	r := vm.regs
	r["1"] = func(a []any) { vm.set(a, xorDecrypt(fmt.Sprint(vm.get(a[0])), fmt.Sprint(vm.get(a[1])))) }
	r["2"] = func(a []any) { vm.set(a, vm.get(a[1])) }
	r["5"] = func(a []any) {
		v := vm.get(a[1])
		switch e := vm.get(a[0]).(type) {
		case []any:
			vm.set(a, append(e, v))
		default:
			vm.set(a, fmt.Sprint(e)+fmt.Sprint(v))
		}
	}
	r["6"] = func(a []any) {
		b := vm.get(a[1])
		idx := vm.get(a[2])
		switch bb := b.(type) {
		case string:
			if n, ok := toInt(idx); ok && n >= 0 && n < len(bb) {
				vm.set(a, string(bb[n]))
			}
		case []any:
			if n, ok := toInt(idx); ok && n >= 0 && n < len(bb) {
				vm.set(a, bb[n])
			}
		}
	}
	r["7"] = func(a []any) {
		fn := vm.get(a[0])
		fa := make([]any, len(a)-1)
		for i := 1; i < len(a); i++ {
			fa[i-1] = vm.get(a[i])
		}
		if f, ok := fn.(func([]any)); ok {
			f(fa)
		}
	}
	r["8"] = func(a []any) { vm.set(a, vm.get(a[1])) }
	r["12"] = func(a []any) { vm.set(a, r) }
	r["13"] = func(a []any) {
		func() {
			defer func() {
				if rc := recover(); rc != nil {
					vm.set(a, fmt.Sprint(rc))
				}
			}()
			fn := vm.get(a[1])
			fa := make([]any, len(a)-2)
			for i := 2; i < len(a); i++ {
				fa[i-2] = vm.get(a[i])
			}
			if f, ok := fn.(func([]any)); ok {
				f(fa)
			}
		}()
	}
	r["14"] = func(a []any) {
		var res any
		if json.Unmarshal([]byte(fmt.Sprint(vm.get(a[1]))), &res) == nil {
			vm.set(a, res)
		}
	}
	r["15"] = func(a []any) { d, _ := compactJSONBytes(vm.get(a[1])); vm.set(a, string(d)) }
	r["17"] = func(a []any) {
		fn := vm.get(a[1])
		fa := make([]any, len(a)-2)
		for i := 2; i < len(a); i++ {
			fa[i-2] = vm.get(a[i])
		}
		if f, ok := fn.(func([]any)); ok {
			f(fa)
		}
	}
	r["18"] = func(a []any) { d, _ := base64.StdEncoding.DecodeString(fmt.Sprint(vm.get(a[0]))); vm.set(a, string(d)) }
	r["19"] = func(a []any) { vm.set(a, base64.StdEncoding.EncodeToString([]byte(fmt.Sprint(vm.get(a[0]))))) }
	r["20"] = func(a []any) {
		if fmt.Sprint(vm.get(a[0])) == fmt.Sprint(vm.get(a[1])) {
			fn := vm.get(a[2])
			fa := make([]any, len(a)-3)
			for i := 3; i < len(a); i++ {
				fa[i-3] = vm.get(a[i])
			}
			if f, ok := fn.(func([]any)); ok {
				f(fa)
			}
		}
	}
	r["22"] = func(a []any) {
		if sl, ok := vm.get(a[1]).([]any); ok {
			sq := vm.queue
			vm.queue = make([]any, len(sl))
			copy(vm.queue, sl)
			vm.run()
			vm.set(a, fmt.Sprint(vm.counter))
			vm.queue = sq
		}
	}
	r["23"] = func(a []any) {
		if vm.get(a[0]) != nil {
			fn := vm.get(a[1])
			fa := make([]any, len(a)-2)
			for i := 2; i < len(a); i++ {
				fa[i-2] = vm.get(a[i])
			}
			if f, ok := fn.(func([]any)); ok {
				f(fa)
			}
		}
	}
	r["24"] = func(a []any) {
		obj, method := vm.get(a[1]), vm.get(a[2])
		vm.set(a, func(fa []any) {
			if o, ok := obj.(string); ok && fmt.Sprint(method) == "indexOf" {
				vm.set(a, strings.Index(o, fmt.Sprint(fa[0])))
			}
		})
	}
	for _, op := range []string{"25", "26", "27", "28"} {
		r[op] = func(a []any) {}
	}
	r["29"] = func(a []any) { av, _ := toFloat(vm.get(a[1])); bv, _ := toFloat(vm.get(a[2])); vm.set(a, av < bv) }
	r["33"] = func(a []any) { av, _ := toFloat(vm.get(a[1])); bv, _ := toFloat(vm.get(a[2])); vm.set(a, av*bv) }
	r["34"] = func(a []any) { vm.set(a, vm.get(a[1])) }
	return vm
}

func (vm *sentinelObsVM) get(key any) any {
	switch k := key.(type) {
	case string:
		return vm.regs[k]
	case float64:
		return vm.regs[fmt.Sprint(int(k))]
	default:
		return vm.regs[fmt.Sprint(k)]
	}
}

func (vm *sentinelObsVM) set(args []any, val any) {
	if len(args) > 0 {
		vm.regs[fmt.Sprint(args[0])] = val
	}
}

func (vm *sentinelObsVM) run() {
	for len(vm.queue) > 0 {
		inst := vm.queue[0]
		vm.queue = vm.queue[1:]
		if ia, ok := inst.([]any); ok && len(ia) > 0 {
			if fn, ok := vm.regs[fmt.Sprint(ia[0])].(func([]any)); ok {
				fn(ia)
			}
		}
		vm.counter++
	}
}

func generateSOTokenFromCollectorDX(collectorDX, proofToken string) string {
	raw, err := base64.StdEncoding.DecodeString(collectorDX)
	if err != nil {
		return ""
	}
	decrypted := xorDecrypt(string(raw), proofToken)
	var program []any
	if json.Unmarshal([]byte(decrypted), &program) != nil {
		return ""
	}
	vm := newSentinelObsVM()
	vm.regs["rt"] = proofToken
	ch := make(chan string, 1)
	vm.regs["3"] = func(a []any) {
		if !vm.finished {
			vm.finished = true
			ch <- base64.StdEncoding.EncodeToString([]byte(fmt.Sprint(vm.get(a[0]))))
		}
	}
	vm.regs["4"] = func(a []any) {
		if !vm.finished {
			vm.finished = true
			ch <- base64.StdEncoding.EncodeToString([]byte(fmt.Sprint(vm.get(a[0]))))
		}
	}
	vm.regs["30"] = func(a []any) {
		fnName := fmt.Sprint(a[0])
		pn := a[1:]
		ac := len(pn) - 1
		body := a[len(a)-1]
		vm.regs[fnName] = func(ca []any) {
			saved := map[string]any{}
			for k, v := range vm.regs {
				saved[k] = v
			}
			for i := 0; i < ac && i < len(ca); i++ {
				vm.regs[fmt.Sprint(pn[i])] = ca[i]
			}
			if bl, ok := body.([]any); ok {
				sq := vm.queue
				vm.queue = make([]any, len(bl))
				copy(vm.queue, bl)
				vm.run()
				vm.queue = sq
			}
			for k := range vm.regs {
				if _, ok := saved[k]; !ok {
					delete(vm.regs, k)
				}
			}
			for k, v := range saved {
				vm.regs[k] = v
			}
		}
	}
	vm.queue = make([]any, len(program))
	copy(vm.queue, program)
	vm.run()
	select {
	case result := <-ch:
		return result
	case <-time.After(500 * time.Millisecond):
		return base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%d", vm.counter)))
	}
}

func toInt(v any) (int, bool) {
	switch v := v.(type) {
	case float64:
		return int(v), true
	case int:
		return v, true
	case json.Number:
		n, e := v.Int64()
		return int(n), e == nil
	case string:
		n, e := strconv.Atoi(v)
		return n, e == nil
	}
	return 0, false
}

func toFloat(v any) (float64, bool) {
	switch v := v.(type) {
	case float64:
		return v, true
	case int:
		return float64(v), true
	case json.Number:
		n, e := v.Float64()
		return n, e == nil
	case string:
		n, e := strconv.ParseFloat(v, 64)
		return n, e == nil
	}
	return 0, false
}

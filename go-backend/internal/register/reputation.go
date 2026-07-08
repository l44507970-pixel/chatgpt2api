package register

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

var hardFailureMarkers = []string{
	"unsupported_email",
	"account_creation_failed",
	"registration_disallowed",
	"The email you provided is not supported",
	"Sorry, we cannot create your account with the given information.",
	"Failed to create account. Please try again.",
}

var softFailureMarkers = []string{
	"等待注册验证码超时",
	"独立登录等待验证码超时",
	"YYDSMail 请求异常",
	"SSLError",
	"ProxyError",
	"RemoteDisconnected",
	"token换取失败",
	"oauth_token_exchange_failed",
}

const (
	lowSuccessMinAttempts = 5
	lowSuccessRate        = 0.2
)

type domainReputationStore struct {
	path string
	mu   sync.Mutex
}

func newDomainReputationStore(path string) *domainReputationStore {
	return &domainReputationStore{path: path}
}

func normalizeDomain(value string) string {
	value = strings.Trim(strings.ToLower(strings.TrimSpace(value)), ".")
	if before, after, ok := strings.Cut(value, "@"); ok {
		_ = before
		value = strings.Trim(after, ".")
	}
	return value
}

func normalizeDomains(values []string) []string {
	out := []string{}
	seen := map[string]struct{}{}
	for _, raw := range values {
		domain := normalizeDomain(raw)
		if domain == "" {
			continue
		}
		if _, ok := seen[domain]; ok {
			continue
		}
		seen[domain] = struct{}{}
		out = append(out, domain)
	}
	return out
}

func classifyFailure(reason string) string {
	for _, marker := range hardFailureMarkers {
		if strings.Contains(reason, marker) {
			return "hard"
		}
	}
	for _, marker := range softFailureMarkers {
		if strings.Contains(reason, marker) {
			return "soft"
		}
	}
	return "soft"
}

func (s *domainReputationStore) RecordSuccess(provider, domain string) map[string]any {
	domain = normalizeDomain(domain)
	if provider = strings.TrimSpace(provider); provider == "" || domain == "" {
		return map[string]any{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	data := s.loadLocked()
	record := s.recordLocked(data, provider, domain)
	record["success"] = intValue(record["success"], 0) + 1
	record["consecutive_fail"] = 0
	record["disabled"] = false
	record["disabled_reason"] = ""
	updateSuccessRate(record)
	record["last_success_at"] = nowISO()
	s.saveLocked(data)
	return copyMap(record)
}

func (s *domainReputationStore) RecordFailure(provider, domain, reason string) map[string]any {
	domain = normalizeDomain(domain)
	bucket := classifyFailure(reason)
	if provider = strings.TrimSpace(provider); provider == "" || domain == "" {
		return map[string]any{"bucket": bucket, "disabled": false, "disabled_changed": false}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	data := s.loadLocked()
	record := s.recordLocked(data, provider, domain)
	wasDisabled := boolValue(record["disabled"], false)
	if bucket == "hard" {
		record["hard_fail"] = intValue(record["hard_fail"], 0) + 1
		record["disabled"] = true
		record["disabled_reason"] = "hard_failure"
	} else {
		record["soft_fail"] = intValue(record["soft_fail"], 0) + 1
	}
	record["consecutive_fail"] = intValue(record["consecutive_fail"], 0) + 1
	updateSuccessRate(record)
	if shouldDisableForLowSuccess(record) {
		record["disabled"] = true
		record["disabled_reason"] = "low_success_rate"
	}
	record["last_failure_at"] = nowISO()
	if len(reason) > 500 {
		reason = reason[:500]
	}
	record["last_failure_reason"] = reason
	s.saveLocked(data)
	out := copyMap(record)
	out["bucket"] = bucket
	out["disabled_changed"] = boolValue(record["disabled"], false) && !wasDisabled
	return out
}

func (s *domainReputationStore) PreferredDomains(provider string, domains []string) []string {
	normalized := normalizeDomains(domains)
	if len(normalized) == 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	records := s.providerDomainsLocked(s.loadLocked(), provider)
	type scoredDomain struct {
		score  int
		domain string
	}
	scored := []scoredDomain{}
	for _, domain := range normalized {
		record := asMap(records[domain])
		if boolValue(record["disabled"], false) {
			continue
		}
		score := intValue(record["success"], 0)*100 -
			intValue(record["hard_fail"], 0)*1000 -
			intValue(record["soft_fail"], 0)*10 -
			intValue(record["consecutive_fail"], 0)*20
		scored = append(scored, scoredDomain{score: score, domain: domain})
	}
	if len(scored) == 0 {
		return nil
	}
	sort.SliceStable(scored, func(i, j int) bool {
		if scored[i].score != scored[j].score {
			return scored[i].score > scored[j].score
		}
		return scored[i].domain < scored[j].domain
	})
	out := make([]string, 0, len(scored))
	for _, item := range scored {
		out = append(out, item.domain)
	}
	return out
}

func (s *domainReputationStore) GoodDomains(provider string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	records := s.providerDomainsLocked(s.loadLocked(), provider)
	type item struct {
		success int
		domain  string
	}
	items := []item{}
	for domain, raw := range records {
		record := asMap(raw)
		if boolValue(record["disabled"], false) || intValue(record["success"], 0) <= 0 {
			continue
		}
		items = append(items, item{success: intValue(record["success"], 0), domain: domain})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].success != items[j].success {
			return items[i].success > items[j].success
		}
		return items[i].domain < items[j].domain
	})
	out := make([]string, 0, len(items))
	for _, item := range items {
		out = append(out, item.domain)
	}
	return out
}

func (s *domainReputationStore) recordLocked(data map[string]any, provider, domain string) map[string]any {
	providers := asMap(data["providers"])
	if len(providers) == 0 {
		providers = map[string]any{}
		data["providers"] = providers
	}
	providerData := asMap(providers[provider])
	if len(providerData) == 0 {
		providerData = map[string]any{}
		providers[provider] = providerData
	}
	domains := asMap(providerData["domains"])
	if len(domains) == 0 {
		domains = map[string]any{}
		providerData["domains"] = domains
	}
	record := asMap(domains[domain])
	if len(record) == 0 {
		record = map[string]any{}
		domains[domain] = record
	}
	if _, ok := record["success"]; !ok {
		record["success"] = 0
	}
	if _, ok := record["hard_fail"]; !ok {
		record["hard_fail"] = 0
	}
	if _, ok := record["soft_fail"]; !ok {
		record["soft_fail"] = 0
	}
	if _, ok := record["consecutive_fail"]; !ok {
		record["consecutive_fail"] = 0
	}
	if _, ok := record["attempts"]; !ok {
		record["attempts"] = 0
	}
	if _, ok := record["success_rate"]; !ok {
		record["success_rate"] = 0.0
	}
	if _, ok := record["disabled_reason"]; !ok {
		record["disabled_reason"] = ""
	}
	if _, ok := record["disabled"]; !ok {
		record["disabled"] = false
	}
	return record
}

func updateSuccessRate(record map[string]any) {
	success := intValue(record["success"], 0)
	hardFail := intValue(record["hard_fail"], 0)
	softFail := intValue(record["soft_fail"], 0)
	attempts := success + hardFail + softFail
	record["attempts"] = attempts
	if attempts == 0 {
		record["success_rate"] = 0.0
		return
	}
	record["success_rate"] = float64(success) / float64(attempts)
}

func shouldDisableForLowSuccess(record map[string]any) bool {
	attempts := intValue(record["attempts"], 0)
	if attempts < lowSuccessMinAttempts {
		return false
	}
	failures := intValue(record["hard_fail"], 0) + intValue(record["soft_fail"], 0)
	return failures >= lowSuccessMinAttempts-1 && floatValue(record["success_rate"], 0) < lowSuccessRate
}

func (s *domainReputationStore) providerDomainsLocked(data map[string]any, provider string) map[string]any {
	providers := asMap(data["providers"])
	providerData := asMap(providers[strings.TrimSpace(provider)])
	return asMap(providerData["domains"])
}

func (s *domainReputationStore) loadLocked() map[string]any {
	raw, err := os.ReadFile(s.path)
	if err != nil {
		return map[string]any{}
	}
	var data map[string]any
	if err := json.Unmarshal(raw, &data); err != nil {
		return map[string]any{}
	}
	return data
}

func (s *domainReputationStore) saveLocked(data map[string]any) {
	_ = os.MkdirAll(filepath.Dir(s.path), 0o755)
	raw, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return
	}
	raw = append(raw, '\n')
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o644); err == nil {
		_ = os.Rename(tmp, s.path)
	}
}

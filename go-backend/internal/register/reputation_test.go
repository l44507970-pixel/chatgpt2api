package register

import "testing"

func TestDomainReputationRecordsHardSoftAndSuccess(t *testing.T) {
	store := newDomainReputationStore(t.TempDir() + "/mail_domain_reputation.json")

	hard := store.RecordFailure("yyds_mail", "User@Bad.EXAMPLE.", "unsupported_email")
	if hard["bucket"] != "hard" || hard["disabled"] != true || hard["disabled_changed"] != true {
		t.Fatalf("hard failure record = %#v", hard)
	}

	disallowed := store.RecordFailure("yyds_mail", "blocked.example", `create_account_http_400, detail={"error":{"code":"registration_disallowed","message":"Sorry, we cannot create your account with the given information."}}`)
	if disallowed["bucket"] != "hard" || disallowed["disabled"] != true || disallowed["disabled_changed"] != true {
		t.Fatalf("registration_disallowed failure record = %#v", disallowed)
	}
	if disallowed["disabled_reason"] != "hard_failure" {
		t.Fatalf("registration_disallowed disabled_reason = %#v", disallowed)
	}

	soft := store.RecordFailure("yyds_mail", "soft.example", "等待注册验证码超时")
	if soft["bucket"] != "soft" || soft["disabled"] == true {
		t.Fatalf("soft failure record = %#v", soft)
	}

	success := store.RecordSuccess("yyds_mail", "bad.example")
	if success["disabled"] == true || success["consecutive_fail"] != 0 {
		t.Fatalf("success should re-enable and reset consecutive fail: %#v", success)
	}

	store.RecordSuccess("yyds_mail", "winner.example")
	preferred := store.PreferredDomains("yyds_mail", []string{"winner.example", "soft.example"})
	wantPreferred := []string{"winner.example", "soft.example"}
	if len(preferred) != len(wantPreferred) {
		t.Fatalf("preferred domains = %#v", preferred)
	}
	for i := range wantPreferred {
		if preferred[i] != wantPreferred[i] {
			t.Fatalf("preferred domains = %#v, want %#v", preferred, wantPreferred)
		}
	}
}

func TestDomainReputationDisablesLowSuccessRate(t *testing.T) {
	store := newDomainReputationStore(t.TempDir() + "/mail_domain_reputation.json")

	store.RecordSuccess("yyds_mail", "weak.example")
	for i := 0; i < 4; i++ {
		record := store.RecordFailure("yyds_mail", "weak.example", "等待注册验证码超时")
		if i < 3 && record["disabled"] == true {
			t.Fatalf("domain disabled too early after failure %d: %#v", i+1, record)
		}
	}
	record := store.RecordFailure("yyds_mail", "weak.example", "等待注册验证码超时")
	if record["disabled"] != true || record["disabled_reason"] != "low_success_rate" {
		t.Fatalf("low success record = %#v", record)
	}
	if got := floatValue(record["success_rate"], 0); got >= lowSuccessRate {
		t.Fatalf("success_rate = %v, want below %v", got, lowSuccessRate)
	}
}

func TestDomainReputationGoodDomainsSortedAndDisabledFiltered(t *testing.T) {
	store := newDomainReputationStore(t.TempDir() + "/mail_domain_reputation.json")

	store.RecordSuccess("yyds_mail", "b.example")
	store.RecordSuccess("yyds_mail", "a.example")
	store.RecordSuccess("yyds_mail", "a.example")
	store.RecordSuccess("yyds_mail", "disabled.example")
	store.RecordFailure("yyds_mail", "disabled.example", "account_creation_failed")

	got := store.GoodDomains("yyds_mail")
	want := []string{"a.example", "b.example"}
	if len(got) != len(want) {
		t.Fatalf("good domains = %#v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("good domains = %#v, want %#v", got, want)
		}
	}
}

func TestNormalizeDomainsRemovesDuplicatesAndEmailPrefix(t *testing.T) {
	got := normalizeDomains([]string{" User@A.EXAMPLE. ", "a.example", "", "b.example."})
	want := []string{"a.example", "b.example"}
	if len(got) != len(want) {
		t.Fatalf("domains = %#v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("domains = %#v, want %#v", got, want)
		}
	}
}

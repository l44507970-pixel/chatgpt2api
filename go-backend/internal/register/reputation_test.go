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

from services.register import domain_reputation


def test_registration_disallowed_is_hard_failure(tmp_path):
    store = domain_reputation.DomainReputationStore(tmp_path / "mail_domain_reputation.json")

    record = store.record_failure(
        "yyds_mail",
        "blocked.example",
        'create_account_http_400, detail={"error":{"code":"registration_disallowed","message":"Sorry, we cannot create your account with the given information."}}',
    )

    assert record["bucket"] == "hard"
    assert record["disabled"] is True
    assert record["disabled_reason"] == "hard_failure"


def test_low_success_rate_disables_domain(tmp_path):
    store = domain_reputation.DomainReputationStore(tmp_path / "mail_domain_reputation.json")

    store.record_success("yyds_mail", "weak.example")
    for _ in range(4):
        record = store.record_failure("yyds_mail", "weak.example", "等待注册验证码超时")
    assert record["disabled"] is False

    record = store.record_failure("yyds_mail", "weak.example", "等待注册验证码超时")

    assert record["disabled"] is True
    assert record["disabled_reason"] == "low_success_rate"
    assert record["success_rate"] < domain_reputation.LOW_SUCCESS_RATE

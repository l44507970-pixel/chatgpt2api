from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DATA_DIR = Path(__file__).resolve().parents[2] / "data"
DEFAULT_FILE = DATA_DIR / "mail_domain_reputation.json"
LOW_SUCCESS_MIN_ATTEMPTS = 5
LOW_SUCCESS_RATE = 0.2

HARD_FAILURE_MARKERS = (
    "unsupported_email",
    "account_creation_failed",
    "registration_disallowed",
    "Sorry, we cannot create your account with the given information.",
    "The email you provided is not supported",
    "Failed to create account. Please try again.",
)

SOFT_FAILURE_MARKERS = (
    "等待注册验证码超时",
    "独立登录等待验证码超时",
    "YYDSMail 请求异常",
    "SSLError",
    "ProxyError",
    "RemoteDisconnected",
    "token换取失败",
    "oauth_token_exchange_failed",
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _domain(value: str) -> str:
    text = str(value or "").strip().lower()
    if "@" in text:
        text = text.rsplit("@", 1)[-1]
    return text.strip(".")


def _domains(values: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        domain = _domain(value)
        if not domain or domain in seen:
            continue
        seen.add(domain)
        out.append(domain)
    return out


def classify_failure(reason: str) -> str:
    text = str(reason or "")
    if any(marker in text for marker in HARD_FAILURE_MARKERS):
        return "hard"
    if any(marker in text for marker in SOFT_FAILURE_MARKERS):
        return "soft"
    return "soft"


def _update_success_rate(record: dict[str, Any]) -> None:
    success = int(record.get("success") or 0)
    hard_fail = int(record.get("hard_fail") or 0)
    soft_fail = int(record.get("soft_fail") or 0)
    attempts = success + hard_fail + soft_fail
    record["attempts"] = attempts
    record["success_rate"] = round(success / attempts, 4) if attempts else 0


def _should_disable_for_low_success(record: dict[str, Any]) -> bool:
    attempts = int(record.get("attempts") or 0)
    if attempts < LOW_SUCCESS_MIN_ATTEMPTS:
        return False
    success_rate = float(record.get("success_rate") or 0)
    failures = int(record.get("hard_fail") or 0) + int(record.get("soft_fail") or 0)
    return failures >= LOW_SUCCESS_MIN_ATTEMPTS - 1 and success_rate < LOW_SUCCESS_RATE


class DomainReputationStore:
    def __init__(self, file_path: Path = DEFAULT_FILE):
        self.file_path = Path(file_path)
        self._lock = threading.RLock()

    def _load_locked(self) -> dict[str, Any]:
        try:
            data = json.loads(self.file_path.read_text(encoding="utf-8"))
        except Exception:
            data = {}
        return data if isinstance(data, dict) else {}

    def _save_locked(self, data: dict[str, Any]) -> None:
        self.file_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.file_path.with_suffix(self.file_path.suffix + ".tmp")
        tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        tmp.replace(self.file_path)

    def _record(self, data: dict[str, Any], provider: str, domain: str) -> dict[str, Any]:
        providers = data.setdefault("providers", {})
        provider_data = providers.setdefault(str(provider or "unknown"), {})
        domains = provider_data.setdefault("domains", {})
        record = domains.setdefault(domain, {})
        record.setdefault("success", 0)
        record.setdefault("hard_fail", 0)
        record.setdefault("soft_fail", 0)
        record.setdefault("consecutive_fail", 0)
        record.setdefault("attempts", 0)
        record.setdefault("success_rate", 0)
        record.setdefault("disabled_reason", "")
        record.setdefault("disabled", False)
        return record

    def record_success(self, provider: str, domain: str) -> dict[str, Any]:
        domain = _domain(domain)
        if not domain:
            return {}
        with self._lock:
            data = self._load_locked()
            record = self._record(data, provider, domain)
            record["success"] = int(record.get("success") or 0) + 1
            record["consecutive_fail"] = 0
            record["disabled"] = False
            record["disabled_reason"] = ""
            _update_success_rate(record)
            record["last_success_at"] = _now()
            self._save_locked(data)
            return dict(record)

    def record_failure(self, provider: str, domain: str, reason: str) -> dict[str, Any]:
        domain = _domain(domain)
        if not domain:
            return {"bucket": classify_failure(reason), "disabled": False, "disabled_changed": False}
        bucket = classify_failure(reason)
        with self._lock:
            data = self._load_locked()
            record = self._record(data, provider, domain)
            was_disabled = bool(record.get("disabled"))
            if bucket == "hard":
                record["hard_fail"] = int(record.get("hard_fail") or 0) + 1
                record["disabled"] = True
                record["disabled_reason"] = "hard_failure"
            else:
                record["soft_fail"] = int(record.get("soft_fail") or 0) + 1
            record["consecutive_fail"] = int(record.get("consecutive_fail") or 0) + 1
            _update_success_rate(record)
            if _should_disable_for_low_success(record):
                record["disabled"] = True
                record["disabled_reason"] = "low_success_rate"
            record["last_failure_at"] = _now()
            record["last_failure_reason"] = str(reason or "")[:500]
            self._save_locked(data)
            out = dict(record)
            out["bucket"] = bucket
            out["disabled_changed"] = bool(record.get("disabled")) and not was_disabled
            return out

    def is_disabled(self, provider: str, domain: str) -> bool:
        domain = _domain(domain)
        if not domain:
            return False
        with self._lock:
            data = self._load_locked()
            record = (((data.get("providers") or {}).get(str(provider or "unknown")) or {}).get("domains") or {}).get(domain) or {}
            return bool(record.get("disabled"))

    def filter_domains(self, provider: str, domains: list[str]) -> list[str]:
        normalized = _domains(domains)
        if not normalized:
            return []
        enabled = [item for item in normalized if not self.is_disabled(provider, item)]
        return enabled or normalized

    def preferred_domains(self, provider: str, domains: list[str]) -> list[str]:
        normalized = _domains(domains)
        if not normalized:
            return []
        with self._lock:
            data = self._load_locked()
            records = (((data.get("providers") or {}).get(str(provider or "unknown")) or {}).get("domains") or {})
            scored: list[tuple[int, str]] = []
            for domain in normalized:
                record = records.get(domain) or {}
                if bool(record.get("disabled")):
                    continue
                success = int(record.get("success") or 0)
                hard_fail = int(record.get("hard_fail") or 0)
                soft_fail = int(record.get("soft_fail") or 0)
                consecutive_fail = int(record.get("consecutive_fail") or 0)
                score = success * 100 - hard_fail * 1000 - soft_fail * 10 - consecutive_fail * 20
                scored.append((score, domain))
            if not scored:
                return []
            best = max(score for score, _ in scored)
            return [domain for score, domain in scored if score == best]

    def good_domains(self, provider: str) -> list[str]:
        with self._lock:
            data = self._load_locked()
            domains = (((data.get("providers") or {}).get(str(provider or "unknown")) or {}).get("domains") or {})
            items = []
            for domain, record in domains.items():
                if not isinstance(record, dict) or bool(record.get("disabled")):
                    continue
                if int(record.get("success") or 0) <= 0:
                    continue
                items.append((int(record.get("success") or 0), str(domain)))
            return [domain for _, domain in sorted(items, key=lambda item: (-item[0], item[1]))]


store = DomainReputationStore()

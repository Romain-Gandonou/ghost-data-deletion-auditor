#!/usr/bin/env python3
"""Evidence-first deletion audit generator for the Ghost Data Still Exists challenge."""

from __future__ import annotations

import csv
import hashlib
import json
import re
import shutil
import sqlite3
import subprocess
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
DATASET = ROOT / "dataset"
OUTPUT = ROOT / "output.csv"
OUTPUT_FIELDS = ("case_id", "deletion_status", "steps_json")

RESOURCE_RE = re.compile(
    r"\b(?:account|analytics|search|support|export|backup|audit_record|"
    r"data_flow|marketing|tombstone|cache|email_delivery)_\d+\b",
    re.IGNORECASE,
)
EMAIL_RE = re.compile(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}")
ISO_RE = re.compile(r"\b20\d{2}-\d{2}-\d{2}(?:[T ][0-9:.+-]+Z?)?\b")

FINDING_ORDER = {
    "REPORT_REMAINING_RECORD": 0,
    "REPORT_EXPOSED_PII": 1,
    "REPORT_ACTIVE_DATA_FLOW": 2,
    "REPORT_RESTORE_RISK": 3,
}
REMEDIATION_ORDER = {
    "DISABLE_DATA_FLOW": 0,
    "BLOCK_RESTORE": 1,
    "DELETE_RECORD": 2,
    "REDACT_RECORD": 3,
    "ANONYMIZE_RECORD": 4,
}
VERIFICATION_ORDER = {
    "VERIFY_RECORD_ABSENT": 0,
    "VERIFY_RECORD_PRESENT": 1,
    "VERIFY_RECORD_REDACTED": 2,
    "VERIFY_RECORD_ANONYMIZED": 3,
    "VERIFY_DATA_FLOW_DISABLED": 4,
    "VERIFY_RESTORE_BLOCKED": 5,
}

TABLE_CATEGORIES = {
    "customer_profiles": ("account_service", "USER_PROFILE"),
    "customer_profiles_primary": ("account_service", "USER_PROFILE"),
    "customer_profiles_failover_replica": ("account_service", "USER_PROFILE"),
    "customer_data_primary": ("database_replica", "GENERIC"),
    "customer_data_read_replica": ("database_replica", "GENERIC"),
    "customer_data_reporting_replica": ("database_replica", "GENERIC"),
    "customer_data_replica_ap_south": ("database_replica", "GENERIC"),
    "customer_data_replica_eu_west": ("database_replica", "GENERIC"),
    "customer_data_failover_replica": ("database_replica", "GENERIC"),
    "customer_search_documents": ("search_service", "SEARCH_INDEX_ENTRY"),
    "search_documents_primary": ("search_service", "SEARCH_INDEX_ENTRY"),
    "customer_analytics_profiles": ("analytics_platform", "ANALYTICS_PROFILE"),
    "support_records": ("support_platform", "SUPPORT_MESSAGE"),
    "connector_subscriptions": ("integration_service", "DATA_FLOW"),
    "backup_restore_entries": ("backup_service", "BACKUP_ARCHIVE"),
    "security_audit_records": ("security_service", "SECURITY_AUDIT_LOG"),
    "customer_exports": ("export_service", "USER_EXPORT"),
}

SYSTEM_ALIASES = {
    "account": "account_service",
    "account_service": "account_service",
    "search": "search_service",
    "search_service": "search_service",
    "analytics": "analytics_platform",
    "analytics_platform": "analytics_platform",
    "support": "support_platform",
    "support_platform": "support_platform",
    "export": "export_service",
    "export_service": "export_service",
    "integration": "integration_service",
    "integration_service": "integration_service",
    "connector": "integration_service",
    "backup": "backup_service",
    "backup_service": "backup_service",
    "security": "security_service",
    "security_service": "security_service",
    "marketing": "marketing_platform",
    "marketing_platform": "marketing_platform",
    "email_delivery": "notification_service",
    "notification": "notification_service",
}


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    value = value.strip()
    if len(value) == 10:
        value += "T00:00:00Z"
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        match = ISO_RE.search(value)
        if not match:
            return None
        try:
            result = datetime.fromisoformat(match.group().replace("Z", "+00:00"))
        except ValueError:
            return None
    if result.tzinfo is None:
        result = result.replace(tzinfo=timezone.utc)
    return result.astimezone(timezone.utc)


def norm(value: Any) -> str:
    return re.sub(r"\s+", " ", str(value or "")).strip().casefold()


def phone_norm(value: Any) -> str:
    return re.sub(r"\D", "", str(value or ""))


def load_subjects() -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    identities = read_csv(DATASET / "user_identities.csv")
    changes = read_csv(DATASET / "user_audit_log.csv")
    by_email: dict[str, dict[str, Any]] = {}
    by_user: dict[str, dict[str, Any]] = {}
    for row in identities:
        subject = {
            "user_id": row["user_id"],
            "name": row["name"],
            "email": row["email"],
            "phone": row["phone"],
            "email_hash": row["email_hash"],
            "emails": {norm(row["email"])} if row["email"] else set(),
            "phones": {phone_norm(row["phone"])} if row["phone"] else set(),
            "hashes": {norm(row["email_hash"])} if row["email_hash"] else set(),
        }
        by_user[row["user_id"]] = subject
        if row["email"]:
            by_email[norm(row["email"])] = subject
    for change in changes:
        subject = by_user.get(change["user_id"])
        if subject is None:
            continue
        field = change["field_name"].casefold()
        for value in (change["old_value"], change["new_value"]):
            if not value:
                continue
            if field == "email":
                subject["emails"].add(norm(value))
                subject["hashes"].add(hashlib.sha256(norm(value).encode("utf-8")).hexdigest())
            elif field == "phone":
                subject["phones"].add(phone_norm(value))
            elif field == "email_hash":
                subject["hashes"].add(norm(value))
        if field == "email":
            by_email[norm(change["old_value"])] = subject
            by_email[norm(change["new_value"])] = subject
    for subject in by_user.values():
        for email in subject["emails"]:
            if email:
                by_email[email] = subject
                subject["hashes"].add(hashlib.sha256(email.encode("utf-8")).hexdigest())
    return by_email, by_user


def load_policy() -> dict[str, dict[str, str]]:
    return {
        row["data_category"]: row
        for row in read_csv(DATASET / "deletion_rules.csv")
    }


def augment_subjects_from_activity(
    by_email: dict[str, dict[str, Any]],
    by_user: dict[str, dict[str, Any]],
) -> None:
    for event in read_csv(DATASET / "system_activity.csv"):
        if event["event_type"] != "LINK_RESOURCE_IDENTITY":
            continue
        details = event["details"]
        user_match = re.search(r"\buser_\d+\b", details)
        if user_match is None or user_match.group().casefold() not in {
            norm(user_id) for user_id in by_user
        }:
            continue
        subject = by_user[user_match.group()]
        subject.setdefault("linked_resources", set()).update(RESOURCE_RE.findall(details))
        if event["resource_id"]:
            subject["linked_resources"].add(event["resource_id"])
        for email in EMAIL_RE.findall(details):
            normalized = norm(email)
            subject["emails"].add(normalized)
            by_email[normalized] = subject


def subject_tokens(subject: dict[str, Any]) -> dict[str, set[str]]:
    return {
        "emails": {norm(x) for x in subject["emails"] if x},
        "hashes": {norm(x) for x in subject["hashes"] if x},
        "phones": {phone_norm(x) for x in subject["phones"] if phone_norm(x)},
        "user_ids": {norm(subject["user_id"])},
        "names": {norm(subject["name"])} if subject.get("name") else set(),
    }


def matching_strength(value: Any, tokens: dict[str, set[str]]) -> int:
    if isinstance(value, dict):
        score = 0
        for key, item in value.items():
            score |= matching_strength(key, tokens)
            score |= matching_strength(item, tokens)
        return score
    if isinstance(value, (list, tuple)):
        score = 0
        for item in value:
            score |= matching_strength(item, tokens)
        return score
    text = norm(value)
    if not text:
        return 0
    score = 0
    if text in tokens["emails"]:
        score |= 1
    if text in tokens["hashes"]:
        score |= 2
    if text in tokens["user_ids"]:
        score |= 4
    digits = phone_norm(text)
    if digits and digits in tokens["phones"]:
        score |= 8
    # Names are only corroborating evidence; they do not independently identify a row.
    if text in tokens["names"]:
        score |= 16
    return score


def infer_system(path: str, context: str, resource: str) -> str:
    prefix = resource.partition("_")[0].casefold()
    if prefix == "audit":
        return "security_service"
    if prefix == "data":
        return "integration_service"
    if prefix == "tombstone":
        return "identity_service"
    if prefix in SYSTEM_ALIASES:
        return SYSTEM_ALIASES[prefix]
    haystack = f"{path} {context}".casefold()
    for alias, system in SYSTEM_ALIASES.items():
        if alias in haystack:
            return system
    prefix = resource.partition("_")[0].casefold()
    return SYSTEM_ALIASES.get(prefix, "database_replica")


def infer_category(path: str, context: str, record: dict[str, Any]) -> str:
    haystack = f"{path} {context} {record.get('record_type', '')} {record.get('collection', '')}".casefold()
    if "tombstone" in haystack or str(record.get("resource_id", "")).startswith("tombstone_"):
        return "ACCOUNT_TOMBSTONE"
    if "connector" in haystack or "data_flow" in haystack or "integration" in haystack:
        return "DATA_FLOW"
    if "backup" in haystack or "restore" in haystack or "archive" in haystack:
        return "BACKUP_ARCHIVE"
    if "audit" in haystack or "security" in haystack or "legal_hold" in haystack:
        return "SECURITY_AUDIT_LOG"
    if "search" in haystack or "index" in haystack:
        return "SEARCH_INDEX_ENTRY"
    if "analytic" in haystack or "telemetry" in haystack:
        return "ANALYTICS_PROFILE"
    if "support_attachment" in haystack or "attachment" in haystack:
        return "SUPPORT_ATTACHMENT"
    if "support" in haystack or "ticket" in haystack or "conversation" in haystack:
        return "SUPPORT_MESSAGE"
    if "export" in haystack:
        return "USER_EXPORT"
    if "marketing" in haystack or "audience" in haystack:
        return "MARKETING_PROFILE"
    if "email_delivery" in haystack or "notification" in haystack:
        return "EMAIL_DELIVERY_LOG"
    if "cache" in haystack:
        return "CACHE_ENTRY"
    if "secondary_identifier" in haystack:
        return "SECONDARY_IDENTIFIER"
    if "account" in haystack or "profile" in haystack:
        return "USER_PROFILE"
    return "GENERIC"


def extract_json_records(
    value: Any, path: str, file_time: datetime, context: str = "",
    inherited_resource: str = "", inherited_time: datetime | None = None,
) -> Iterable[dict[str, Any]]:
    if isinstance(value, dict):
        resource = str(value.get("resource_id") or inherited_resource)
        record_time = next(
            (parse_time(value.get(key)) for key in
             ("observed_at", "captured_at", "recorded_at", "updated_at", "indexed_at", "created_at")
             if parse_time(value.get(key)) is not None),
            inherited_time or file_time,
        )
        local_context = f"{context} {value.get('system', '')} {value.get('collection', '')} {value.get('data_store', '')}"
        if resource:
            yield {
                "resource_id": resource,
                "system_id": infer_system(path, local_context, resource),
                "category": infer_category(path, local_context, value),
                "payload": value,
                "path": path,
                "captured_at": record_time,
                "file_time": file_time,
                "context": local_context,
                "claim": False,
            }
        for key, item in value.items():
            if isinstance(item, (dict, list)):
                yield from extract_json_records(
                    item, path, file_time, f"{local_context} {key}",
                    resource, record_time,
                )
    elif isinstance(value, list):
        for item in value:
            yield from extract_json_records(item, path, file_time, context, inherited_resource, inherited_time)


def sql_records(path: Path, file_id: str, file_time: datetime) -> list[dict[str, Any]]:
    db = sqlite3.connect(":memory:")
    try:
        db.executescript(path.read_text(encoding="utf-8", errors="replace"))
        tables = db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        ).fetchall()
        result = []
        for (table,) in tables:
            columns = [row[1] for row in db.execute(f'PRAGMA table_info("{table}")')]
            for values in db.execute(f'SELECT * FROM "{table}"'):
                row = dict(zip(columns, values))
                resource = str(row.get("resource_id") or "")
                if not resource:
                    continue
                system, category = TABLE_CATEGORIES.get(
                    table, (infer_system(str(path), table, resource), infer_category(str(path), table, row))
                )
                if category == "GENERIC":
                    system = infer_system(str(path), str(row.get("collection_name", table)), resource)
                    if "collection_name" in row:
                        category = infer_category(str(path), str(row["collection_name"]), row)
                # JSON-encoded replica payloads carry their own resource category and fields.
                payload = dict(row)
                if isinstance(row.get("record_json"), str):
                    try:
                        embedded = json.loads(row["record_json"])
                    except json.JSONDecodeError:
                        embedded = {}
                    if isinstance(embedded, dict):
                        payload.update(embedded)
                        category = infer_category(str(path), str(row.get("collection_name", "")), embedded)
                result.append({
                    "resource_id": resource,
                    "system_id": system,
                    "category": category,
                    "payload": payload,
                    "path": str(path),
                    "captured_at": file_time,
                    "file_time": file_time,
                    "context": table,
                    "claim": False,
                })
        return result
    finally:
        db.close()


def text_records(path: Path, file_id: str, file_time: datetime) -> list[dict[str, Any]]:
    if path.suffix.lower() == ".png":
        executable = shutil.which("tesseract")
        if executable is None:
            print(f"Warning: OCR skipped for {path}; install Tesseract to read screenshot evidence.", file=sys.stderr)
            return []
        completed = subprocess.run(
            [executable, str(path), "stdout"], capture_output=True, text=True, check=False
        )
        if completed.returncode != 0:
            print(f"Warning: could not OCR {path}: {completed.stderr.strip()}", file=sys.stderr)
            return []
        text = completed.stdout
        rows = [(f"ocr_{i}", line) for i, line in enumerate(text.splitlines(), 1) if line.strip()]
    elif path.suffix.lower() == ".pdf":
        completed = subprocess.run(
            ["pdftotext", str(path), "-"], capture_output=True, text=True, check=False
        )
        if completed.returncode != 0:
            print(f"Warning: could not extract text from {path}: {completed.stderr.strip()}", file=sys.stderr)
            return []
        text = completed.stdout
        rows = [
            (f"paragraph_{i}", paragraph)
            for i, paragraph in enumerate(re.split(r"\n\s*\n", text), 1)
            if paragraph.strip()
        ]
    else:
        text = path.read_text(encoding="utf-8", errors="replace")
        rows = [(f"line_{i}", line) for i, line in enumerate(text.splitlines(), 1) if line.strip()]
    grouped: dict[str, list[str]] = defaultdict(list)
    for label, content in rows:
        resources = sorted(set(RESOURCE_RE.findall(content)))
        for resource in resources:
            grouped[resource].append(content)
    result = []
    for resource, contents in grouped.items():
        content = "\n".join(contents)
        result.append({
            "resource_id": resource,
            "system_id": infer_system(str(path), content, resource),
            "category": infer_category(str(path), content, {"resource_id": resource}),
            "payload": {"text": content},
            "path": str(path),
            "captured_at": file_time,
            "file_time": file_time,
            "context": content,
            "claim": True,
        })
    return result


def load_evidence() -> list[dict[str, Any]]:
    manifest = read_csv(DATASET / "evidence_files.csv")
    records: list[dict[str, Any]] = []
    for entry in manifest:
        file_path = DATASET / entry["file_path"]
        file_time = parse_time(entry["captured_at"])
        if file_time is None:
            continue
        suffix = file_path.suffix.lower()
        if suffix == ".sql":
            records.extend(sql_records(file_path, entry["file_id"], file_time))
        elif suffix == ".json":
            try:
                parsed = json.loads(file_path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                print(f"Warning: could not parse {file_path}: {exc}", file=sys.stderr)
                continue
            records.extend(extract_json_records(parsed, str(file_path), file_time))
        elif suffix in {".log", ".txt", ".pdf", ".png"}:
            records.extend(text_records(file_path, entry["file_id"], file_time))
    evidence_ids = {str(DATASET / entry["file_path"]): entry["file_id"] for entry in manifest}
    for record in records:
        record["evidence_id"] = evidence_ids.get(record["path"], "")
    return records


def payload_has_direct_pii(record: dict[str, Any], tokens: dict[str, set[str]]) -> bool:
    payload = record["payload"]
    if not isinstance(payload, dict):
        return False
    for key, value in payload.items():
        if key.casefold() in {"email", "phone", "full_name", "name", "email_hash",
                              "requester_email", "requester_phone", "requester_name",
                              "owner_email", "owner_phone", "customer_email"}:
            if matching_strength(value, tokens) & (1 | 2 | 8 | 16):
                return True
    return False


def record_match(record: dict[str, Any], tokens: dict[str, set[str]]) -> bool:
    payload = record["payload"]
    if matching_strength(payload, tokens) & (1 | 2 | 4 | 8):
        return True
    if isinstance(payload, dict) and isinstance(payload.get("text"), str):
        text = norm(payload["text"])
        if any(token and token in text for token in tokens["emails"] | tokens["hashes"] | tokens["user_ids"]):
            return True
        if any(name and len(name) > 3 and name in text for name in tokens["names"]):
            return True
        for phone in tokens["phones"]:
            pattern = r"\D*".join(re.escape(digit) for digit in phone)
            if phone and re.search(rf"(?<!\d){pattern}(?!\d)", text):
                return True
    return False


def recency_key(record: dict[str, Any]) -> tuple[datetime, datetime]:
    return record["captured_at"], record["file_time"]


def active_value(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return norm(value) in {"true", "yes", "enabled", "active", "1", "allowed"}


def classify_record(
    record: dict[str, Any],
    tokens: dict[str, set[str]],
    audit_at: datetime,
    policy: dict[str, dict[str, str]] | None = None,
) -> dict[str, Any] | None:
    policy = policy or load_policy()
    payload = record["payload"]
    if not isinstance(payload, dict):
        payload = {"text": str(payload)}
    category = record["category"]
    required_action = policy.get(category, {}).get("required_action", "")
    resource = record["resource_id"]
    system = record["system_id"]
    text = norm(payload.get("text", ""))
    direct_pii = payload_has_direct_pii(record, tokens)
    lower_payload = norm(payload)

    # A 404/NOT_FOUND readback is an evidence-backed absence, not a remaining record.
    if record["claim"] and re.search(r"\b(404|not[_ ]found|absent|no matching record|zero[_ ]hits)\b", text):
        return {"kind": "compliant", "operation": "VERIFY_RECORD_ABSENT", "state": "ABSENT"}
    status_code = payload.get("status_code")
    if status_code is not None and str(status_code).isdigit() and int(status_code) >= 400:
        return {"kind": "compliant", "operation": "VERIFY_RECORD_ABSENT", "state": "ABSENT"}
    if category == "USER_PROFILE" and norm(payload.get("account_status")) in {"deleted", "absent", "not_found"}:
        return {"kind": "compliant", "operation": "VERIFY_RECORD_ABSENT", "state": "ABSENT"}

    if category in {"DATA_FLOW"}:
        enabled = payload.get("enabled")
        if enabled is None:
            enabled = bool(re.search(r"\b(enabled|active|remains enabled|continuous sync)\b", lower_payload))
        if active_value(enabled):
            return {"kind": "flow", "operation": "REPORT_ACTIVE_DATA_FLOW", "state": "ACTIVE",
                    "remediation": "DISABLE_DATA_FLOW", "verify": "VERIFY_DATA_FLOW_DISABLED"}
        return {"kind": "compliant", "operation": "VERIFY_DATA_FLOW_DISABLED", "state": "DISABLED"}
    if category == "BACKUP_ARCHIVE":
        allowed = payload.get("restore_allowed")
        if allowed is None:
            allowed = bool(re.search(r"\b(can still be restored|restore allowed|restore_access=true)\b", lower_payload))
        if active_value(allowed):
            return {"kind": "restore", "operation": "REPORT_RESTORE_RISK", "state": "ACTIVE",
                    "remediation": "BLOCK_RESTORE", "verify": "VERIFY_RESTORE_BLOCKED"}
        return {"kind": "compliant", "operation": "VERIFY_RESTORE_BLOCKED", "state": "BLOCKED"}
    if category == "SECURITY_AUDIT_LOG":
        expiry = parse_time(payload.get("retention_until"))
        if payload.get("legal_hold") or "legal_hold" in lower_payload:
            return {"kind": "retained", "operation": "VERIFY_RECORD_PRESENT", "state": "PRESENT"}
        if expiry is None or expiry >= audit_at:
            return {"kind": "retained", "operation": "VERIFY_RECORD_PRESENT", "state": "PRESENT"}
        return {"kind": "compliant", "operation": "VERIFY_RECORD_ABSENT", "state": "ABSENT",
                "remediation": "DELETE_RECORD"}
    if category == "ACCOUNT_TOMBSTONE":
        if direct_pii:
            return {"kind": "pii", "operation": "REPORT_EXPOSED_PII", "state": "PRESENT",
                    "remediation": "REDACT_RECORD", "verify": "VERIFY_RECORD_REDACTED"}
        return {"kind": "compliant", "operation": "VERIFY_RECORD_REDACTED", "state": "REDACTED"}

    if required_action == "DELETE" and category != "SUPPORT_ATTACHMENT":
        return {"kind": "remaining", "operation": "REPORT_REMAINING_RECORD", "state": "PRESENT",
                "remediation": "DELETE_RECORD", "verify": "VERIFY_RECORD_ABSENT"}
    if required_action == "ANONYMIZE":
        # A stable customer reference still makes the profile attributable.
        ref = payload.get("customer_reference") or payload.get("user_id")
        attributable = bool(ref and norm(ref) in tokens["user_ids"]) or direct_pii
        if attributable:
            return {"kind": "pii", "operation": "REPORT_EXPOSED_PII", "state": "PRESENT",
                    "remediation": "ANONYMIZE_RECORD", "verify": "VERIFY_RECORD_ANONYMIZED"}
        return {"kind": "compliant", "operation": "VERIFY_RECORD_ANONYMIZED", "state": "ANONYMIZED"}
    if category == "SUPPORT_ATTACHMENT" or (
        category == "SUPPORT_MESSAGE" and required_action == "DELETE"
    ):
        return {"kind": "remaining", "operation": "REPORT_REMAINING_RECORD", "state": "PRESENT",
                "remediation": "DELETE_RECORD", "verify": "VERIFY_RECORD_ABSENT"}
    if category == "SUPPORT_MESSAGE" and required_action == "REDACT":
        if direct_pii:
            return {"kind": "pii", "operation": "REPORT_EXPOSED_PII", "state": "PRESENT",
                    "remediation": "REDACT_RECORD", "verify": "VERIFY_RECORD_REDACTED"}
        return {"kind": "compliant", "operation": "VERIFY_RECORD_REDACTED", "state": "REDACTED"}
    if category == "EMAIL_DELIVERY_LOG" and required_action == "REDACT":
        if direct_pii:
            return {"kind": "pii", "operation": "REPORT_EXPOSED_PII", "state": "PRESENT",
                    "remediation": "REDACT_RECORD", "verify": "VERIFY_RECORD_REDACTED"}
        return {"kind": "compliant", "operation": "VERIFY_RECORD_REDACTED", "state": "REDACTED"}
    if category == "GENERIC":
        # Opaque records are only actionable if they explicitly expose subject identifiers.
        if direct_pii:
            return {"kind": "remaining", "operation": "REPORT_REMAINING_RECORD", "state": "PRESENT",
                    "remediation": "DELETE_RECORD", "verify": "VERIFY_RECORD_ABSENT"}
    if category == "database_replica":
        return {"kind": "remaining", "operation": "REPORT_REMAINING_RECORD", "state": "PRESENT",
                "remediation": "DELETE_RECORD", "verify": "VERIFY_RECORD_ABSENT"}
    return None


def authorized_deletion(text: str) -> bool:
    text = norm(text)
    if re.search(r"削除|消去", text):
        return True
    deletion = re.search(
        r"\b(delete|deleted|deleting|deletion|erase|erased|erasure|remove|removed|removal|"
        r"close (?:my|the|this) account|"
        r"account closure|forget me|suppression|supprimer|suppression définitive|effacer|"
        r"borrar|eliminar|eliminación|cerrar mi cuenta|gone)\b",
        text,
        re.IGNORECASE,
    )
    non_deletion = re.search(
        r"\b(access|export my data|copy of my data|correct|correction|update my|change my|"
        r"rectify|rectification|opt out|unsubscribe|stop marketing|marketing preference|"
        r"accès|corriger|modifier|désabonner|marketing|acceder|corregir|actualizar)\b",
        text,
        re.IGNORECASE,
    )
    return bool(deletion) and not (non_deletion and not re.search(
        r"\b(delete|deleted|deleting|deletion|erase|erased|erasure|remove|removed|removal|"
        r"supprimer|suppression|effacer|borrar|eliminar|eliminación|gone)\b",
        text,
        re.IGNORECASE,
    ))


def step(phase: str, system: str, resource: str, operation: str, state: str, evidence: str) -> dict[str, Any]:
    return {
        "step_no": 0,
        "phase": phase,
        "system_id": system,
        "resource_id": resource,
        "operation": operation,
        "state": state,
        "evidence_id": evidence,
    }


def ordered_steps(findings: list[dict[str, Any]], remediations: list[dict[str, Any]],
                  verifications: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings.sort(key=lambda x: (FINDING_ORDER[x["operation"]], x["system_id"], x["resource_id"]))
    remediations.sort(key=lambda x: (REMEDIATION_ORDER[x["operation"]], x["system_id"], x["resource_id"]))
    verifications.sort(key=lambda x: (VERIFICATION_ORDER[x["operation"]], x["system_id"], x["resource_id"]))
    result = findings + remediations + verifications
    for index, item in enumerate(result, 1):
        item["step_no"] = index
    return result


def audit_request(request: dict[str, str], by_email: dict[str, dict[str, Any]],
                  by_user: dict[str, dict[str, Any]], evidence: list[dict[str, Any]],
                  policy: dict[str, dict[str, str]]) -> dict[str, Any]:
    if not authorized_deletion(request["request_text"]):
        return {"case_id": request["case_id"], "deletion_status": "NOT_APPLICABLE", "steps_json": []}
    subject = by_email.get(norm(request["email"]))
    if subject is None:
        return {"case_id": request["case_id"], "deletion_status": "INCOMPLETE", "steps_json": []}
    audit_at = parse_time(request["audit_at"]) or datetime.max.replace(tzinfo=timezone.utc)
    tokens = subject_tokens(subject)
    identity_matches = [
        record for record in evidence
        if record["captured_at"] <= audit_at and record_match(record, tokens)
    ]
    linked_resources = {record["resource_id"] for record in identity_matches}
    linked_resources.update(subject.get("linked_resources", set()))
    related = [
        record for record in evidence
        if record["captured_at"] <= audit_at and record["resource_id"] in linked_resources
    ]
    # Keep the latest observed representation for each concrete resource.
    latest: dict[tuple[str, str], dict[str, Any]] = {}
    for record in related:
        key = (record["system_id"], record["resource_id"])
        if key not in latest or recency_key(record) > recency_key(latest[key]):
            latest[key] = record

    findings: list[dict[str, Any]] = []
    remediation: list[dict[str, Any]] = []
    verification: list[dict[str, Any]] = []
    unresolved = not bool(latest)
    for record in latest.values():
        result = classify_record(record, tokens, audit_at, policy)
        if result is None:
            continue
        evidence_id = record["evidence_id"]
        if result["kind"] in {"remaining", "pii", "flow", "restore"}:
            findings.append(step("FINDING", record["system_id"], record["resource_id"],
                                 result["operation"], result["state"], evidence_id))
            remediation.append(step("REMEDIATION", record["system_id"], record["resource_id"],
                                    result["remediation"],
                                    {"DELETE_RECORD": "ABSENT", "REDACT_RECORD": "REDACTED",
                                     "ANONYMIZE_RECORD": "ANONYMIZED", "DISABLE_DATA_FLOW": "DISABLED",
                                     "BLOCK_RESTORE": "BLOCKED"}[result["remediation"]], ""))
            verification.append(step("VERIFICATION", record["system_id"], record["resource_id"],
                                     result["verify"],
                                     {"VERIFY_RECORD_ABSENT": "ABSENT", "VERIFY_RECORD_REDACTED": "REDACTED",
                                      "VERIFY_RECORD_ANONYMIZED": "ANONYMIZED",
                                      "VERIFY_DATA_FLOW_DISABLED": "DISABLED",
                                      "VERIFY_RESTORE_BLOCKED": "BLOCKED"}[result["verify"]], ""))
            unresolved = False
        elif result["kind"] == "retained":
            verification.append(step("VERIFICATION", record["system_id"], record["resource_id"],
                                     "VERIFY_RECORD_PRESENT", "PRESENT",
                                     evidence_id if not findings else ""))
        elif result["kind"] == "compliant" and (
            record["system_id"] == "account_service"
            and result["operation"] == "VERIFY_RECORD_ABSENT"
        ):
            verification.append(step("VERIFICATION", record["system_id"], record["resource_id"],
                                     result["operation"], result["state"], evidence_id))
    account_absence_proven = any(
        item["system_id"] == "account_service"
        and item["operation"] == "VERIFY_RECORD_ABSENT"
        and item["evidence_id"]
        for item in verification
    )
    if unresolved:
        # Lack of current evidence is not proof of deletion; keep the case open for verification.
        verification.append(step("VERIFICATION", "account_service", subject["user_id"],
                                 "VERIFY_RECORD_ABSENT", "ABSENT", ""))
    if not account_absence_proven and not any(
        item["system_id"] == "account_service" and item["operation"] == "VERIFY_RECORD_ABSENT"
        for item in verification
    ):
        account_resources = sorted(
            resource for resource in linked_resources if resource.startswith("account_")
        )
        verification.append(step(
            "VERIFICATION", "account_service",
            account_resources[0] if account_resources else subject["user_id"],
            "VERIFY_RECORD_ABSENT", "ABSENT", "",
        ))
    complete = account_absence_proven and bool(verification) and not findings and not remediation and not unresolved
    status = "COMPLETE" if complete else "INCOMPLETE"
    if status == "COMPLETE":
        # Completed cases may only contain evidence-backed verification steps.
        verification = [
            step("VERIFICATION", item["system_id"], item["resource_id"],
                 item["operation"], item["state"], item["evidence_id"])
            for item in verification if item["evidence_id"]
        ]
    else:
        verification = [
            step("VERIFICATION", item["system_id"], item["resource_id"],
                 item["operation"], item["state"], "")
            for item in verification
        ]
    steps = ordered_steps(findings, remediation, verification)
    return {"case_id": request["case_id"], "deletion_status": status, "steps_json": steps}


def main() -> None:
    requests = read_csv(DATASET / "deletion_requests.csv")
    by_email, by_user = load_subjects()
    augment_subjects_from_activity(by_email, by_user)
    policy = load_policy()
    evidence = load_evidence()
    rows = [audit_request(request, by_email, by_user, evidence, policy) for request in requests]
    rows.sort(key=lambda row: row["case_id"])
    with OUTPUT.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=OUTPUT_FIELDS)
        writer.writeheader()
        for row in rows:
            writer.writerow({
                "case_id": row["case_id"],
                "deletion_status": row["deletion_status"],
                "steps_json": json.dumps(row["steps_json"], ensure_ascii=False, separators=(",", ":")),
            })
    print(f"Wrote {len(rows)} rows to {OUTPUT}")


if __name__ == "__main__":
    main()

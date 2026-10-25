#!/usr/bin/env python3
"""Validate the generated CSV and measure exact accuracy on public sample answers."""

from __future__ import annotations

import csv
import json
import sys
import unittest
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import main as auditor  # noqa: E402


ROOT = Path(__file__).resolve().parents[2]
DATASET = ROOT / "dataset"
OUTPUT = ROOT / "output.csv"
STEP_FIELDS = {
    "step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id"
}
PHASES = {"FINDING", "REMEDIATION", "VERIFICATION"}
STATUSES = {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"}


def csv_rows(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def additional_cases() -> list[tuple[str, Any, Any]]:
    email, users = auditor.load_subjects()
    historical = next(
        (address for address, subject in email.items()
         if address != auditor.norm(subject["email"])),
        None,
    )
    historical_user = email[historical]["user_id"] if historical else None
    tests: list[tuple[str, Any, Any]] = [
        (
            "Non-deletion marketing preference is not applicable",
            auditor.authorized_deletion("Please unsubscribe me from marketing emails."),
            False,
        ),
        (
            "A French explicit erasure request is authorized",
            auditor.authorized_deletion("Je demande la suppression définitive de mon compte."),
            True,
        ),
        (
            "Historical email resolves to its current user",
            historical_user is not None
            and email[historical]["user_id"] == historical_user,
            True,
        ),
        (
            "A subject-attributable analytics row requires anonymization",
            auditor.classify_record(
                {
                    "resource_id": "analytics_test",
                    "system_id": "analytics_platform",
                    "category": "ANALYTICS_PROFILE",
                    "payload": {"resource_id": "analytics_test", "customer_reference": users[next(iter(users))]["user_id"]},
                    "path": "synthetic-test",
                    "captured_at": auditor.parse_time("2026-01-01T00:00:00Z"),
                    "file_time": auditor.parse_time("2026-01-01T00:00:00Z"),
                    "context": "",
                    "claim": False,
                },
                auditor.subject_tokens(users[next(iter(users))]),
                auditor.parse_time("2026-01-02T00:00:00Z"),
            )["remediation"],
            "ANONYMIZE_RECORD",
        ),
    ]
    return tests


def validate_output() -> dict[str, Any]:
    if not OUTPUT.exists():
        raise FileNotFoundError(f"Missing generated output: {OUTPUT}")
    with OUTPUT.open(encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames != list(auditor.OUTPUT_FIELDS):
            raise AssertionError(f"Unexpected header: {reader.fieldnames}")
        rows = list(reader)
    requests = csv_rows(DATASET / "deletion_requests.csv")
    expected_ids = {row["case_id"] for row in requests}
    output_ids = [row["case_id"] for row in rows]
    if len(rows) != 518 or set(output_ids) != expected_ids or len(set(output_ids)) != len(output_ids):
        raise AssertionError("Output does not contain exactly one row for every request.")
    if output_ids != sorted(output_ids):
        raise AssertionError("Output is not sorted by case_id.")
    manifest_ids = {row["file_id"] for row in csv_rows(DATASET / "evidence_files.csv")}
    for row in rows:
        if row["deletion_status"] not in STATUSES:
            raise AssertionError(f"Invalid status for {row['case_id']}.")
        steps = json.loads(row["steps_json"])
        if not isinstance(steps, list):
            raise AssertionError(f"steps_json is not an array for {row['case_id']}.")
        if row["deletion_status"] == "NOT_APPLICABLE" and steps:
            raise AssertionError(f"NOT_APPLICABLE has non-empty steps for {row['case_id']}.")
        for index, item in enumerate(steps, 1):
            if set(item) != STEP_FIELDS or item["step_no"] != index or item["phase"] not in PHASES:
                raise AssertionError(f"Invalid step structure/order for {row['case_id']} step {index}.")
            if item["evidence_id"] and item["evidence_id"] not in manifest_ids:
                raise AssertionError(f"Unknown evidence ID in {row['case_id']}.")
            if row["deletion_status"] == "COMPLETE" and (
                item["phase"] != "VERIFICATION" or not item["evidence_id"]
            ):
                raise AssertionError(f"COMPLETE step lacks evidence-backed verification for {row['case_id']}.")
            if row["deletion_status"] == "INCOMPLETE" and item["phase"] != "FINDING" and item["evidence_id"]:
                raise AssertionError(f"Future step cites evidence for {row['case_id']}.")
    return {"rows": len(rows), "statuses": {key: sum(r["deletion_status"] == key for r in rows) for key in sorted(STATUSES)}}


def compare_samples() -> dict[str, Any]:
    sample_requests = csv_rows(DATASET / "sample_deletion_requests.csv")
    expected = {row["case_id"]: row for row in csv_rows(DATASET / "sample_output.csv")}
    by_email, by_user = auditor.load_subjects()
    auditor.augment_subjects_from_activity(by_email, by_user)
    policy = auditor.load_policy()
    evidence = auditor.load_evidence()
    actual = {
        request["case_id"]: auditor.audit_request(request, by_email, by_user, evidence, policy)
        for request in sample_requests
    }
    correct_status = 0
    exact_cases = 0
    gold_steps = 0
    exact_steps = 0
    field_correct = 0
    field_total = 0
    exact_sequences = 0
    for case_id, gold_row in expected.items():
        got = actual[case_id]
        gold_steps_list = json.loads(gold_row["steps_json"])
        got_steps = got["steps_json"]
        correct_status += got["deletion_status"] == gold_row["deletion_status"]
        sequence_exact = got_steps == gold_steps_list
        exact_sequences += sequence_exact
        exact_cases += got["deletion_status"] == gold_row["deletion_status"] and sequence_exact
        for i, gold_step in enumerate(gold_steps_list):
            gold_steps += 1
            got_step = got_steps[i] if i < len(got_steps) else {}
            exact_steps += got_step == gold_step
            for field in STEP_FIELDS:
                field_total += 1
                field_correct += got_step.get(field) == gold_step.get(field)
    count = len(expected)
    return {
        "cases": count,
        "status_accuracy": correct_status / count,
        "exact_case_accuracy": exact_cases / count,
        "exact_sequence_accuracy": exact_sequences / count,
        "step_accuracy": exact_steps / gold_steps if gold_steps else 0,
        "field_accuracy": field_correct / field_total if field_total else 0,
        "gold_step_count": gold_steps,
        "field_count": field_total,
        "actual": actual,
        "expected": expected,
    }


class CustomCases(unittest.TestCase):
    def test_non_deletion_is_not_authorized(self) -> None:
        self.assertFalse(auditor.authorized_deletion("Please send me a copy of my data."))

    def test_french_erasure_request_is_authorized(self) -> None:
        self.assertTrue(
            auditor.authorized_deletion("Je demande la suppression définitive de mon compte.")
        )

    def test_historical_email_is_resolved(self) -> None:
        by_email, _ = auditor.load_subjects()
        historical = next(
            address for address, subject in by_email.items()
            if address != auditor.norm(subject["email"])
        )
        self.assertIn(by_email[historical]["user_id"], auditor.load_subjects()[1])

    def test_analytics_requires_anonymization(self) -> None:
        _, users = auditor.load_subjects()
        subject = next(iter(users.values()))
        record = {
            "resource_id": "analytics_test",
            "system_id": "analytics_platform",
            "category": "ANALYTICS_PROFILE",
            "payload": {"resource_id": "analytics_test", "customer_reference": subject["user_id"]},
            "path": "synthetic-test",
            "captured_at": auditor.parse_time("2026-01-01T00:00:00Z"),
            "file_time": auditor.parse_time("2026-01-01T00:00:00Z"),
            "context": "",
            "claim": False,
        }
        result = auditor.classify_record(
            record, auditor.subject_tokens(subject), auditor.parse_time("2026-01-02T00:00:00Z")
        )
        self.assertEqual(result["remediation"], "ANONYMIZE_RECORD")

    def test_step_order_is_consecutive_and_phase_ordered(self) -> None:
        items = auditor.ordered_steps(
            [auditor.step("FINDING", "search_service", "search_1",
                          "REPORT_REMAINING_RECORD", "PRESENT", "evidence_01")],
            [auditor.step("REMEDIATION", "search_service", "search_1",
                          "DELETE_RECORD", "ABSENT", "")],
            [auditor.step("VERIFICATION", "search_service", "search_1",
                          "VERIFY_RECORD_ABSENT", "ABSENT", "")],
        )
        self.assertEqual([x["step_no"] for x in items], [1, 2, 3])
        self.assertEqual([x["phase"] for x in items], ["FINDING", "REMEDIATION", "VERIFICATION"])


def main() -> None:
    summary = validate_output()
    metrics = compare_samples()
    print("Output validation:", summary)
    print(
        f"Public sample: status={metrics['status_accuracy']:.1%}, "
        f"exact cases={metrics['exact_case_accuracy']:.1%}, "
        f"exact sequences={metrics['exact_sequence_accuracy']:.1%}, "
        f"steps={metrics['step_accuracy']:.1%}, fields={metrics['field_accuracy']:.1%}"
    )
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(CustomCases)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if not result.wasSuccessful():
        raise SystemExit(1)
    print("Sample case mismatches:")
    for case_id, gold in metrics["expected"].items():
        got = metrics["actual"][case_id]
        if got["deletion_status"] != gold["deletion_status"] or got["steps_json"] != json.loads(gold["steps_json"]):
            print(
                f"  {case_id}: status={got['deletion_status']} (expected {gold['deletion_status']}), "
                f"steps={len(got['steps_json'])} (expected {len(json.loads(gold['steps_json']))})"
            )


if __name__ == "__main__":
    main()

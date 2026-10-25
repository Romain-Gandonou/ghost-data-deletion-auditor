# Ghost Data Still Exists — deletion audit agent

This repository contains a deterministic Python baseline for the HackerRank
Orchestrate "Ghost Data Still Exists" deletion-audit challenge. The challenge
dataset and generated predictions are intentionally not included.

## Get the participant dataset

Obtain the participant-facing dataset from the official challenge repository:

<https://github.com/interviewstreet/hackerrank-orchestrate-october26>

Place its `dataset/` folder beside this repository's `code/` directory:

```text
ghost-data-deletion-auditor/
├── dataset/
└── code/
```

Do not copy organizer-only data, private answer keys, credentials, or any
other restricted material.

## Run

Use Python 3.10 or newer:

```bash
python3 code/main.py
python3 code/evaluation/main.py
```

The program uses only the Python standard library. It writes `output.csv` at
the repository root. PDF text extraction uses the local `pdftotext` command
when available. Tesseract is optional; if it is not installed, PNG evidence
is skipped with an explicit warning.

## Approach

The pipeline resolves current and historical identifiers, follows identity
links in system activity, parses JSON, text, PDF, and SQLite-compatible SQL
evidence, and filters observations by each request's `audit_at`. It applies
the provided deletion rules to evidence grouped by system and resource, then
serializes ordered findings, remediation actions, and verification steps.
Non-deletion requests produce `NOT_APPLICABLE` with an empty steps array.

The evaluation script checks the output schema and structure, compares
results with the participant-facing public examples, and runs synthetic
tests. Public examples are used for evaluation only, not to generate
predictions.

## Evaluation and limitations

On the 32 public examples, the recorded status accuracy is 65.6%; exact
status-and-sequence accuracy is 9.4%. These results indicate that the
solution is an experimental baseline, not a reliable production deletion
auditor. Known limitations include heuristic resource classification and
skipped screenshots when Tesseract is unavailable. See
[`code/evaluation/evaluation_report.md`](code/evaluation/evaluation_report.md)
for results and
[`code/evaluation/usage_report.md`](code/evaluation/usage_report.md) for
runtime usage.

No model API is called when running the program.

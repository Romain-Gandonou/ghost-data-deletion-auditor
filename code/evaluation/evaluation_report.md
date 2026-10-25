# Evaluation report

## Dataset and method

The evaluation uses the 32 participant-facing public examples in
`dataset/sample_deletion_requests.csv` and their documented expected output
in `dataset/sample_output.csv`. The sample file is used only for evaluation,
never to construct the 518 predictions. The full prediction file is checked
for its exact header, row count, case coverage, case ordering, valid JSON
arrays, consecutive step numbers, allowed phases/statuses, evidence IDs, and
evidence rules for `COMPLETE` and `INCOMPLETE`.

## Public-sample results

| Metric | Result |
| --- | ---: |
| Sample cases | 32 |
| Case-level status accuracy | 21/32 (65.6%) |
| Exact-case accuracy (status and complete ordered step array) | 3/32 (9.4%) |
| Exact-sequence accuracy | 3/32 (9.4%) |
| Exact step accuracy, aligned by position | 32.6% |
| Exact field accuracy across expected steps | 56.6% |

Step accuracy is the number of exactly matching step objects at the same
position divided by the number of expected steps. Field accuracy compares
the seven required fields for expected steps at matching positions. These
are public-sample measurements, not estimates of hidden-test performance.

## Full-dataset structural validation

The latest generated `output.csv` contains 518 sorted rows with the required
header, valid ordered JSON arrays, and these status counts:

| Status | Rows |
| --- | ---: |
| `COMPLETE` | 37 |
| `INCOMPLETE` | 449 |
| `NOT_APPLICABLE` | 32 |

All five authored synthetic tests passed:

1. A marketing unsubscribe request is not authorized as a deletion.
2. A French explicit erasure request is authorized.
3. A historical email resolves to the corresponding current user.
4. An attributable analytics profile requires anonymization.
5. Step numbering is consecutive and phases are ordered.

## Failures and improvements

- The classifier is conservative: absence of a verified account-service
  deletion can produce `INCOMPLETE` even where the public expected result is
  `COMPLETE`.
- Several expected findings and checks are missing. The most important known
  cause is that the execution environment has no Tesseract binary, so the 11
  PNG screenshots are skipped. The generator reports each skipped image.
- Some sample cases were incorrectly marked `COMPLETE` because retained
  evidence was present while an active synchronization or restore risk was
  not recognized. Resource/category inference remains heuristic.
- Step arrays often differ in operation selection, resource coverage, and
  evidence choice, which explains the low exact-sequence and exact-case
  scores despite valid serialization.
- Improvements made during development include historical identifier
  resolution, activity-linked resource discovery, audit-time filtering,
  policy-driven action selection, grouping evidence by concrete resource,
  explicit account-absence verification for `COMPLETE`, and regression tests
  for authorization, identity resolution, anonymization, and ordering.

## Conclusion

The output meets the machine-readable structural contract, but the public
semantic scores are not strong enough to claim reliable or complete auditing.
The submission should be treated as a baseline; installing and validating
OCR and improving evidence classification are priority follow-ups.

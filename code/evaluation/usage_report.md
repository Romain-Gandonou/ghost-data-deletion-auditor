# Usage and cost report

## Final full-dataset run

The latest run processed all 518 requests using `python3 code/main.py`.
Evaluation used `python3 code/evaluation/main.py`.

| Usage field | Result |
| --- | ---: |
| Model provider | None |
| Model name | Not applicable — no model invoked |
| Model/API calls | 0 |
| Input tokens | 0 |
| Output tokens | 0 |
| Total model tokens | 0 |
| Average model tokens per request | 0 |
| Estimated model cost | $0.00 |
| Estimated model cost per request | $0.00 |

The implementation is a local deterministic Python pipeline. It makes no
external model or API calls, so token usage and model costs are zero rather
than estimated from an unreported provider. The Python process did emit
warnings that OCR was skipped for 11 PNG files because Tesseract was not
installed. PDF extraction is attempted via the local `pdftotext` utility.

No API credentials, personal data, or sensitive configuration are required.

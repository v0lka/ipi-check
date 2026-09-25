# FP-corpus — regression fixtures for false positives

This corpus is the *negative* counterpart to `samples/ipi-injections/` and
`samples/malicious-skills/`. Every fixture here is **benign** content that a
real-world repository legitimately contains, yet each one previously (or would
otherwise) trip a detection rule. The regression suite
[`tests/test_fp_regression.py`](../../tests/test_fp_regression.py) asserts that
these fixtures do **not** produce a `BLOCK` verdict.

The corpus is derived from the false-positive taxonomy in
[`docs/development/ipi-check-roadmap.md`](../../docs/development/ipi-check-roadmap.md)
§1.1 (FP-1 … FP-14).

## Map: fixture → FP class → expected verdict

| Fixture | FP class | Expected |
| --- | --- | --- |
| `cyrillic-docs/` | FP-1 homoglyph noise on Cyrillic text | PASS |
| `emoji-docs/` | FP-2 variation selectors on emoji | PASS |
| `binary-assets/` | FP-3 binary assets scanned as text | skipped |
| `binary-skill/` | FP-3 / FP-14 binary asset bundled with a skill | PASS |
| `dense-findings.md` | FP-4 no dedup / per-file cap | findings capped |
| `security-tooling/` | FP-5 attack examples quoted in docs/code | REVIEW max |
| `security-tooling/scripts/` | FP-11 severity parity for source code | REVIEW max |
| `build-config/` | FP-5 / FP-10 destructive build script | REVIEW max |
| `contradiction-docs/` | FP-12 heuristics fire on normal docs | PASS |
| `pass-heuristics/AGENTS.md` | FP-13 heuristic results emitted for PASS | no heuristic results |
| `deploy-skill/` | FP-6…FP-10, FP-14 skill markers & aggregation | REVIEW max |
| `quoted-frontmatter-skill/` | IN-16 quoted frontmatter | PASS |

`BLOCK` is never an acceptable verdict for any fixture in this directory.

## Discovery note

Most fixtures are ordinary Markdown documents. ipi-check only discovers
repository-root Markdown, Markdown under a dot-directory, agent-instruction
files, source code, and skill files — so the regression tests copy the relevant
fixture into a discoverable location (root-level document or skill directory)
before running the pipeline. This mirrors how the documents would be laid out
in a real repository.

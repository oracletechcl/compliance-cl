---
name: collector-assessment-report
description: Review any OCI, on-premises, or hybrid collector evidence bundle against this repository's packs, references, and legal sources, then produce a mock-aligned executive HTML compliance dashboard with evidence-traceable pass/partial/fail status, remediation, Oracle product candidates, and cost assumptions. Use when a user asks to assess, review, report on, or visualize collector output supplied as an absolute collector-run directory or a .zip, .tar, .tar.gz, or .tgz archive.
---

# Collector Assessment Report

## Hard-stop input gate

Require the user to provide the collector output explicitly in the invocation as one absolute path. Accept only:

- a collector output directory containing exactly one `evidence-bundle.json`; or
- a `.zip`, `.tar`, `.tar.gz`, or `.tgz` archive containing exactly one `evidence-bundle.json`.

If the invocation omits the path, gives a relative path, or names multiple candidates, **stop immediately** and ask: `Provide the absolute path to one collector output directory or .zip/.tar/.tar.gz/.tgz archive.` Do not search `collector/out`, infer from open files, choose the newest run, reuse a path from an earlier invocation, inspect evidence, or begin an assessment. This gate is mandatory even when a likely run is visible.

## Workflow

1. Validate that the explicit path exists and has an accepted type. Do not mutate the collector bundle.
2. Locate the repository root containing `packs/`, `references/`, and `sources/`. Stop with a clear error if any corpus directory is absent.
3. Run the deterministic draft generator:

   ```bash
   python3 skills/collector-assessment-report/scripts/generate_report.py \
     --collector-output /absolute/path/from/user \
     --repo-root /absolute/path/to/compliance-cl
   ```

   The script safely validates archives, rejects traversal, links, excessive members, and excessive uncompressed size, validates the bundle shape, sanitizes displayed identifiers, derives OCI/on-premises/hybrid scope from the supplied records, indexes evidence, discovers controls/packs/sources, and writes `report-data.json` plus `report.html`. It never treats mere resource presence as a pass.
4. Read the generated `report-data.json`. Inspect the cited raw files and only the relevant control, pack, reference, and primary-source passages. Read [references/assessment-contract.md](references/assessment-contract.md) before authoring the reviewed assessment.
5. Create `assessment.json` in the generated output directory. Override only conclusions supported by cited collector evidence or repository material. Record rationale, evidence references, remediation, and the suggested Oracle/OCI product or explicitly state that no product alone satisfies the control.
6. Render the reviewed result:

   ```bash
   python3 skills/collector-assessment-report/scripts/generate_report.py \
     --collector-output /absolute/path/from/user \
     --repo-root /absolute/path/to/compliance-cl \
     --assessment /absolute/path/to/assessment.json
   ```

7. Verify that `report.html` is self-contained, opens without network access, filters/searches correctly, and matches `report-data.json`. Report both output paths to the user.

## Assessment rules

- Use `pass`, `partial`, or `fail` in report output. Normalize an incoming legacy `unknown` assessment to `fail`.
- Treat `present` as evidence that a resource exists, not proof that a control passes. The deterministic draft caps it at `partial`.
- Mark a control `fail` when collected evidence contradicts a requirement **or required evidence is absent**. Preserve `evidence_state: not_evidenced` and explain that the failure is an evidence gap rather than an observed configuration violation.
- Keep every conclusion traceable to evidence IDs/raw refs and repository control/pack/source paths. Distinguish observed infrastructure from application/process/legal facts.
- Compute framework degree as `(pass + 0.5 * partial) / required controls`, with missing evidence scoring zero. Display evidence coverage and the no-evidence failure count beside it. Describe this as an evidence-based readiness score, not a legal-compliance certification.
- Identify assessed products from collected inventory and evidence source metadata. Support OCI, on-premises database, middleware, and hybrid bundles without assuming a provider or region. Do not imply that an unobserved product is deployed.
- Phrase Oracle, OCI, and on-premises products as remediation candidates. Explain enablement and residual process/configuration work; no product purchase proves legal compliance.
- Give costs only with currency, as-of date, assumptions, pricing basis, and source. Use a sourced range when defensible; otherwise use `Quote required`. Never fabricate SKU prices or silently apply list prices, discounts, regions, storage, ingestion, or retention assumptions.
- Preserve collector redaction. Do not reproduce secrets, tokens, private keys, raw OCIDs, personal email addresses, or sensitive payloads in the report. Cite redacted identifiers only.
- Include this disclaimer: `Informational technical assessment only; not legal advice or a certification of compliance.`

## Output location

- Directory input: `<collector-run>/analysis/collector-assessment-report/`
- Archive input: `<archive-parent>/<archive-name-without-extension>-analysis/`
- Explicit override: pass `--output-dir /absolute/path`.

The deliverables are `report.html`, `report-data.json`, and the reviewed `assessment.json`. Temporary archive extraction is isolated and removed automatically.

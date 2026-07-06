---
name: collector-assessment-report
description: Review any OCI, on-premises, or hybrid collector evidence bundle against this repository's packs, references, and legal sources, then produce a mock-aligned Spanish executive HTML compliance dashboard with evidence-traceable pass/partial/fail status, remediation, and Oracle product candidates. Use when a user asks to assess, review, report on, or visualize collector output supplied as an absolute collector-run directory or a .zip, .tar, .tar.gz, or .tgz archive.
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
- Pivot the assessment on reviewed components first: group evidence by human-readable component, evaluate its associated controls, and calculate a component status and percentage before presenting control details.
- Preserve a separate `resource_id` and identifier type for every component. Display an OCI OCID when collected, an on-premises target alias when applicable, or an explicit technical/no-applicable identifier for events and process-only expected components. Explain strict-redaction pseudonyms.
- Never render an empty or opaque component name. Normalize UUID, OCID, hash, and redacted identifiers to provider/service plus the evaluated aspect. For missing evidence, use an explicitly expected component and never imply it was observed.
- Phrase Oracle, OCI, and on-premises products as remediation candidates. Bind the candidate, enablement steps, and residual process/configuration work to the affected control or risk action; no product purchase proves legal compliance.
- Split open remediation actions into two exclusive catalogs: `product` for actions materially enabled by an Oracle product, and `process` for governance, legal, organizational, or application-process work. Do not attach an Oracle product to process-only actions. A control qualifies for the `product` track only when a product can materially mitigate it **and** the collector reviewed at least one Oracle/OCI component for it; a product-mitigable control with no reviewed Oracle component is an evidence gap and must move to the `process` track. The product track (Track A) must never contain an entry without a reviewed Oracle component.
- Split the assessment into two independently scored tracks and render each as its own section with its own readiness score, narrative, and clickable risk matrix: **Track A** for controls whose mitigation is materially enabled by an Oracle product, and **Track B** for process/governance/legal controls. Both matrices must navigate to the affected control details, and no Track B control may carry an Oracle product as its closure. Do not render a separate blended global-score panel; the per-track score is the only readiness percentage shown, and it is color-coded (green/amber/red) and paired with a "Meta recomendada: ≥ 90%" caption, using the same ≥90%/≥50% thresholds for the color as for the recommendation. Every risk matrix must clearly label both axes: an "Impacto" title over the impact columns (Bajo/Medio/Alto) and a "Probabilidad" title beside the probability rows (Baja/Media/Alta) — never render impact without an equally visible probability axis label.
- Enrich, do not duplicate: carry product/track and evidence-coverage detail through the **"Cumplimiento por dimensión"** and **"¿Qué falta para alcanzar el cumplimiento?"** sections instead of a separate detected-product compliance table. Each dimension row is clickable, shows its pass/partial/fail counts, evidence coverage percentage, a Track A/B breakdown, and its driving gap. The gap list shows every open (non-`pass`) control — not a capped top-N — each with a Track A/B badge, a one-line mitigation hint (the Oracle product name for Track A, or "Acción de proceso/gobierno" for Track B), its compliance percentage, and a missing-evidence subtotal. Both remain clickable into the single-pane detail panel.
- Keep the per-component table ("Evaluación por componentes revisados") and both action catalogs ("Acciones asociadas a productos Oracle" and "Acciones asociadas a procesos") computed in `report-data.json`, but render all three sections `hidden` by default — their content is superseded by the dimension/gap views for everyday reading, but stays available in the DOM/data for later use.
- Consolidate every control detail into one single-pane panel ("single plane of glass"): a matrix cell, a dimension row, a prioritized gap, or a reviewed component all focus the same panel, and its search/status/track/framework filters operate on the same surface. Each card shows the full detail at once — status/matrix level, affected products and resources identified by name and OCID where applicable, evidence found, expected reference, non-compliant components, mitigation action, and recommended Oracle product — with no jump to a separate detailed-controls section. Default state shows all controls worst-first.
- For every expanded control, render a complete, Spanish-language detail block with: evidence found, expected evidence/reference, matrix status and compliance percentage, mitigation action, and recommended Oracle product with a detailed explanation of why it mitigates the specific gap and what must be enabled. Do not omit a field: state `No se encontró evidencia` or `No se definió una referencia esperada verificable` when appropriate.
- Structure the **"Acción de mitigación"** field as an explanation plus concrete, ordered, step-by-step instructions (`remediation_steps`), not prose alone. When the control's mitigation is materially enabled by an Oracle product (Track A), append one final, visually distinct step naming that product and stating exactly what to do with it (the enablement instructions) — do not leave the product mention only in the separate "Producto Oracle recomendado" field.
- When a user selects a risk-matrix cell, preserve that cell's status color and compliance semantics in the selected control view. The control detail must visibly identify the same status (`Conforme`, `Parcial` or `No conforme`) and percentage; color is an aid, never the only status indicator.
- Do not render a global product-mitigation or cost-estimate section. Omit pricing from the report unless the user explicitly requests it in a later scope; never fabricate SKU prices or silently apply list prices, discounts, regions, storage, ingestion, or retention assumptions.
- Render the entire report in Spanish — every heading, label, summary, call to action, and the disclaimer — with no mixed-language content. Preserve only evidence identifiers, source paths, product names, and quoted legal text where translation would reduce traceability. A reviewed assessment overlay's `rationale`/`remediation`/`remediation_steps` text must also be authored in Spanish; translate any English overlay content before rendering.
- Preserve collector redaction. Do not reproduce secrets, tokens, private keys, raw OCIDs, personal email addresses, or sensitive payloads in the report. Cite redacted identifiers only.
- Include this disclaimer: `Evaluación técnica informativa únicamente; no constituye asesoría legal ni una certificación de cumplimiento.`

## Output location

- Directory input: `<collector-run>/analysis/collector-assessment-report/`
- Archive input: `<archive-parent>/<archive-name-without-extension>-analysis/`
- Explicit override: pass `--output-dir /absolute/path`.

The deliverables are `report.html`, `report-data.json`, and the reviewed `assessment.json`. Temporary archive extraction is isolated and removed automatically.

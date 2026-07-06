# Assessment overlay contract

Use this contract after the deterministic draft has indexed the collector and repository corpus. Keep the overlay concise: omit controls whose draft conclusion is already correct.

## JSON shape

```json
{
  "schema": 1,
  "assessed_product": "Nombre legible de la carga de trabajo o producto",
  "scope_notes": "Qué cubrió el colector y qué no pudo cubrir",
  "controls": {
    "sec-logs": {
      "status": "partial",
      "rationale": "Existen recursos de logs de OCI, pero el paquete no acredita la retención requerida ni la cobertura de auditoría de aplicación.",
      "evidence_refs": [
        "ev-example",
        "raw/oci/logging/<collected-region>.json",
        "references/controls.md",
        "packs/ley-21719/pack.md"
      ],
      "remediation": "Defina los eventos de auditoría, habilite las fuentes de log faltantes, configure la retención, proteja el acceso y pruebe el enrutamiento de alertas.",
      "remediation_steps": [
        "Defina los eventos de auditoría obligatorios para infraestructura y aplicación.",
        "Habilite las fuentes de log faltantes.",
        "Configure la retención y proteja el acceso a los registros.",
        "Pruebe el enrutamiento de alertas de extremo a extremo."
      ],
      "oracle_product": {
        "name": "OCI Logging and OCI Monitoring",
        "why": "Centraliza logs, métricas, alarmas y notificaciones.",
        "enablement": "Cree grupos de logs, habilite logs de servicio/aplicación, configure alarmas y tópicos de Notifications."
      }
    }
  }
}
```

Reviewed overlays may contain legacy `unknown`, but report output normalizes it to `fail` with `evidence_state: not_evidenced`. Required evidence that is absent is not compliant. `evidence_refs` must name evidence IDs, bundle-relative raw paths, or repository-relative `packs/`, `references/`, and `sources/` paths that were actually reviewed.

`remediation_steps` is an optional, non-empty array of concrete, ordered, Spanish-language step strings that back the `remediation` explanation. When omitted, the draft's default steps for that control ID are kept. When the control is on the product track (Track A), the renderer automatically appends one final step naming the recommended Oracle product and its enablement instructions — do not duplicate that product step inside the overlay's own `remediation_steps`; keep those steps focused on the process/configuration work the analyst must still do. Every string field an analyst authors (`rationale`, `remediation`, `remediation_steps`, `scope_notes`, `assessed_product`) must be written in Spanish; the renderer does not translate overlay content, and English text in these fields will render as English in the report.

## Status decision table

| Evidence state | Status |
|---|---|
| Direct, sufficient evidence satisfies the whole control | `pass` |
| Some required capability is evidenced, but material requirements remain unproved or incomplete | `partial` |
| Direct evidence contradicts a requirement | `fail` |
| Required evidence is absent, outside collector scope, ambiguous, or not machine-verifiable | `fail` with `evidence_state: not_evidenced` |

Explain whether each failure is an observed contradiction or a missing-evidence failure. Keep collector errors and skipped services as coverage limitations as well; they do not erase the obligation to provide evidence for a required control.

## Product guidance

Use observed inventory and evidence source metadata to identify current products across OCI, on-premises, and hybrid scope. Product recommendations are candidates, not conclusions. Common mappings include:

| Control need | Candidate Oracle/OCI capability |
|---|---|
| Audit and access logs | OCI Audit, Logging, Logging Analytics |
| Detection and response | OCI Cloud Guard, Security Zones, Events, Notifications |
| Secrets and keys | OCI Vault, Secrets, Key Management |
| Database security | Oracle Data Safe, Database Vault, Audit Vault and Database Firewall |
| Identity and MFA | OCI IAM Identity Domains |
| Network/TLS edge | OCI Certificates, WAF, Load Balancer, API Gateway |
| Backup and recovery | OCI Backup services, Full Stack Disaster Recovery |
| Data discovery/governance | OCI Data Catalog or Oracle Enterprise Data Management capabilities |
| Governance/process controls | Oracle Fusion Cloud Risk Management or a documented process |

If a control needs governance, contracts, training, legal review, or application behavior, state that no Oracle product alone closes it. Do not add a standalone cost estimate or generic product-mitigation section to this report.

## Required control detail

Every rendered control must expose the following fields in Spanish inside its expandable detail, in this order or an equally clear visual grouping:

| Field | Required content |
|---|---|
| `Evidencia encontrada` | Componentes, servicios y condiciones realmente observados en la recolección. Si no se recolectó evidencia, indíquelo como no conforme; no invente evidencia ni muestre rutas internas. |
| `Referencia esperada` | Descripción detallada del resultado, configuración, proceso y pruebas que debían existir. Diferénciela de la evidencia recolectada. No muestre nombres ni rutas de archivos internos; describa en lenguaje humano la evidencia mínima esperada y los requisitos normativos aplicables. |
| `Componentes revisados no conformes` | Identifique el componente, servicio y condición observada que no acredita el control. Si no hubo evidencia, muestre el componente objetivo del control y deje explícito que es una expectativa, no una observación recolectada. Nunca deje el componente vacío. |
| `Estatus` | Human-readable matrix status (`Conforme`, `Parcial`, `No conforme`) plus a deterministic compliance percentage. Explain that it is the evidence-based degree for this control, not a legal certification. |
| `Acción de mitigación` | A short explanation of the gap plus an ordered, concrete step-by-step list (`remediation_steps`) needed to close it — not prose alone. When the control is on the product track, the last step must name the specific Oracle product and state exactly what to do with it (the enablement action), rendered distinctly from the process steps. |
| `Producto Oracle recomendado` | Candidate product/capability, its enablement steps, and a detailed explanation of why it mitigates this particular gap. State residual work and say explicitly when no product alone closes the control. |

## Component-first assessment and action catalogs

The report must first group collected evidence by human-readable component and calculate, for every component:

- provider, service, type, and evaluated aspect;
- OCID or other operational `resource_id`, plus its identifier type; for process-only expected components use an explicit `No aplica` value;
- whether it was observed or is only an expected component for a missing-evidence control;
- associated control IDs;
- evidence count;
- worst control status and deterministic average compliance percentage.

Only after this component assessment may the report render remediation catalogs. Open actions must be assigned to exactly one category:

- `Acciones asociadas a productos Oracle`: technical actions materially enabled by a named Oracle product, with why it applies, enablement work, component, control, acceptance evidence, and closure criterion. A control qualifies here only when a product can materially mitigate it **and** the collector reviewed at least one Oracle/OCI component for it. A product-mitigable control with no reviewed Oracle component (an evidence gap) moves to the process catalog; the product track/matrix must never contain an entry without a reviewed Oracle component.
- `Acciones asociadas a procesos`: governance, legal, organizational, incident, or application-process actions. Do not attach a product merely because one could support adjacent work.

Render a separate clickable risk matrix for each action category, each inside its own scored track section (Track A = Oracle-product-enabled controls; Track B = process/governance/legal controls). Each track shows an independent evidence-based readiness score, a narrative, and its matrix. The product matrix may contain only product-enabled controls; the process matrix may contain only process controls. Both must retain matrix-to-detail navigation.

Do not render a separate detected-product compliance table. Instead enrich the dimension and gap sections directly:

- **Cumplimiento por dimensión**: each dimension row is clickable (focuses the single-pane panel to that dimension's controls) and shows pass/partial/fail counts, evidence coverage percentage, a Track A/B control-count breakdown, and its driving (worst) gap by name.
- **¿Qué falta para alcanzar el cumplimiento?**: list every open (non-`pass`) control, not a capped top-N. Each row is clickable, shows a Track A/B badge, a one-line mitigation hint (the Oracle product name for Track A, "Acción de proceso/gobierno" for Track B), and its compliance percentage. Show a missing-evidence subtotal (`not_evidenced` count of the open total) beneath the aggregate count.

The per-component table (`Evaluación por componentes revisados`) and the product-actions catalog (`Acciones asociadas a productos Oracle`) remain computed in `report-data.json` and present in the DOM, but their sections render `hidden` by default — the dimension/gap views carry that information for everyday reading.

Use a deterministic control percentage consistent with the status: `Conforme` = 100%; `Parcial` = 50%; `No conforme` = 0%. A future evidence-backed scoring model may use another percentage, but it must document its calculation and never inflate an absent-evidence failure above 0%.

### Matrix-to-detail interaction

All control detail lives in one consolidated single-pane panel — a matrix cell, a dimension row, a prioritized gap, and a reviewed component all focus the same panel, whose own search/status/track/framework filters operate on that same surface, and whose default state lists every control worst-first. Each rendered card is self-contained (status/matrix level, affected products and resources by name and OCID where applicable, evidence found, expected reference, non-compliant components, mitigation, and recommended Oracle product); there is no separate detailed-controls section to navigate to.

Each populated risk-matrix cell must be selectable. On selection, filter the consolidated panel to its controls and carry the selected matrix semantics into the control details:

- use the same status color family as the selected matrix cell (green for `Conforme`, amber for `Parcial`, red for `No conforme`);
- show the text status and percentage adjacent to the color for accessibility;
- retain the selected state until the user clears filters or selects another cell; and
- do not rely on color alone to communicate compliance.

## Required report qualities

- Display assessed workload and observed OCI/on-premises technologies separately, without assuming provider, region, or deployment model.
- Match the simplified executive mock structure: assessment metadata, KPI strip, dimension scores, compliance gaps, per-track scored risk matrices, 90-day action plan, benefits, and detailed controls. Do not render a single blended global-score panel (e.g. a donut spanning all tracks) or a blended-score conclusion narrative: mixing product-enabled and process controls into one number is not a clear metric. Only the independently scored Track A/Track B percentages are shown; do not add a summary sentence that recomputes a single blended score elsewhere in the report.
- Each risk matrix must show both axes clearly labeled: an "Impacto" (impact) title over the Bajo/Medio/Alto columns, and a "Probabilidad" (probability) title beside the Baja/Media/Alta rows. Never render just one axis title.
- Show the "Meta recomendada: ≥ 90%" target beside each track's score, and color-code that per-track percentage (green/amber/red) using the same ≥90%/≥50%/below-50% thresholds as the recommendation, so the color and the stated target agree.
- Make every populated risk-matrix cell actionable: selecting it must navigate to or filter the related control details.
- For every control detail, show evidence found, expected reference, matrix status plus percentage, mitigation action, and a recommended Oracle product with why/enablement. The selected risk-cell color and status must remain visible in the control detail.
- Bind the Oracle/OCI remediation candidate and enablement information to the affected control or risk action. Do not render standalone product-mitigation or cost-estimate panels.
- Show framework score, pass/partial/fail counts, missing-evidence failures, and evidence coverage.
- Provide searchable/filterable controls and expandable evidence/remediation details.
- Include collector coverage errors without turning them into failed controls.
- Link each legal conclusion to repository sources when the source supports it.
- Keep the HTML self-contained; do not load CDN scripts, fonts, analytics, or remote styles.
- Render all human-facing report prose in Spanish, with no mixed-language content anywhere in the report — including any analyst-authored overlay text. Preserve evidence identifiers, product names, source paths, and verbatim legal quotations only where translation would make the evidence less traceable.
- Render mitigation actions as an explanation plus ordered step-by-step instructions, with an explicit final step naming the Oracle product and what to do with it whenever the control is on the product track.
- End with: `Evaluación técnica informativa únicamente; no constituye asesoría legal ni una certificación de cumplimiento.`

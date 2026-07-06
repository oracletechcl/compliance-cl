# Assessment overlay contract

Use this contract after the deterministic draft has indexed the collector and repository corpus. Keep the overlay concise: omit controls whose draft conclusion is already correct.

## JSON shape

```json
{
  "schema": 1,
  "assessed_product": "Human-readable workload or product name",
  "scope_notes": "What the collector covered and could not cover",
  "controls": {
    "sec-logs": {
      "status": "partial",
      "rationale": "OCI log resources exist, but the bundle does not prove required retention or application audit coverage.",
      "evidence_refs": [
        "ev-example",
        "raw/oci/logging/<collected-region>.json",
        "references/controls.md",
        "packs/ley-21719/pack.md"
      ],
      "remediation": "Define audit events, enable the missing log sources, set retention, protect access, and test alert routing.",
      "oracle_product": {
        "name": "OCI Logging and OCI Monitoring",
        "why": "Centralizes logs, metrics, alarms, and notifications.",
        "enablement": "Create log groups, enable service/custom logs, configure alarms and Notifications topics.",
        "cost": {
          "estimate": "Quote required",
          "currency": "USD",
          "as_of": "<report-generation YYYY-MM-DD>",
          "pricing_basis": "Monthly ingestion, retained GB, query usage, and regional price list",
          "assumptions": ["Target region not priced in this offline assessment", "No negotiated discount assumed"],
          "source": "https://www.oracle.com/cloud/price-list/"
        }
      }
    }
  }
}
```

Reviewed overlays may contain legacy `unknown`, but report output normalizes it to `fail` with `evidence_state: not_evidenced`. Required evidence that is absent is not compliant. `evidence_refs` must name evidence IDs, bundle-relative raw paths, or repository-relative `packs/`, `references/`, and `sources/` paths that were actually reviewed.

## Status decision table

| Evidence state | Status |
|---|---|
| Direct, sufficient evidence satisfies the whole control | `pass` |
| Some required capability is evidenced, but material requirements remain unproved or incomplete | `partial` |
| Direct evidence contradicts a requirement | `fail` |
| Required evidence is absent, outside collector scope, ambiguous, or not machine-verifiable | `fail` with `evidence_state: not_evidenced` |

Explain whether each failure is an observed contradiction or a missing-evidence failure. Keep collector errors and skipped services as coverage limitations as well; they do not erase the obligation to provide evidence for a required control.

## Product and cost guidance

Use observed inventory and evidence source metadata to identify current products across OCI, on-premises, and hybrid scope. Product recommendations are candidates, not conclusions. Common mappings include:

| Control need | Candidate Oracle/OCI capability | Typical cost driver |
|---|---|---|
| Audit and access logs | OCI Audit, Logging, Logging Analytics | ingestion, retained GB, queries |
| Detection and response | OCI Cloud Guard, Security Zones, Events, Notifications | service tier, events, destinations |
| Secrets and keys | OCI Vault, Secrets, Key Management | key versions, HSM tier, secret operations |
| Database security | Oracle Data Safe, Database Vault, Audit Vault and Database Firewall | database target/service edition or quote |
| Identity and MFA | OCI IAM Identity Domains | identity-domain edition and active users |
| Network/TLS edge | OCI Certificates, WAF, Load Balancer, API Gateway | certificate operations, bandwidth, requests, shape |
| Backup and recovery | OCI Backup services, Full Stack Disaster Recovery | protected capacity, storage, operations, region |
| Data discovery/governance | OCI Data Catalog or Oracle Enterprise Data Management capabilities | catalog capacity/service subscription |
| Governance/process controls | Oracle Fusion Cloud Risk Management or a documented process | subscription/users; often quote required |

If a control needs governance, contracts, training, legal review, or application behavior, state that no Oracle product alone closes it. For current prices, use only an official Oracle pricing page or user-provided rate card, record the retrieval date and region/currency, and show the calculation. Without those inputs, report `Quote required` rather than a numeric amount.

## Required report qualities

- Display assessed workload and observed OCI/on-premises technologies separately.
- Match the executive mock structure: assessment metadata, global score donut, KPI strip, dimension scores, compliance gaps, risk matrix, Oracle mitigation table, cost estimate, 90-day action plan, conclusion, benefits, and detailed controls.
- Show framework score, pass/partial/fail counts, missing-evidence failures, and evidence coverage.
- Provide searchable/filterable controls and expandable evidence/remediation details.
- Include collector coverage errors without turning them into failed controls.
- Link each legal conclusion to repository sources when the source supports it.
- Keep the HTML self-contained; do not load CDN scripts, fonts, analytics, or remote styles.
- End with: `Informational technical assessment only; not legal advice or a certification of compliance.`

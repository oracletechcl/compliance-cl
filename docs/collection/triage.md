# Collector live test and triage — Kairos OCI compartment

Date: 2026-07-06  
Repository: `compliance-cl`  
Target source: `/Users/dralquinta/Documents/DevOps/my-projects/kairos/portal/.env`  
Mode: read-only OCI SDK collection, strict redaction

> This document is a technical collection and analysis record. It is not legal advice and does not
> certify legal compliance.

## Executive status

- A real OCI compartment was resolved from the Kairos Autonomous Database OCID without copying
  credentials into this repository.
- The first bundle was structurally valid but unusable: OCI SDK values were discarded and only SDK
  metadata maps were written.
- The collector was patched with TDD. The current reviewable bundle contains real OCI configuration
  values, valid source references, hashed OCI identifiers, and no private key/bearer/password material.
- Current review bundle:
  `collector/out/kairos-compartment-certified-fast-20260706/`.
- A final rerun is being produced after additional SDK adapter corrections. Its final location and
  certification result are recorded at the end of this document.

## Target resolution

The Kairos `.env` contains one infrastructure selector: `KAIROS_DB_OCID`, an Autonomous Database OCID.
Database credentials, DSN, wallet path, wallet password, and IAM token file were unset. The OCID encodes
`us-sanjose-1`; a read-only `get_autonomous_database` call resolved its parent compartment.

Resolved non-secret facts:

- Database display name: `kairos`
- Workload: OLTP
- Lifecycle: AVAILABLE
- Free tier: no
- Data Safe registration: NOT_REGISTERED
- Region: `us-sanjose-1`
- Compartment count selected for collection: 1

No raw OCID, API key, fingerprint, private key, token, password, or wallet value is documented here.

## Runtime configuration

The temporary runtime YAML used:

- `auth: config_file`, profile `DEFAULT`, local `~/.oci/config`
- exact parent compartment only; no tenancy-wide sweep
- one region: `us-sanjose-1`
- `services: all` (31 registered OCI service collectors)
- on-premises DB and middleware disabled
- strict redaction
- 32 service-level worker threads for the optimized run
- 5-second connect timeout and 30-second normal read timeout
- explicit OCI `NoneRetryStrategy`; the collector retains bounded 429 backoff
- 120-second bounded read floor only for Audit and Threat Intelligence

Temporary configs live under `/private/tmp` with mode `0600`; they are not repository artifacts.

## Installation and verification

Environment:

- Python 3.14.3
- virtual environment: `.venv`
- editable package: `oracle-compliance-collector[all]`
- OCI SDK 2.181.0
- python-oracledb 4.0.1
- pytest 9.1.1

Install command:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip setuptools wheel
.venv/bin/python -m pip install -e './collector[all]'
```

Final integrated regression before the last live pass:

```text
203 passed in 24.28s
Successfully built oracle_compliance_collector-0.1.0.tar.gz
Successfully built oracle_compliance_collector-0.1.0-py3-none-any.whl
```

The initial sandboxed suite showed 182 passes and 10 customer-package failures because isolated builds
could not reach PyPI. Re-running with approved network access produced a clean suite; those failures were
environmental, not product regressions.

## How the script runs

From `collector/`:

```bash
./run-collector.sh --config /private/tmp/kairos-collector-certified-final.config.yaml --dry-run
./run-collector.sh --config /private/tmp/kairos-collector-certified-final.config.yaml
```

The wrapper forwards to the installed `collector run` command. It uses the script default output parent
`./out`, so execution from `collector/` lands under `collector/out/<run.name>/`.

Each region/service is a separate `CollectorTask`. The orchestrator uses a bounded
`ThreadPoolExecutor`, isolates collector failures, merges results after completion, and returns:

- 0: complete
- 2: partial/skipped service or nonfatal collector error
- 1: fatal error

## Baseline bundle — rejected

Path: `collector/out/kairos-compartment-triage-20260706/`

The baseline passed JSON Schema but failed semantic certification:

| Metric | Baseline |
|---|---:|
| Files | 18 |
| Bytes | 449,900 |
| Evidence/inventory records | 95 / 95 |
| Unique evidence IDs | 16 |
| Unique inventory IDs | 1 |
| Resources named `unknown` | 95 |
| Metadata-only raw records | 95 |
| Services scanned/skipped | 28 / 3 |
| Nonfatal errors | 5 |

Root cause: OCI SDK generated models store resource values behind generated properties/private fields.
They do not expose `to_dict()`. The generic serializer filtered private fields and retained only
`swagger_types` and `attribute_map`. Unit tests used dictionaries and did not model the real SDK layout.

## Implemented collector fixes

1. Serialize OCI SDK-style models through their generated `swagger_types` properties, including nested
   models. Real IDs, display names, lifecycle, network, encryption, backup, TLS, and policy fields now
   survive normalization.
2. Resolve Logging Analytics namespace at tenancy scope.
3. Build evidence IDs from stable resource IDs, not display names.
4. Hash emails deterministically in strict mode (`email.sha256:<digest>`); minimal mode is unchanged.
5. Raise full-stack parallelism from 8 to 32, with default 16 for other runs.
6. Configure documented SDK connect/read timeouts and close each SDK HTTP session after its task.
7. Override generated operations that silently use Oracle's 10-minute default retry strategy with
   `NoneRetryStrategy`; keep the collector's bounded 429 backoff.
8. Do not pass `page=None` to SDK list operations that do not accept a page argument.
9. Route Cloud Guard calls through its configured reporting region.
10. Use tenancy scope plus an SDK-supported one-item/one-page bound when Threat Intelligence is selected
    explicitly. Exclude it from implicit `services: all` because `list_indicators` is an Oracle global
    feed, not customer-compartment inventory.
11. Bound Audit to one SDK-default page from the exact 30-day UTC window and disclose continuation as a
    coverage warning instead of performing an unbounded log export.
12. Derive stable inventory/evidence identity from OCI `event_id` when an Audit event has no conventional
    `id`, `display_name`, or `name`.
13. Record both implicit service exclusions and bounded-sample warnings in bundle coverage metadata.

Oracle SDK references:

- [SDK overview](https://docs.oracle.com/en-us/iaas/Content/API/SDKDocs/pythonsdk.htm)
- [Connection/read timeouts](https://docs.oracle.com/en-us/iaas/tools/python/latest/customize_service_client/connection_read_timeout.html)
- [Retry strategies](https://docs.oracle.com/en-us/iaas/tools/python/latest/sdk_behaviors/retries.html)
- [Pagination helpers](https://docs.oracle.com/en-us/iaas/tools/python/latest/api/pagination.html)

## First valid optimized bundle

Path: `collector/out/kairos-compartment-certified-fast-20260706/`

Timed result: 208.74 seconds; exit 2 (partial).

| Metric | Result |
|---|---:|
| Files | 18 |
| Bytes | 871,528 |
| Evidence/inventory records | 102 / 102 |
| Unique inventory IDs | 102 |
| Resources named `unknown` | 0 |
| Metadata-only raw records | 0 |
| Raw records with an identifier field | 102 |
| Services scanned/skipped | 28 / 3 |
| Nonfatal errors | 5 |
| JSON Schema errors | 0 |
| Missing source references | 0 |
| Non-hashed OCID tokens | 0 |
| Private-key/bearer/password markers | 0 |

This bundle is valid for review, but it predates the final stable evidence-ID and email fixes. Keep it for
comparison; use the final bundle for downstream analysis.

## Data collected in the first valid bundle

The run produced 16 non-empty service raw files:

- API Gateway: 6
- Block Storage: 5
- Compute: 12
- Container Instances: 20
- Database: 2
- Functions: 9
- Load Balancer: 3
- Logging: 4
- Monitoring: 5
- MySQL: 4
- Networking: 7
- Notifications: 2
- Object Storage: 16
- OKE: 3
- Vault: 2
- WAF: 2

Twelve additional services completed successfully with zero records. The first valid run skipped Audit,
Logging Analytics, and Threat Intelligence. Five nonfatal errors were recorded: Audit list events,
Block Storage boot-volume enumeration, Cloud Guard problems, Logging Analytics namespace, and Threat
Intelligence indicators. The final SDK fixes target each code-caused failure; product availability and
permissions remain legitimate reasons for exit 2.

## Technical security observations

Observed OCI configuration includes:

- 12 compute instances; legacy IMDS endpoints disabled on only 1, PV encryption in transit enabled on 2.
- 2 Autonomous Databases with Oracle-managed encryption and 60-day backup retention; mandatory mTLS is
  disabled on both; Data Guard is disabled.
- 6 public API Gateways.
- 3 public load balancers; two expose HTTP-only listeners, one exposes TLS 1.2/1.3 on 443 while backend
  sets do not show backend TLS.
- 5 block volumes with valid configuration records; boot-volume coverage depended on the paginator fix.
- 5 enabled monitoring alarms, 4 active log groups, and 2 notification topics.
- 2 Vault records were in a deleted lifecycle state.
- OKE control endpoint exposure, NSG binding, image policy, admission policy, and node encryption require
  remediation review.

These are technical signals, not legal verdicts. Missing customer-managed keys do not prove absence of
OCI default encryption.

## Kairos source review findings

The repo skill's discovery phase also inspected the Kairos portal source. Highest-priority source findings:

1. Critical: login accepts an active Oracle email without validating password, SSO assertion, signed
   identity token, MFA, or challenge. A known bootstrap-admin email can be impersonated.
2. Critical: named seller/account-plan data is bundled in unauthenticated static frontend assets.
3. High: seller/account access scope is calculated but not enforced by provider API routes.
4. High: sessions have no TTL/idle expiry, do not revalidate user role/activation, and use browser
   `localStorage` bearer tokens.
5. High: delegated cookie/JWT/header captures persist without cleanup; login accepts arbitrary server
   paths for auth JSON.
6. High: browser stores and backend user JSON lack complete retention/deletion workflows.
7. Medium: there is no compliance-grade backend audit trail for login/admin/provider actions.
8. Medium: privacy notice, consent/acknowledgment, and data-subject-right workflows were not found.

Detailed source references and resulting control states are written to the downstream analysis artifacts.

## Final bundle certification

Certified output: `collector/out/kairos-compartment-certified-final-20260706/`

Timed result: 49.56 seconds; exit 2 (declared partial coverage). This is 4.21x faster than the first valid
208.74-second run, a 76.3% elapsed-time reduction.

| Metric | Certified result |
|---|---:|
| Files / bytes | 21 / 6,250,175 |
| Raw JSON files / parsed records | 19 / 1,933 |
| Evidence / inventory records | 1,933 / 1,933 |
| Unique evidence / inventory IDs | 1,933 / 1,933 |
| Missing or duplicate IDs | 0 |
| Resources named `unknown` | 0 |
| Metadata-only raw records | 0 |
| Raw records without an identity field | 0 |
| Missing source references | 0 |
| JSON Schema errors | 0 |
| Collector errors | 0 |
| Services scanned / explicitly skipped | 30 / 1 |
| Raw OCIDs / emails / credential markers | 0 / 0 / 0 |

The bundle contains 1,664 `present` and 269 `unknown` evidence signals. Strict redaction produced 19,656
deterministic OCID pseudonyms and no raw OCIDs. The only partial-coverage declarations are intentional:

- Threat Intelligence is excluded from implicit `services: all`; it remains available by explicit opt-in.
- Audit contains the first 100 events from the 30-day window; OCI returned a continuation token, which is
  recorded as a bounded-sample warning.

Non-empty service records: Logging Analytics 1,624; Audit 100; Cloud Guard 92; Block Storage 20;
Container Instances 20; Object Storage 16; Compute 12; Functions 9; Networking 7; API Gateway 6;
Monitoring 5; Logging 4; MySQL 4; OKE 3; Load Balancer 3; Database 2; Notifications 2; Vault 2; WAF 2.

Post-patch validation completed with `233 passed`. The wheel and source archive rebuilt successfully at
`collector/dist/oracle_compliance_collector-0.1.0-py3-none-any.whl` and
`collector/dist/oracle_compliance_collector-0.1.0.tar.gz`.

## Final analysis and reusable skill

The reviewed assessment generated from the explicit certified-run path is located at:

- `collector/out/kairos-compartment-certified-final-20260706/analysis/collector-assessment-report/assessment.json`
- `collector/out/kairos-compartment-certified-final-20260706/analysis/collector-assessment-report/report-data.json`
- `collector/out/kairos-compartment-certified-final-20260706/analysis/collector-assessment-report/report.html`

The final report derives its scope directly from the supplied bundle: 29 controls, 7 partial and 22 no
conformes. It has no `unknown` status: absence of required evidence is represented as a
`not_evidenced` failure. The self-contained HTML is fully in Spanish, follows the executive mock layout,
and derives OCI, on-premises, or hybrid scope from each supplied bundle. Its risk matrix and the gap rows
are clickable: they filter and take the reviewer to the affected control details. Remediation and the
Oracle product candidate are displayed for each control; the separate global mitigation and cost panels
were intentionally removed.

Cada detalle ahora presenta evidencia encontrada, la referencia y fuente de evidencia esperada desde el
catálogo, estado de cumplimiento con porcentaje y color de la celda de riesgo, acción de mitigación, y el
producto Oracle recomendado con su justificación y habilitación sugerida.

La referencia esperada se muestra como una descripción del resultado, configuración, proceso y pruebas
mínimas requeridas; no expone rutas ni nombres de archivos internos. Cuando existe evidencia insuficiente,
el detalle identifica el componente o servicio revisado y la condición que no acredita cumplimiento.

El contrato de evidencia ahora deriva un componente estructurado y no vacío para cada registro del collector,
de forma uniforme en OCI, base de datos on-premises, SQL directo y middleware. Para controles sin evidencia,
el informe muestra un componente objetivo del alcance como expectativa, no como un hallazgo observado.
Los UUID, OCID y valores con hash no se usan como nombre visible del componente: se normalizan a servicio y
aspecto legibles, por ejemplo `OCI Audit — Configuración de auditoría`. El plan de acción ya no contiene
resultados esperados genéricos; cada fila identifica el control y componente, evidencia de aceptación y
criterio de cierre correspondiente.

El informe pivota primero por componente revisado: agrupa la evidencia, calcula estado y porcentaje del
componente, y muestra los controles asociados. Las acciones abiertas se publican después en dos catálogos
exclusivos: acciones habilitadas por productos Oracle y acciones de proceso sin producto asociado.
Cada categoría tiene su propia matriz de riesgo clickeable. Los componentes conservan por separado su
`resource_id`: OCID cuando está disponible, alias on-premises o identificador técnico del evento; la
redacción estricta puede seudonimizar ese valor sin convertirlo en el nombre humano del componente.

The reusable, version-controlled Codex skill is at `skills/collector-assessment-report/` and is installed
through `~/.codex/skills/collector-assessment-report`. It hard-stops unless each invocation supplies one
absolute collector-output directory or `.zip`/`.tar`/`.tar.gz`/`.tgz` archive. It does not infer the newest
run or contain Kairos paths, regions, dates, counts, or outcomes. Archive traversal, links, oversized member
sets, and excessive uncompressed size are rejected. Fifteen portability/privacy/archive/interaction tests
and the Codex skill validator pass. The HTML is self-contained, searchable, and filterable; JavaScript
syntax and a headless-Chrome visual render passed validation.

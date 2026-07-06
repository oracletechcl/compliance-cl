from __future__ import annotations

import json
import io
import os
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "scripts" / "generate_report.py"


class GenerateReportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.repo = self.root / "repo"
        (self.repo / "packs" / "law").mkdir(parents=True)
        (self.repo / "references").mkdir()
        (self.repo / "sources").mkdir()
        (self.repo / "references" / "controls.md").write_text(
            "| id | Control | 21.719 | 21.595 | Crosswalk | Fuente de evidencia |\n"
            "|---|---|---|---|---|---|\n"
            "| `sec-logs` | Audit logs | Sí | Sí | ISO A.8.15 | código |\n"
            "| `sec-mfa` | MFA | Sí | control de acceso | ISO A.8.5 | código/infra/usuario |\n"
            "| `gov-politicas` | Políticas documentadas | Sí | Sí | ISO A.5.1 | documentos aprobados |\n",
            encoding="utf-8",
        )
        (self.repo / "packs" / "law" / "pack.md").write_text("Requires `sec-logs`, `sec-mfa`, and `gov-politicas`.\n", encoding="utf-8")
        (self.repo / "sources" / "law.txt").write_text("Primary source.\n", encoding="utf-8")
        self.run = self.root / "run"
        (self.run / "raw").mkdir(parents=True)
        (self.run / "raw" / "logs.json").write_text("{}\n", encoding="utf-8")
        self.bundle = {
            "schema": 1,
            "collector_version": "test",
            "generated_at": "fixture-generated-at",
            "run": {"name": "fixture"},
            "inventory": [{"type": "logging", "region": "fixture-region-1"}],
            "evidence": [
                {
                    "id": "ev-1",
                    "signal": "present",
                    "confidence": "medium",
                    "resource": "ocid1.instance.realm.region.rawidentifier admin@example.test Bearer abc.def.ghi -----BEGIN PRIVATE KEY-----very-secret-----END PRIVATE KEY-----",
                    "control_ids": ["sec-logs"],
                    "source": {"collector": "oci.logging", "ref": "raw/logs.json"},
                }
            ],
            "errors": [],
        }
        (self.run / "evidence-bundle.json").write_text(json.dumps(self.bundle), encoding="utf-8")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def invoke(
        self, collector: Path | str, *extra: str, env: dict[str, str] | None = None
    ) -> subprocess.CompletedProcess[str]:
        command_environment = os.environ.copy()
        command_environment.update(env or {})
        return subprocess.run(
            [sys.executable, str(SCRIPT), "--collector-output", str(collector), "--repo-root", str(self.repo), *extra],
            text=True,
            capture_output=True,
            check=False,
            env=command_environment,
        )

    def test_requires_absolute_collector_path(self) -> None:
        result = self.invoke("relative/run")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must be an absolute path", result.stderr)

    def test_generates_conservative_self_contained_report(self) -> None:
        result = self.invoke(self.run)
        self.assertEqual(result.returncode, 0, result.stderr)
        output = self.run / "analysis" / "collector-assessment-report"
        data = json.loads((output / "report-data.json").read_text(encoding="utf-8"))
        controls = {item["id"]: item for item in data["controls"]}
        self.assertEqual(controls["sec-logs"]["status"], "partial")
        self.assertEqual(controls["sec-mfa"]["status"], "fail")
        self.assertEqual(controls["sec-mfa"]["evidence_state"], "not_evidenced")
        self.assertEqual(data["frameworks"][0]["score"], 0.1667)
        report = (output / "report.html").read_text(encoding="utf-8")
        self.assertIn("id=\"report-data\"", report)
        self.assertNotIn("<script src=", report)
        self.assertNotIn("<link rel=\"stylesheet\"", report)
        self.assertNotIn("Evaluación basada en evidencia del colector", report)
        self.assertNotIn('id="hero-subtitle"', report)

    def test_report_matches_executive_mock_dashboard_structure(self) -> None:
        result = self.invoke(self.run)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = (
            self.run / "analysis" / "collector-assessment-report" / "report.html"
        ).read_text(encoding="utf-8")
        for marker in (
            'class="oracle-wordmark"',
            'id="executive-header"',
            'id="key-indicators"',
            'id="dimensions"',
            'id="compliance-gaps"',
            'id="risk-tracks"',
            'id="action-plan"',
            'id="benefits-panel"',
            'id="selection-panel"',
        ):
            self.assertIn(marker, report)
        # The Conclusión panel was removed: its blended score narrative was a
        # fixed-looking, unclear metric duplicating the same ambiguity as the
        # removed global-score panel.
        self.assertNotIn('id="conclusion"', report)
        self.assertNotIn('conclusion-copy', report)
        self.assertNotIn('presenta un puntaje basado en evidencia de', report)
        # The consolidated single-pane detail surface replaces the old separate
        # detailed-controls section.
        self.assertNotIn('id="detailed-controls"', report)
        # The detected-product compliance table was scrapped: dimension and
        # gap sections now carry that information instead.
        self.assertNotIn('id="product-compliance"', report)
        self.assertNotIn('function renderProductCompliance(', report)
        self.assertNotIn('product_compliance', report)
        # Component assessment and product-actions are hidden (not removed):
        # the ids remain so the underlying data stays available, but the
        # sections are not shown by default.
        self.assertIn('id="component-assessment" hidden', report)
        self.assertIn('id="product-actions" hidden', report)
        # The blended global compliance score panel was removed because its
        # calculation was unclear; per-track (Track A/B) scores remain the
        # only readiness percentages shown, each color-coded and carrying the
        # >=90% recommendation.
        self.assertNotIn('id="global-score"', report)
        self.assertNotIn('Puntaje global de cumplimiento', report)
        self.assertNotIn('id="score-donut"', report)
        self.assertNotIn('conic-gradient', report)
        self.assertIn('class="track-target"', report)
        self.assertEqual(report.count('Meta recomendada: ≥ 90%'), 2)
        self.assertIn("--oracle-red:#c74634", report)
        self.assertIn("@media print", report)
        # Runtime assignment via dataset produces the data-control-ids DOM
        # attribute for each clickable risk matrix cell.
        self.assertIn('dataset.controlIds', report)
        self.assertIn('selectControls', report)
        self.assertIn('id="selection-panel"', report)
        self.assertIn('function detailCard(', report)
        self.assertIn('function applyFilters(', report)
        self.assertNotIn('id="product-mitigations"', report)
        self.assertNotIn('id="cost-estimate"', report)
        self.assertIn("No se proporcionó evidencia obligatoria", report)
        self.assertIn("Acción de mitigación", report)
        self.assertIn("Producto Oracle recomendado", report)
        self.assertIn("Referencia esperada", report)
        self.assertIn("Estado de cumplimiento (matriz)", report)
        self.assertIn("Por qué lo mitiga", report)
        self.assertNotIn("Score global de compliance", report)
        self.assertNotIn("Evidence, remediation", report)
        self.assertNotIn("Potential cost", report)
        # The whole report must render in Spanish, including the disclaimer.
        self.assertIn("Evaluación técnica informativa únicamente", report)
        self.assertNotIn("Informational technical assessment only", report)
        # Both risk matrices must show a clear Y axis (Probabilidad) alongside
        # the existing X axis (Impacto), not just the impact axis alone.
        self.assertEqual(report.count('class="risk-axis-title">Impacto'), 2)
        self.assertEqual(report.count('class="risk-y-axis-title">Probabilidad'), 2)

    def test_risk_matrix_navigation_binds_to_rendered_control_details(self) -> None:
        """Risk navigation is interactive and remains independent of cloud provider."""
        result = self.invoke(self.run)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = (
            self.run / "analysis" / "collector-assessment-report" / "report.html"
        ).read_text(encoding="utf-8")

        # A risk cell carries the selected controls and focuses the single
        # consolidated detail panel that renders full control detail — evidence,
        # expected reference, affected products/OCIDs and mitigation — in one place.
        self.assertIn("risk-cell", report)
        self.assertIn("cell.dataset.controlIds=items.map(c=>c.id).join(',')", report)
        self.assertIn("selectControls(items,", report)
        self.assertIn("function detailCard(", report)
        self.assertIn("Productos y recursos afectados (OCID donde aplica)", report)
        self.assertIn("function applyFilters(", report)
        self.assertIn("card.id='control-'+c.id", report)

        # Mitigation/product advice belongs to every selected control detail,
        # not to a provider-specific or report-global panel.
        self.assertIn("Acción de mitigación", report)
        self.assertIn("Producto Oracle recomendado", report)
        self.assertNotIn('id="product-mitigations"', report)
        self.assertNotIn('id="cost-estimate"', report)

    def test_control_details_include_expected_evidence_and_matrix_percentage(self) -> None:
        result = self.invoke(self.run)
        self.assertEqual(result.returncode, 0, result.stderr)
        output = self.run / "analysis" / "collector-assessment-report"
        data = json.loads((output / "report-data.json").read_text(encoding="utf-8"))
        control = {item["id"]: item for item in data["controls"]}["sec-mfa"]

        self.assertEqual(control["compliance_percent"], 0)
        self.assertIn("Se espera que", control["expected_reference"]["requirement"])
        self.assertNotIn(".md", json.dumps(control["expected_reference"]))
        self.assertIn("código/infra/usuario", control["expected_reference"]["evidence_expected"])

        report = (output / "report.html").read_text(encoding="utf-8")
        self.assertIn("evidenciaEncontrada", report)
        self.assertIn("referenciaEsperada", report)
        self.assertIn("estadoMatriz", report)
        self.assertIn("componentesNoConformes", report)
        self.assertIn("compliance_percent", report)
        self.assertIn("matrix-"+"critical", report)
        self.assertIn("is-selected", report)

    def test_action_plan_results_are_control_specific_and_evidence_traceable(self) -> None:
        result = self.invoke(self.run)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = (
            self.run / "analysis" / "collector-assessment-report" / "report.html"
        ).read_text(encoding="utf-8")

        # Each plan row is built from a real control, its component, expected
        # evidence, acceptance criterion, and available evidence references.
        self.assertIn("function accionPlanControl", report)
        self.assertIn("function resultadoEsperadoControl", report)
        self.assertIn("componentesDelControl(c)", report)
        self.assertIn("Evidencia de aceptación", report)
        self.assertIn("Criterio de cierre", report)
        self.assertIn("Trazabilidad de partida", report)
        self.assertIn("accionPlanControl(c)", report)
        self.assertIn("resultadoEsperadoControl(c)", report)
        self.assertNotIn("Evidencia verificable y reducción de la brecha.", report)
        self.assertNotIn("Control sostenido y trazabilidad.", report)

    def test_report_pivots_on_components_and_splits_action_catalog(self) -> None:
        result = self.invoke(self.run)
        self.assertEqual(result.returncode, 0, result.stderr)
        output = self.run / "analysis" / "collector-assessment-report"
        data = json.loads((output / "report-data.json").read_text(encoding="utf-8"))

        assessments = data["component_assessments"]
        self.assertTrue(assessments)
        self.assertTrue(all(item["name"] and item["service"] for item in assessments))
        self.assertTrue(all(item["status"] in {"pass", "partial", "fail"} for item in assessments))
        self.assertTrue(all(0 <= item["compliance_percent"] <= 100 for item in assessments))
        self.assertTrue(all(item["control_ids"] for item in assessments))
        self.assertEqual(next(item for item in assessments if item["origin"] == "observed")["status"], "partial")
        self.assertTrue(all(item["status"] == "fail" for item in assessments if item["origin"] == "expected"))

        catalog = data["action_catalog"]
        self.assertTrue(catalog["product"])
        self.assertTrue(catalog["process"])
        self.assertTrue(all(item["category"] == "product" for item in catalog["product"]))
        self.assertTrue(all(item["category"] == "process" for item in catalog["process"]))

        # Invariant: the product track (Track A) must never carry a control
        # without a reviewed Oracle/OCI component. Such controls belong to the
        # process track (Track B).
        controls_by_id = {c["id"]: c for c in data["controls"]}
        oracle_providers = {"OCI", "On-Premises"}
        for control in data["controls"]:
            has_oracle = any(
                (ev.get("component") or {}).get("provider") in oracle_providers
                for ev in control["evidence"]
            )
            if control["action_category"] == "product":
                self.assertTrue(
                    has_oracle,
                    f"{control['id']} is on the product track without a reviewed Oracle component",
                )
        self.assertEqual(controls_by_id["sec-mfa"]["action_category"], "process")

        # Independently scored tracks (the detected-product compliance pivot
        # was scrapped in favor of enriching dimensions/gaps directly).
        self.assertNotIn("product_compliance", data)
        self.assertIn("track_scores", data)
        for category in ("product", "process"):
            track = data["track_scores"][category]
            self.assertEqual(set(track["counts"]), {"pass", "partial", "fail"})
            self.assertTrue(0.0 <= track["score"] <= 1.0)

        report = (output / "report.html").read_text(encoding="utf-8")
        # Hidden (not removed): ids remain, but the sections carry `hidden`.
        self.assertIn('id="component-assessment" hidden', report)
        self.assertIn('id="product-actions" hidden', report)
        self.assertIn('id="process-actions" hidden', report)
        self.assertIn('id="product-track"', report)
        self.assertIn('id="process-track"', report)
        self.assertIn('id="product-track-score"', report)
        self.assertIn('id="process-track-score"', report)
        self.assertIn('id="product-risk-grid"', report)
        self.assertIn('id="process-risk-grid"', report)
        self.assertNotIn("Productos Oracle detectados y su estado de cumplimiento", report)
        self.assertIn("Evaluación por componentes revisados", report)
        self.assertIn("Acciones asociadas a productos Oracle", report)
        self.assertIn("Acciones asociadas a procesos", report)
        self.assertIn("renderRiskMatrix", report)

        # Mitigation actions carry an explanation plus ordered, concrete steps;
        # product-track controls get an explicit auto-appended step naming the
        # Oracle product and what to do with it.
        self.assertTrue(all(isinstance(c.get("remediation_steps"), list) and c["remediation_steps"] for c in data["controls"]))
        self.assertIn("function pasosMitigacion(", report)
        self.assertIn("function mitigationBlock(", report)
        self.assertIn("mitigation-product-step", report)
        self.assertIn("mitigationBlock('Acción de mitigación'", report)

        # Enriched dimension rows: clickable, with pass/partial/fail counts,
        # evidence coverage, and a Track A/B breakdown.
        self.assertIn("id=\"dimension-rows\"", report)
        self.assertIn("dimension-row risk-action", report)
        self.assertIn("dimension-track", report)
        self.assertIn("cumple · ", report)
        self.assertIn("Brecha principal: ", report)

        # Enriched gap rows: every open gap (not capped at 5), a Track badge,
        # a one-line mitigation hint, and a missing-evidence subtotal.
        self.assertNotIn("gaps.slice(0,5)", report)
        self.assertIn("gap-track", report)
        self.assertIn("id=\"gap-total-sub\"", report)

    def test_each_control_has_an_observed_or_expected_component(self) -> None:
        result = self.invoke(self.run)
        self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads(
            (self.run / "analysis" / "collector-assessment-report" / "report-data.json").read_text(encoding="utf-8")
        )

        for control in data["controls"]:
            components = control["components"]
            self.assertTrue(components, control["id"])
            self.assertTrue(all(item["name"].strip() and item["service"].strip() and item["aspect"].strip() and item["resource_id"].strip() for item in components), control["id"])

        by_id = {item["id"]: item for item in data["controls"]}
        self.assertEqual(by_id["sec-logs"]["components"][0]["origin"], "observed")
        self.assertEqual(by_id["sec-mfa"]["components"][0]["origin"], "expected")
        self.assertIn("Componente objetivo", by_id["sec-mfa"]["components"][0]["name"])

    def test_legacy_opaque_component_name_is_normalized_for_display(self) -> None:
        evidence = self.bundle["evidence"][0]
        evidence.update(
            {
                "resource": "csi-0d514092-b314-4bad-af7a-5909aa36a7a9",
                "attribute": "volume_encryption",
                "source": {"collector": "oci.block_storage"},
                "component": {
                    "id": "cmp-old",
                    "name": "csi-0d514092-b314-4bad-af7a-5909aa36a7a9",
                    "type": "storage",
                    "provider": "OCI",
                    "service": "ocid1.volume.sha256:opaque",
                },
            }
        )
        (self.run / "evidence-bundle.json").write_text(json.dumps(self.bundle), encoding="utf-8")

        result = self.invoke(self.run)
        self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads(
            (self.run / "analysis" / "collector-assessment-report" / "report-data.json").read_text(encoding="utf-8")
        )
        component = {item["id"]: item for item in data["controls"]}["sec-logs"]["components"][0]
        self.assertEqual(component["name"], "OCI Block Storage — Cifrado de volumen")
        self.assertEqual(component["service"], "OCI Block Storage")

    def test_sanitizes_sensitive_display_values_in_json_and_html(self) -> None:
        result = self.invoke(self.run)
        self.assertEqual(result.returncode, 0, result.stderr)
        output = self.run / "analysis" / "collector-assessment-report"
        emitted = (output / "report-data.json").read_text(encoding="utf-8") + (output / "report.html").read_text(encoding="utf-8")
        self.assertNotRegex(emitted, r"(?i)\bocid1\.")
        self.assertNotRegex(emitted, r"(?i)[\w.%+-]+@[\w.-]+\.[a-z]{2,}")
        self.assertNotRegex(emitted, r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+")
        self.assertNotIn("BEGIN PRIVATE KEY", emitted)
        self.assertNotIn("very-secret", emitted)
        self.assertIn("[oci-id:sha256:", emitted)
        self.assertIn("[email:sha256:", emitted)

    def test_rejects_zip_traversal(self) -> None:
        archive = self.root / "bad.zip"
        with zipfile.ZipFile(archive, "w") as target:
            target.writestr("../evidence-bundle.json", json.dumps(self.bundle))
        result = self.invoke(archive)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unsafe archive member", result.stderr)

    def test_accepts_zip_and_uses_archive_output_location(self) -> None:
        archive = self.root / "collector-run.zip"
        with zipfile.ZipFile(archive, "w") as target:
            target.writestr("collector/evidence-bundle.json", json.dumps(self.bundle))
            target.writestr("collector/raw/logs.json", "{}\n")
        result = self.invoke(archive)
        self.assertEqual(result.returncode, 0, result.stderr)
        output = self.root / "collector-run-analysis"
        self.assertTrue((output / "report.html").is_file())
        self.assertTrue((output / "report-data.json").is_file())

    def test_rejects_archive_over_member_limit(self) -> None:
        archive = self.root / "too-many.zip"
        with zipfile.ZipFile(archive, "w") as target:
            target.writestr("collector/evidence-bundle.json", json.dumps(self.bundle))
            target.writestr("collector/raw/logs.json", "{}\n")
        result = self.invoke(archive, env={"COLLECTOR_REPORT_MAX_ARCHIVE_MEMBERS": "1"})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("member safety limit", result.stderr)

    def test_rejects_archive_over_uncompressed_byte_limit(self) -> None:
        archive = self.root / "too-large.zip"
        with zipfile.ZipFile(archive, "w") as target:
            target.writestr("collector/evidence-bundle.json", json.dumps(self.bundle))
        result = self.invoke(archive, env={"COLLECTOR_REPORT_MAX_ARCHIVE_UNCOMPRESSED_BYTES": "16"})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("uncompressed safety limit", result.stderr)

    def test_accepts_compressed_tar(self) -> None:
        archive = self.root / "collector-run.tar.gz"
        payloads = {
            "collector/evidence-bundle.json": json.dumps(self.bundle).encode(),
            "collector/raw/logs.json": b"{}\n",
        }
        with tarfile.open(archive, "w:gz") as target:
            for name, payload in payloads.items():
                info = tarfile.TarInfo(name)
                info.size = len(payload)
                target.addfile(info, io.BytesIO(payload))
        result = self.invoke(archive)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.root / "collector-run-analysis" / "report.html").is_file())

    def test_review_overlay_changes_status_and_is_preserved(self) -> None:
        assessment = self.root / "assessment.json"
        assessment.write_text(
            json.dumps(
                {
                    "schema": 1,
                    "assessed_product": "Fixture application",
                    "scope_notes": "Reviewed fixture scope.",
                    "controls": {
                        "sec-logs": {
                            "status": "pass",
                            "rationale": "Explicit fixture review.",
                            "evidence_refs": ["ev-1", "references/controls.md"],
                        }
                    },
                }
            ),
            encoding="utf-8",
        )
        result = self.invoke(self.run, "--assessment", str(assessment))
        self.assertEqual(result.returncode, 0, result.stderr)
        output = self.run / "analysis" / "collector-assessment-report"
        data = json.loads((output / "report-data.json").read_text(encoding="utf-8"))
        controls = {item["id"]: item for item in data["controls"]}
        self.assertEqual(controls["sec-logs"]["status"], "pass")
        self.assertEqual(data["assessed_product"], "Fixture application")
        self.assertTrue((output / "assessment.json").is_file())

    def test_overlay_can_supply_custom_remediation_steps(self) -> None:
        assessment = self.root / "steps-assessment.json"
        assessment.write_text(
            json.dumps(
                {
                    "schema": 1,
                    "controls": {
                        "sec-logs": {
                            "status": "partial",
                            "rationale": "Revisión con pasos personalizados.",
                            "evidence_refs": ["ev-1", "references/controls.md"],
                            "remediation_steps": [
                                "Paso uno personalizado.",
                                "Paso dos personalizado.",
                            ],
                        }
                    },
                }
            ),
            encoding="utf-8",
        )
        result = self.invoke(self.run, "--assessment", str(assessment))
        self.assertEqual(result.returncode, 0, result.stderr)
        output = self.run / "analysis" / "collector-assessment-report"
        data = json.loads((output / "report-data.json").read_text(encoding="utf-8"))
        controls = {item["id"]: item for item in data["controls"]}
        self.assertEqual(
            controls["sec-logs"]["remediation_steps"],
            ["Paso uno personalizado.", "Paso dos personalizado."],
        )

    def test_overlay_rejects_empty_remediation_steps(self) -> None:
        assessment = self.root / "bad-steps-assessment.json"
        assessment.write_text(
            json.dumps({"schema": 1, "controls": {"sec-logs": {"remediation_steps": []}}}),
            encoding="utf-8",
        )
        result = self.invoke(self.run, "--assessment", str(assessment))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("remediation_steps", result.stderr)

    def test_reviewed_unknown_is_reported_as_not_compliant(self) -> None:
        assessment = self.root / "unknown-assessment.json"
        assessment.write_text(
            json.dumps(
                {
                    "schema": 1,
                    "controls": {
                        "sec-mfa": {
                            "status": "unknown",
                            "rationale": "Required evidence was not provided.",
                            "evidence_refs": [],
                        }
                    },
                }
            ),
            encoding="utf-8",
        )
        result = self.invoke(self.run, "--assessment", str(assessment))
        self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads(
            (
                self.run
                / "analysis"
                / "collector-assessment-report"
                / "report-data.json"
            ).read_text(encoding="utf-8")
        )
        control = {item["id"]: item for item in data["controls"]}["sec-mfa"]
        self.assertEqual(control["status"], "fail")
        self.assertEqual(control["evidence_state"], "not_evidenced")
        normalized = json.loads(
            (
                self.run
                / "analysis"
                / "collector-assessment-report"
                / "assessment.json"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(normalized["controls"]["sec-mfa"]["status"], "fail")

    def test_accepts_analysis_items_overlay_and_promotes_finding_to_rationale(self) -> None:
        """Existing analysis output may group control decisions under summary/items."""
        finding = "No se obtuvo evidencia de MFA administrativo para el alcance evaluado."
        assessment = self.root / "analysis-items-assessment.json"
        assessment.write_text(
            json.dumps(
                {
                    "schema": 1,
                    "controls": {
                        "summary": {"total": 2, "pass": 0, "partial": 0, "fail": 0, "unknown": 2},
                        "items": {
                            "sec-mfa": {
                                "status": "unknown",
                                "finding": finding,
                            }
                        },
                    },
                }
            ),
            encoding="utf-8",
        )

        result = self.invoke(self.run, "--assessment", str(assessment))
        self.assertEqual(result.returncode, 0, result.stderr)
        output = self.run / "analysis" / "collector-assessment-report"
        data = json.loads((output / "report-data.json").read_text(encoding="utf-8"))
        control = {item["id"]: item for item in data["controls"]}["sec-mfa"]
        self.assertEqual(control["status"], "fail")
        self.assertEqual(control["evidence_state"], "not_evidenced")
        self.assertEqual(control["rationale"], finding)

        # The finding is carried into the rendered report data and can be
        # displayed in the selected control detail without provider assumptions.
        report = (output / "report.html").read_text(encoding="utf-8")
        self.assertIn(finding, report)

    def test_onprem_evidence_drives_provider_neutral_scope(self) -> None:
        onprem = self.root / "onprem-run"
        (onprem / "raw" / "onprem").mkdir(parents=True)
        (onprem / "raw" / "onprem" / "database.json").write_text("{}\n", encoding="utf-8")
        (onprem / "raw" / "onprem" / "middleware.json").write_text("{}\n", encoding="utf-8")
        bundle = {
            "schema": 1,
            "collector_version": "hybrid-test",
            "generated_at": "fixture-onprem-generated-at",
            "run": {"name": "onprem-only-assessment"},
            "inventory": [],
            "evidence": [
                {
                    "id": "ev-db",
                    "layer": "database",
                    "signal": "present",
                    "confidence": "high",
                    "resource": "finance-db",
                    "control_ids": ["sec-logs"],
                    "source": {
                        "collector": "direct_sql",
                        "product": "Oracle Database",
                        "ref": "raw/onprem/database.json",
                    },
                },
                {
                    "id": "ev-mw",
                    "layer": "middleware",
                    "signal": "present",
                    "confidence": "high",
                    "resource": "payments-domain",
                    "control_ids": ["sec-mfa"],
                    "source": {
                        "collector": "middleware",
                        "product": "weblogic",
                        "ref": "raw/onprem/middleware.json",
                    },
                },
            ],
            "errors": [],
        }
        (onprem / "evidence-bundle.json").write_text(json.dumps(bundle), encoding="utf-8")
        result = self.invoke(onprem)
        self.assertEqual(result.returncode, 0, result.stderr)
        output = onprem / "analysis" / "collector-assessment-report"
        data = json.loads((output / "report-data.json").read_text(encoding="utf-8"))
        products = {item["name"] for item in data["observed_products"]}
        self.assertEqual(data["bundle"]["providers"], ["On-Premises"])
        self.assertEqual(data["bundle"]["layers"], ["database", "middleware"])
        self.assertIn("Oracle Database", products)
        self.assertIn("Oracle WebLogic Server", products)
        report = (output / "report.html").read_text(encoding="utf-8")
        self.assertNotIn("Observed OCI products", report)
        self.assertNotIn("Collector-scoped OCI workload", report)

    def test_derives_materially_different_bundle_without_run_assumptions(self) -> None:
        other = self.root / "other-product-run"
        (other / "raw").mkdir(parents=True)
        (other / "raw" / "identity.json").write_text("{}\n", encoding="utf-8")
        bundle = {
            "schema": 9,
            "collector_version": "different-version",
            "generated_at": "different-generated-at",
            "run": {"name": "unrelated-product-assessment"},
            "inventory": [
                {"type": "vault", "region": "eu-frankfurt-1"},
                {"type": "vault", "region": "eu-frankfurt-1"},
                {"type": "waf", "region": "eu-frankfurt-1"},
            ],
            "evidence": [
                {
                    "id": "ev-different",
                    "signal": "disabled",
                    "confidence": "high",
                    "resource": "identity-policy",
                    "control_ids": ["sec-mfa"],
                    "source": {"collector": "oci.identity", "ref": "raw/identity.json"},
                }
            ],
            "errors": [],
        }
        (other / "evidence-bundle.json").write_text(json.dumps(bundle), encoding="utf-8")
        result = self.invoke(other)
        self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads(
            (other / "analysis" / "collector-assessment-report" / "report-data.json").read_text(encoding="utf-8")
        )
        controls = {item["id"]: item for item in data["controls"]}
        products = {item["type"]: item["count"] for item in data["observed_products"]}
        self.assertEqual(data["assessed_product"], "unrelated-product-assessment")
        self.assertEqual(data["bundle"]["regions"], ["eu-frankfurt-1"])
        self.assertEqual(data["bundle"]["inventory_count"], 3)
        self.assertEqual(data["bundle"]["evidence_count"], 1)
        self.assertEqual(products, {"vault": 2, "waf": 1})
        self.assertEqual(controls["sec-mfa"]["status"], "fail")


if __name__ == "__main__":
    unittest.main()

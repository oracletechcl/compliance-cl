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
            "| id | Control | Law |\n|---|---|---|\n| `sec-logs` | Audit logs | yes |\n| `sec-mfa` | MFA | yes |\n",
            encoding="utf-8",
        )
        (self.repo / "packs" / "law" / "pack.md").write_text("Requires `sec-logs` and `sec-mfa`.\n", encoding="utf-8")
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
        self.assertEqual(data["frameworks"][0]["score"], 0.25)
        report = (output / "report.html").read_text(encoding="utf-8")
        self.assertIn("id=\"report-data\"", report)
        self.assertNotIn("<script src=", report)
        self.assertNotIn("<link rel=\"stylesheet\"", report)

    def test_report_matches_executive_mock_dashboard_structure(self) -> None:
        result = self.invoke(self.run)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = (
            self.run / "analysis" / "collector-assessment-report" / "report.html"
        ).read_text(encoding="utf-8")
        for marker in (
            'class="oracle-wordmark"',
            'id="executive-header"',
            'id="global-score"',
            'id="key-indicators"',
            'id="dimensions"',
            'id="compliance-gaps"',
            'id="risk-matrix"',
            'id="product-mitigations"',
            'id="cost-estimate"',
            'id="action-plan"',
            'id="conclusion"',
            'id="detailed-controls"',
        ):
            self.assertIn(marker, report)
        self.assertIn("conic-gradient", report)
        self.assertIn("--oracle-red:#c74634", report)
        self.assertIn("@media print", report)

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

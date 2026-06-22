import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BACKEND_ROOT = ROOT / "Backend"
for path in (BACKEND_ROOT, ROOT):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from scanner.ai_enrichment import (
    build_deepseek_prompt_package,
    generate_report_sections,
    load_deepseek_config,
    parse_deepseek_report_sections,
)
from scanner.reporter import generate_html_report, generate_pdf_report


def sample_report():
    return {
        "domain": "example.com",
        "target": "https://example.com",
        "scan_id": "scan-test-1",
        "scan_time": "2026-06-22T00:00:00Z",
        "profile": "light",
        "risk_score": 42,
        "risk_label": "Moderate Risk",
        "summary": {
            "total_findings": 2,
            "confirmed_findings": 1,
            "confirmed_app_vulns": 1,
            "candidate_findings": 1,
            "alive_hosts": 1,
        },
        "stages": {
            "alive_probing": {"data": []},
            "js_secrets": {"data": []},
            "s3_buckets": {"data": []},
        },
        "findings": [
            {
                "id": "finding-1",
                "title": "Missing security header",
                "severity": "Medium",
                "status": "confirmed",
                "url": "https://example.com/account?token=super-secret-token&view=1",
                "evidence_summary": "Authorization: Bearer abcdefghijklmnopqrstuvwxyz123456",
                "remediation": "Add the missing header.",
                "cookie": "sessionid=do-not-send",
            }
        ],
        "recommendations": ["Add missing browser security headers."],
        "known_vulnerabilities": {"targeted": {"items": []}},
    }


class DeepSeekReportGenerationTests(unittest.TestCase):
    def test_mock_deepseek_response_parses_and_pdf_renders(self):
        raw_response = {
            "model": "deepseek-v4-pro",
            "choices": [
                {
                    "message": {
                        "content": json.dumps({
                            "executive_summary": "The application has a moderate externally visible risk posture.",
                            "key_risks": ["Missing browser hardening increases client-side exposure."],
                            "recommendations": ["Prioritize confirmed findings and rerun the scan."],
                            "limitations": "Based on supplied scanner evidence only.",
                        })
                    }
                }
            ],
        }
        parsed = parse_deepseek_report_sections(raw_response)
        report = sample_report()
        report["report_sections"] = generate_report_sections(report, {
            **parsed,
            "model": raw_response["model"],
            "generated_by": "DeepSeek Chat Completions API",
        })

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            html_path = tmp_path / "report.html"
            pdf_path = tmp_path / "report.pdf"
            generate_html_report(report, str(html_path))
            self.assertTrue(generate_pdf_report(report, str(pdf_path)))
            self.assertTrue(html_path.exists())
            self.assertGreater(pdf_path.stat().st_size, 1000)

    def test_prompt_package_is_sanitized(self):
        prompt = build_deepseek_prompt_package(sample_report())
        with tempfile.TemporaryDirectory() as tmp:
            prompt_path = Path(tmp) / "deepseek_prompt.json"
            prompt_path.write_text(json.dumps(prompt, ensure_ascii=False, indent=2), encoding="utf-8")
            prompt_text = prompt_path.read_text(encoding="utf-8").lower()

        self.assertIn("scanner_evidence", prompt)
        self.assertNotIn("bearer abcdef", prompt_text)
        self.assertNotIn("sessionid", prompt_text)
        self.assertNotIn("super-secret-token", prompt_text)
        self.assertNotIn("cookie", prompt_text)
        self.assertNotIn("authorization", prompt_text)
        self.assertIn("view=1", prompt_text)

    def test_real_api_smoke_test_is_manual_in_this_environment(self):
        config = load_deepseek_config()
        self.assertIn("enabled", config)
        self.assertIn("has_real_key", config)
        raise unittest.SkipTest(
            "Automatic DeepSeek egress is disabled in this Codex environment. "
            "Run the same smoke flow manually from your backend after adding a real key."
        )


if __name__ == "__main__":
    unittest.main()

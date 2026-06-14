from __future__ import annotations

import tempfile
import unittest
from types import SimpleNamespace
from pathlib import Path
from unittest.mock import patch

from sift_mind.config import load_config
from sift_mind.runtime import TOOL_GROUPS, host_environment_status, model_hardware_plan, model_status, readiness_report


DOCUMENTED_TOOL_NAMES = {
    "get_amcache",
    "parse_mft",
    "analyze_prefetch",
    "list_registry_hives",
    "get_registry_key",
    "extract_shellbags",
    "parse_lnk_files",
    "get_usnjrnl_entries",
    "list_processes",
    "get_network_connections",
    "extract_injected_code",
    "find_hidden_modules",
    "get_handles",
    "scan_memory_yara",
    "parse_evtx",
    "get_security_events",
    "get_logon_events",
    "get_process_creation_events",
    "build_super_timeline",
    "correlate_timestamps",
    "get_artifact_at_time",
    "parse_pcap_summary",
    "extract_dns_queries",
    "get_http_requests",
}


class RuntimeReadinessTests(unittest.TestCase):
    def test_tool_groups_cover_documented_tool_names(self) -> None:
        self.assertEqual(DOCUMENTED_TOOL_NAMES, set(TOOL_GROUPS))

    def test_fixture_readiness_has_output_writable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = load_config(
                case_root="fixture/case",
                output_dir=tmp,
                evidence_chain_path=str(Path(tmp) / "evidence_chain.log"),
                execution_log_path=str(Path(tmp) / "agent_execution_log.jsonl"),
                ledger_db_path=str(Path(tmp) / "ledger.db"),
                mode="fixture",
            )
            report = readiness_report(config)
            self.assertTrue(report["status"]["fixture_ready"])
            self.assertIn("external_tools", report)
            self.assertIn("host_environment", report)
            self.assertIn("ollama", report)
            self.assertEqual(report["model_hardware_plan"]["hardware_profile"]["ram_gb"], 16)
            self.assertEqual(report["model_hardware_plan"]["recommended_primary"], "qwen2.5-coder:7b")

    def test_model_hardware_plan_prefers_configured_7b_when_available(self) -> None:
        config = load_config(mode="fixture")
        plan = model_hardware_plan(
            config,
            {
                "provider": "ollama",
                "reachable": True,
                "configured_model": "qwen2.5-coder:7b",
                "fallback_model": "qwen2.5-coder:3b",
                "model_available": True,
                "fallback_available": True,
                "available_models": ["qwen2.5-coder:7b", "qwen2.5-coder:3b", "qwen2.5-coder:14b"],
            },
        )

        self.assertEqual(plan["selected_model"], "qwen2.5-coder:7b")
        self.assertEqual(plan["selection_source"], "configured_primary")
        self.assertTrue(plan["selected_profile"]["fits_rtx_3050_6gb"])
        self.assertTrue(plan["ready_for_local_demo"])

    def test_model_hardware_plan_uses_configured_3b_fallback(self) -> None:
        config = load_config(mode="fixture")
        plan = model_hardware_plan(
            config,
            {
                "provider": "ollama",
                "reachable": True,
                "configured_model": "qwen2.5-coder:7b",
                "fallback_model": "qwen2.5-coder:3b",
                "model_available": False,
                "fallback_available": True,
                "available_models": ["qwen2.5-coder:3b"],
            },
        )

        self.assertEqual(plan["selected_model"], "qwen2.5-coder:3b")
        self.assertEqual(plan["selection_source"], "configured_fallback")
        self.assertIn("Configured primary model is not downloaded", " ".join(plan["warnings"]))

    def test_sift_readiness_flags_managed_paths_inside_case_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            case_root = Path(tmp) / "case"
            case_root.mkdir()
            output_dir = case_root / "out"
            config = load_config(
                case_root=str(case_root),
                output_dir=str(output_dir),
                evidence_chain_path=str(output_dir / "evidence_chain.log"),
                execution_log_path=str(output_dir / "agent_execution_log.jsonl"),
                ledger_db_path=str(Path(tmp) / "ledger.db"),
                mode="sift",
            )
            report = readiness_report(config)
            self.assertFalse(report["status"]["sift_ready"])
            self.assertFalse(report["paths"]["output_dir"]["outside_case_root"])
            self.assertFalse(report["paths"]["evidence_chain_parent"]["outside_case_root"])
            self.assertFalse(report["paths"]["execution_log_parent"]["outside_case_root"])
            self.assertFalse(output_dir.exists())

    def test_windows_host_environment_reports_missing_wsl_distribution(self) -> None:
        config = load_config(mode="sift")
        no_distro_output = (
            "Windows Subsystem for Linux has no installed distributions.\r\n"
            "Use 'wsl.exe --install <Distro>' to install.\r\n"
        ).encode("utf-16-le")
        with patch("platform.system", return_value="Windows"), patch("shutil.which", return_value="C:\\Windows\\System32\\wsl.exe"), patch(
            "subprocess.run",
            return_value=SimpleNamespace(returncode=1, stdout=no_distro_output, stderr=b""),
        ):
            report = host_environment_status(config)

        self.assertTrue(report["windows_host"])
        self.assertFalse(report["wsl"]["ready"])
        self.assertEqual(report["wsl"]["status"], "NO_DISTRIBUTION")
        self.assertEqual(report["wsl"]["installed_distributions"], [])
        self.assertIn("Install a WSL distribution", report["wsl"]["recommendation"])

    def test_windows_host_environment_parses_wsl_distribution(self) -> None:
        config = load_config(mode="sift")
        distro_output = "  NAME      STATE           VERSION\r\n* Ubuntu    Running         2\r\n".encode("utf-16-le")
        with patch("platform.system", return_value="Windows"), patch("shutil.which", return_value="C:\\Windows\\System32\\wsl.exe"), patch(
            "subprocess.run",
            return_value=SimpleNamespace(returncode=0, stdout=distro_output, stderr=b""),
        ):
            report = host_environment_status(config)

        self.assertTrue(report["wsl"]["ready"])
        self.assertEqual(report["wsl"]["status"], "READY")
        self.assertEqual(report["wsl"]["installed_distributions"][0]["name"], "Ubuntu")

    def test_cloud_model_status_checks_api_key_presence_without_secret(self) -> None:
        with patch.dict(
            "os.environ",
            {
                "SIFT_MIND_MODEL_PROVIDER": "openai-compatible",
                "SIFT_MIND_MODEL": "cloud-model",
                "SIFT_MIND_MODEL_HOST": "https://example.test/v1",
                "SIFT_MIND_CLOUD_API_KEY_ENV": "SIFT_TEST_KEY",
                "SIFT_TEST_KEY": "secret-value",
            },
            clear=True,
        ):
            config = load_config()
            status = model_status(config)
        self.assertEqual(status["provider"], "openai-compatible")
        self.assertTrue(status["api_key_present"])
        self.assertNotIn("secret-value", str(status))


if __name__ == "__main__":
    unittest.main()

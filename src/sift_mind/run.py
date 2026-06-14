"""Command line entrypoint for SIFT-MIND."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .agent.loop import FixtureAgentRunner
from .agent.model_brief import write_model_case_brief
from .config import load_config
from .ledger.ledger import EpistemicLedger
from .model_provider import ModelProviderError, build_model_client
from .production_audit import production_audit
from .report.writer import ReportWriter
from .runtime import readiness_report
from .sift_smoke import run_sift_preflight, run_sift_smoke, smoke_manifest_schema
from .submission import package_demo


def _print_json(data: object) -> None:
    print(json.dumps(data, indent=2, sort_keys=True, default=str))


def doctor_command(args: argparse.Namespace) -> int:
    config = _config_from_args(args)
    result = readiness_report(config)
    _print_json(result)
    return 0


def readiness_command(args: argparse.Namespace) -> int:
    config = _config_from_args(args)
    result = readiness_report(config)
    _print_json(result)
    target = args.target
    if target == "fixture":
        return 0 if result["status"]["fixture_ready"] else 1
    if target == "sift":
        return 0 if result["status"]["sift_ready"] else 1
    if target == "model":
        return 0 if result["status"]["model_ready"] else 1
    return 0


def model_smoke_command(args: argparse.Namespace) -> int:
    config = _config_from_args(args)
    client = build_model_client(config.model)
    schema = {
        "type": "object",
        "properties": {
            "status": {"type": "string"},
            "role": {"type": "string"},
            "safety": {"type": "string"},
        },
        "required": ["status", "role", "safety"],
    }
    prompt = (
        "Return a compact JSON health check for SIFT-MIND. "
        "Use status=ok, role=local_model, safety=bounded_json."
    )
    try:
        result = client.generate_json(prompt, schema)
    except ModelProviderError as exc:
        _print_json({"status": "ERROR", "error": str(exc)})
        return 1
    _print_json({"status": "OK", "response": result})
    return 0


def model_brief_command(args: argparse.Namespace) -> int:
    config = _config_from_args(args)
    ledger = EpistemicLedger(config.ledger_db_path)
    output = args.output or str(Path(config.output_dir) / "model_case_brief.json")
    result = write_model_case_brief(ledger, config, output)
    _print_json(result)
    return 0 if result["status"] == "OK" else 1


def run_command(args: argparse.Namespace) -> int:
    config = _config_from_args(args)
    if config.mode != "fixture":
        print("The autonomous runner is currently production-safe in fixture mode only.")
        print("Use `sift-mind serve-mcp` for real SIFT tool execution through MCP.")
        return 2
    result = FixtureAgentRunner(config).run()
    _print_json(result)
    return 0


def verify_chain_command(args: argparse.Namespace) -> int:
    ledger = EpistemicLedger(args.ledger_db)
    writer = ReportWriter(ledger, evidence_chain_path=args.evidence_chain, execution_log_path=args.execution_log)
    result = writer.verify_evidence_chain(args.evidence_chain)
    _print_json(result)
    return 0 if result["status"] == "VERIFIED" else 1


def package_demo_command(args: argparse.Namespace) -> int:
    config = _config_from_args(args)
    result = package_demo(
        output_dir=config.output_dir,
        ledger_db_path=config.ledger_db_path,
        evidence_chain_path=config.evidence_chain_path,
        execution_log_path=config.execution_log_path,
        package_dir=args.package_dir,
        repo_root=args.repo_root,
        preflight_report_path=args.preflight_report,
        smoke_report_path=args.smoke_report,
        audit_report_path=args.audit_report,
        model_brief_report_path=args.model_brief_report,
        archive_path=args.archive_path,
    )
    _print_json(result)
    return 0 if result["status"] == "OK" else 1


def production_audit_command(args: argparse.Namespace) -> int:
    config = _config_from_args(args)
    result = production_audit(
        config,
        repo_root=args.repo_root,
        package_dir=args.package_dir,
        archive_path=args.archive_path,
        target=args.target,
    )
    if args.report:
        report_path = Path(args.report)
        report_path.parent.mkdir(parents=True, exist_ok=True)
        result["report_path"] = str(report_path)
        report_path.write_text(json.dumps(result, indent=2, sort_keys=True, default=str), encoding="utf-8")
    _print_json(result)
    return 0 if result["blocking_failure_count"] == 0 else 1


def sift_smoke_command(args: argparse.Namespace) -> int:
    config = _config_from_args(args)
    result = run_sift_smoke(config, args.manifest, args.report, fresh=args.fresh)
    _print_json(result)
    if args.allow_tool_errors:
        return 0
    return 0 if result["status"] == "OK" else 1


def sift_preflight_command(args: argparse.Namespace) -> int:
    config = _config_from_args(args)
    result = run_sift_preflight(config, args.manifest, args.report)
    _print_json(result)
    return 0 if result["status"] == "READY" else 1


def manifest_schema_command(args: argparse.Namespace) -> int:
    result = smoke_manifest_schema()
    if args.output:
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
    _print_json(result)
    return 0


def serve_mcp_command(args: argparse.Namespace) -> int:
    from .mcp_server.server import run_server

    config = _config_from_args(args)
    run_server(config)
    return 0


def _config_from_args(args: argparse.Namespace):
    return load_config(
        case_root=getattr(args, "case_root", None),
        output_dir=getattr(args, "output_dir", None),
        evidence_chain_path=getattr(args, "evidence_chain", None),
        execution_log_path=getattr(args, "execution_log", None),
        ledger_db_path=getattr(args, "ledger_db", None),
        baseline_path=getattr(args, "baseline", None),
        mode=getattr(args, "mode", None),
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sift-mind")
    sub = parser.add_subparsers(dest="command", required=True)

    doctor = sub.add_parser("doctor", help="Inspect runtime and external SIFT tool availability.")
    doctor.add_argument("--mode", choices=["fixture", "sift"], default="fixture")
    doctor.add_argument("--case-root", default=None)
    doctor.add_argument("--output-dir", default=None)
    doctor.add_argument("--evidence-chain", default=None)
    doctor.add_argument("--execution-log", default=None)
    doctor.add_argument("--ledger-db", default=None)
    doctor.add_argument("--baseline", default=None)
    doctor.set_defaults(func=doctor_command)

    readiness = sub.add_parser("readiness", help="Return nonzero if the selected runtime target is not ready.")
    readiness.add_argument("--target", choices=["fixture", "sift", "model"], default="fixture")
    readiness.add_argument("--mode", choices=["fixture", "sift"], default="fixture")
    readiness.add_argument("--case-root", default=None)
    readiness.add_argument("--output-dir", default=None)
    readiness.add_argument("--evidence-chain", default=None)
    readiness.add_argument("--execution-log", default=None)
    readiness.add_argument("--ledger-db", default=None)
    readiness.add_argument("--baseline", default=None)
    readiness.set_defaults(func=readiness_command)

    smoke = sub.add_parser("model-smoke", help="Run a tiny bounded JSON prompt through the configured model.")
    smoke.add_argument("--mode", choices=["fixture", "sift"], default="fixture")
    smoke.add_argument("--case-root", default=None)
    smoke.add_argument("--output-dir", default=None)
    smoke.add_argument("--evidence-chain", default=None)
    smoke.add_argument("--execution-log", default=None)
    smoke.add_argument("--ledger-db", default=None)
    smoke.add_argument("--baseline", default=None)
    smoke.set_defaults(func=model_smoke_command)

    brief = sub.add_parser("model-brief", help="Generate a ledger-only bounded JSON case brief with citation validation.")
    brief.add_argument("--mode", choices=["fixture", "sift"], default="fixture")
    brief.add_argument("--case-root", default=None)
    brief.add_argument("--output-dir", default=None)
    brief.add_argument("--evidence-chain", default=None)
    brief.add_argument("--execution-log", default=None)
    brief.add_argument("--ledger-db", default=None)
    brief.add_argument("--baseline", default=None)
    brief.add_argument("--output", default=None)
    brief.set_defaults(func=model_brief_command)

    run = sub.add_parser("run", help="Run the deterministic fixture demo pipeline.")
    run.add_argument("--case-root", default=None)
    run.add_argument("--output-dir", default=None)
    run.add_argument("--evidence-chain", default=None)
    run.add_argument("--execution-log", default=None)
    run.add_argument("--ledger-db", default=None)
    run.add_argument("--baseline", default=None)
    run.add_argument("--mode", choices=["fixture", "sift"], default="fixture")
    run.set_defaults(func=run_command)

    serve = sub.add_parser("serve-mcp", help="Start the SIFT-MIND MCP server.")
    serve.add_argument("--case-root", default=None)
    serve.add_argument("--output-dir", default=None)
    serve.add_argument("--evidence-chain", default=None)
    serve.add_argument("--execution-log", default=None)
    serve.add_argument("--ledger-db", default=None)
    serve.add_argument("--baseline", default=None)
    serve.add_argument("--mode", choices=["fixture", "sift"], default="fixture")
    serve.set_defaults(func=serve_mcp_command)

    verify = sub.add_parser("verify-chain", help="Verify report findings against evidence hashes.")
    verify.add_argument("--ledger-db", required=True)
    verify.add_argument("--evidence-chain", required=True)
    verify.add_argument("--execution-log", default=None)
    verify.set_defaults(func=verify_chain_command)

    package = sub.add_parser("package-demo", help="Create a judge-facing fixture demo package manifest.")
    package.add_argument("--output-dir", required=True)
    package.add_argument("--ledger-db", required=True)
    package.add_argument("--evidence-chain", required=True)
    package.add_argument("--execution-log", required=True)
    package.add_argument("--package-dir", required=True)
    package.add_argument("--repo-root", default=None)
    package.add_argument("--preflight-report", default=None)
    package.add_argument("--smoke-report", default=None)
    package.add_argument("--audit-report", default=None)
    package.add_argument("--model-brief-report", default=None)
    package.add_argument("--archive-path", default=None)
    package.add_argument("--mode", choices=["fixture", "sift"], default="fixture")
    package.add_argument("--baseline", default=None)
    package.set_defaults(func=package_demo_command)

    audit = sub.add_parser("production-audit", help="Audit production readiness against the SIFT-MIND requirement set.")
    audit.add_argument("--target", choices=["fixture", "sift"], default="fixture")
    audit.add_argument("--mode", choices=["fixture", "sift"], default="fixture")
    audit.add_argument("--case-root", default=None)
    audit.add_argument("--output-dir", default=None)
    audit.add_argument("--evidence-chain", default=None)
    audit.add_argument("--execution-log", default=None)
    audit.add_argument("--ledger-db", default=None)
    audit.add_argument("--baseline", default=None)
    audit.add_argument("--package-dir", default=None)
    audit.add_argument("--archive-path", default=None)
    audit.add_argument("--repo-root", default=None)
    audit.add_argument("--report", default=None)
    audit.set_defaults(func=production_audit_command)

    sift_smoke = sub.add_parser("sift-smoke", help="Run typed wrappers from a case artifact manifest.")
    sift_smoke.add_argument("--manifest", required=True)
    sift_smoke.add_argument("--report", default=None)
    sift_smoke.add_argument("--fresh", action="store_true")
    sift_smoke.add_argument("--allow-tool-errors", action="store_true")
    sift_smoke.add_argument("--mode", choices=["fixture", "sift"], default="sift")
    sift_smoke.add_argument("--case-root", default=None)
    sift_smoke.add_argument("--output-dir", default=None)
    sift_smoke.add_argument("--evidence-chain", default=None)
    sift_smoke.add_argument("--execution-log", default=None)
    sift_smoke.add_argument("--ledger-db", default=None)
    sift_smoke.add_argument("--baseline", default=None)
    sift_smoke.set_defaults(func=sift_smoke_command)

    sift_preflight = sub.add_parser("sift-preflight", help="Validate a SIFT smoke manifest without running tools.")
    sift_preflight.add_argument("--manifest", required=True)
    sift_preflight.add_argument("--report", default=None)
    sift_preflight.add_argument("--mode", choices=["fixture", "sift"], default="sift")
    sift_preflight.add_argument("--case-root", default=None)
    sift_preflight.add_argument("--output-dir", default=None)
    sift_preflight.add_argument("--evidence-chain", default=None)
    sift_preflight.add_argument("--execution-log", default=None)
    sift_preflight.add_argument("--ledger-db", default=None)
    sift_preflight.add_argument("--baseline", default=None)
    sift_preflight.set_defaults(func=sift_preflight_command)

    manifest_schema = sub.add_parser("manifest-schema", help="Print or write the public-sample smoke manifest JSON Schema.")
    manifest_schema.add_argument("--output", default=None)
    manifest_schema.set_defaults(func=manifest_schema_command)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())

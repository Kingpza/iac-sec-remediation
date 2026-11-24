#!/usr/bin/env python3
"""
Ethical Student Repository Batch Scanner & Aggregator.

Enforces explicit student consent via a CSV manifest, strips Git history and
sensitive local artifacts into an anonymized staging workspace, scans each
consented project with Checkov (+ Gitleaks if available), and generates both
per-repo JSON reports and an aggregated cross-project summary.
"""

import argparse
import csv
import json
import os
import shutil
import subprocess
import sys
from typing import Dict, List

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

import pipeline  # noqa: E402

CONSENT_TRUE = {"yes", "y", "true", "1", "co", "dong y"}
STRIP_DIRS = {".git", "node_modules", ".terraform", "__pycache__", ".venv", "venv"}
STRIP_FILES = {".env", ".env.local", ".env.production", "id_rsa", "id_ed25519"}


def init_manifest(manifest_path: str) -> None:
    """Create a clean consent_manifest.csv header."""
    os.makedirs(os.path.dirname(manifest_path) or ".", exist_ok=True)
    with open(manifest_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["folder_name", "repo_id", "consented", "notes"])
    print(f"[OK] Da tao manifest tai: {manifest_path}")


def stage_anonymized_copy(src_dir: str, dst_dir: str) -> None:
    """Copy student project excluding .git history, local env secrets, and build caches."""
    if os.path.exists(dst_dir):
        shutil.rmtree(dst_dir)

    def _ignore(directory: str, entries: List[str]) -> List[str]:
        ignored = []
        for entry in entries:
            full = os.path.join(directory, entry)
            if os.path.isdir(full) and entry in STRIP_DIRS:
                ignored.append(entry)
            elif os.path.isfile(full) and (entry in STRIP_FILES or entry.endswith((".pem", ".key", ".p12"))):
                ignored.append(entry)
        return ignored

    shutil.copytree(src_dir, dst_dir, ignore=_ignore)


def load_consented_entries(manifest_path: str) -> List[Dict[str, str]]:
    """Load CSV manifest and return only rows with explicit consent."""
    consented_rows: List[Dict[str, str]] = []
    with open(manifest_path, "r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            folder = (row.get("folder_name") or "").strip()
            repo_id = (row.get("repo_id") or "").strip()
            consent = (row.get("consented") or "").strip().lower()
            if not folder or not repo_id:
                continue
            if consent not in CONSENT_TRUE:
                print(f"[SKIP] Bo qua '{folder}' ({repo_id}) vi chua co xac nhan dong y (consented={consent!r}).")
                continue
            consented_rows.append({"folder_name": folder, "repo_id": repo_id})
    return consented_rows


def process_student_batch(
    raw_dir: str,
    manifest_path: str,
    staged_root: str,
    reports_repos_dir: str,
    llm_provider: str = "auto",
) -> int:
    """Anonymize, scan, and aggregate all consented student repositories."""
    entries = load_consented_entries(manifest_path)
    if not entries:
        print("[WARN] Khong co do an nao du dieu kien (consented=yes).")
        return 0

    os.makedirs(staged_root, exist_ok=True)
    os.makedirs(reports_repos_dir, exist_ok=True)

    processed = 0
    for entry in entries:
        src = os.path.join(raw_dir, entry["folder_name"])
        repo_id = entry["repo_id"]
        if not os.path.isdir(src):
            print(f"[WARN] Khong tim thay thu muc do an: {src}")
            continue

        staged = os.path.join(staged_root, repo_id)
        stage_anonymized_copy(src, staged)

        ckv_json = os.path.join(staged_root, f"{repo_id}_checkov.json")
        gl_json = os.path.join(staged_root, f"{repo_id}_gitleaks.json")

        proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "checkov.main",
                "-d",
                ".",
                "--skip-download",
                "--enable-secret-scan-all-files",
                "--quiet",
                "--output",
                "json",
                "--soft-fail",
            ],
            cwd=staged,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        with open(ckv_json, "w", encoding="utf-8") as f:
            f.write(proc.stdout.strip() or "{}")

        has_gl = False
        gl_bin = pipeline.find_gitleaks_executable()
        if gl_bin:
            subprocess.run(
                [
                    gl_bin,
                    "detect",
                    f"--source={staged}",
                    "--no-git",
                    "--report-format=json",
                    f"--report-path={gl_json}",
                    "--exit-code=0",
                ],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
            has_gl = os.path.exists(gl_json)

        findings = pipeline.normalize_findings(
            ckv_json,
            gl_json if has_gl else None,
            repo_id=repo_id,
            strip_prefixes=[repo_id],
        )
        cache: Dict = {}
        for item in findings:
            item["remediation"] = pipeline.generate_remediation(item, llm_provider=llm_provider, cache=cache)

        metrics, _ = pipeline.verify_rescan(findings, None, repo_id=repo_id)
        metrics["tool_metadata"] = pipeline.collect_tool_metadata(ckv_json, llm_provider=llm_provider)
        metrics["scan_scope"] = pipeline.summarize_scan_scope(ckv_json, source_dir=staged)
        out_json = os.path.join(reports_repos_dir, f"{repo_id}.json")
        out_md = os.path.join(reports_repos_dir, f"{repo_id}_SUMMARY.md")
        with open(out_json, "w", encoding="utf-8") as f:
            json.dump({"summary_metrics": metrics, "findings": findings}, f, ensure_ascii=False, indent=2)
        pipeline.export_markdown_summary(findings, metrics, [], out_md)
        processed += 1
        print(f"[OK] Da quet & an danh {repo_id}: {len(findings)} phat hien")

    if processed > 0:
        pipeline.aggregate_reports(
            reports_repos_dir,
            "reports/aggregate_report.json",
            "reports/AGGREGATE_SUMMARY.md",
        )
    return processed


def main() -> None:
    parser = argparse.ArgumentParser(description="Batch anonymized scanner for consented student projects")
    parser.add_argument("--init-manifest", default="", help="Create a sample consent_manifest.csv at this path")
    parser.add_argument("--raw-dir", default="dataset/raw_student_repos", help="Directory of raw student folders")
    parser.add_argument("--manifest", default="dataset/consent_manifest.csv", help="Consent manifest CSV")
    parser.add_argument("--staged-dir", default="dataset/anonymized_staging", help="Anonymized staging folder")
    parser.add_argument("--reports-dir", default="reports/repos", help="Output per-repo JSON directory")
    parser.add_argument("--llm-provider", choices=["auto", "gemini", "none"], default="auto")
    args = parser.parse_args()

    if args.init_manifest:
        init_manifest(args.init_manifest)
        return

    if not os.path.exists(args.manifest):
        print(f"[LOI] Chua co file manifest: {args.manifest}. Chay --init-manifest {args.manifest} de tao mau.")
        sys.exit(1)

    process_student_batch(
        raw_dir=args.raw_dir,
        manifest_path=args.manifest,
        staged_root=args.staged_dir,
        reports_repos_dir=args.reports_dir,
        llm_provider=args.llm_provider,
    )


if __name__ == "__main__":
    main()

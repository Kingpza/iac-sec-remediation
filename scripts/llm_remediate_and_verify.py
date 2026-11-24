#!/usr/bin/env python3
"""
End-to-end LLM Remediation & Re-scan Verification Harness.

1. Scans a source directory with Checkov (+ Gitleaks if installed).
2. Copies the project to an isolated output workspace.
3. Redacts secrets and calls Gemini API per affected file to generate patched IaC files.
4. Re-scans the LLM-patched workspace with Checkov (+ Gitleaks) and computes the
   genuine LLM Re-scan Pass Rate via pipeline.verify_rescan().
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import urllib.request
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

import pipeline  # noqa: E402

IGNORE_DIRS = {".git", ".terraform", "node_modules", "__pycache__", ".venv"}


def _copy_workspace(src: str, dst: str) -> None:
    if os.path.exists(dst):
        shutil.rmtree(dst)
    shutil.copytree(
        src,
        dst,
        ignore=shutil.ignore_patterns(*IGNORE_DIRS),
    )


def _run_checkov(target_dir: str, out_json: str) -> None:
    cmd = [
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
    ]
    proc = subprocess.run(cmd, cwd=target_dir, capture_output=True, text=True, encoding="utf-8", errors="replace")
    os.makedirs(os.path.dirname(out_json) or ".", exist_ok=True)
    with open(out_json, "w", encoding="utf-8") as f:
        f.write(proc.stdout.strip() or "{}")


def _run_gitleaks(target_dir: str, out_json: str) -> bool:
    gl_bin = pipeline.find_gitleaks_executable()
    if not gl_bin:
        return False
    cmd = [
        gl_bin,
        "detect",
        f"--source={target_dir}",
        "--no-git",
        "--report-format=json",
        f"--report-path={out_json}",
        "--exit-code=0",
    ]
    subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    return os.path.exists(out_json)


def _extract_json_object(raw_text: str) -> Optional[Dict[str, Any]]:
    cleaned = raw_text.strip()
    if cleaned.startswith("```"):
        lines = cleaned.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        cleaned = "\n".join(lines).strip()
    try:
        obj = json.loads(cleaned)
        return obj if isinstance(obj, dict) else None
    except json.JSONDecodeError:
        return None


def request_llm_file_patch(
    file_path: str,
    sanitized_file_content: str,
    file_findings: List[Dict[str, Any]],
    api_key: str,
) -> Tuple[str, str, Optional[str]]:
    """Call Gemini API to patch all IaC findings in one file while preserving functionality."""
    rules_list = "\n".join(
        f"- {f['rule_id']} (line {f['line_start']}): {f.get('rule_name', '')}"
        for f in file_findings
    )
    prompt = (
        "You are a DevSecOps security engineer. Fix ALL listed security misconfigurations "
        "in the following Infrastructure-as-Code file while preserving functional intent and valid syntax.\n"
        f"File: {file_path}\n"
        f"Findings to fix:\n{rules_list}\n\n"
        "File content (secrets redacted):\n"
        f"```\n{sanitized_file_content}\n```\n\n"
        "Return ONLY a JSON object with two keys:\n"
        '1. "summary": concise Vietnamese explanation of changes made.\n'
        '2. "patched_content": the complete updated file content ready to save and re-scan.'
    )

    url = (
        "https://generativelanguage.googleapis.com/v1beta/models/"
        f"gemini-2.5-flash:generateContent?key={api_key}"
    )
    payload = json.dumps(
        {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {"responseMimeType": "application/json"},
        }
    ).encode("utf-8")
    req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=45) as resp:
            res_json = json.loads(resp.read().decode("utf-8"))
            raw_text = res_json["candidates"][0]["content"]["parts"][0]["text"]
            parsed = _extract_json_object(raw_text)
            if not parsed or "patched_content" not in parsed:
                return "LLM_PARSE_ERROR", "Khong phan tich duoc JSON ban va tu LLM.", None
            return "LLM_API_SUCCESS", str(parsed.get("summary", "")), str(parsed["patched_content"])
    except Exception as exc:
        return f"LLM_API_ERROR ({exc})", f"Loi goi API LLM: {exc}", None


def run_llm_remediation_verify(
    source_dir: str,
    out_workspace: str,
    repo_id: str,
    out_json: str,
    out_md: str,
    dry_run: bool = False,
) -> Dict[str, Any]:
    """Run before-scan, LLM file patching into isolated workspace, after-scan, and verify."""
    os.makedirs("reports", exist_ok=True)
    src_base = os.path.basename(os.path.abspath(source_dir))
    dst_base = os.path.basename(os.path.abspath(out_workspace))

    before_ckv = os.path.join("reports", f"_llm_{repo_id}_checkov_before.json")
    before_gl = os.path.join("reports", f"_llm_{repo_id}_gitleaks_before.json")
    after_ckv = os.path.join("reports", f"_llm_{repo_id}_checkov_after.json")
    after_gl = os.path.join("reports", f"_llm_{repo_id}_gitleaks_after.json")

    _run_checkov(source_dir, before_ckv)
    has_gl_before = _run_gitleaks(source_dir, before_gl)

    before_findings = pipeline.normalize_findings(
        before_ckv,
        before_gl if has_gl_before else None,
        repo_id=repo_id,
        strip_prefixes=[src_base],
    )
    seen_before = {(f["repo_id"], f["file_path"], f["rule_id"], f["line_start"]) for f in before_findings}
    ext_before, _ = pipeline.scan_extended_files(source_dir, repo_id=repo_id, seen_keys=seen_before)
    before_findings.extend(ext_before)

    _copy_workspace(source_dir, out_workspace)
    api_key = None if dry_run else os.getenv("GEMINI_API_KEY")

    by_file: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for f in before_findings:
        by_file[f["file_path"]].append(f)

    patched_files = 0
    for rel_path, file_findings in by_file.items():
        abs_file = os.path.join(out_workspace, rel_path)
        if not os.path.isfile(abs_file):
            continue
        with open(abs_file, "r", encoding="utf-8", errors="replace") as fp:
            raw_content = fp.read()
        sanitized_content = pipeline.redact_sensitive_data(raw_content)

        if not api_key:
            status = "SKIPPED_NO_API_KEY"
            summary = "Chua dat GEMINI_API_KEY (hoac dang chay --dry-run); chua sinh ban va LLM."
            patched_content = None
        else:
            status, summary, patched_content = request_llm_file_patch(
                rel_path, sanitized_content, file_findings, api_key
            )

        if patched_content is not None:
            with open(abs_file, "w", encoding="utf-8") as fp:
                fp.write(patched_content)
            patched_files += 1

        for item in file_findings:
            item["patch_applied"] = patched_content is not None
            item["remediation"] = {"status": status, "suggestion": summary}

    if patched_files > 0:
        _run_checkov(out_workspace, after_ckv)
        has_gl_after = _run_gitleaks(out_workspace, after_gl)
        after_findings = pipeline.normalize_findings(
            after_ckv,
            after_gl if has_gl_after else None,
            repo_id=repo_id,
            strip_prefixes=[dst_base, src_base],
        )
        seen_after = {(f["repo_id"], f["file_path"], f["rule_id"], f["line_start"]) for f in after_findings}
        ext_after, _ = pipeline.scan_extended_files(out_workspace, repo_id=repo_id, seen_keys=seen_after)
        after_findings.extend(ext_after)
    else:
        after_findings = None

    metrics, remaining = pipeline.verify_rescan(before_findings, after_findings, repo_id=repo_id)
    metrics["patched_files_count"] = patched_files

    os.makedirs(os.path.dirname(out_json) or ".", exist_ok=True)
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump({"summary_metrics": metrics, "findings": before_findings}, f, ensure_ascii=False, indent=2)

    pipeline.export_markdown_summary(before_findings, metrics, remaining, out_md)
    return metrics


def main() -> None:
    parser = argparse.ArgumentParser(description="Apply LLM remediation patches and verify via re-scan")
    parser.add_argument("--source", required=True, help="Source IaC directory")
    parser.add_argument("--out-workspace", default="reports/llm_patched_preview", help="Isolated patched copy")
    parser.add_argument("--repo-id", default="PROJECT_LLM")
    parser.add_argument("--out-json", default="reports/llm_verification_report.json")
    parser.add_argument("--out-md", default="reports/LLM_VERIFICATION_REPORT.md")
    parser.add_argument("--dry-run", action="store_true", help="Skip live Gemini API call")
    args = parser.parse_args()

    metrics = run_llm_remediation_verify(
        source_dir=args.source,
        out_workspace=args.out_workspace,
        repo_id=args.repo_id,
        out_json=args.out_json,
        out_md=args.out_md,
        dry_run=args.dry_run,
    )
    print(
        f"[OK] [{args.repo_id}] Findings: {metrics['total_before']} | "
        f"Patched files: {metrics['patched_files_count']} | "
        f"Rescan pass rate: {metrics['rescan_pass_rate_percent']}"
    )


if __name__ == "__main__":
    main()

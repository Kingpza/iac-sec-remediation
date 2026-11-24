#!/usr/bin/env python3
"""
IaC Security Scanning, Sanitization, Remediation & Verification Pipeline.

Supports:
1. `scan` mode: Scan a single repository/folder (Checkov + Gitleaks), redact secrets,
   classify findings, generate remediation suggestions via Gemini API,
   and produce statistical tables without fabricating re-scan pass rates.
2. `verify` mode: Compare before/after scans to compute accurate overall and per-category
   re-scan pass rates.
3. `aggregate` mode: Combine multiple per-repo JSON reports (e.g., anonymized student
   projects) into cross-project thesis statistics.
"""

import argparse
import glob
import importlib.metadata
import json
import os
import re
import shutil
import subprocess
import urllib.request
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple

CAT_ACCESS = "Overly Permissive Access (Mở cổng / Quyền truy cập quá rộng)"
CAT_STORAGE = "Public Storage (Kho lưu trữ công khai)"
CAT_SECRETS = "Hardcoded Secrets (Bí mật ghi cứng trong mã)"
CAT_OTHER = "Other IaC Misconfiguration (Cấu hình bảo mật IaC khác)"

ALL_CATEGORIES = [CAT_ACCESS, CAT_STORAGE, CAT_SECRETS, CAT_OTHER]

SECRET_RULE_IDS = {
    "CKV_AWS_41",
    "CKV_SECRET_2",
    "CKV_SECRET_6",
}

STORAGE_RULE_IDS = {
    "CKV_AWS_19",
    "CKV_AWS_20",
    "CKV_AWS_53",
    "CKV_AWS_54",
    "CKV_AWS_55",
    "CKV_AWS_56",
    "CKV_AWS_57",
    "CKV2_AWS_6",
}

ACCESS_RULE_IDS = {
    "CKV_AWS_17",
    "CKV_AWS_24",
    "CKV_AWS_25",
    "CKV_AWS_88",
    "CKV_AWS_260",
    "CKV_AWS_277",
    "CKV_AWS_382",
    "CKV_K8S_16",
    "CKV_K8S_20",
    "CKV_K8S_23",
    "CKV_K8S_37",
    "CKV_K8S_38",
    "CKV_K8S_40",
    "CKV_DOCKER_1",
    "CKV_DOCKER_3",
}

# Values that represent safe references/booleans rather than literal hardcoded secrets.
SAFE_VALUE_PREFIXES = ("var.", "local.", "data.", "aws_", "${", "<REDACTED")
SAFE_LITERAL_VALUES = {"true", "false", "null", "none", "optional", "required"}

SECRET_PATTERNS = [
    (re.compile(r'-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----'), '<REDACTED_PRIVATE_KEY>'),
    (re.compile(r'\b(AKIA|ASIA)[0-9A-Z]{16}\b'), '<REDACTED_AWS_ACCESS_KEY>'),
    (re.compile(r'\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b'), '<REDACTED_GITHUB_TOKEN>'),
    (re.compile(r'\bgithub_pat_[A-Za-z0-9_]{20,}\b'), '<REDACTED_GITHUB_TOKEN>'),
    (re.compile(r'\bsk_(live|test)_[A-Za-z0-9]{16,}\b'), '<REDACTED_API_KEY>'),
    (re.compile(r'(arn:aws:[a-z0-9-]+:[a-z0-9-]*:+)\d{12}(:)'), r'\1<REDACTED_ACCOUNT_ID>\2'),
    (re.compile(r'[A-Za-z]:\\Users\\[^\\/\s"\']+'), '<USER_HOME>'),
    (re.compile(r'/home/[^/\s"\']+'), '<USER_HOME>'),
]

KV_SECRET_PATTERN = re.compile(
    r'(?i)\b([A-Za-z0-9_]*(?:secret_key|secret_access_key|password|passwd|jwt_secret|api_key|private_key|access_key|auth_token)\b)\s*([:=])\s*(["\']?)([^"\'\s\r\n]+)\3'
)
K8S_ENV_VALUE_PATTERN = re.compile(
    r'(?im)^(\s*value:\s*)(["\']?)([^"\'\r\n]+)\2'
)
HIGH_ENTROPY_PATTERN = re.compile(r'(?<![A-Za-z0-9/+=_-])([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=_-])')


def _is_safe_secret_placeholder(val: str) -> bool:
    stripped = val.strip().strip("\"'")
    lower = stripped.lower()
    if not stripped or lower in SAFE_LITERAL_VALUES:
        return True
    return stripped.startswith(SAFE_VALUE_PREFIXES)


def redact_sensitive_data(snippet: str) -> str:
    """Redact credentials, tokens, high-entropy strings, and local user paths."""
    if not snippet:
        return ""
    cleaned = snippet
    for pattern, replacement in SECRET_PATTERNS:
        cleaned = pattern.sub(replacement, cleaned)

    def _replace_kv(match: re.Match) -> str:
        key, sep, quote, val = match.groups()
        if _is_safe_secret_placeholder(val):
            return match.group(0)
        return f"{key}{sep}{quote}<REDACTED_SECRET>{quote}"

    cleaned = KV_SECRET_PATTERN.sub(_replace_kv, cleaned)

    def _replace_k8s_val(match: re.Match) -> str:
        prefix, quote, val = match.groups()
        if _is_safe_secret_placeholder(val):
            return match.group(0)
        return f'{prefix}"<REDACTED_SECRET>"'

    cleaned = K8S_ENV_VALUE_PATTERN.sub(_replace_k8s_val, cleaned)
    cleaned = HIGH_ENTROPY_PATTERN.sub("<REDACTED_HIGH_ENTROPY_KEY>", cleaned)
    return cleaned


def normalize_file_path(file_path: str, strip_prefixes: Sequence[str] = ()) -> str:
    """Normalize OS path separators and optionally strip comparison root prefixes."""
    norm = (file_path or "").replace("\\", "/").lstrip("/")
    for prefix in strip_prefixes:
        clean_prefix = prefix.replace("\\", "/").strip("/")
        if clean_prefix and norm.startswith(f"{clean_prefix}/"):
            norm = norm[len(clean_prefix) + 1 :]
    return norm


def classify_category(rule_id: str, rule_name: str, tool: str = "Checkov") -> str:
    """Classify a finding into one of the four standardized IaC security categories."""
    rid = (rule_id or "").upper()
    text = f"{rid} {rule_name or ''}".lower()

    if tool.lower() == "gitleaks" or rid in SECRET_RULE_IDS or rid.startswith("CKV_SECRET_"):
        return CAT_SECRETS
    if any(k in text for k in ("hardcoded", "hard coded", "password", "credential", "private key")):
        return CAT_SECRETS

    if rid in STORAGE_RULE_IDS:
        return CAT_STORAGE
    if any(w in text for w in ("s3", "bucket", "storage", "blob")) and any(
        w in text for w in ("public", "acl", "access block", "restrict_public")
    ):
        return CAT_STORAGE

    if rid in ACCESS_RULE_IDS:
        return CAT_ACCESS
    if any(
        k in text
        for k in (
            "0.0.0.0",
            "ingress",
            "egress",
            "security group",
            "publicly accessible",
            "public ip",
            "privileged",
            "allowprivilegeescalation",
            "root container",
            "hostnetwork",
            "hostpid",
            "hostipc",
            "net_raw",
            "capabilities",
            "service account token",
        )
    ):
        return CAT_ACCESS

    return CAT_OTHER


def find_gitleaks_executable() -> Optional[str]:
    """Locate gitleaks on PATH or in standard Windows WinGet install folders."""
    on_path = shutil.which("gitleaks")
    if on_path:
        return on_path
    local_app = os.getenv("LOCALAPPDATA", "")
    if local_app:
        winget_link = os.path.join(local_app, "Microsoft", "WinGet", "Links", "gitleaks.exe")
        if os.path.isfile(winget_link):
            return winget_link
        matches = glob.glob(
            os.path.join(local_app, "Microsoft", "WinGet", "Packages", "Gitleaks.Gitleaks*", "gitleaks.exe")
        )
        if matches:
            return matches[0]
    return None


def _load_json_safe(path: Optional[str]) -> Any:
    if not path or not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as f:
        raw = f.read().strip()
    if not raw:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return None


def has_valid_scan_payload(path: Optional[str]) -> bool:
    """Return True only if path holds a non-empty Checkov, Gitleaks, or Prowler JSON payload."""
    data = _load_json_safe(path)
    if data is None:
        return False
    if isinstance(data, list):
        if len(data) == 0:
            return False
        return any(
            isinstance(item, dict)
            and (
                item.get("results") is not None
                or item.get("RuleID") is not None
                or item.get("CheckID") is not None
                or item.get("status_code") is not None
            )
            for item in data
        )
    if isinstance(data, dict):
        return "results" in data
    return False


def parse_prowler_findings(
    prowler_path: Optional[str],
    repo_id: str = "REPO_LAB_01",
    seen_keys: Optional[set] = None,
) -> List[Dict[str, Any]]:
    """Parse Prowler v3 legacy JSON or v4 OCSF JSON findings into the unified schema."""
    results: List[Dict[str, Any]] = []
    if seen_keys is None:
        seen_keys = set()

    data = _load_json_safe(prowler_path)
    if not isinstance(data, list):
        return results

    for idx, item in enumerate(data, start=1):
        if not isinstance(item, dict):
            continue

        # Detect Prowler v4 OCSF format vs Prowler v3 legacy JSON format
        if "status_code" in item or "finding_info" in item:
            if str(item.get("status_code", "")).upper() != "FAIL":
                continue
            finding_info = item.get("finding_info") or {}
            metadata = item.get("metadata") or {}
            resources = item.get("resources") or [{}]
            res0 = resources[0] if isinstance(resources[0], dict) else {}
            unmapped = item.get("unmapped") or {}

            rule_id = str(
                unmapped.get("check_id")
                or metadata.get("event_code")
                or finding_info.get("uid")
                or f"PROWLER_CHECK_{idx}"
            )
            rule_name = str(finding_info.get("title") or item.get("status_detail") or rule_id)
            resource_id = str(res0.get("uid") or res0.get("name") or "cloud-resource")
            service = str(res0.get("group", {}).get("name") if isinstance(res0.get("group"), dict) else res0.get("type") or "aws")
            snippet = str(item.get("status_detail") or finding_info.get("desc") or resource_id)
        else:
            if str(item.get("Status", "")).upper() != "FAIL":
                continue
            rule_id = str(item.get("CheckID") or f"PROWLER_CHECK_{idx}")
            rule_name = str(item.get("CheckTitle") or item.get("StatusExtended") or rule_id)
            resource_id = str(item.get("ResourceArn") or item.get("ResourceId") or "cloud-resource")
            service = str(item.get("ServiceName") or "aws")
            snippet = str(item.get("StatusExtended") or item.get("Risk") or resource_id)

        norm_resource = redact_sensitive_data(resource_id)
        dedup_key = (repo_id, norm_resource, rule_id, 0)
        if dedup_key in seen_keys:
            continue
        seen_keys.add(dedup_key)

        results.append(
            {
                "finding_id": f"{repo_id}_{rule_id}_{idx}",
                "repo_id": repo_id,
                "tool": "Prowler",
                "framework": f"cloud-runtime:{service}",
                "category": classify_category(rule_id, f"{rule_name} {snippet}", "Prowler"),
                "rule_id": rule_id,
                "rule_name": rule_name,
                "file_path": norm_resource,
                "line_start": 0,
                "line_end": 0,
                "sanitized_code": redact_sensitive_data(snippet),
                "eligible_for_llm": True,
            }
        )
    return results


def normalize_findings(
    checkov_path: Optional[str],
    gitleaks_path: Optional[str],
    repo_id: str = "REPO_LAB_01",
    strip_prefixes: Sequence[str] = (),
    prowler_path: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Parse Checkov, Gitleaks & optional Prowler JSON reports into a unified, redacted finding schema."""
    normalized: List[Dict[str, Any]] = []
    seen_keys = set()

    checkov_data = _load_json_safe(checkov_path)
    if checkov_data:
        blocks = checkov_data if isinstance(checkov_data, list) else [checkov_data]
        for block in blocks:
            if not isinstance(block, dict):
                continue
            check_type = block.get("check_type", "iac")
            failed = block.get("results", {}).get("failed_checks", [])
            for item in failed:
                file_path = normalize_file_path(item.get("file_path", ""), strip_prefixes)
                rule_id = item.get("check_id", "UNKNOWN_RULE")
                rule_name = item.get("check_name", "")
                line_range = item.get("file_line_range") or [0, 0]
                line_start = line_range[0] if len(line_range) > 0 else 0
                line_end = line_range[1] if len(line_range) > 1 else line_start
                dedup_key = (repo_id, file_path, rule_id, line_start)
                if dedup_key in seen_keys:
                    continue
                seen_keys.add(dedup_key)

                raw_code = "".join(line[1] for line in item.get("code_block", []) if len(line) > 1)
                normalized.append(
                    {
                        "finding_id": f"{repo_id}_{rule_id}_L{line_start}",
                        "repo_id": repo_id,
                        "tool": "Checkov",
                        "framework": check_type,
                        "category": classify_category(rule_id, rule_name, "Checkov"),
                        "rule_id": rule_id,
                        "rule_name": rule_name,
                        "file_path": file_path,
                        "line_start": line_start,
                        "line_end": line_end,
                        "sanitized_code": redact_sensitive_data(raw_code),
                        "eligible_for_llm": True,
                    }
                )

    gitleaks_data = _load_json_safe(gitleaks_path)
    if isinstance(gitleaks_data, list):
        for leak in gitleaks_data:
            if not isinstance(leak, dict):
                continue
            file_path = normalize_file_path(leak.get("File", ""), strip_prefixes)
            rule_id = leak.get("RuleID", "GITLEAKS_SECRET")
            rule_name = leak.get("Description", "Hardcoded secret detected")
            start_line = leak.get("StartLine", 0)
            end_line = leak.get("EndLine", start_line)
            dedup_key = (repo_id, file_path, rule_id, start_line)
            if dedup_key in seen_keys:
                continue
            seen_keys.add(dedup_key)

            normalized.append(
                {
                    "finding_id": f"{repo_id}_{rule_id}_L{start_line}",
                    "repo_id": repo_id,
                    "tool": "Gitleaks",
                    "framework": "secrets",
                    "category": CAT_SECRETS,
                    "rule_id": rule_id,
                    "rule_name": rule_name,
                    "file_path": file_path,
                    "line_start": start_line,
                    "line_end": end_line,
                    "sanitized_code": redact_sensitive_data(leak.get("Match", "")),
                    "eligible_for_llm": True,
                }
            )

    if prowler_path:
        normalized.extend(parse_prowler_findings(prowler_path, repo_id=repo_id, seen_keys=seen_keys))

    return normalized


def generate_remediation(
    finding: Dict[str, Any],
    llm_provider: str = "auto",
    cache: Optional[Dict[Tuple[str, str], Dict[str, str]]] = None,
    llm_budget: Optional[List[int]] = None,
) -> Dict[str, str]:
    """Generate remediation guidance via Gemini API."""
    cache_key = (finding["rule_id"], finding["sanitized_code"])
    if cache is not None and cache_key in cache:
        cached = dict(cache[cache_key])
        cached["cached"] = "true"
        return cached

    if llm_provider == "none":
        return {"status": "LLM_DISABLED", "suggestion": ""}

    api_key = os.getenv("GEMINI_API_KEY") if llm_provider in ("auto", "gemini") else None
    if not api_key:
        return {"status": "NO_API_KEY", "suggestion": ""}

    if llm_budget is not None and llm_budget[0] <= 0:
        return {"status": "LLM_BUDGET_REACHED", "suggestion": ""}

    prompt = (
        "Bạn là chuyên gia DevSecOps. Hãy phân tích lỗi cấu hình IaC dưới đây và đề xuất cách sửa giữ nguyên chức năng.\n"
        f"- Công cụ: {finding['tool']} ({finding.get('framework', 'iac')})\n"
        f"- Nhóm lỗi: {finding['category']}\n"
        f"- Mã quy tắc: {finding['rule_id']} - {finding.get('rule_name', '')}\n"
        f"- Tệp: {finding['file_path']} (dòng {finding['line_start']})\n"
        f"- Đoạn mã (đã ẩn danh bí mật):\n```\n{finding['sanitized_code']}\n```\n"
        "Trả lời ngắn gọn bằng tiếng Việt theo 3 mục:\n"
        "1. Nguyên nhân & Rủi ro\n"
        "2. Đoạn mã sửa đề xuất (HCL/YAML/Dockerfile cụ thể)\n"
        "3. Cách kiểm chứng lại"
    )
    try:
        if llm_budget is not None:
            llm_budget[0] -= 1
        url = (
            "https://generativelanguage.googleapis.com/v1beta/models/"
            f"gemini-2.5-flash:generateContent?key={api_key}"
        )
        payload = json.dumps({"contents": [{"parts": [{"text": prompt}]}]}).encode("utf-8")
        req = urllib.request.Request(
            url, data=payload, headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=25) as resp:
            res_json = json.loads(resp.read().decode("utf-8"))
            text = res_json["candidates"][0]["content"]["parts"][0]["text"]
            result = {"status": "LLM_API_SUCCESS", "suggestion": text}
            if cache is not None:
                cache[cache_key] = result
            return result
    except Exception as exc:
        return {"status": f"LLM_API_ERROR ({exc})", "suggestion": ""}


EXTENDED_SCAN_EXTS = {
    ".py", ".ipynb", ".java", ".js", ".ts", ".jsx", ".tsx",
    ".env", ".properties", ".ini", ".conf", ".cfg",
    ".json", ".xml", ".sql",
}

EXTENDED_SKIP_DIRS = {
    ".git", "node_modules", ".venv", "venv", "__pycache__",
    ".terraform", "target", "build", "dist", ".idea", ".vscode",
}

EXTENDED_RULES: List[Tuple[str, str, str, re.Pattern]] = [
    (
        "EXT_BIND_ALL",
        "App binds to all interfaces (0.0.0.0) or wildcard CORS",
        CAT_ACCESS,
        re.compile(r'(?i)(?:0\.0\.0\.0|Access-Control-Allow-Origin["\']?\s*[:=]\s*["\']\*["\']|allowedOrigins\s*\(\s*["\']\*["\']|allow_origins\s*=\s*\[\s*["\']\*["\'])'),
    ),
    (
        "EXT_DEBUG_ENABLED",
        "Debug mode enabled in application/config",
        CAT_OTHER,
        re.compile(r'(?i)\b(?:DEBUG\s*=\s*True|debug\s*=\s*True|spring\.jpa\.show-sql\s*=\s*true)\b'),
    ),
    (
        "EXT_SSL_DISABLED",
        "TLS/SSL certificate verification disabled",
        CAT_ACCESS,
        re.compile(r'(?i)(?:verify\s*=\s*False|rejectUnauthorized\s*:\s*false|ssl\s*=\s*False)'),
    ),
    (
        "EXT_PUBLIC_ACL_CODE",
        "Public ACL configured in application SDK code",
        CAT_STORAGE,
        re.compile(r'(?i)(?:ACL\s*=\s*["\']public-read(?:-write)?["\']|public-read-write)'),
    ),
    (
        "EXT_HARDCODED_SECRET",
        "Potential hardcoded password, secret, or connection string credential",
        CAT_SECRETS,
        re.compile(
            r'(?i)(?:\b(?:password|passwd|db_pass|db_password|secret_key|jwt_secret|api_key|private_key)\b\s*[:=]\s*["\'][^"\']{4,}["\']|(?:mysql|postgres|postgresql|mongodb(?:\+srv)?|redis):\/\/[^:\s"\']+?:[^@\s"\']+@)'
        ),
    ),
    (
        "EXT_INSECURE_EXEC",
        "Insecure command execution or unsafe deserialization (shell=True / os.system / eval / pickle)",
        CAT_OTHER,
        re.compile(r'\b(?:os\.system\s*\(|eval\s*\(|pickle\.loads\s*\(|yaml\.load\s*\(|Runtime\.getRuntime\(\)\.exec\s*\()|shell\s*=\s*True'),
    ),
]


def scan_extended_files(
    source_dir: Optional[str],
    repo_id: str,
    seen_keys: Optional[set] = None,
) -> Tuple[List[Dict[str, Any]], int]:
    """Scan non-IaC source and config files (.py, .java, .js, .env, etc.) for security issues."""
    if not source_dir or not os.path.isdir(source_dir):
        return [], 0

    if seen_keys is None:
        seen_keys = set()

    findings: List[Dict[str, Any]] = []
    scanned_count = 0

    for root, dirs, files in os.walk(source_dir):
        dirs[:] = [d for d in dirs if d not in EXTENDED_SKIP_DIRS]
        for fname in files:
            low = fname.lower()
            ext = os.path.splitext(low)[1]
            if ext not in EXTENDED_SCAN_EXTS and not low.startswith(".env"):
                continue

            full_path = os.path.join(root, fname)
            rel_path = os.path.relpath(full_path, source_dir).replace("\\", "/")
            try:
                if os.path.getsize(full_path) > 2 * 1024 * 1024:
                    continue
                with open(full_path, "r", encoding="utf-8", errors="ignore") as fp:
                    lines = fp.readlines()
            except OSError:
                continue

            scanned_count += 1
            for line_no, line_text in enumerate(lines, start=1):
                stripped = line_text.strip()
                if not stripped or stripped.startswith(("#", "//", "/*", "*")):
                    continue
                for rule_id, rule_name, category, pattern in EXTENDED_RULES:
                    if pattern.search(line_text):
                        if rule_id == "EXT_HARDCODED_SECRET" and any(
                            safe in stripped for safe in ("os.getenv", "os.environ", "System.getenv", "${", "<REDACTED", "process.env")
                        ):
                            continue
                        dedup_key = (repo_id, rel_path, rule_id, line_no)
                        if dedup_key in seen_keys:
                            continue
                        seen_keys.add(dedup_key)
                        findings.append(
                            {
                                "finding_id": f"{repo_id}_{rule_id}_L{line_no}",
                                "repo_id": repo_id,
                                "tool": "ExtendedAppScanner",
                                "framework": ext.lstrip(".") or "config",
                                "category": category,
                                "rule_id": rule_id,
                                "rule_name": rule_name,
                                "file_path": rel_path,
                                "line_start": line_no,
                                "line_end": line_no,
                                "sanitized_code": redact_sensitive_data(stripped),
                                "eligible_for_llm": True,
                            }
                        )
    return findings, scanned_count


def collect_tool_metadata(checkov_path: Optional[str], llm_provider: str = "auto") -> Dict[str, str]:
    """Collect tool versions and active LLM model ID for reproducibility (Section 11.4)."""
    checkov_ver = "unknown"
    data = _load_json_safe(checkov_path)
    blocks = data if isinstance(data, list) else ([data] if isinstance(data, dict) else [])
    for b in blocks:
        if isinstance(b, dict):
            ver = (b.get("summary") or {}).get("checkov_version")
            if ver:
                checkov_ver = str(ver)
                break
    if checkov_ver == "unknown":
        try:
            checkov_ver = importlib.metadata.version("checkov")
        except Exception:
            pass

    gitleaks_ver = "not-installed"
    gl_bin = find_gitleaks_executable()
    if gl_bin:
        try:
            proc = subprocess.run([gl_bin, "version"], capture_output=True, text=True, timeout=5)
            out = (proc.stdout or proc.stderr or "").strip().splitlines()
            if out:
                gitleaks_ver = out[0].strip()
        except Exception:
            gitleaks_ver = "installed"

    has_key = bool(os.getenv("GEMINI_API_KEY")) and llm_provider in ("auto", "gemini")
    return {
        "checkov_version": checkov_ver,
        "gitleaks_version": gitleaks_ver,
        "llm_model": "gemini-2.5-flash" if has_key else "none (static-scan-only)",
    }


def summarize_scan_scope(
    checkov_path: Optional[str],
    source_dir: Optional[str] = None,
    extended_files_scanned: int = 0,
) -> Dict[str, Any]:
    """Count scanned IaC + extended app files vs remaining files (Section 11.4)."""
    iac_files = set()
    passed_checks = 0
    failed_checks = 0
    parsing_errors = 0
    resource_count = 0

    data = _load_json_safe(checkov_path)
    blocks = data if isinstance(data, list) else ([data] if isinstance(data, dict) else [])
    for b in blocks:
        if not isinstance(b, dict):
            continue
        res = b.get("results") or {}
        summary = b.get("summary") or {}
        res_passed = res.get("passed_checks", [])
        res_failed = res.get("failed_checks", [])

        for item in res_passed:
            if item.get("file_path"):
                iac_files.add(normalize_file_path(item["file_path"]))
        for item in res_failed:
            if item.get("file_path"):
                iac_files.add(normalize_file_path(item["file_path"]))

        # When Checkov runs with --quiet, passed_checks list is omitted, so read summary counts.
        passed_checks += int(summary.get("passed") if summary.get("passed") is not None else len(res_passed))
        failed_checks += int(summary.get("failed") if summary.get("failed") is not None else len(res_failed))
        parsing_errors += int(summary.get("parsing_errors") or 0)
        resource_count += int(summary.get("resource_count") or 0)

    total_repo_files = None
    out_of_scope_files = None
    iac_ext_files = 0
    if source_dir and os.path.isdir(source_dir):
        skip_dirs = EXTENDED_SKIP_DIRS
        iac_exts = {".tf", ".tfvars", ".bicep", ".yaml", ".yml"}
        count = 0
        for _, dirs, files in os.walk(source_dir):
            dirs[:] = [d for d in dirs if d not in skip_dirs]
            for fn in files:
                count += 1
                low = fn.lower()
                if low == "dockerfile" or low.endswith(".dockerfile") or os.path.splitext(low)[1] in iac_exts:
                    iac_ext_files += 1
        total_repo_files = count
        effective_iac_files = max(len(iac_files), iac_ext_files if (passed_checks + failed_checks + resource_count) > 0 else 0)
        out_of_scope_files = max(0, count - effective_iac_files - extended_files_scanned)
    else:
        effective_iac_files = len(iac_files)

    has_iac_scope = (passed_checks + failed_checks + resource_count) > 0
    has_any_scope = has_iac_scope or extended_files_scanned > 0
    return {
        "has_iac_scope": has_iac_scope,
        "has_any_scope": has_any_scope,
        "iac_files_scanned": effective_iac_files,
        "extended_files_scanned": extended_files_scanned,
        "resource_count": resource_count,
        "passed_checks": passed_checks,
        "failed_checks": failed_checks,
        "parsing_errors": parsing_errors,
        "total_repo_files": total_repo_files,
        "out_of_scope_files": out_of_scope_files,
    }


def verify_rescan(
    before_findings: List[Dict[str, Any]],
    after_findings: Optional[List[Dict[str, Any]]],
    repo_id: str,
) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """Compare before/after findings using multiset matching on (file_path, rule_id)."""
    timestamp = datetime.now(timezone.utc).isoformat()
    category_counts = Counter(f["category"] for f in before_findings)

    if after_findings is None:
        summary = {
            "repo_id": repo_id,
            "mode": "scan",
            "timestamp": timestamp,
            "total_before": len(before_findings),
            "total_after": None,
            "total_applied_and_rescanned": 0,
            "passed_rescan_count": None,
            "remaining_count": None,
            "rescan_pass_rate_percent": None,
            "by_category": {
                cat: {
                    "before": category_counts.get(cat, 0),
                    "passed": None,
                    "remaining": None,
                    "pass_rate_percent": None,
                }
                for cat in ALL_CATEGORIES
            },
        }
        return summary, []

    remaining_pool = Counter((f["file_path"], f["rule_id"]) for f in after_findings)
    applied_by_cat: Counter = Counter()
    passed_by_cat: Counter = Counter()
    remaining_by_cat: Counter = Counter()
    remaining_findings: List[Dict[str, Any]] = []
    not_applied_count = 0

    for f in before_findings:
        key = (f["file_path"], f["rule_id"])
        if f.get("patch_applied") is False:
            f["rescan_status"] = "NOT_APPLIED"
            not_applied_count += 1
            if remaining_pool[key] > 0:
                remaining_pool[key] -= 1
            continue

        applied_by_cat[f["category"]] += 1
        if remaining_pool[key] > 0:
            remaining_pool[key] -= 1
            f["rescan_status"] = "FAILED_STILL_PRESENT"
            remaining_by_cat[f["category"]] += 1
            remaining_findings.append(f)
        else:
            f["rescan_status"] = "PASSED_RESCAN"
            passed_by_cat[f["category"]] += 1

    # Track newly introduced findings in after_findings not present before remediation
    new_pool = Counter(remaining_pool)
    new_after_findings: List[Dict[str, Any]] = []
    for af in after_findings:
        key = (af["file_path"], af["rule_id"])
        if new_pool[key] > 0:
            new_pool[key] -= 1
            new_after_findings.append(
                {
                    "rule_id": af["rule_id"],
                    "rule_name": af.get("rule_name", ""),
                    "file_path": af["file_path"],
                    "line_start": af.get("line_start", 0),
                    "category": af.get("category", CAT_OTHER),
                }
            )

    total_before = len(before_findings)
    total_applied = sum(applied_by_cat.values())
    passed_count = sum(passed_by_cat.values())
    pass_rate = round((passed_count / total_applied * 100), 2) if total_applied > 0 else 0.0

    by_category = {}
    for cat in ALL_CATEGORIES:
        b = category_counts.get(cat, 0)
        a = applied_by_cat.get(cat, 0)
        p = passed_by_cat.get(cat, 0)
        r = remaining_by_cat.get(cat, 0)
        by_category[cat] = {
            "before": b,
            "applied": a,
            "passed": p,
            "remaining": r,
            "pass_rate_percent": round((p / a * 100), 2) if a > 0 else None,
        }

    summary = {
        "repo_id": repo_id,
        "mode": "verify",
        "timestamp": timestamp,
        "total_before": total_before,
        "total_after": len(after_findings),
        "total_applied_and_rescanned": total_applied,
        "not_applied_count": not_applied_count,
        "passed_rescan_count": passed_count,
        "remaining_count": total_applied - passed_count,
        "new_after_count": len(new_after_findings),
        "new_after_findings": new_after_findings,
        "rescan_pass_rate_percent": pass_rate,
        "by_category": by_category,
    }
    return summary, remaining_findings


def _short_snippet(code: str, max_len: int = 120) -> str:
    compact = " ".join(code.split()).replace("|", "\\|").replace("`", "'")
    if len(compact) <= max_len:
        return compact
    return compact[: max_len - 3] + "..."


def _short_suggestion(text: str, max_len: int = 160) -> str:
    compact = " ".join((text or "").split()).replace("|", "\\|").replace("`", "'")
    if not compact:
        return "-"
    if len(compact) <= max_len:
        return compact
    return compact[: max_len - 3] + "..."


def export_markdown_summary(
    findings: List[Dict[str, Any]],
    metrics: Dict[str, Any],
    remaining_findings: List[Dict[str, Any]],
    out_md: str,
) -> None:
    """Write a thesis-ready Markdown report with category stats, rule stats, and findings."""
    is_verify = metrics.get("mode") == "verify"
    total_before = metrics["total_before"]
    scope = metrics.get("scan_scope") or {}
    tool_meta = metrics.get("tool_metadata") or {}
    has_any_scope = scope.get("has_any_scope", True)
    iac_files = scope.get("iac_files_scanned")
    ext_files = scope.get("extended_files_scanned", 0)
    out_of_scope = scope.get("out_of_scope_files")

    if total_before == 0 and not has_any_scope:
        status_label = f"NGOÀI PHẠM VI QUÉT (0 tệp hỗ trợ; {out_of_scope if out_of_scope is not None else '?'} tệp ngoài phạm vi)"
    elif total_before == 0:
        status_label = f"KHÔNG PHÁT HIỆN LỖI (0 lỗi | {iac_files} tệp IaC, {ext_files} tệp mã nguồn/cấu hình)"
    else:
        status_label = f"PHÁT HIỆN {total_before} LỖI BẢO MẬT"

    lines = [
        "# Báo cáo Quét Lỗi Cấu hình Bảo mật IaC & Sinh Gợi ý Khắc phục",
        "",
        f"- **Kết quả quét:** **`{status_label}`**",
        f"- **Mã dự án (`repo_id`):** `{metrics['repo_id']}`",
        f"- **Chế độ chạy:** `{'Kiểm chứng trước/sau (verify)' if is_verify else 'Quét đánh giá (scan)'}`",
        f"- **Thời gian:** `{metrics['timestamp']}`",
    ]
    if tool_meta:
        lines.append(
            f"- **Phiên bản công cụ & mô hình:** `Checkov {tool_meta.get('checkov_version', 'unknown')}` | "
            f"`Gitleaks {tool_meta.get('gitleaks_version', 'N/A')}` | "
            f"`LLM: {tool_meta.get('llm_model', 'none')}`"
        )
    if scope:
        scope_text = f"`{iac_files}` tệp IaC (`{scope.get('passed_checks', 0)}` đạt, `{scope.get('failed_checks', 0)}` vi phạm) | `{ext_files}` tệp mã nguồn/cấu hình mở rộng"
        if out_of_scope is not None:
            scope_text += f" | `{out_of_scope}` tệp khác"
        lines.append(f"- **Phạm vi tệp quét:** {scope_text}")

    lines.append(f"- **Tổng phát hiện ban đầu (Before):** `{total_before}`")
    if is_verify:
        lines.extend(
            [
                f"- **Tổng phát hiện sau sửa (After):** `{metrics['total_after']}`",
                f"- **Số lỗi đã áp dụng sửa & quét lại hợp lệ:** `{metrics['total_applied_and_rescanned']}` (không áp dụng được: `{metrics.get('not_applied_count', 0)}`)",
                f"- **Số lỗi vượt quét lại (Passed Re-scan):** `{metrics['passed_rescan_count']}`",
                f"- **Số lỗi còn tồn tại (Remaining):** `{metrics['remaining_count']}`",
                f"- **Cảnh báo mới phát sinh sau sửa:** `{metrics.get('new_after_count', 0)}`",
                f"- **Tỷ lệ vượt quét lại (Re-scan Pass Rate):** **`{metrics['rescan_pass_rate_percent']}%`**",
            ]
        )
    else:
        lines.append(
            "- **Tỷ lệ vượt quét lại:** `N/A (chế độ scan đơn lẻ — chưa có lần quét lại sau sửa)`"
        )

    lines.extend(["", "## 1. Bảng thống kê lỗi cấu hình theo loại", ""])
    if is_verify:
        lines.append("| Nhóm lỗi | Số lượng (Before) | Tỷ lệ (%) | Vượt quét lại | Còn tồn tại | Tỷ lệ vượt (%) |")
        lines.append("|---|---:|---:|---:|---:|---:|")
    else:
        lines.append("| Nhóm lỗi | Số lượng | Tỷ lệ (%) |")
        lines.append("|---|---:|---:|")

    for cat in ALL_CATEGORIES:
        stat = metrics["by_category"].get(cat, {})
        cnt = stat.get("before", 0)
        share = round((cnt / total_before * 100), 2) if total_before > 0 else 0.0
        if is_verify:
            p = stat.get("passed", 0)
            r = stat.get("remaining", 0)
            pr = f"{stat['pass_rate_percent']}%" if stat.get("pass_rate_percent") is not None else "N/A"
            lines.append(f"| {cat} | {cnt} | {share}% | {p} | {r} | {pr} |")
        else:
            lines.append(f"| {cat} | {cnt} | {share}% |")

    # Group by (tool, rule_id, category, rule_name)
    rule_groups: Dict[Tuple[str, str, str, str], List[Dict[str, Any]]] = defaultdict(list)
    for f in findings:
        rule_groups[(f["tool"], f["rule_id"], f["category"], f.get("rule_name", ""))].append(f)

    lines.extend(["", "## 2. Bảng thống kê theo quy tắc kiểm tra", ""])
    if not findings:
        lines.append("*Không có lỗi nào được phát hiện.*")
    else:
        if is_verify:
            lines.append("| Công cụ | Mã quy tắc | Nhóm lỗi | Mô tả | Số lượng | Vượt quét lại |")
            lines.append("|---|---|---|---|---:|---:|")
        else:
            lines.append("| Công cụ | Mã quy tắc | Nhóm lỗi | Mô tả | Số lượng |")
            lines.append("|---|---|---|---|---:|")

        for (tool, rule_id, cat, rule_name), items in sorted(
            rule_groups.items(), key=lambda kv: (-len(kv[1]), kv[0][1])
        ):
            desc = (rule_name or "").replace("|", "\\|")
            if is_verify:
                passed_cnt = sum(1 for x in items if x.get("rescan_status") == "PASSED_RESCAN")
                lines.append(f"| {tool} | `{rule_id}` | {cat} | {desc} | {len(items)} | {passed_cnt}/{len(items)} |")
            else:
                lines.append(f"| {tool} | `{rule_id}` | {cat} | {desc} | {len(items)} |")

    lines.extend(["", "## 3. Chi tiết phát hiện & Gợi ý khắc phục (đã ẩn danh)", ""])
    if not findings:
        lines.append("*Không có lỗi cấu hình bảo mật hay bí mật lộ nào được phát hiện.*")
    else:
        if is_verify:
            lines.append("| ID | Công cụ | Nhóm lỗi | Quy tắc | Tệp & Dòng | Trạng thái quét lại | Nguồn gợi ý | Tóm tắt gợi ý | Mã đã làm sạch |")
            lines.append("|---|---|---|---|---|---|---|---|---|")
        else:
            lines.append("| ID | Công cụ | Nhóm lỗi | Quy tắc | Tệp & Dòng | Nguồn gợi ý | Tóm tắt gợi ý | Mã đã làm sạch |")
            lines.append("|---|---|---|---|---|---|---|---|")

        for f in findings:
            rem = f.get("remediation", {})
            status = rem.get("status", "N/A")
            suggestion = _short_suggestion(rem.get("suggestion", ""))
            snippet = _short_snippet(f.get("sanitized_code", ""))
            loc = f"`{f['file_path']}:{f['line_start']}`"
            if is_verify:
                rescan_st = f"`{f.get('rescan_status', 'N/A')}`"
                lines.append(
                    f"| `{f['finding_id']}` | {f['tool']} | {f['category']} | `{f['rule_id']}` | {loc} | {rescan_st} | `{status}` | {suggestion} | `{snippet}` |"
                )
            else:
                lines.append(
                    f"| `{f['finding_id']}` | {f['tool']} | {f['category']} | `{f['rule_id']}` | {loc} | `{status}` | {suggestion} | `{snippet}` |"
                )

    if is_verify and remaining_findings:
        lines.extend(["", "## 4. Các lỗi chưa vượt qua lần quét lại", ""])
        lines.append("| ID | Quy tắc | Tệp & Dòng | Mô tả |")
        lines.append("|---|---|---|---|")
        for rf in remaining_findings:
            desc = (rf.get("rule_name") or "").replace("|", "\\|")
            lines.append(f"| `{rf['finding_id']}` | `{rf['rule_id']}` | `{rf['file_path']}:{rf['line_start']}` | {desc} |")

    new_after = metrics.get("new_after_findings") or []
    if is_verify and new_after:
        lines.extend(["", "## 5. Cảnh báo mới phát sinh sau khi sửa", ""])
        lines.append("| Quy tắc | Nhóm lỗi | Tệp & Dòng | Mô tả |")
        lines.append("|---|---|---|---|")
        for nf in new_after:
            desc = (nf.get("rule_name") or "").replace("|", "\\|")
            lines.append(f"| `{nf['rule_id']}` | {nf['category']} | `{nf['file_path']}:{nf['line_start']}` | {desc} |")

    with open(out_md, "w", encoding="utf-8") as fp:
        fp.write("\n".join(lines) + "\n")


def aggregate_reports(input_dir: str, out_json: str, out_md: str) -> None:
    """Aggregate multiple per-repo JSON reports into cross-project thesis statistics."""
    pattern = os.path.join(input_dir, "*.json")
    files = sorted(
        p for p in glob.glob(pattern)
        if os.path.basename(p) not in {
            "checkov_before.json",
            "checkov_after.json",
            "gitleaks_before.json",
            "gitleaks_after.json",
            "normalized_remediation_report.json",
            os.path.basename(out_json),
        }
    )

    repos = []
    cat_before: Counter = Counter()
    cat_passed: Counter = Counter()
    rule_counts: Counter = Counter()
    total_before = 0
    total_passed = 0
    verified_before = 0

    for path in files:
        data = _load_json_safe(path)
        if not isinstance(data, dict) or "summary_metrics" not in data:
            continue
        sm = data["summary_metrics"]
        repo_id = sm.get("repo_id", os.path.basename(path))
        repos.append(sm)
        total_before += sm.get("total_before", 0)
        if sm.get("mode") == "verify" and sm.get("passed_rescan_count") is not None:
            verified_before += sm.get("total_before", 0)
            total_passed += sm.get("passed_rescan_count", 0)
        for cat in ALL_CATEGORIES:
            cstat = sm.get("by_category", {}).get(cat, {})
            cat_before[cat] += cstat.get("before", 0)
            if cstat.get("passed") is not None:
                cat_passed[cat] += cstat.get("passed", 0)
        for f in data.get("findings", []):
            rule_counts[(f.get("tool", ""), f.get("rule_id", ""), f.get("category", ""))] += 1

    overall_pass_rate = round((total_passed / verified_before * 100), 2) if verified_before > 0 else None
    agg_payload = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "repo_count": len(repos),
        "total_findings": total_before,
        "verified_findings": verified_before,
        "passed_rescan_count": total_passed if verified_before > 0 else None,
        "overall_rescan_pass_rate_percent": overall_pass_rate,
        "by_category": {
            cat: {
                "count": cat_before[cat],
                "share_percent": round((cat_before[cat] / total_before * 100), 2) if total_before > 0 else 0.0,
                "passed_rescan": cat_passed[cat] if verified_before > 0 else None,
            }
            for cat in ALL_CATEGORIES
        },
        "repos": repos,
    }
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(agg_payload, f, ensure_ascii=False, indent=2)

    lines = [
        "# Thống kê Tổng hợp Nhiều Đồ án Sinh viên (Đã ẩn danh)",
        "",
        f"- **Số lượng đồ án đã quét:** `{len(repos)}`",
        f"- **Tổng số lỗi phát hiện:** `{total_before}`",
        f"- **Tỷ lệ vượt quét lại (trên tập có kiểm chứng):** `{f'{overall_pass_rate}%' if overall_pass_rate is not None else 'N/A'}`",
        "",
        "## 1. Thống kê theo loại lỗi trên toàn bộ tập đồ án",
        "",
        "| Nhóm lỗi | Số lượng | Tỷ lệ (%) |",
        "|---|---:|---:|",
    ]
    for cat in ALL_CATEGORIES:
        cnt = cat_before[cat]
        share = round((cnt / total_before * 100), 2) if total_before > 0 else 0.0
        lines.append(f"| {cat} | {cnt} | {share}% |")

    lines.extend(["", "## 2. Thống kê theo từng đồ án (`repo_id`)", "", "| Repo ID | Chế độ | Số lỗi (Before) | Vượt quét lại | Tỷ lệ vượt |", "|---|---|---:|---:|---:|"])
    for r in repos:
        pr = f"{r['rescan_pass_rate_percent']}%" if r.get("rescan_pass_rate_percent") is not None else "N/A"
        pc = r.get("passed_rescan_count") if r.get("passed_rescan_count") is not None else "-"
        lines.append(f"| `{r['repo_id']}` | `{r.get('mode', 'scan')}` | {r.get('total_before', 0)} | {pc} | {pr} |")

    lines.extend(["", "## 3. Top quy tắc vi phạm phổ biến", "", "| Công cụ | Mã quy tắc | Nhóm lỗi | Số lượt vi phạm |", "|---|---|---|---:|"])
    for (tool, rule_id, cat), cnt in rule_counts.most_common(20):
        lines.append(f"| {tool} | `{rule_id}` | {cat} | {cnt} |")

    with open(out_md, "w", encoding="utf-8") as fp:
        fp.write("\n".join(lines) + "\n")
    print(f"[OK] Da tong hop {len(repos)} do an | Tong loi: {total_before}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="IaC Security Remediation & Verification Pipeline")
    parser.add_argument("--mode", choices=["auto", "scan", "verify", "aggregate"], default="auto")
    parser.add_argument("--repo-id", default="PROJECT_SCAN")
    parser.add_argument("--checkov-before", default="reports/raw/checkov_before.json")
    parser.add_argument("--gitleaks-before", default="reports/raw/gitleaks_before.json")
    parser.add_argument("--prowler-before", default="reports/raw/prowler_before.json")
    parser.add_argument("--checkov-after", default="reports/raw/checkov_after.json")
    parser.add_argument("--gitleaks-after", default="reports/raw/gitleaks_after.json")
    parser.add_argument("--prowler-after", default="reports/raw/prowler_after.json")
    parser.add_argument("--strip-before-prefix", action="append", default=[])
    parser.add_argument("--strip-after-prefix", action="append", default=[])
    parser.add_argument("--llm-provider", choices=["auto", "gemini", "none"], default="auto")
    parser.add_argument("--max-llm-calls", type=int, default=30)
    parser.add_argument("--out-json", default="reports/normalized_remediation_report.json")
    parser.add_argument("--out-md", default="reports/SUMMARY_REPORT.md")
    parser.add_argument("--source-dir", default="", help="Optional source directory for out-of-scope file stats")
    parser.add_argument("--after-dir", default="", help="Optional patched directory for extended verify scanning")
    parser.add_argument("--aggregate-dir", default="reports/repos")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    os.makedirs(os.path.dirname(args.out_json) or ".", exist_ok=True)
    os.makedirs(os.path.dirname(args.out_md) or ".", exist_ok=True)

    if args.mode == "aggregate":
        aggregate_reports(args.aggregate_dir, args.out_json, args.out_md)
        return

    mode = args.mode
    if mode == "auto":
        has_after = (
            has_valid_scan_payload(args.checkov_after)
            or has_valid_scan_payload(args.gitleaks_after)
            or has_valid_scan_payload(args.prowler_after)
        )
        mode = "verify" if has_after else "scan"

    before_findings = normalize_findings(
        args.checkov_before,
        args.gitleaks_before,
        repo_id=args.repo_id,
        strip_prefixes=args.strip_before_prefix,
        prowler_path=args.prowler_before,
    )

    ext_scanned_files = 0
    if args.source_dir and os.path.isdir(args.source_dir):
        seen_ext = {(f["repo_id"], f["file_path"], f["rule_id"], f["line_start"]) for f in before_findings}
        ext_findings, ext_scanned_files = scan_extended_files(args.source_dir, args.repo_id, seen_keys=seen_ext)
        before_findings.extend(ext_findings)

    cache: Dict[Tuple[str, str], Dict[str, str]] = {}
    llm_budget = [args.max_llm_calls] if args.max_llm_calls > 0 else None
    for item in before_findings:
        item["remediation"] = generate_remediation(
            item,
            llm_provider=args.llm_provider,
            cache=cache,
            llm_budget=llm_budget,
        )

    after_findings: Optional[List[Dict[str, Any]]] = None
    if mode == "verify":
        after_findings = normalize_findings(
            args.checkov_after,
            args.gitleaks_after,
            repo_id=args.repo_id,
            strip_prefixes=args.strip_after_prefix,
            prowler_path=args.prowler_after,
        )
        if args.after_dir and os.path.isdir(args.after_dir):
            seen_after = {(f["repo_id"], f["file_path"], f["rule_id"], f["line_start"]) for f in after_findings}
            ext_after, _ = scan_extended_files(args.after_dir, args.repo_id, seen_keys=seen_after)
            after_findings.extend(ext_after)

    metrics, remaining_findings = verify_rescan(before_findings, after_findings, repo_id=args.repo_id)
    metrics["tool_metadata"] = collect_tool_metadata(args.checkov_before, llm_provider=args.llm_provider)
    metrics["scan_scope"] = summarize_scan_scope(
        args.checkov_before,
        source_dir=args.source_dir or None,
        extended_files_scanned=ext_scanned_files,
    )

    payload = {
        "summary_metrics": metrics,
        "findings": before_findings,
    }
    with open(args.out_json, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)

    export_markdown_summary(before_findings, metrics, remaining_findings, args.out_md)

    total = len(before_findings)
    has_any_scope = metrics["scan_scope"]["has_any_scope"]
    iac_files = metrics["scan_scope"]["iac_files_scanned"]
    ext_files = metrics["scan_scope"]["extended_files_scanned"]
    passed_checks = metrics["scan_scope"]["passed_checks"]
    out_of_scope = metrics["scan_scope"]["out_of_scope_files"]
    print("----------------------------------------------------------------------------")
    if total == 0 and not has_any_scope:
        print(f"[KET QUA] [{args.repo_id}] NGOAI PHAM VI QUET (0 tep ho tro; {out_of_scope if out_of_scope is not None else '?'} tep khac)")
    elif total == 0:
        print(f"[KET QUA] [{args.repo_id}] KHONG PHAT HIEN LOI (0 loi | {iac_files} tep IaC [{passed_checks} dat], {ext_files} tep ma nguon/cau hinh)")
    else:
        print(f"[KET QUA] [{args.repo_id}] PHAT HIEN {total} LOI BAO MAT ({iac_files} tep IaC, {ext_files} tep ma nguon/cau hinh)")
        for cat in ALL_CATEGORIES:
            cnt = metrics["by_category"].get(cat, {}).get("before", 0)
            print(f"  - {cat}: {cnt} loi")
    if mode == "verify":
        print(
            f"[KIEM CHUNG] Vuot quet lai: {metrics['passed_rescan_count']}/{total} "
            f"({metrics['rescan_pass_rate_percent']}%) | Canh bao moi: {metrics.get('new_after_count', 0)}"
        )
    print("----------------------------------------------------------------------------")


if __name__ == "__main__":
    main()

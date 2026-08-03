#!/usr/bin/env python3
"""Check HTML/JS file(s) for 4 common client-side security issues:
hardcoded secrets, innerHTML XSS, sensitive console.log, http:// external requests.

Usage: check_security.py <file1.html|file1.js> [file2 ...]
Prints a JSON array (one object per file) to stdout.
"""
import json
import re
import sys
from pathlib import Path

# ---- 1) hardcoded password / API key -------------------------------------

SECRET_VAR_RE = re.compile(
    r"""\b(?P<varname>password|passwd|pwd|api[_-]?key|apikey|secret(?:[_-]?key)?|
        access[_-]?key|auth[_-]?token|token|client[_-]?secret)\b
        \s*[:=]\s*
        [\'"`](?P<value>[^\'"`]{4,})[\'"`]""",
    re.IGNORECASE | re.VERBOSE,
)

PLACEHOLDER_RE = re.compile(
    r"^(your|xxx+|changeme|change_me|example|test|placeholder|todo|dummy|fake|sample|\$\{|\{\{|<.*>$)",
    re.IGNORECASE,
)

KNOWN_KEY_PATTERNS = [
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS Access Key"),
    (re.compile(r"sk-[A-Za-z0-9]{20,}"), "OpenAI 형식 Secret Key"),
    (re.compile(r"ghp_[A-Za-z0-9]{36}"), "GitHub Personal Access Token"),
    (re.compile(r"AIza[0-9A-Za-z_\-]{35}"), "Google API Key"),
    (re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}"), "Slack Token"),
]


def check_hardcoded_secrets(lines: list[str]) -> dict:
    items = []
    for i, line in enumerate(lines, start=1):
        for pattern, label in KNOWN_KEY_PATTERNS:
            m = pattern.search(line)
            if m:
                items.append({"line": i, "kind": label, "snippet": line.strip()[:160]})

        for m in SECRET_VAR_RE.finditer(line):
            value = m.group("value")
            if PLACEHOLDER_RE.match(value.strip()):
                continue
            items.append({
                "line": i,
                "kind": m.group("varname"),
                "snippet": line.strip()[:160],
            })
    return {"status": "fail" if items else "pass", "severity": "critical" if items else None, "items": items}


# ---- 2) innerHTML without escaping (XSS) ----------------------------------

INNERHTML_RE = re.compile(r"\.innerHTML\s*\+?=\s*(?P<rhs>.+?);?\s*(?://.*)?$")
SAFE_STATIC_RE = re.compile(r"""^(['"`])(?:(?!\1).)*\1$""")
ESCAPE_HINT_RE = re.compile(r"\b(sanitize|escapeHtml|escape_html|DOMPurify)\b", re.IGNORECASE)


def check_xss_innerhtml(lines: list[str]) -> dict:
    items = []
    for i, line in enumerate(lines, start=1):
        m = INNERHTML_RE.search(line)
        if not m:
            continue
        rhs = m.group("rhs").strip()
        if SAFE_STATIC_RE.match(rhs) and "${" not in rhs:
            continue
        if ESCAPE_HINT_RE.search(rhs):
            continue
        items.append({"line": i, "snippet": line.strip()[:160]})
    return {"status": "fail" if items else "pass", "severity": "critical" if items else None, "items": items}


# ---- 3) sensitive info in console.log -------------------------------------

CONSOLE_LOG_RE = re.compile(r"console\.log\s*\(([^)]*)\)")
SENSITIVE_ARG_RE = re.compile(
    r"\b(password|passwd|pwd|token|secret|apikey|api[_-]?key|credential|auth|"
    r"session[_-]?id|ssn|card[_-]?number|access[_-]?key)\b",
    re.IGNORECASE,
)


def check_console_log_sensitive(lines: list[str]) -> dict:
    items = []
    for i, line in enumerate(lines, start=1):
        for m in CONSOLE_LOG_RE.finditer(line):
            args = m.group(1)
            hit = SENSITIVE_ARG_RE.search(args)
            if hit:
                items.append({"line": i, "kind": hit.group(1), "snippet": line.strip()[:160]})
    return {"status": "fail" if items else "pass", "severity": "warning" if items else None, "items": items}


# ---- 4) http:// (non-TLS) external request --------------------------------

HTTP_RE = re.compile(r"""(?P<quote>['"`])http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0)(?P<rest>[^'"`\s]*)(?P=quote)""")
REQUEST_CONTEXT_RE = re.compile(
    r"fetch\s*\(|XMLHttpRequest|\.open\s*\(|axios|WebSocket|importScripts|EventSource",
    re.IGNORECASE,
)


def check_http_external(lines: list[str]) -> dict:
    items = []
    for i, line in enumerate(lines, start=1):
        for m in HTTP_RE.finditer(line):
            url = "http://" + m.group("rest")
            severity = "warning" if REQUEST_CONTEXT_RE.search(line) else "suggestion"
            items.append({"line": i, "url": url, "severity": severity, "snippet": line.strip()[:160]})
    has_warning = any(it["severity"] == "warning" for it in items)
    status = "fail" if items else "pass"
    overall_severity = "warning" if has_warning else ("suggestion" if items else None)
    return {"status": status, "severity": overall_severity, "items": items}


def check_file(path: Path) -> dict:
    text = path.read_bytes().decode("utf-8", errors="replace")
    lines = text.splitlines()
    return {
        "file": str(path),
        "checks": {
            "hardcoded_secrets": check_hardcoded_secrets(lines),
            "xss_innerhtml": check_xss_innerhtml(lines),
            "console_log_sensitive": check_console_log_sensitive(lines),
            "http_external": check_http_external(lines),
        },
    }


def main():
    # Windows terminals often default stdout to a non-UTF-8 codepage (e.g. cp949),
    # which would mangle the Korean text this tool emits.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    if len(sys.argv) < 2:
        print("Usage: check_security.py <file1.html|file1.js> [file2 ...]", file=sys.stderr)
        sys.exit(1)
    results = [check_file(Path(p)) for p in sys.argv[1:]]
    print(json.dumps(results, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()

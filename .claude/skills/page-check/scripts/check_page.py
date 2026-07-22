#!/usr/bin/env python3
"""Check HTML file(s) for title, broken internal links, image alt, viewport meta, UTF-8 encoding.

Usage: check_page.py <file1.html> [file2.html ...]
Prints a JSON array (one object per file) to stdout.
"""
import json
import re
import sys
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlparse

EXTERNAL_SCHEMES = {"http", "https", "mailto", "tel", "javascript", "data"}
MEANINGLESS_ALT = {"image", "img", "photo", "picture", "pic", "icon", "banner", "untitled"}


def is_external_or_special(url: str) -> bool:
    if not url or url.startswith("#"):
        return True
    if url.startswith("//"):
        return True
    parsed = urlparse(url)
    return bool(parsed.scheme) and parsed.scheme.lower() in EXTERNAL_SCHEMES


class PageParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.title_text = []
        self.title_line = None
        self.in_title = False
        self.has_title_tag = False
        self.links = []            # (url, line, tag)
        self.imgs = []             # (src, alt_present, alt_value, line)
        self.viewport_meta = None  # (content, line)
        self.charset_meta = None   # (charset, line)

    def handle_starttag(self, tag, attrs):
        line = self.getpos()[0]
        attrs_dict = dict(attrs)

        if tag == "title":
            self.has_title_tag = True
            self.in_title = True
            self.title_line = line

        elif tag in ("a", "link", "script", "source", "iframe"):
            url_attr = "href" if tag in ("a", "link") else "src"
            url = attrs_dict.get(url_attr)
            if url:
                self.links.append((url, line, tag))

        if tag == "img":
            src = attrs_dict.get("src")
            alt_present = "alt" in attrs_dict
            alt_value = attrs_dict.get("alt")
            self.imgs.append((src, alt_present, alt_value, line))
            if src:
                self.links.append((src, line, "img"))

        if tag == "meta":
            name = (attrs_dict.get("name") or "").lower()
            if name == "viewport":
                self.viewport_meta = (attrs_dict.get("content", ""), line)

            charset = attrs_dict.get("charset")
            if charset:
                self.charset_meta = (charset, line)

            http_equiv = (attrs_dict.get("http-equiv") or "").lower()
            if http_equiv == "content-type":
                content = attrs_dict.get("content", "")
                m = re.search(r"charset=([\w-]+)", content, re.I)
                if m:
                    self.charset_meta = (m.group(1), line)

    def handle_endtag(self, tag):
        if tag == "title":
            self.in_title = False

    def handle_data(self, data):
        if self.in_title:
            self.title_text.append(data)


def check_title(parser: PageParser) -> dict:
    text = "".join(parser.title_text).strip()
    if not parser.has_title_tag:
        return {"status": "fail", "severity": "critical", "issue": "missing"}
    if not text:
        return {"status": "fail", "severity": "critical", "issue": "empty", "line": parser.title_line}
    if len(text) < 2:
        return {"status": "warn", "severity": "suggestion", "issue": "too_short", "value": text, "line": parser.title_line}
    return {"status": "pass", "value": text, "line": parser.title_line}


def check_broken_links(parser: PageParser, base_dir: Path) -> dict:
    items = []
    seen = set()
    for url, line, tag in parser.links:
        if is_external_or_special(url):
            continue
        path_part = url.split("#")[0].split("?")[0]
        if not path_part:
            continue
        key = (path_part, line)
        if key in seen:
            continue
        seen.add(key)

        # a leading "/" is treated as relative to the HTML file's own directory
        # (site root), since there is no way to know the real deploy root here.
        clean = path_part.lstrip("/") if path_part.startswith("/") else path_part
        resolved = (base_dir / clean).resolve()
        if not resolved.exists():
            items.append({"url": url, "line": line, "tag": tag, "resolved": str(resolved)})
    return {"status": "fail" if items else "pass", "severity": "critical" if items else None, "items": items}


def check_img_alt(parser: PageParser) -> dict:
    missing = []
    meaningless = []
    for src, alt_present, alt_value, line in parser.imgs:
        if not alt_present:
            missing.append({"src": src, "line": line})
            continue
        norm = (alt_value or "").strip().lower()
        stem = Path(src).stem.lower() if src else ""
        if norm and (norm in MEANINGLESS_ALT or (stem and norm == stem)):
            meaningless.append({"src": src, "line": line, "alt": alt_value})
    status = "fail" if missing else ("warn" if meaningless else "pass")
    return {"status": status, "missing": missing, "meaningless": meaningless}


def check_viewport(parser: PageParser) -> dict:
    if not parser.viewport_meta:
        return {"status": "fail", "severity": "warning", "issue": "missing"}
    content, line = parser.viewport_meta
    if "width=device-width" not in content.replace(" ", "").lower():
        return {"status": "warn", "severity": "suggestion", "issue": "non_standard", "content": content, "line": line}
    return {"status": "pass", "content": content, "line": line}


def check_encoding(raw_bytes: bytes, parser: PageParser) -> dict:
    try:
        raw_bytes.decode("utf-8")
        decodable = True
    except UnicodeDecodeError:
        decodable = False

    text_sample = raw_bytes.decode("utf-8", errors="ignore")
    has_korean = bool(re.search(r"[가-힣]", text_sample))

    if not parser.charset_meta:
        severity = "critical" if has_korean else "warning"
        return {"status": "fail", "severity": severity, "issue": "missing", "decodable_as_utf8": decodable, "has_korean": has_korean}

    charset, line = parser.charset_meta
    if charset.strip().lower() not in ("utf-8", "utf8"):
        return {"status": "fail", "severity": "critical", "issue": "wrong_charset", "declared": charset, "line": line}

    if not decodable:
        return {"status": "fail", "severity": "critical", "issue": "declared_but_not_actual_utf8", "declared": charset, "line": line}

    idx = raw_bytes.lower().find(b"charset")
    if 0 <= idx > 1024:
        return {"status": "warn", "severity": "suggestion", "issue": "position", "declared": charset, "line": line}

    return {"status": "pass", "declared": charset, "line": line}


def check_file(path: Path) -> dict:
    raw_bytes = path.read_bytes()
    text = raw_bytes.decode("utf-8", errors="replace")
    parser = PageParser()
    parser.feed(text)

    return {
        "file": str(path),
        "checks": {
            "title": check_title(parser),
            "broken_links": check_broken_links(parser, path.parent),
            "img_alt": check_img_alt(parser),
            "viewport": check_viewport(parser),
            "encoding": check_encoding(raw_bytes, parser),
        },
    }


def main():
    # Windows terminals often default stdout to a non-UTF-8 codepage (e.g. cp949),
    # which would mangle the very Korean text this tool is supposed to check.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    if len(sys.argv) < 2:
        print("Usage: check_page.py <file1.html> [file2.html ...]", file=sys.stderr)
        sys.exit(1)
    results = [check_file(Path(p)) for p in sys.argv[1:]]
    print(json.dumps(results, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()

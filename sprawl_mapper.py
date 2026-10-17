#!/usr/bin/env python3
"""api-key-sprawl-mapper.

Maps API key sprawl across your repos.

Scans files for API key patterns from a built-in per-service pattern
table, then groups findings by distinct key. For each key it records a
SHA-256 fingerprint of the key material - the full key is NEVER printed.
Output shows only: service + redacted display (prefix...***) + the files
it appears in + occurrence count.

Report:
  SPRAWL    - a key found in 2+ files: rotation priority, ranked by spread.
  CONTAINED - a key found in exactly 1 file.

`--fail-on-sprawl` exits 1 when any sprawl is found, so it can gate CI.

Stdlib only.
"""

import argparse
import hashlib
import os
import re
import sys

# (service name, regex, group index holding the key material)
PATTERNS = [
    ("Stripe",
     re.compile(r'\b(?:sk_live|rk_live)_[0-9a-zA-Z]{24,}\b'), 0),
    ("AWS",
     re.compile(r'\bAKIA[0-9A-Z]{16}\b'), 0),
    ("GitHub",
     re.compile(r'\b(?:ghp|gho)_[0-9a-zA-Z]{36}\b'), 0),
    ("GitHub",
     re.compile(r'\bgithub_pat_[0-9a-zA-Z_]{22,}\b'), 0),
    ("Slack",
     re.compile(r'\bxox[baprs]-[0-9a-zA-Z-]{10,}\b'), 0),
    ("OpenAI",
     re.compile(r'\bsk-(?:proj-)?[0-9a-zA-Z]{20,}\b'), 0),
    ("SendGrid",
     re.compile(r'\bSG\.[0-9a-zA-Z_\-]{22,}\b'), 0),
    ("Twilio",
     re.compile(r'\b(?:SK|AC)[0-9a-f]{32}\b'), 0),
    ("Mailgun",
     re.compile(r'\bkey-[0-9a-f]{32}\b'), 0),
    ("Google",
     re.compile(r'\bAIza[0-9A-Za-z_\-]{35}\b'), 0),
    ("DigitalOcean",
     re.compile(r'\bdop_v1_[0-9a-f]{64}\b'), 0),
    ("Generic",
     re.compile(r'(?i)\b(?:api[_-]?key|secret[_-]?key|access[_-]?token)'
                r'\s*[:=]\s*["\']([^"\']{16,})["\']'), 1),
]

SKIP_DIRS = {
    ".git", "node_modules", ".venv", "venv", "__pycache__",
    "dist", "build", ".tox", "site-packages", ".idea",
    ".vscode", ".mypy_cache", ".pytest_cache", "vendor",
}

# Extensions never scanned (binaries, images, archives, lockfiles full of hashes).
SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".ico", ".svg",
    ".pdf", ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar",
    ".exe", ".dll", ".so", ".dylib", ".o", ".a", ".class", ".pyc",
    ".mp3", ".mp4", ".mov", ".avi", ".wav", ".woff", ".woff2", ".ttf",
}

DISPLAY_PREFIX_LEN = 8


def iter_files(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            _, ext = os.path.splitext(name.lower())
            if ext not in SKIP_EXTENSIONS:
                yield os.path.join(dirpath, name)


def read_text_safely(path):
    try:
        with open(path, "r", encoding="utf-8", errors="strict") as fh:
            return fh.read()
    except (OSError, UnicodeDecodeError):
        return None


def fingerprint(key):
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def redact(key):
    """Redacted display: first 8 chars + '...***'. Never the full key."""
    prefix = key[:DISPLAY_PREFIX_LEN] if len(key) > DISPLAY_PREFIX_LEN else key[:4]
    return f"{prefix}...***"


def scan(root):
    """Return {key_material: {'service', 'fingerprint', 'files': {path: count}}}."""
    keys = {}
    for path in iter_files(root):
        text = read_text_safely(path)
        if text is None:
            continue
        claimed = []  # (start, end) spans already counted in this file
        for service, pattern, group in PATTERNS:
            for match in pattern.finditer(text):
                start, end = match.span(group)
                if any(start < cs_end and end > cs_start for cs_start, cs_end in claimed):
                    continue  # same physical occurrence, already counted
                claimed.append((start, end))
                key = match.group(group)
                entry = keys.setdefault(key, {
                    "service": service,
                    "fingerprint": fingerprint(key),
                    "files": {},
                })
                # First pattern wins the service label for a key.
                entry["files"][path] = entry["files"].get(path, 0) + 1
    return keys


def build_report(keys, root):
    sprawl, contained = [], []
    for key, entry in keys.items():
        item = {
            "service": entry["service"],
            "display": redact(key),
            "fingerprint": entry["fingerprint"],
            "files": sorted(os.path.relpath(p, root) for p in entry["files"]),
            "file_count": len(entry["files"]),
            "occurrences": sum(entry["files"].values()),
        }
        if len(entry["files"]) >= 2:
            sprawl.append(item)
        else:
            contained.append(item)
    sprawl.sort(key=lambda i: (-i["file_count"], -i["occurrences"]))
    contained.sort(key=lambda i: (i["service"], i["display"]))
    return sprawl, contained


def report_text(sprawl, contained, total_keys):
    lines = ["api-key-sprawl-mapper report",
             f"distinct keys found: {total_keys}", ""]
    if sprawl:
        lines.append(f"SPRAWL ({len(sprawl)}) - same key in 2+ files, rotate first:")
        for i, item in enumerate(sprawl, 1):
            lines.append(f"  {i}. [{item['service']}] {item['display']} "
                         f"sha256:{item['fingerprint'][:16]}... "
                         f"({item['file_count']} files, {item['occurrences']} occurrences)")
            for f in item["files"]:
                lines.append(f"       - {f}")
        lines.append("")
    if contained:
        lines.append(f"CONTAINED ({len(contained)}) - single file each:")
        for item in contained:
            lines.append(f"  - [{item['service']}] {item['display']} "
                         f"sha256:{item['fingerprint'][:16]}... -> {item['files'][0]}")
        lines.append("")
    if not sprawl and not contained:
        lines.append("clean - no API keys detected.")
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Map API key sprawl across your repos. "
                    "Full key material is never printed.")
    parser.add_argument("path", help="directory to scan")
    parser.add_argument("--fail-on-sprawl", action="store_true",
                        help="exit 1 when any key is found in 2+ files")
    args = parser.parse_args(argv)

    root = os.path.abspath(args.path)
    if not os.path.isdir(root):
        print(f"error: not a directory: {root}", file=sys.stderr)
        return 2

    keys = scan(root)
    sprawl, contained = build_report(keys, root)
    print(report_text(sprawl, contained, len(keys)))

    if args.fail_on_sprawl and sprawl:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

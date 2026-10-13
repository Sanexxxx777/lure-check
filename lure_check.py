#!/usr/bin/env python3
"""Spot GitHub repos that are malware bait: obfuscated install commands in the
README, or a throwaway owner account with no code in the repo.

Two independent signals, both measured on 321 trending repos: a README with an
OBFUSCATED install command, and a throwaway owner account with no code in the
repo. Plain `curl|wget URL | sh`, `irm URL | iex` and `iex (irm https://literal-url)`
are deliberately NOT flagged: 38 of 314 legit repos use them, flagging would
drown the result in false positives.

The owner signal is the gap between account creation and repo creation, not the
account's age now: a real lure's owner was already 34 days old when the repo
was listed on a trending page, so an "account younger than N days" rule would
have missed it.

    python3 lure_check.py owner/repo [owner/repo ...]     # live check via the GitHub API
    python3 lure_check.py --readme path/to/README.md      # offline: README rule only
    python3 lure_check.py --json owner/repo               # one JSON object per repo

Exit code: 1 if any repo is a LURE, else 2 if any could not be checked (repo
404, rate limit, network), else 0. Set GITHUB_TOKEN to raise the API rate limit
(60 requests/hour unauthenticated); the token is only sent to api.github.com
and is never printed.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import unicodedata
import urllib.request
from datetime import datetime, timedelta
from pathlib import Path

OWNER_GAP_DAYS = 30
TINY_REPO_KB = 10
TIMEOUT_S = 10
API = "https://api.github.com"

_ZERO_WIDTH_RE = re.compile("[​-‏⁠﻿]")  # escaped: no invisible chars in source

_REV_RE = re.compile(r"-join\b[^\n]{0,200}?\[\s*-1\s*\.\.", re.I)
_IEX_IRM_RE = re.compile(
    r"\b(?:iex|invoke-expression)\s*\(\s*(?:irm|iwr|invoke-restmethod|invoke-webrequest)\s*\(", re.I)
_B64_RES = [
    re.compile(r"base64\s+(?:-d|--decode|-D)\b[^\n]*\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b", re.I),
    re.compile(r"FromBase64String[^\n]*\b(?:iex|invoke-expression)\b", re.I),
    re.compile(r"\b(?:iex|invoke-expression)\b[^\n]*FromBase64String", re.I),
    re.compile(r"powershell(?:\.exe)?\b[^\n]*\s-e(?:nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{40,}", re.I),
    re.compile(r"exec\s*\(\s*(?:base64\.)?b64decode", re.I),
]
_HIDDEN_RES = [
    re.compile(r"-w(?:indowstyle)?\s+hid(?:den)?\b", re.I),
    re.compile(r"\bmshta(?:\.exe)?\s+\S", re.I),
    re.compile(r"\bcertutil(?:\.exe)?\s+[-/](?:decode|urlcache)\b", re.I),
    re.compile(r"\bbitsadmin(?:\.exe)?\s+/transfer\b", re.I),
]

_CODELESS_FILE_RE = re.compile(r"^(?:(?:readme|license|licence)(?:\.[a-z0-9]+)?|\.git(?:attributes|ignore))$", re.I)
_REPO_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


# --- the rules (no network) -------------------------------------------------

def _normalize(raw: str) -> str:
    """Undo cheap obfuscation: look-alike chars, zero-width chars, PowerShell
    backtick escapes (i`e`x) — and markdown code-span backticks along the way."""
    text = unicodedata.normalize("NFKC", raw)
    text = _ZERO_WIDTH_RE.sub("", text)
    return text.replace("`", "")


def readme_reason(raw: str) -> str | None:
    """Scans the RAW README (HTML/links stripped would hide the command)."""
    text = _normalize(raw)
    if _REV_RE.search(text):
        return "reversed-string URL in the install command"
    if _IEX_IRM_RE.search(text):
        return "iex(irm(...)) with a computed URL"
    if any(r.search(text) for r in _B64_RES):
        return "base64 blob decoded and executed"
    if any(r.search(text) for r in _HIDDEN_RES):
        return "hidden launch via a Windows system tool"
    return None


def _parse_dt(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))  # 3.10 rejects a bare 'Z'


def _gap(repo_created_at: str, owner_created_at: str) -> timedelta:
    return _parse_dt(repo_created_at) - _parse_dt(owner_created_at)


def _human_gap(gap: timedelta) -> str:
    secs = max(gap.total_seconds(), 0)
    if secs < 3600:
        return f"{int(secs // 60)} min"
    if secs < 48 * 3600:
        return f"{int(secs // 3600)} h"
    return f"{int(secs // 86400)} days"


def _codeless(size_kb: int | None, top_level: list | None) -> bool:
    if size_kb is not None and size_kb <= TINY_REPO_KB:
        return True
    # None / [] = unknown (failed request): never hide a legit repo on that.
    if not top_level:
        return False
    return all(t == "file" and _CODELESS_FILE_RE.match(n) for t, n in top_level)


def owner_reason(repo_created_at: str, owner_created_at: str,
                 size_kb: int | None, top_level: list | None) -> str | None:
    """Throwaway account + no code. The signal is the gap between account and
    repo creation, not the account's age now: the real lure's owner was already
    34 days old when it was listed."""
    gap = _gap(repo_created_at, owner_created_at)
    if gap >= timedelta(days=OWNER_GAP_DAYS):
        return None
    if _codeless(size_kb, top_level):
        return f"owner account created {_human_gap(gap)} before the repo, and the repo has no code"
    return None


def lure_reason(meta: dict, raw_readme: str, owner_created_at_fn, top_level_fn) -> str | None:
    """README first (no API calls spent), then the owner check; the contents
    request is made only when the repo is young AND not already known tiny."""
    reason = readme_reason(raw_readme)
    if reason:
        return reason
    login, repo_created = meta.get("owner_login"), meta.get("repo_created_at")
    if not login or not repo_created:
        return None
    owner_created = owner_created_at_fn(login)
    if not owner_created:
        return None
    if _gap(repo_created, owner_created) >= timedelta(days=OWNER_GAP_DAYS):
        return None
    size_kb = meta.get("repo_size_kb")
    top_level = top_level_fn() if (size_kb is None or size_kb > TINY_REPO_KB) else None
    return owner_reason(repo_created, owner_created, size_kb, top_level)


# --- GitHub client (stdlib) -------------------------------------------------

def _headers(accept: str | None = None) -> dict:
    headers = {"User-Agent": "lure-check"}
    if accept:
        headers["Accept"] = accept
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _http_get(url: str, accept: str | None = None) -> tuple[int, dict, str]:
    """One GET -> (status, lower-cased headers, body text). HTTP error statuses
    are returned, not raised; network failures raise OSError (URLError is one)."""
    import urllib.error

    req = urllib.request.Request(url, headers=_headers(accept))
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_S) as resp:
            status, hdrs, body = resp.status, resp.headers, resp.read()
    except urllib.error.HTTPError as e:
        status, hdrs, body = e.code, e.headers, b""
    headers = {k.lower(): v for k, v in (hdrs.items() if hdrs else [])}
    return status, headers, body.decode("utf-8", errors="replace")


class GitHub:
    """Neutral-on-failure fetchers: every method returns its empty value ('' /
    {} / None) when a request fails, and records WHY in `failure` /
    `rate_limited` / `not_found` / `notes` so the CLI can say "could not check"
    instead of reading a failed request as "clean". Call reset() per repo."""

    def __init__(self) -> None:
        self.reset()

    def reset(self) -> None:
        self.failure: str | None = None   # why the last repo-level request failed
        self.rate_limited = False
        self.not_found = False
        self.notes: list[str] = []        # checks skipped for this repo

    def _get(self, path: str, accept: str | None = None) -> str | None:
        """Body on HTTP 200, else None with the reason recorded."""
        try:
            status, headers, body = _http_get(API + path, accept)
        except (OSError, ValueError) as e:
            self.failure = f"network error: {e}"
            return None
        if status in (403, 429) and headers.get("x-ratelimit-remaining") == "0":
            self.rate_limited = True
            self.failure = "GitHub rate limit hit (set GITHUB_TOKEN for a higher limit)"
            return None
        if status == 404:
            self.not_found = True
            self.failure = "not found"
            return None
        if status != 200:
            self.failure = f"HTTP {status}"
            return None
        return body

    def repo_meta(self, full_name: str) -> dict:
        body = self._get(f"/repos/{full_name}")
        if body is None:
            return {}
        try:
            data = json.loads(body)
            owner = data.get("owner")
            return {
                "repo_size_kb": data.get("size"),
                "repo_created_at": data.get("created_at"),
                "owner_login": owner.get("login") if isinstance(owner, dict) else None,
            }
        except (ValueError, AttributeError):
            self.failure = "unexpected response from GitHub"
            return {}

    def readme_raw(self, full_name: str) -> str:
        body = self._get(f"/repos/{full_name}/readme", accept="application/vnd.github.raw+json")
        return body if body is not None else ""

    def owner_created_at(self, login: str) -> str | None:
        body = self._get(f"/users/{login}")
        if body is None:
            self.notes.append("owner lookup failed")
            return None
        try:
            created = json.loads(body).get("created_at")
        except (ValueError, AttributeError):
            created = None
        if not isinstance(created, str):
            self.notes.append("owner lookup failed")
            return None
        return created

    def top_level_entries(self, full_name: str) -> list[tuple[str, str]] | None:
        body = self._get(f"/repos/{full_name}/contents/")
        if body is not None:
            try:
                data = json.loads(body)
            except ValueError:
                data = None
            if isinstance(data, list):
                return [(str(e.get("type")), str(e.get("name"))) for e in data if isinstance(e, dict)]
        self.notes.append("contents unavailable")
        return None


# --- CLI --------------------------------------------------------------------

def check_repo(gh: GitHub, full_name: str) -> dict:
    """-> {repo, verdict: lure|ok|unknown, reason, partial: [notes]}."""
    out = {"repo": full_name, "verdict": "unknown", "reason": None, "partial": []}
    if not _REPO_NAME_RE.match(full_name):
        out["reason"] = "not an owner/repo name"
        return out
    gh.reset()
    meta = gh.repo_meta(full_name)
    if not meta:
        if gh.not_found:
            out["reason"] = "repo not found (deleted or private)"
        else:
            out["reason"] = gh.failure or "no data from GitHub"
        return out
    raw = gh.readme_raw(full_name)
    no_readme = raw == "" and not gh.rate_limited
    reason = lure_reason(meta, raw, gh.owner_created_at, lambda: gh.top_level_entries(full_name))
    if reason:  # a positive stands even if a later request failed
        out["verdict"], out["reason"] = "lure", reason
        return out
    if gh.rate_limited:
        out["reason"] = gh.failure
        return out
    out["verdict"] = "ok"
    if no_readme:
        out["partial"].append("no README")
    out["partial"].extend(gh.notes)
    return out


def _format(res: dict) -> str:
    repo, verdict = res["repo"], res["verdict"]
    if verdict == "lure":
        return f"LURE  {repo}  {res['reason']}"
    if verdict == "unknown":
        return f"??    {repo}  could not check: {res['reason']}"
    suffix = f"  (partial: {', '.join(res['partial'])})" if res["partial"] else ""
    return f"ok    {repo}{suffix}"


def check_readme_file(path: str) -> dict:
    out = {"repo": path, "verdict": "unknown", "reason": None, "partial": []}
    try:
        raw = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        out["reason"] = f"cannot read file: {e.strerror or e}"
        return out
    reason = readme_reason(raw)
    out["verdict"], out["reason"] = ("lure", reason) if reason else ("ok", None)
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Flag GitHub repos that look like malware bait.")
    ap.add_argument("repos", nargs="*", metavar="owner/repo", help="repos to check via the GitHub API")
    ap.add_argument("--readme", metavar="PATH", help="offline: apply the README rule to a local file")
    ap.add_argument("--json", action="store_true", help="one JSON object per line: {repo, verdict, reason, partial}")
    args = ap.parse_args(argv)
    if bool(args.readme) == bool(args.repos):
        ap.error("give owner/repo arguments, or --readme PATH (not both)")

    if args.readme:
        results = [check_readme_file(args.readme)]
    else:
        gh = GitHub()
        results = [check_repo(gh, r) for r in args.repos]

    for res in results:
        print(json.dumps(res, ensure_ascii=False) if args.json else _format(res))
    verdicts = {r["verdict"] for r in results}
    return 1 if "lure" in verdicts else 2 if "unknown" in verdicts else 0


if __name__ == "__main__":
    sys.exit(main())

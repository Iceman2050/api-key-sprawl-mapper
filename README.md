# api-key-sprawl-mapper

Your Stripe secret is in `config.py`, `webhooks.py`, *and* that deploy script from 2023. When it leaks, you won't rotate one key — you'll hunt through every repo wondering where else it was pasted.

This is a zero-dependency CLI that scans your repos for API keys across 11 services, groups them by distinct key, and reports **SPRAWL** (same key in 2+ files — rotation priority, ranked by spread) vs **CONTAINED** (single file). Full key material is **never printed**: output shows service + redacted `prefix...***` + a SHA-256 fingerprint + file list. `--fail-on-sprawl` exits 1, so it gates CI.

## Quickstart (30 seconds)

```bash
python3 sprawl_mapper.py ./your-repo --fail-on-sprawl
```

No installs, no dependencies — Python 3.9+ stdlib only.

## Example output

Real output from a real run against a demo tree (exit code was `1` because sprawl was found):

```
api-key-sprawl-mapper report
distinct keys found: 2

SPRAWL (1) - same key in 2+ files, rotate first:
  1. [Stripe] sk_live_...*** sha256:78a08441f4314f0a... (3 files, 3 occurrences)
       - api/billing.py
       - api/webhooks.py
       - scripts/deploy.sh

CONTAINED (1) - single file each:
  - [GitHub] ghp_abc1...*** sha256:06bd03cfe97cdfad... -> ci.yml
```

Note: only the first 8 characters of each key are shown. The full key never appears in output, logs, or reports.

## Detected services (11)

Stripe (`sk_live_`/`rk_live_`), AWS (`AKIA…`), GitHub (`ghp_`/`gho_`/`github_pat_`), Slack (`xox[baprs]-`), OpenAI (`sk-`/`sk-proj-`), SendGrid (`SG.`), Twilio (`SK`/`AC`), Mailgun (`key-`), Google (`AIza`), DigitalOcean (`dop_v1_`), plus a generic `api_key`/`secret_key`/`access_token` assignment catcher.

## What it does NOT do

- It does **not** verify keys against live APIs. A match is a *shape* match — test keys and examples will be flagged too. That's intentional: even a test key in 3 files is sprawl worth knowing about.
- It does **not** detect keys split across lines, built by concatenation, or fetched from vaults/secret managers at runtime. Static text scan only.
- It does **not** revoke or rotate anything. It tells you *what* to rotate, in *what order*.
- It is **not** a replacement for secret scanning on push (e.g. GitHub secret scanning / push protection). Run this *before* things get committed.
- Fingerprints are SHA-256 of the key string — useful for matching the same key across reports, not a substitute for a proper secret inventory.

## Tests

```bash
python -m unittest discover -s tests -v   # 10 tests, all green
```

Tests build a real fixture tree (same Stripe key in 3 files, one GitHub token in 1 file, one clean file) and assert exact sprawl counts, redacted display, and that no raw key material appears in output.

## License

MIT — see [LICENSE](LICENSE).

## Built by Ingenious AI

This tool is part of the Ingenious AI security platform suite:

- [DisclosureGuard](https://wa.me/5016691053?text=Hi%20Ingenious%20AI%21%20I%20want%20early%20access%20to%20DisclosureGuard.)
- [ModelMinder](https://wa.me/5016691053?text=Hi%20Ingenious%20AI%21%20I%20want%20early%20access%20to%20ModelMinder.)
- [TermsWatch](https://wa.me/5016691053?text=Hi%20Ingenious%20AI%21%20I%20want%20early%20access%20to%20TermsWatch.)
- [Vibe-Code Audit](https://wa.me/5016691053?text=Hi%20Ingenious%20AI%21%20I%20want%20early%20access%20to%20Vibe-Code%20Audit.)
- [Rogue-Agent Defense](https://wa.me/5016691053?text=Hi%20Ingenious%20AI%21%20I%20want%20early%20access%20to%20Rogue-Agent%20Defense.)
- [BreachHunter](https://wa.me/5016691053?text=Hi%20Ingenious%20AI%21%20I%20want%20early%20access%20to%20BreachHunter.)
- [ChatBreaker](https://wa.me/5016691053?text=Hi%20Ingenious%20AI%21%20I%20want%20early%20access%20to%20ChatBreaker.)
- [Agent Flight Recorder](https://wa.me/5016691053?text=Hi%20Ingenious%20AI%21%20I%20want%20early%20access%20to%20Agent%20Flight%20Recorder.)
- [Agent Auth Gateway](https://wa.me/5016691053?text=Hi%20Ingenious%20AI%21%20I%20want%20early%20access%20to%20Agent%20Auth%20Gateway.)
- [DomainGuard](https://wa.me/5016691053?text=Hi%20Ingenious%20AI%21%20I%20want%20early%20access%20to%20DomainGuard.)
- [ContentCraft AI](https://wa.me/5016691053?text=Hi%20Ingenious%20AI%21%20I%20want%20early%20access%20to%20ContentCraft%20AI.)

Built with Muse — try it free: invite code 2HCQH1

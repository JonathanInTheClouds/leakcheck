# leakcheck

Scan your git history for leaked secrets before they become a problem.

```bash
leakcheck scan

# Scanning 142 commits...
#
#   leakcheck found 2 potential secrets
#
#   ── HIGH ──────────────────────────────────────────
#
#   ⚠  AWS Access Key ID
#      File:   config/deploy.rb (line 12)
#      Commit: a1b2c3d4 — Jonathan Dowdell (2026-01-15)
#      Match:  AKIA****
#      Rule:   aws-access-key  (suppress with: leakcheck ignore aws-access-key)
#
#   ── MEDIUM ────────────────────────────────────────
#
#   ⚠  Committed .env file
#      File:   .env (line 1)
#      Commit: e5f6g7h8 — Jonathan Dowdell (2025-12-01)
#      Rule:   env-file  (suppress with: leakcheck ignore env-file)
```

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/JonathanInTheClouds/leakcheck/main/install.sh | bash
```

Or build from source:
```bash
git clone https://github.com/JonathanInTheClouds/leakcheck
cd leakcheck
make install
```

## Usage

```bash
leakcheck scan                  # scan full git history
leakcheck scan --staged         # scan staged files only (pre-commit)
leakcheck scan --format json    # output as JSON (great for CI)
leakcheck report                # full report with remediation steps
leakcheck ignore high-entropy   # suppress a rule
leakcheck watch                 # install as git pre-commit hook
```

## Detection rules

| Rule | What it detects | Severity |
|---|---|---|
| `aws-access-key` | AWS Access Key IDs (`AKIA...`) | HIGH |
| `aws-secret-key` | AWS Secret Access Keys | HIGH |
| `private-key` | RSA/EC/DSA/OpenSSH private keys | HIGH |
| `github-token` | GitHub Personal Access Tokens | HIGH |
| `stripe-key` | Stripe API keys (`sk_live`, `pk_live`) | HIGH |
| `slack-token` | Slack tokens (`xoxb`, `xoxp`...) | HIGH |
| `slack-webhook` | Slack webhook URLs | MEDIUM |
| `generic-api-key` | Generic API key assignments | MEDIUM |
| `generic-secret` | Generic password/secret assignments | MEDIUM |
| `env-file` | Committed `.env` files | MEDIUM |
| `high-entropy` | High entropy strings (possible secrets) | LOW |

## Pre-commit hook

```bash
leakcheck watch
# ✓ Pre-commit hook installed at .git/hooks/pre-commit
# leakcheck will now scan staged files before every commit.
```

After installing, leakcheck blocks commits that contain secrets:
```bash
git commit -m "add config"
# leakcheck: secrets detected in staged files. Commit aborted.
# Run 'leakcheck scan --staged' for details.
# To bypass: git commit --no-verify
```

## Suppressing false positives

```bash
leakcheck ignore high-entropy
# ✓ Added "high-entropy" to .leakcheckignore
```

Commit `.leakcheckignore` to share the ignore list with your team.

## CI integration

```yaml
- name: Check for leaked secrets
  run: leakcheck scan --format json --quiet
```

Returns exit code 1 if HIGH or MEDIUM findings are detected.

## Development

```bash
make build    # build binary
make test     # run tests
make release  # build all platform binaries into dist/
```

## License

MIT

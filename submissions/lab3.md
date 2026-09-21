# Lab 3 Submission

## Task 1

### Signing configuration

```text
gpg.format: ssh
user.signingkey: /Users/vi/.ssh/id_ed25519.pub
commit.gpgsign: true
```

The public key was also registered on GitHub as a signing key. Local signature verification uses `/Users/vi/.config/git/allowed_signers`.

### Local signature verification

```text
commit 3f06512fc5b828e211a5a0c5abab945f84617f52
Verified "git" signature for fromirand@gmail.com with ED25519 key SHA256:B9RlX429NVw0h0ICY7aHSkj8/egqBewXLhob10jQX6s
Author: Vi <fromirand@gmail.com>

    test: first signed commit
```

GitHub commit with the Verified badge:

https://github.com/ViAlexiV/DevSecOps-Intro/commit/3f06512fc5b828e211a5a0c5abab945f84617f52

Without signing, someone could set the commit author to `Vi <fromirand@gmail.com>` and make a malicious change in this repository appear to come from me. The Verified badge shows that GitHub validated a cryptographic signature made with the signing key registered to my account, so the editable author line alone is no longer accepted as proof of authorship.

## Task 2

### Hook configuration

The repository contains `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.29.1
    hooks:
      - id: gitleaks

  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v6.0.0
    hooks:
      - id: detect-private-key
      - id: check-added-large-files
```

### Blocked secret commit

I staged `submissions/leak-attempt.txt` with the fake token supplied by the lab and attempted to commit it. The commit was blocked:

```text
Detect hardcoded secrets.................................................Failed
- hook id: gitleaks
- exit code: 1

Finding:     GH_PAT=REDACTED
Secret:      REDACTED
RuleID:      github-pat
File:        submissions/leak-attempt.txt
Line:        1
Fingerprint: submissions/leak-attempt.txt:github-pat:1

WRN leaks found: 1

detect private key.......................................................Passed
check for added large files..............................................Passed
```

The log still showed the previous signed commit, proving that the rejected commit was not created:

```text
3f06512 (HEAD -> feature/lab3, origin/feature/lab3) test: first signed commit
```

### Tuning gitleaks

An `[allowlist]` entry in `.gitleaks.toml` can narrowly permit a known fake `AKIA...` documentation value by exact value, regex, fingerprint, or other specific criterion while continuing to scan the rest of the repository. It becomes unsafe when the expression is broad enough to match real credentials, or when a placeholder is later replaced with a real secret that still matches the exception.

Excluding the entire `docs/` path is simpler, but it prevents gitleaks from inspecting every file in that directory. It stops being safe as soon as documentation may contain copied commands, configuration examples, generated output, or accidentally pasted real credentials, because those secrets would bypass the scanner completely.

## Task 3

### History before rewriting

```text
3f5cc02 docs: usage notes
55fe6a5 feat: empty log
e919e8f feat: add config
5c066dd init
```

The first count was:

```text
git log -p | grep -c 'ghp_AAAA'
2
```

### Initial refusal

The first rewrite attempt produced:

```text
Aborting: Refusing to destructively overwrite repo history since
this does not look like a fresh clone.
  (expected at most one entry in the reflog for HEAD)
Please operate on a fresh clone instead.  If you want to proceed
anyway, use --force.
```

Although this was a newly initialized sandbox, `git filter-repo` judged freshness using the number of HEAD reflog entries created by the test commits. Because `/tmp/lab3-bonus` was an isolated throwaway repository, I reviewed the target and repeated the command with `--force`.

### History after rewriting

```text
79140e4 docs: usage notes
af6659f feat: empty log
a9e9e86 feat: add config
5c066dd init
```

The three required counts were:

```text
Secret before rewrite: 2
Secret after rewrite:  0
REDACTED after rewrite: 2
```

Rewriting history removes the credential from reachable Git objects, but it does not make the credential safe again. The incident ends by revoking or rotating the exposed credential, because copies may remain in clones, forks, caches, CI logs, or an attacker's possession; a real cleanup would then re-add any removed remote and force-push the rewritten history while coordinating with collaborators.
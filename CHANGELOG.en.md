[中文](CHANGELOG.md) | [**English**](CHANGELOG.en.md)

# Changelog

## 4.5.0

All three fixes come from one real session (the plugin blocked a working session twice in a morning):

- **Narrower guard.** Any argument containing the vault directory string used to refuse the whole
  call — including `compress` summaries, a report sent to another agent, and a script that only
  named the directory as a variable. Now only calls whose *path or command arguments* address the
  vault are refused (`file_path` / `command` / `cwd` / `paths` …, or a value that is itself an
  absolute path). `date`, `ls /var/tmp`, `php -l` and friends keep working.
- **A worse bug fixed on the way.** When a caller had no session id (`exec.agent` missing), the old
  `!owner && store.hasFiles()` branch denied *every* tool — one agent runtime that could not report
  its session id took the whole machine's tooling down. It now refuses only vault-touching calls.
- **New `write_secret` primitive** (the important one): `private_local_process({operation:
  "write_secret", reference, target, key_path, mode})` writes the vault value straight into the
  named key of a target config file. Supports `.env` / `.ini` / `.properties` / `.yml` / `.toml` /
  `.json` (dotted path) / `.php` / `.js` / `.ts` (`define('K', …)` or `'K' => …`), and seeds a
  missing file in the target's own format. It returns only `{ok, status, target, keyPath, changed,
  fingerprint (8 chars)}` — **the value is never returned**. Only the matched value bytes change;
  the file's mode is preserved.
- **`private_local_status` answers in one call**: `mode: local_only | normal`, `restricts` (what is
  limited now), `openTools` (what still works), `releaseWhen` (how it ends).
- **Exit redaction.** Every tool result is scrubbed before it reaches the transcript: `sk-` /
  `AKIA` / `ghp_` / JWT / `Bearer` and other high-entropy credential shapes become
  "first 4 chars + fingerprint". This is aimed at the agent's own `sed`/`grep` slip-up (the real
  incident: a `sed` that failed to mask a DashScope key printed it into the session log). Token-wise
  linear scan, ~114 ms for 1 MB; paths, git SHAs, UUIDs and `tmp-` handles are left alone.
- Guard refusals now name the way forward (`write_secret`) instead of only saying "paused".

## 4.4.1

- Fix five PII false positives: Latin label words (`code` / `name`) had no word boundary, so
  `postcode` / `decode` / `username` / `hostname` made nearby digits look like an OTP and the
  suffix look like a name label.
- Address and ID/account values now stop at the clause boundary and before the next label
  instead of swallowing the following phone number or account.
- OTP same-clause detection now also splits on Chinese and ASCII commas and enumeration commas:
  `验证码：123456，您正在支付 5000 元` no longer reports the amount as a second OTP.
- A regression test covers each of the five cases.

## 4.4.0

- Content classification (`provider-config` / `server-login` / `db-credential` / `bank-sms` /
  `identity` / `api-keys` / `mixed` / `unknown`) with sensitivity, evidence and advice.
- Masked-skeleton classification with fixed-length placeholders; the classifier never sees a value.
- TF-IDF char n-gram linear fallback (144 KB, < 1 ms) plus an evaluation harness with gates.
- PII recognizers with checksums (GB 11643 ID, Luhn + issuer prefix, mobile prefixes, same-clause OTP).
- Old digests are upgraded on start.

## 4.3.0

- **Breaking:** saving a file no longer locks the session. The lock froze every tool exactly when the
  user wanted the file used; bytes are still protected by refusing store-naming calls.
- Legacy locks keep working and release when the last file disappears.

## 4.1.0 – 4.2.0

- Per-entry deletion with two-step confirmation; `POST /api/secret-vault/delete`.
- `ask_user_question` stays available in a locked session (it can never carry a value).
- Host rescue CLI; auto-release when the store empties; scoped fail-closed.
- Insertion retries once, then falls back to the clipboard.

## 4.0.x

- Local-only hand-over: plaintext stays in a random local file, only handles leave.

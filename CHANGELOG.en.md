[中文](CHANGELOG.md) | [**English**](CHANGELOG.en.md)

# Changelog

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

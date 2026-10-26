# dsh-secret-vault

Paste secrets, API keys, or PII into the DSH web UI and let the agent **act on them without ever
reading them**. The plugin stores the body in a local file, hands the model an opaque handle plus a
value-free digest, and refuses any tool call that names the private directory.

```text
you paste ──► local file (0600, random name)          ← body lives here, never in chat/logs
                    │
                    ├─► handle + shape digest ──► model  (addresses, model ids, secret lengths +
                    │                                     fingerprints, PII types, content kind)
                    └─► masked skeleton ──► classifier   ([[SECRET]] / [[PII]] / [[URL]], fixed length)
```

## Why

Putting a key in chat is forever: it lands in the session log, in the request sent to the model
provider, and in every backup of those. This plugin moves the hand-over out of the chat channel, so
the agent can use a credential without the plaintext ever entering its context.

## What it does

- **Local drop box** — random `tmp-<32 hex>` file, directory `700`, file `600`, 128 KiB cap, daily
  04:00 cleanup of used files (unused expire after 24 h).
- **Deterministic field extraction** (no model, < 1 ms): URLs, model ids, secret tokens with
  length + fingerprint, PII (mainland ID with the GB 11643 check digit, bank card with Luhn +
  issuer prefix, mobile numbers by prefix, OTP by same-clause keyword, e-mail), labels, JSON paths.
- **Content classification** (rules → TF-IDF linear model → abstain): `provider-config`,
  `server-login`, `db-credential`, `bank-sms`, `identity`, `api-keys`, `mixed`, `unknown`, plus
  `sensitivity`, `confidence`, auditable `evidence`, and an `advice` line.
- **Masks before classifying** — the classifier only ever sees `[[SECRET]]` / `[[PII]]` / `[[URL]]`
  placeholders (fixed length: a length-coded placeholder would leak the size).
- **Guard** — any tool call whose arguments name the private directory is refused, so `read`, `cat`
  or a glob cannot walk the bytes into context by accident.
- **Host rescue CLI** — `secret-vault status | fields | release | purge | cleanup`; no browser needed,
  never prints values.
- **Fail-closed is scoped** — a broken store only refuses store-touching calls instead of freezing
  every session's tools.

Classification is a **suggestion**: nothing here triggers an automatic action. Reading a bank SMS as
a provider config would be irreversible, so the UI labels it and a human decides.

## Install

DSH bundle, installed from Git:

```bash
# in the DSH plugin manager, add the bundle spec
git+https://github.com/yuloop/dsh-secret-vault
```

Or add the plugin market index so it shows up in Discover:

```text
https://raw.githubusercontent.com/yuloop/dsh-secret-vault/main/marketplace/index.json
```

Settings → Plugins → Marketplace → add that URL.

## Use

1. Open the key icon next to the composer, paste anything (one secret, a config blob, a bank SMS,
   mixed nonsense with values in the middle of a sentence).
2. Save. The panel shows one line: `模型供应商配置 · 敏感:secret · 网址2 · 模型1 · 密钥1`.
3. Ask for the work. The model calls `private_local_status` to get the handle and reacts to the
   digest — it never needs the path pasted into the chat.
4. Delete the file when done (two-step confirm), or let the daily sweep take it.

## Tools exposed to the model

| tool | returns |
|---|---|
| `private_local_status` | handle, used flag, `shape` (kind/sensitivity/evidence/advice/counts), no values |
| `private_local_process` | runs one of six fixed text transforms (`copy`, `trim_edges`, `normalize_newlines`, `json_pretty`, `json_compact`, `dedupe_lines`) and returns status + a new handle |

No delete tool, no shell, no HTTP: the model cannot reach the bytes, only act around them.

## Host commands

```bash
secret-vault status [session]        # entries and locks (read-only)
secret-vault fields   [id]           # field digest + classification, values never printed
secret-vault cleanup                 # run the 04:00 sweep now
secret-vault purge <session> --yes   # delete that session's files (irreversible)
```

Equivalent without the symlink: `node bin/secret-vault.mjs …`.

## Security model — what is and is not guaranteed

Guaranteed by construction:

- the body never travels through the chat, attachment or LLM channel;
- tool results for private content carry types, lengths and fingerprints only;
- the classifier sees a masked skeleton, and the skeleton is never persisted;
- `state.json` holds no values (asserted by tests, including a `state.json` grep).

Not guaranteed:

- **OS-level isolation.** DSH runs as one user; other processes, other plugins, backups and any
  root shell on that host could read the file. Moving the vault into a separate low-privilege
  process is future work.
- A deliberately crafted script can still exfiltrate a value; the guard stops accidents, not intent.
- Whatever you configure with a secret keeps its own plaintext copy (that is the point of using it).

## Development

```bash
npm test                          # 57 tests: parsing, PII checks, classification, routes, runtime
node tools/train-tfidf.mjs        # retrain the 144 KB linear classifier (synthetic corpus)
node tools/eval-classify.mjs      # gates: high-cost mistakes 0 · abstain ≤25% · P99<100ms · macro-F1≥0.85
```

The evaluation corpus is synthetic, so treat its 0.897 macro-F1 as an upper bound; the harness is
built so real samples can replace it.

MIT licensed.

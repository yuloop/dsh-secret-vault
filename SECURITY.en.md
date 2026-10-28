[中文](SECURITY.md) | [**English**](SECURITY.en.md)

# Security policy

## Reporting a vulnerability

Use a GitHub private security advisory (`Security` → `Advisories`), or contact the maintainer directly.
**Please do not open a public issue for a guard bypass or anything that could leak a value.**

## Scope and threat model

This plugin moves private bytes out of the model's view; it is **not** an OS sandbox.

**In scope:**

- a value reaching the model context, a tool result, or `state.json` through any path the plugin controls;
- a tool call whose path or command arguments address the private directory, not being refused;
- the classifier receiving anything other than masked text;
- a host command printing a value or a skeleton;
- a credential-shaped string slipping past exit redaction into the transcript (this layer is new in
  4.5.0; missed patterns are still worth reporting).

**Out of scope (documented limits, not vulnerabilities):**

- another process under the same user reading the files;
- a script written by the user or the agent deliberately reading and printing a value;
- the plaintext copy left behind in whatever configuration the secret was used to set up.

## Operational hardening checklist

- Exclude `$DSH_HOME/secret-vault` from backups and synchronised directories.
- Run host commands as the same user as DSH, never through an untrusted channel.
- Treat `secret-vault purge <session> --yes` as irreversible.

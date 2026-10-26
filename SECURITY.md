# Security policy

## Report a vulnerability

Open a private security advisory on GitHub (`Security` → `Advisories`), or e-mail the maintainer.
Please do not file a public issue for a bypass of the guard or for anything that could leak a value.

## Scope and threat model

This plugin moves private bytes out of the model's reach; it is **not** an operating-system sandbox.

In scope:

- a value reaching the model context, a tool result, or `state.json` by any route the plugin controls;
- a tool call naming the private directory that the guard fails to refuse;
- the classifier receiving anything other than masked text;
- the host CLI printing a value or a skeleton.

Out of scope (documented limits, not vulnerabilities):

- other processes running as the same user reading the files;
- a user- or agent-authored script that deliberately reads and prints a value;
- plaintext copies created after a secret is used to configure something else.

## Hardening checklist for operators

- keep `$DSH_HOME/secret-vault` out of backups and sync folders;
- run the host CLI as the same user that owns DSH, never over an untrusted channel;
- treat `secret-vault purge <session> --yes` as irreversible.

# WWU vi_kings SSH Tool

Concurrent SSH management tool for WWU's PRCCDC/NCCDC team. Built for the first minutes of a live competition.

```
██╗   ██╗██╗        ██╗  ██╗██╗███╗   ██╗ ██████╗ ███████╗
██║   ██║██║        ██║ ██╔╝██║████╗  ██║██╔════╝ ██╔════╝
██║   ██║██║        █████╔╝ ██║██╔██╗ ██║██║  ███╗███████╗
╚██╗ ██╔╝██║        ██╔═██╗ ██║██║╚██╗██║██║   ██║╚════██║
 ╚████╔╝ ██║███████╗██║  ██╗██║██║ ╚████║╚██████╔╝███████║
```

---

### Recommended competition workflow

**Pre-competition (before the event starts):**
1. Build `targets.txt` directly or use `[3] Add host (wizard)` to add each machine interactively from the topology document.
2. Run `[6] Generate SSH keypair` to create your team's key.
3. Verify the tool connects to at least one test box.

**Round 1 — lock the red team out (first ~10 minutes):**
1. `[7] Inject authorized keys` → push your key to root on every machine.
2. `[9] Password audit` → confirm which machines still have the default credential and rotate immediately.
3. `[8] Change account password` → rotate any service accounts the audit won't cover.

**Ongoing:**
- `[1] Live monitoring dashboard` → auto-refreshing fleet view showing TCP reachability, login viability, auth method, key posture, password coverage, and snapshot count.
- `[10] Deep password audit` → verify every `/etc/shadow` account after a suspected compromise.
- `[5] List snapshots` → review pre-change backups if a service breaks after hardening.
- `[13] Restore snapshots` → revert one host by selecting the exact backed-up files to restore together.

---

### Gains

- **Speed** — key injection and password rotation across all machines takes roughly the same time as doing one manually.
- **Failsafe access** — key injection runs first so you retain access even if a password gets changed out from under you.
- **Shared credential store** — every password change is written to `metadata.json` and retained in password history so the whole team works off the same state.
- **Pre-change snapshots** — `/etc/shadow`, `/etc/passwd`, and `authorized_keys` are snapshotted before every write operation.
- **No traces** — commands run over exec channels (no bash history); passwords are piped via stdin and never appear in process listings.

### Risks

- **Operator machine is a single point of failure.** `metadata.json` holds plaintext credentials and `data/id_rsa` unlocks every hardened machine. Keep the operator machine off the competition network.
- **Key injection can be reversed.** A red team with root can overwrite `authorized_keys` at any time. Re-run injection periodically.
- **Mid-rotation failure leaves credentials uncertain.** If `chpasswd` fails partway through, check `metadata.json` and verify access manually before moving on.
- **Deep audit requires root.** Reading `/etc/shadow` will fail if the stored credential doesn't have adequate privilege.
- **This tool does not harden `sshd_config`.** Password authentication stays open until you disable it manually. Key injection alone is not sufficient hardening.

---

## Setup

```bash
python3 -m venv .venv
.venv/bin/pip install -e .
```

Edit `targets.txt` from the competition topology document, or add hosts interactively from the menu wizard or the `add-host` CLI command:
```
# label,host,port
web-1,10.0.0.10,22
db-1,10.0.0.11,22
```

`targets.txt` supports exactly `label,host,port`. The preferred SSH login username is stored in `data/metadata.json`, and target keys remain `host:port`. The add-host wizard preserves existing comments and rejects duplicate `host:port` entries, then optionally tests the SSH connection (trying the local key first, then falling back to a password that gets stored in `metadata.json` on success).

Managed SSH keys default to RSA in `data/id_rsa` and `data/id_rsa.pub`. Existing `data/id_ed25519` keys are still recognized as a compatibility fallback until you regenerate and reinject RSA keys.

For legacy CCDC boxes running pre-7.2 OpenSSH (which only understand `ssh-rsa` SHA-1 signatures), the tool's legacy connection fallback disables `rsa-sha2-512` / `rsa-sha2-256` so key authentication still succeeds against old servers.

```bash
.venv/bin/python -m vikings_ssh   # interactive menu
```

---

## Menu

```
[1] Live monitoring dashboard
[2] List targets
[3] Add host (wizard)
[4] Show metadata
[5] List snapshots
[6] Generate SSH keypair
[7] Inject authorized keys
[8] Change account password
[9] Password audit          (SSH auth check)
[10] Deep password audit    (/etc/shadow check)
[11] View credentials
[12] Export credentials
[13] Restore snapshots
[q] Quit
```

## CLI

| Command | Key flags |
|---------|-----------|
| `dashboard` | `--timeout`, `--workers`, `--interval`, `--once` |
| `targets` | (no flags) |
| `add-host` | `--label`, `--host`, `--port`, `--username`, `--test` |
| `credentials` | `--target-key` |
| `export-credentials` | `--target-key`, `--output` |
| `generate-key` | `--comment`, `--overwrite` |
| `inject-keys` | `--target-key`, `--user` |
| `change-password` | `--target-key`, `--account`, `--generate` |
| `audit-passwords` | `--target-key`, `--username`, `--rotate` |
| `deep-audit-passwords` | `--target-key`, `--username`, `--rotate` |
| `snapshot-add` | `--target-key`, `--source-path`, `--from-file`, `--reason` |
| `snapshot-restore` | `--target-key`, `--snapshot-id` |

## Files

```
targets.txt          Host inventory (label,host,port)
data/authorized_keys Public keys to inject
data/id_rsa          Generated private key (keep secret, mode 600)
data/metadata.json   Credential store + preferred SSH usernames (treat as sensitive)
data/exports/        Readable credential exports
snapshots/           Pre-change file backups
```

The goal of this project is to restrict the permissions of Claude.

Even if LLMs ask for permissions, they can bypass permissions with scripts to
access folders you didn't explicitly authorize. Additionally, this is all controlled by Anthropic, if
they change the logic of the permissions and if there is the smallest bug or vulnerability. Claude
could access everything.

Additionally, as we've seen with the malicious axios npm package, anyone running npm update for
Claude code that day would have been affected.

Sources:
  - https://www.securityweek.com/critical-vulnerability-in-claude-code-emerges-days-after-source-leak/
  - https://coder.com/blog/what-the-claude-code-leak-tells-us-about-supply-chain-security
  - https://www.zscaler.com/blogs/security-research/anthropic-claude-code-leak
  - https://www.trendmicro.com/en_us/research/26/d/weaponizing-trust-claude-code-lures-and-github-release-payloads.html
  - https://www.securityweek.com/claude-code-flaws-exposed-developer-devices-to-silent-hacking/
  - https://cybersecuritynews.com/claude-generated-commit-adds-promptmink-malware/
  - https://cyberunit.com/insights/claude-code-source-code-leak-business-implications/
  - https://papers.ssrn.com/sol3/papers.cfm?abstract_id=6504920

## At a glance

| Problem to mitigate | Action taken | What can still be done |
|---|---|---|
| Secrets/config in `$HOME` (`.ssh`, `.aws`, `.claude`, `.git-credentials`, …) | • blanket deny ACL on every `$HOME` dotfile/dir<br>• `$HOME` traverse-only, no `ls` | • files added after scan unprotected → re-run<br>• `umask 077` |
| Project secrets (`.env*`, `*.pem`, `*.key`, `id_rsa*`, `tfstate*`, `credentials*`) | • deny-list ACL on matching files<br>• recursive deny on `.aws` / `.ssh` / `.terraform` dirs | • scan-time files only<br>• new secrets inherit `rwx` → re-run / daily timer |
| Sandbox over-broad filesystem access | • `rwx` + default ACL only on `LLM_ALLOWED_DIRS`<br>• traversal granted up the chain | • `.git` reachable (needed for workflow)<br>• copied/restored files may carry own ACLs |
| New `$HOME` files readable by other local users | • default ACL `o::---` on `$HOME` | • new files only<br>• `umask 077` as belt-and-suspenders<br>• allowed-dir files shared w/ `llm_group` by design |
| Privilege of switching into the sandbox | • sudoers `NOPASSWD`, one-way (you → `llm_restricted`)<br>• `sw` alias | • foothold if your own account is compromised (by design) |
| Claude binary trust / reachability | • installed **as `llm_restricted`** into its own `~/.local/bin` (sha256-pinned installer)<br>• PATH export in sandbox `.bashrc` | • `llm_restricted` owns its binary → can self-update inside the jail<br>• re-pin hash when the installer changes |
| Cloud IAM creds via IMDS (`169.254.169.254`) | • UID-scoped nftables block (`harden-host.sh`) | • only if `harden-host.sh` run<br>• cloud VMs only |
| Persistence across reboots | • `loginctl disable-linger` (`harden-host.sh`) | • `crontab` / user units writable → keep lingering off |
| Data exfiltration / outbound network | • optional UID-scoped nftables FQDN allowlist (`APPLY_EGRESS=1`) | • off by default<br>• DNS exfil still open<br>• resolved IPs go stale → re-run<br>• no IPv6 |
| Code run as you later (git hooks, `Makefile`, npm `postinstall`, build hooks) | • — (OS sandbox cannot help) | • biggest residual risk<br>• review repos before `make` / `npm install` / `git pull` |
| Token/secret use by the sandbox | • — (not set up) | • auth-injecting proxy<br>• agent socket<br>• short-lived token issuer<br>• sudoers wrapper |
| Misc local escalation | • explicit non-recursive ACL on `/tmp` | • setuid binaries (`find / -perm -4000`)<br>• `docker.sock` if present<br>• shell commands unaudited |

## How to run

Two scripts, run in order. Both require `sudo`.

```bash
# 1. Create the sandbox user, ACLs on $HOME / projects, sensitive-file deny
#    list, and a sudoers entry so you can become llm_restricted without a
#    password. Also installs Claude Code as llm_restricted (sha256-pinned
#    installer) if it's not already in its ~/.local/bin. Idempotent — re-run
#    any time you add new files / repos / Claude versions and want the rules
#    refreshed.
sudo bash setup-llm-restricted_for_claude.sh

# 2. (Optional) Host-wide hardening: disable systemd lingering for the user,
#    block the cloud metadata service (169.254.169.254) for the UID, and —
#    if APPLY_EGRESS=1 — pin the UID's outbound traffic to a small FQDN
#    allowlist via nftables.
sudo bash harden-host.sh
# To enable the strict egress allowlist (will break web fetches outside the list):
sudo APPLY_EGRESS=1 bash harden-host.sh

# 3. Switch to the sandboxed user (NOPASSWD via the sudoers entry from step 1).
sudo -i -u llm_restricted

# 4. Launch Claude Code. First run prompts for auth; the credentials are
#    stored in /home/llm_restricted/.claude/, isolated from your own.
claude
```

See **What this setup brings** below for what each rule actually does, and
**Pitfalls** for residual risks the OS sandbox doesn't cover.

## Namespace + seccomp sandbox (`claude-sandboxed`)

`setup-llm-restricted_for_claude.sh` covers the OS-level layer (user/group,
ACLs, sudoers, and the AppArmor-for-bwrap profile). The *runtime* confinement is
provided by a separate launcher, **`claude-sandboxed`**, which wraps Claude Code
in [bubblewrap](https://github.com/containers/bubblewrap):

- **All namespaces unshared** (`--unshare-all`) with networking re-enabled
  (`--share-net`) and `--new-session` (blocks TIOCSTI terminal injection).
- **Private mount namespace** — only explicitly bind-mounted paths are visible
  (`~/projects`, `/home/emily/projects`, `~/.claude`, plus a minimal read-only
  `/usr`, `/lib`, `/etc/ssl`, …). The rest of `$HOME` is a tmpfs; `/sys` and
  `/run` (except the systemd-resolved stub) are absent.
- **seccomp-bpf filter** — ~49 dangerous syscalls rejected with `EPERM`: kernel
  module loading, `kexec`/`reboot`, `ptrace`/`process_vm_*`, `bpf`, `io_uring`,
  `perf_event_open`, raw sockets, clock/hostname changes, etc. Generated from
  `generate-seccomp-filter.c`.

The setup script aliases `claude='claude-sandboxed'` in the restricted user's
`.bashrc`, so an interactive `claude` launches through the wrapper (convenience
only — the raw binary is still reachable via full path or `command claude`).

### Installing / updating the wrapper + filter

The wrapper and its compiled seccomp filter are installed **manually** (the
setup script does not copy them). Run on the **host** — the targets live under
the restricted user's `~/.local`, which is read-only inside the jail. Requires
`gcc` and `libseccomp-dev`:

```bash
cd /home/<you>/projects/restrict_llm

# 1. install the launcher
sudo install -Dm755 claude-sandboxed /home/llm_restricted/.local/bin/claude-sandboxed

# 2. compile the generator and emit the BPF the launcher loads at startup
gcc -O2 -o generate-seccomp-filter generate-seccomp-filter.c -lseccomp
sudo ./generate-seccomp-filter -o /home/llm_restricted/.local/share/claude/seccomp-filter.bpf

# 3. make sure the restricted user can read them
sudo chown -R llm_restricted:llm_group \
  /home/llm_restricted/.local/bin/claude-sandboxed \
  /home/llm_restricted/.local/share/claude/seccomp-filter.bpf
```

Re-run steps 2–3 whenever you edit the blocklist in `generate-seccomp-filter.c`,
then **restart the Claude session** so the new filter is loaded (it's read from a
file descriptor at launch, not re-read live).

### Nested bwrap — why `mount`/`umount2`/`pivot_root` stay allowed

Claude Code's own Bash tool spawns a **nested** bwrap on Linux — it does this
even when Claude Code's *internal* sandbox is toggled off. For that inner bwrap
to initialize inside this outer sandbox, the seccomp filter must leave `mount`,
`umount2`, and `pivot_root` unblocked. bwrap's first setup step is
`mount(NULL, "/", NULL, MS_SLAVE|MS_REC, NULL)`; if `mount` is blocked, seccomp
returns `EPERM` and **every shell command dies** with:

```
bwrap: Failed to make / slave: Operation not permitted
```

The filter therefore ships with those three syscalls allowed (see the comment at
the top of the mount section in `generate-seccomp-filter.c`). This does **not**
widen filesystem access: which host paths are reachable is enforced by the outer
mount namespace + bind mounts, so a nested mount only rearranges the
already-restricted view. The only cost is restored kernel mount-API attack
surface — an acceptable trade to let Claude Code run shell commands at all.
`chroot` and the newer mount-API calls (`fsopen`, `move_mount`, `open_tree`, …)
stay blocked (standard bwrap doesn't need them).

## What this setup brings

- User and group
  - Creates group `llm_group`.
  - Creates user `llm_restricted` (home `/home/llm_restricted`, primary group `llm_group`, shell `/bin/bash`).
  - Locks the password (passwd -l) — no console / SSH-password / su access.
  - Adds you (the invoking user) to `llm_group` so files Claude creates stay accessible.
- Filesystem ACLs (POSIX)
  - `g:llm_group:x` on your $HOME → traverse only (no ls, no reading other dotfiles).
  - `g:llm_group:rwx` (recursive + default) on each `LLM_ALLOWED_DIRS` entry → full edit / move / delete in your project trees.
  - `g:llm_group:rwx` (non-recursive) on /tmp.
  - `g:llm_group:---` (deny) on sensitive paths:
    - Every dotfile/dotdir directly under your $HOME (no exceptions). This blanket deny covers `.claude`, `.ssh`, `.aws`, `.gnupg`, `.config`, `.git-credentials`, `.local`, etc.
    - In allowed dirs: files matching `.env*`, `*.pem`, `*.key`, `id_rsa*`, `id_ed25519*`, `terraform.tfstate*`, `credentials*`
    - In allowed dirs: directories named `.aws`, `.ssh`, `.terraform` (recursive deny + default deny)
- Claude Code binary
  - If `/home/llm_restricted/.local/bin/claude` is missing, installs it **as `llm_restricted`** via the official `https://claude.ai/install.sh`, so the binary — and any later self-update / postinstall code — runs as the sandbox UID, never as root or you.
  - The installer is downloaded to a temp file and its sha256 verified against a pinned value before running (fails closed on mismatch). Override or disable with `CLAUDE_INSTALLER_SHA256=<hash>` / `CLAUDE_INSTALLER_SHA256=""`.
  - Adds `~/.local/bin` to the restricted user's `.bashrc` PATH so `claude` / `claude-sandboxed` resolve. Setup never executes the binary — the smoke test only checks it is present.
- Shared config for the restricted Claude
  - Sets `export CLAUDE_CONFIG_DIR=/home/llm_restricted/.claude` in the restricted user's `.bashrc` and migrates any existing `~/.claude.json` into that directory. The bwrap wrapper makes `$HOME` a tmpfs and only binds `~/.claude`, so the default home-root `~/.claude.json` would be invisible (and a single-file bind breaks Claude's atomic temp+rename writes with `EBUSY`). Relocating it into the bound `~/.claude` dir keeps it readable and writable inside the jail. `bwrap` has no `--clearenv`, so the exported var propagates from an interactive shell into the sandbox.
  - The restricted user has its own `/home/llm_restricted/.claude/` (created on first run).
  - To share `CLAUDE.md`, agents, plugins, or settings with the restricted Claude, keep them in a directory under `LLM_ALLOWED_DIRS` (e.g. `~/projects/claude_config/`) and symlink the files into `/home/llm_restricted/.claude/`. The restricted user can read `LLM_ALLOWED_DIRS` but not your own `~/.claude/` — so direct symlinks from the restricted home into your private `.claude/` will fail by design.
- Sudoers
  - Writes `/etc/sudoers.d/llm_restricted`: lets you `sudo -u llm_restricted /bin/bash` without a password. One direction only `llm_restricted` itself has no sudo rights.
- AppArmor profile for bwrap (Ubuntu 24.04+)
  - When `kernel.apparmor_restrict_unprivileged_userns=1` is active, writes `/etc/apparmor.d/bwrap` granting only the `userns` permission so the `claude-sandboxed` bwrap wrapper can create user namespaces. Without it, bwrap fails with `setting up uid map: Permission denied`. The global restriction stays on for every other binary. No-op on hosts without the restriction / without bwrap / without `apparmor_parser`.
- Convenience alias
  - Appends `alias sw='sudo -i -u llm_restricted'` to `/home/$INVOKING_USER/.alias` (creates the file if missing). Source it from your shell rc (e.g. add `[ -f ~/.alias ] && . ~/.alias` to `~/.bashrc` / `~/.zshrc`) so `sw` drops you into the sandboxed shell. Idempotent — guarded by a marker line so re-runs don't duplicate the entry.

## Pitfalls — how Claude (or a compromised tool it runs) could still cause harm

  - `/tmp` and other world-writable paths. `/tmp` (and `/var/tmp`, `/dev/shm`) are accessible to all
    users by default. Anything Claude downloads, builds, or extracts there is fully under its
    control. If you cp something out of /tmp later as your user, you're trusting whatever's there.
  - Files created in `ALLOWED_DIRS` after setup are not auto-protected. A new .env you drop into a
    repo after running the script inherits the broad rwx ACL. The deny list only applies to files
    that existed at scan time. Re-run the script after major changes — or set up a daily systemd
    timer.
  - Newly cloned repos may carry their own ACLs. git clone typically creates fresh files which
    inherit the default ACL — fine. But cp -p, tar -p, or restore-from-backup can drop files with
    original ownership and explicit ACLs that override the parent's defaults. Spot-check getfacl on
    imported trees.
  - While `~/.git/` access is disabled, local project's .git are accessible, Claude can:
    - Run git config to set a credential helper or core.sshCommand.
    - Run git commit --amend --no-edit to silently rewrite history that you wrote.
    - Run git push to remotes (if a credential helper is configured globally for your user — check:
      git config --global --get credential.helper. If it points to cache or store, those store creds
      in user-readable files; the cache helper uses a socket in XDG_RUNTIME_DIR/, owned by your user
      — Claude can't reach it, OK. The store helper writes ~/.git-credentials plain-text — make sure
      that's outside the allowed dirs).
    - Add post-commit / pre-push hooks that run when you later run git in that repo.
  - Ambient credentials & sockets that aren't in ~/.
    - AWS instance metadata service (IMDS) at 169.254.169.254 — reachable from any user on EC2. If this machine were on EC2
  with an instance role, llm_restricted could grab credentials over HTTP. Check curl http://169.254.169.254/latest/meta-data/
   from inside the sandbox; if it works, that's an exposure.
    - Docker / Podman socket: /var/run/docker.sock if present and group docker membership leaks → root-equivalent. Verify
  llm_restricted is not in docker. (groups llm_restricted should show only llm_group.)
    - systemd user manager, dbus session, gpg-agent, ssh-agent: if you're logged in graphically as $INVOKING_USER, those agents have
  sockets in /run/user/$UID/. By default /run/user/<$INVOKING_USER-uid> is mode 700 and inaccessible to other users — but worth
  double-checking with stat /run/user/$(id -u).
    - Pulseaudio / Wayland / X11 sockets — in a normal desktop, these belong to your user; llm_restricted can't connect. But
  if you set xhost + or share XDG_RUNTIME_DIR, it could.
  - Setuid / capability binaries. A buggy setuid binary anywhere on $PATH is a privilege escalation route for any local user,
   including llm_restricted. Run find / -perm -4000 -type f 2>/dev/null periodically.
  - Network egress = data exfiltration. Claude can read files in allowed dirs (which now includes anything not on the deny
  list) and curl them anywhere. The OS sandbox doesn't prevent leaking your project source code. If you care about that, you
  need network-level controls (egress firewall, only-Anthropic-API allowlist).
  - Shell escape via the binary itself. Claude Code as a tool can run arbitrary shell commands the model decides on. The OS
  sandbox bounds what those shell commands can do, but doesn't audit them. Logs are local to llm_restricted's home and the
  model can edit/delete them.
  - Git hooks / Makefiles / build scripts in your repos can run as your user later. llm_restricted can plant a malicious
  Makefile, package.json postinstall, .git/hooks/post-checkout, pyproject.toml build hook, etc. The next time you make, npm
  install, pip install -e ., or git pull (some hooks fire on pull), it runs as $INVOKING_USER, with full access to your secrets. This
  is the single biggest practical risk — OS sandboxing doesn't help.
  - systemd --user units and crontabs for llm_restricted. Once it's a real user, it can write crontab -e and
  ~/.config/systemd/user/. Anything dropped there persists across reboots and runs whenever its user manager starts.
  Detection: loginctl enable-linger llm_restricted would let units run without a session — disable with loginctl
  disable-linger llm_restricted if you want to bound this.
  - The sudoers entry is a foothold by design. Anyone who compromises your user account can sudo -i -u llm_restricted bash
  without a password. So this isn't isolation between you-and-attacker; it's isolation between you-as-trusted-user and
  you-as-running-an-LLM. If your account itself is compromised, the sandbox doesn't help.

## Recommended host-side hygiene

These changes apply to **your own user account**, not the sandbox — they reduce
the blast radius if anything running as you (Claude, a build script, a VS Code
extension, etc.) reads ambient secrets.

### Stop using `credential.helper = store`

The `store` helper writes git credentials plaintext to `~/.git-credentials`,
one URL per line in the form `https://user:token@host/path`. Mode is 600 so
the OS protects it from other users — but anyone running *as you* gets the
raw tokens. Replace it with an in-memory or keyring-backed helper:

```bash
git config --global --unset credential.helper
```

Best practice (most likely already enforced): switch repos to SSH (`git@github.com:org/repo.git`)
and skip HTTPS auth entirely.


## Optional host hardening: `harden-host.sh`

`setup-llm-restricted_for_claude.sh` only touches the sandbox user. If you also
want network egress restrictions, IMDS blocking, and no systemd lingering, run
the companion script **after** the user has been created:

The egress allowlist is **opt-in** (`APPLY_EGRESS=1`); without it, the
script still installs the IMDS block, disables lingering, and tightens
`/tmp` — no impact on outbound web traffic.

> **Heads-up if you enable `APPLY_EGRESS=1`: expect web fetches to break.**
> The allowlist is intentionally narrow — only the FQDNs explicitly resolved
> into the nftables set are reachable. Anything Claude tries to do that
> touches a host outside that list will fail: random `curl`/`wget` of
> arbitrary URLs, package installs from registries you didn't enable,
> fetching Docker images, hitting a Stack Overflow / docs site, calling an
> internal API, etc. If you need a particular host reachable, add it via
> `EXTRA_FQDNS=` and re-run, or set `ALLOW_PACKAGE_REGISTRIES=1` for the
> common npm/pypi case. Claude itself still works because `api.anthropic.com`
> is allowed; git over HTTPS to github.com works for the same reason.

```bash
sudo bash harden-host.sh
```

What it does:

- **Disables systemd lingering** for `llm_restricted` (`loginctl disable-linger`).
  User-level units / timers can no longer keep running across reboots without
  an active session — closes a persistence path.
- **Blocks the cloud metadata service** (`169.254.169.254`) via an nftables
  rule scoped to the `llm_restricted` UID. On a cloud VM with an instance
  role, this closes the "sandbox → IAM token → your S3 buckets" escalation
  path; your own shells still reach IMDS normally because the rule is
  UID-scoped. On a normal workstation/laptop the address isn't routed
  anywhere, so the rule is a no-op.
- **Egress allowlist (UID-scoped, nftables)**. Resolves a list of FQDNs
  (`api.anthropic.com`, `statsig.anthropic.com`, `claude.ai`,
  `github.com`/`api.github.com`/`codeload.github.com`/`*.githubusercontent.com`)
  at install time, pins the IPs into a set, and drops everything else for the
  UID — DNS (UDP/TCP 53) and HTTPS to the resolved IPs are allowed; nothing
  else. The rules live in their own table (`inet llm_egress`) so they don't
  conflict with `ufw`, `firewalld`, or hand-rolled rules.

### Knobs

| Env var | Default | Effect |
|---|---|---|
| `LLM_USER` | `llm_restricted` | Which user to filter |
| `APPLY_EGRESS` | `0` | Set to `1` to install the FQDN allowlist (drops all other outbound for the UID). Leave at `0` to keep only the IMDS block + lingering. |
| `ALLOW_PACKAGE_REGISTRIES` | `0` | (Only meaningful with `APPLY_EGRESS=1`.) Set to `1` to also allow `registry.npmjs.org`, `pypi.org`, `files.pythonhosted.org` |
| `EXTRA_FQDNS` | (empty) | (Only meaningful with `APPLY_EGRESS=1`.) Space-separated extra hostnames to add to the allowlist |

### Caveats

- **DNS-resolved IPs go stale.** GitHub's edge IPs in particular rotate. Re-run
  `harden-host.sh` to refresh, or schedule it with a daily systemd timer:
  ```
  systemd-run --on-calendar=daily --unit=harden-host bash /home/$INVOKING_USER/projects/restrict_llm/harden-host.sh
  ```
- **DNS itself is not allowlisted.** UDP/TCP 53 is open to whatever resolver is
  configured, so DNS exfiltration is still possible. To close that, pin DNS
  to a specific resolver (`ip daddr 1.1.1.1` etc.) — left out of the default
  rules to avoid breaking systemd-resolved setups.
- **No IPv6 allowlist by default.** The default rules only cover IPv4. If your
  network has IPv6, add an `allow_v6` set + `ip6 daddr @allow_v6` rule, or
  block IPv6 egress entirely for the UID.

### Reversal

```bash
# Undo nftables rules
sudo nft delete table inet llm_egress 2>/dev/null
sudo rm -f /etc/nftables.d/llm_egress.nft
sudo sed -i '/llm_egress.nft/d;/managed by harden-host.sh/d' /etc/nftables.conf

# Lingering is already off when creating a fresh user, enable it only if you want it.
```

## Future improvements

- Fold the `claude-sandboxed` install + seccomp-filter generation into
  `setup-llm-restricted_for_claude.sh` (currently a manual step — see
  "Installing / updating the wrapper + filter" above).
- Switch the seccomp filter from a denylist to an allowlist (more secure but
  more fragile — see the rationale comment in `generate-seccomp-filter.c`).
- IPv6 egress allowlist + DNS pinning in `harden-host.sh`.

## What this setup does NOT do

Across all three scripts (`setup-llm-restricted_for_claude.sh`,
`claude-sandboxed`, `harden-host.sh`):

  - **No resource limits** (CPU / memory / disk / process count) — no cgroup caps anywhere.
  - **No `.git/` deny** — Claude Code needs git for its workflow, so `.git/` is reachable inside allowed dirs.
  - **No re-scan trigger** — the sensitive-file deny list is a one-shot scan at
    `setup-llm-restricted_for_claude.sh` run time; secrets added afterward inherit the
    broad `rwx` ACL until you re-run it.
  - **No automatic wrapper install** — `claude-sandboxed` and its seccomp BPF are installed
    manually (see "Installing / updating the wrapper + filter"); the setup script only
    aliases `claude` to the wrapper.
  - **No network restriction by default** — `harden-host.sh` always installs the IMDS block
    and disables lingering, but the egress allowlist is opt-in (`APPLY_EGRESS=1`); without it,
    outbound traffic is unrestricted. Even with it, DNS exfil and IPv6 egress stay open (see caveats).
  - **No command auditing** — the sandbox bounds what shell commands can do but doesn't log or inspect them.

#!/bin/bash
# Set up llm_restricted_opencode user (in llm_group_opencode) for running
# opencode with OS-level sandboxing. Idempotent: safe to re-run after adding
# new files (re-applies ACLs and re-scans the deny list).
#
# Deliberately a SEPARATE user/group from setup-llm-restricted_for_claude.sh's
# llm_restricted/llm_group: if either sandboxed CLI tool is compromised, it
# still can't read the other tool's config, credentials, or seccomp filter.
#
# Run with: sudo bash setup-llm-restricted_for_opencode.sh
#
# Override defaults via env, e.g.:
#   sudo LLM_ALLOWED_DIRS="/srv/code /opt/work" bash setup-llm-restricted_for_opencode.sh

set -euo pipefail

# ── User-facing knobs ────────────────────────────────────────────────────────
# Invoking user is auto-detected from sudo. Falls back to $USER otherwise.
INVOKING_USER="${SUDO_USER:-$USER}"
INVOKING_HOME=$(getent passwd "$INVOKING_USER" | cut -d: -f6)

# Space-separated list of directories the restricted user gets rwx on.
# Default is one entry: $HOME/projects. Same tree the Claude sandbox uses —
# only the user/group differ, so both tools can work the same project dirs
# without sharing credentials or config.
LLM_ALLOWED_DIRS="${LLM_ALLOWED_DIRS:-$INVOKING_HOME/projects}"

LLM_USER="${LLM_USER:-llm_restricted_opencode}"
LLM_GROUP="${LLM_GROUP:-llm_group_opencode}"

# opencode's official installer puts the binary in the invoking user's own
# ~/.opencode/bin (not ~/.local/bin), so that's where the opencode-sandboxed
# wrapper expects to find it too.
OPENCODE_BIN_DIR="/home/$LLM_USER/.opencode/bin"

# sha256 of https://opencode.ai/install, verified before it is run. Pinned to
# the version reviewed on 2026-09-06; upstream updates the installer over
# time, so a mismatch here means "review the new installer, then update this
# hash" — it fails closed rather than running unreviewed code. Set to "" to
# skip.
#OPENCODE_INSTALLER_SHA256="${OPENCODE_INSTALLER_SHA256:-fc3c1b2123f49b6df545a7622e5127d21cd794b15134fc3b66e1ca49f7fb297e}"
OPENCODE_INSTALLER_SHA256=""
# Sudoers wrapper for ergonomic switching. Set CREATE_SUDOERS=0 to skip.
# Able to switch from invoking_user to llm_user with the $SW_ALIAS alias.
# Both the sudoers file and the alias are keyed off $LLM_USER / $SW_ALIAS so
# setting up a second restricted user (different LLM_USER) doesn't clobber
# the first one's wrapper — override SW_ALIAS too when doing that. Defaults
# to "swo" (not "sw") so it coexists with the Claude sandbox's alias.
CREATE_SUDOERS="${CREATE_SUDOERS:-1}"
SW_ALIAS="${SW_ALIAS:-swo}"
# ─────────────────────────────────────────────────────────────────────────────

if [ "$(id -u)" -ne 0 ]; then
    echo "Must run as root (sudo bash $0)" >&2
    exit 1
fi
if [ -z "$INVOKING_HOME" ] || [ ! -d "$INVOKING_HOME" ]; then
    echo "Could not resolve home directory for '$INVOKING_USER'" >&2
    exit 1
fi
for dir in $LLM_ALLOWED_DIRS; do
    if [ ! -d "$dir" ]; then
        echo "LLM_ALLOWED_DIRS entry does not exist: $dir" >&2
        exit 1
    fi
done

echo "Setting up $LLM_USER for invoking user: $INVOKING_USER"
echo "  LLM_ALLOWED_DIRS  = $LLM_ALLOWED_DIRS"
echo "  OPENCODE_BIN_DIR  = $OPENCODE_BIN_DIR"
echo

echo "==> 1. Creating group + user"
groupadd -f "$LLM_GROUP"
if ! id "$LLM_USER" >/dev/null 2>&1; then
    useradd -m -g "$LLM_GROUP" -s /bin/bash "$LLM_USER"
fi
passwd -l "$LLM_USER" >/dev/null

# Invoking user needs to be in $LLM_GROUP so files created by $LLM_USER
# in the allowed dirs remain accessible.
usermod -aG "$LLM_GROUP" "$INVOKING_USER"

# Helper: walk up from a target path and grant traversal to a subject ACL,
# stopping at / or at $INVOKING_HOME. Used for paths outside the home dir.
add_traversal() {
    local target="$1" subject="$2" current
    current=$(dirname "$target")
    while [ "$current" != "/" ] && [ "$current" != "$INVOKING_HOME" ]; do
        setfacl -m "$subject:x" "$current" 2>/dev/null || true
        current=$(dirname "$current")
    done
}

echo "==> 2. ACLs: traverse on \$HOME, rwx+default on each allowed dir"
setfacl -m "g:$LLM_GROUP:x" "$INVOKING_HOME"

# Default ACL on $HOME: newly-created entries deny the "other" class. u::/g::
# are auto-derived from the dir mode so we don't tighten anything else. Only
# affects new files; existing entries keep their current ACLs. Stacks with
# umask — umask is applied first to the mode bits, this can only further
# restrict. A no-op if setup-llm-restricted_for_claude.sh already set this.
setfacl -d -m o::--- "$INVOKING_HOME"

# /tmp is already world-accessible (mode 1777) on most systems, but apply an
# explicit ACL grant so access stays consistent if anyone tightens /tmp later.
# No recursion — the sticky bit on /tmp already isolates users from each other,
# and we don't want to scan files owned by other users.
setfacl -m "g:$LLM_GROUP:rwx" /tmp

for dir in $LLM_ALLOWED_DIRS; do
    setfacl -R    -m "g:$LLM_GROUP:rwx" "$dir"
    setfacl -R -d -m "g:$LLM_GROUP:rwx" "$dir"
    add_traversal "$dir" "g:$LLM_GROUP"
done

echo "==> 3. Install opencode for $LLM_USER (if missing) + set PATH"
# The binary lives in $LLM_USER's own home ($OPENCODE_BIN_DIR), owned by that
# user, so no cross-user ACL is needed to reach it. If it isn't there yet,
# install it AS $LLM_USER: the binary and any future self-update code then
# run as the sandbox UID, never as root or the invoking user.
# The installer is downloaded to a temp file first (owned by $LLM_USER) so it
# can be checksum-verified rather than piped straight into a shell.
if [ -x "$OPENCODE_BIN_DIR/opencode" ]; then
    echo "    already installed at $OPENCODE_BIN_DIR/opencode — skipping"
else
    echo "    not found — installing as $LLM_USER via https://opencode.ai/install"
    INSTALLER_TMP=$(sudo -u "$LLM_USER" mktemp)
    sudo -u "$LLM_USER" curl -fsSL https://opencode.ai/install -o "$INSTALLER_TMP"
    if [ -n "$OPENCODE_INSTALLER_SHA256" ]; then
        echo "$OPENCODE_INSTALLER_SHA256  $INSTALLER_TMP" | sha256sum -c - \
            || { echo "    installer sha256 mismatch — aborting" >&2; rm -f "$INSTALLER_TMP"; exit 1; }
    else
        echo "    WARNING: OPENCODE_INSTALLER_SHA256 not set — running installer unverified"
    fi
    sudo -u "$LLM_USER" -H bash "$INSTALLER_TMP"
    rm -f "$INSTALLER_TMP"
fi

# Make `opencode` resolvable in $LLM_USER's shell by putting $OPENCODE_BIN_DIR
# on its .bashrc PATH. Idempotent: a marker line guards against duplicating
# the export on re-runs. (The installer also tries to add this itself, but we
# don't rely on that — this is the same belt-and-suspenders approach the
# Claude setup script uses.)
LLM_BASHRC="/home/$LLM_USER/.bashrc"
PATH_MARKER="# managed by setup-llm-restricted_for_opencode.sh: opencode PATH"
if [ -f "$LLM_BASHRC" ] && ! grep -qF "$PATH_MARKER" "$LLM_BASHRC"; then
    {
        echo
        echo "$PATH_MARKER"
        echo "export PATH=\"$OPENCODE_BIN_DIR:\$PATH\""
    } >> "$LLM_BASHRC"
    chown "$LLM_USER:$LLM_GROUP" "$LLM_BASHRC"
fi

# opencode-sandboxed bind-mounts these two dirs into the jail so config and
# credentials persist across sessions. Unlike ~/.opencode/bin (created by the
# installer's own `mkdir -p`), opencode only creates these lazily on first
# config write / first `opencode auth login` — so on a completely fresh
# install, bwrap's --bind would fail with "No such file or directory" before
# opencode ever got the chance to create them itself. Pre-create them here.
install -d -o "$LLM_USER" -g "$LLM_GROUP" \
    "/home/$LLM_USER/.config/opencode" \
    "/home/$LLM_USER/.local/share/opencode"

# Default interactive launches of `opencode` through the bwrap+seccomp
# wrapper. Idempotent: guarded by its own marker. Note this is
# convenience-grade only — it covers interactive shells; the raw binary is
# still reachable via full path or `command opencode`. Pair with chattr +i on
# the shell-init files if you want this default to be tamper-resistant.
ALIAS_MARKER="# managed by setup-llm-restricted_for_opencode.sh: opencode sandbox alias"
if [ -f "$LLM_BASHRC" ] && ! grep -qF "$ALIAS_MARKER" "$LLM_BASHRC"; then
    {
        echo
        echo "$ALIAS_MARKER"
        echo "alias opencode='opencode-sandboxed'"
    } >> "$LLM_BASHRC"
    chown "$LLM_USER:$LLM_GROUP" "$LLM_BASHRC"
fi

echo "==> 4. Deny list: every dotfile/dotdir directly under \$HOME"
# Blanket-deny anything starting with '.' at the top of $HOME. Nothing is
# exempted. Symlinks are denied on both the link and the resolved target
# (when reachable).
shopt -s nullglob
for entry in "$INVOKING_HOME"/.??*; do
    if [ -L "$entry" ]; then
        # Symlinks don't carry meaningful ACLs on Linux (the kernel follows
        # them for permission checks). Deny on the resolved target instead.
        target=$(readlink -f "$entry" 2>/dev/null || true)
        if [ -n "$target" ] && [ -e "$target" ]; then
            if [ -d "$target" ]; then
                setfacl -R    -m "g:$LLM_GROUP:---" "$target" 2>/dev/null || true
                setfacl -R -d -m "g:$LLM_GROUP:---" "$target" 2>/dev/null || true
            else
                setfacl -m "g:$LLM_GROUP:---" "$target" 2>/dev/null || true
            fi
        fi
    elif [ -d "$entry" ]; then
        setfacl -R    -m "g:$LLM_GROUP:---" "$entry" 2>/dev/null || true
        setfacl -R -d -m "g:$LLM_GROUP:---" "$entry" 2>/dev/null || true
    elif [ -e "$entry" ]; then
        setfacl -m "g:$LLM_GROUP:---" "$entry" 2>/dev/null || true
    fi
done
shopt -u nullglob

echo "==> 5. Deny list: sensitive files + dirs under each allowed dir"
for dir in $LLM_ALLOWED_DIRS; do
    find "$dir" -type f \( \
           -name '.env'         -o \
           -name '.env.*'       -o \
           -name '*.pem'        -o \
           -name '*.key'        -o \
           -name 'id_rsa*'      -o \
           -name 'id_ed25519*'  -o \
           -name 'terraform.tfstate'        -o \
           -name 'terraform.tfstate.backup' -o \
           -name 'credentials.json'         -o \
           -name 'credentials' \
        \) -exec setfacl -m "g:$LLM_GROUP:---" {} +

    while IFS= read -r -d '' subdir; do
        setfacl -R    -m "g:$LLM_GROUP:---" "$subdir"
        setfacl -R -d -m "g:$LLM_GROUP:---" "$subdir"
    done < <(find "$dir" -type d \( -name '.aws' -o -name '.ssh' -o -name '.terraform' \) -prune -print0)
done

if [ "$CREATE_SUDOERS" -eq 1 ]; then
    echo "==> 6. Sudoers wrapper for ergonomic switching"
    # Filename keyed by $LLM_USER so this doesn't overwrite the Claude
    # sandbox user's sudoers entry (or vice versa).
    cat > "/etc/sudoers.d/$LLM_USER" <<SUDOERS
$INVOKING_USER ALL=($LLM_USER) NOPASSWD: /bin/bash
SUDOERS
    chmod 0440 "/etc/sudoers.d/$LLM_USER"
    visudo -cf "/etc/sudoers.d/$LLM_USER" >/dev/null
fi

echo "==> 7. Convenience alias '$SW_ALIAS' in $INVOKING_HOME/.alias"
# Idempotent: marker line guards against duplication on re-runs. The user is
# expected to source ~/.alias from their shell rc (~/.bashrc / ~/.zshrc).
# Marker is keyed by $SW_ALIAS so this adds its own entry alongside the
# Claude sandbox's "sw" alias instead of clobbering it.
ALIAS_FILE="$INVOKING_HOME/.alias"
ALIAS_MARKER="# managed by setup-llm-restricted_for_opencode.sh: $SW_ALIAS"
if [ ! -f "$ALIAS_FILE" ]; then
    touch "$ALIAS_FILE"
    chown "$INVOKING_USER:$(id -gn "$INVOKING_USER")" "$ALIAS_FILE"
    chmod 0644 "$ALIAS_FILE"
fi
if ! grep -qF "$ALIAS_MARKER" "$ALIAS_FILE"; then
    {
        echo
        echo "$ALIAS_MARKER"
        echo "alias $SW_ALIAS='sudo -i -u $LLM_USER'"
    } >> "$ALIAS_FILE"
fi

echo "==> 8. AppArmor: allow bwrap to create user namespaces (Ubuntu 24.04+)"
# Ubuntu 23.10+ restricts unprivileged user namespaces via AppArmor
# (kernel.apparmor_restrict_unprivileged_userns=1). bwrap is not setuid, so the
# opencode-sandboxed wrapper can't unshare a userns and fails with
# "setting up uid map: Permission denied". A per-binary profile granting only
# `userns` exempts bwrap while leaving the global restriction on for everything
# else (least privilege). No-op when the restriction isn't active, bwrap is
# absent, or apparmor_parser isn't installed (e.g. non-Ubuntu hosts). Also a
# no-op if setup-llm-restricted_for_claude.sh already installed this profile —
# the profile applies to the bwrap binary itself, not to a specific user.
BWRAP_BIN=$(command -v bwrap || echo /usr/bin/bwrap)
RESTRICT=$(sysctl -n kernel.apparmor_restrict_unprivileged_userns 2>/dev/null || echo 0)
if [ "$RESTRICT" = "1" ] && [ -x "$BWRAP_BIN" ] && command -v apparmor_parser >/dev/null 2>&1; then
    cat > /etc/apparmor.d/bwrap <<APPARMOR
abi <abi/4.0>,
include <tunables/global>

profile bwrap $BWRAP_BIN flags=(unconfined) {
  userns,
  include if exists <local/bwrap>
}
APPARMOR
    apparmor_parser -r /etc/apparmor.d/bwrap
else
    echo "    skipped (restriction off, bwrap missing, or apparmor_parser absent)"
fi

# First entry of LLM_ALLOWED_DIRS for the smoke tests.
FIRST_ALLOWED=$(echo "$LLM_ALLOWED_DIRS" | awk '{print $1}')

echo
echo "==> Done. Quick smoke tests:"
echo
echo "  id $LLM_USER"
id "$LLM_USER"
echo
echo "  Enumerate $INVOKING_HOME — expect 'Permission denied':"
sudo -u "$LLM_USER" ls "$INVOKING_HOME" 2>&1 | sed 's/^/    /' || true
echo
echo "  Read $INVOKING_HOME/.ssh — expect 'Permission denied' (or 'No such file'):"
sudo -u "$LLM_USER" ls "$INVOKING_HOME/.ssh" 2>&1 | sed 's/^/    /' || true
echo
echo "  Write+delete in $FIRST_ALLOWED:"
sudo -u "$LLM_USER" bash -c "echo ok > $FIRST_ALLOWED/.llm_test && rm $FIRST_ALLOWED/.llm_test && echo PASS" 2>&1 | sed 's/^/    /'
echo
echo "  opencode installed for $LLM_USER:"
if [ -x "$OPENCODE_BIN_DIR/opencode" ]; then
    echo "    PASS ($OPENCODE_BIN_DIR/opencode)"
else
    echo "    MISSING — install it as $LLM_USER (see step 3)"
fi
echo
echo "Run interactively with:  sudo -i -u $LLM_USER"
echo "Then:                    opencode"
echo "(first run: 'opencode auth login' — creds stored in /home/$LLM_USER/.local/share/opencode/)"

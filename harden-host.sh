#!/bin/bash
# Optional host-wide hardening for the llm_restricted sandbox.
# Run *after* setup-llm-restricted_for_claude.sh has created the user.
#
# Run with: sudo bash harden-host.sh
#
# Knobs:
#   LLM_USER=llm_restricted              # which UID to filter
#   APPLY_EGRESS=0                       # 1 → install FQDN allowlist (breaks web)
#   ALLOW_PACKAGE_REGISTRIES=0           # 1 → also allow npm/pypi (only with APPLY_EGRESS=1)
#   EXTRA_FQDNS=""                       # space-separated extra hostnames to allow

set -euo pipefail

LLM_USER="${LLM_USER:-llm_restricted}"
APPLY_EGRESS="${APPLY_EGRESS:-0}"
ALLOW_PACKAGE_REGISTRIES="${ALLOW_PACKAGE_REGISTRIES:-0}"
EXTRA_FQDNS="${EXTRA_FQDNS:-}"

if [ "$(id -u)" -ne 0 ]; then
    echo "Must run as root (sudo bash $0)" >&2
    exit 1
fi

LLM_UID=$(id -u "$LLM_USER" 2>/dev/null || true)
if [ -z "$LLM_UID" ]; then
    echo "User '$LLM_USER' not found — run setup-llm-restricted_for_claude.sh first" >&2
    exit 1
fi

echo "Hardening host for $LLM_USER (UID $LLM_UID)"
echo

# ── 1. Disable systemd lingering ─────────────────────────────────────────────
echo "==> 1. Disabling systemd lingering for $LLM_USER"
# Without lingering, the user manager (and any --user units / timers it runs)
# only stays alive while a session is active. With lingering enabled, a
# malicious cron-like unit could persist across reboots without anyone logged
# in as that user.
loginctl disable-linger "$LLM_USER" 2>/dev/null || true

# Verify by checking for /var/lib/systemd/linger/<user> (the marker file
# loginctl creates when lingering is enabled). Avoids the misleading
# "User ID … is not logged in or lingering" error that `loginctl show-user`
# emits for an account with no active session — which is the *expected*
# state for our locked sandbox user.
if [ -e "/var/lib/systemd/linger/$LLM_USER" ]; then
    echo "    Linger=yes (unexpected — disable-linger may have failed)"
else
    echo "    Linger=no (correct — user-level units won't persist without a session)"
fi
echo

# ── 2. nftables: IMDS block (always) + optional egress allowlist ────────────
# IMDS (cloud instance metadata at 169.254.169.254) is always blocked for
# this UID — cheap, no false positives off-cloud. The full FQDN allowlist
# is opt-in via APPLY_EGRESS=1 because it breaks any web fetch outside the
# allowlist, which many users don't want.
echo "==> 2. nftables (IMDS block always; egress allowlist if APPLY_EGRESS=1)"

NFT_FILE=/etc/nftables.d/llm_egress.nft
mkdir -p /etc/nftables.d

if [ "$APPLY_EGRESS" -eq 1 ]; then
    ALLOW_FQDNS=(
        api.anthropic.com
        statsig.anthropic.com
        claude.ai
        github.com
        api.github.com
        codeload.github.com
        objects.githubusercontent.com
        raw.githubusercontent.com
    )
    if [ "$ALLOW_PACKAGE_REGISTRIES" -eq 1 ]; then
        ALLOW_FQDNS+=(registry.npmjs.org pypi.org files.pythonhosted.org)
    fi
    for fqdn in $EXTRA_FQDNS; do
        ALLOW_FQDNS+=("$fqdn")
    done

    declare -A IPS=()
    for fqdn in "${ALLOW_FQDNS[@]}"; do
        while IFS= read -r ip; do
            [ -n "$ip" ] && IPS["$ip"]=1
        done < <(getent ahostsv4 "$fqdn" 2>/dev/null | awk '{print $1}' | sort -u)
    done
    if [ "${#IPS[@]}" -eq 0 ]; then
        echo "    DNS resolution failed for every entry — refusing to install rules" >&2
        exit 1
    fi
    echo "    APPLY_EGRESS=1: ${#IPS[@]} IPv4 addresses across ${#ALLOW_FQDNS[@]} hostnames"

    {
        printf 'table inet llm_egress {\n'
        printf '    set allow_v4 {\n'
        printf '        type ipv4_addr\n'
        printf '        elements = {\n'
        printf '            %s,\n' "${!IPS[@]}" | sed '$ s/,$//'
        printf '        }\n'
        printf '    }\n\n'
        printf '    chain output {\n'
        printf '        type filter hook output priority 0; policy accept;\n\n'
        printf '        # Only this UID is filtered\n'
        printf '        meta skuid != %s accept\n\n' "$LLM_UID"
        printf '        # Always drop cloud metadata for this UID\n'
        printf '        ip daddr 169.254.169.254 drop\n\n'
        printf '        # Loopback + DNS\n'
        printf '        oif lo accept\n'
        printf '        udp dport 53 accept\n'
        printf '        tcp dport 53 accept\n\n'
        printf '        # HTTPS only to the resolved allowlist\n'
        printf '        ip daddr @allow_v4 tcp dport 443 accept\n\n'
        printf '        # Drop everything else for this UID\n'
        printf '        counter drop\n'
        printf '    }\n'
        printf '}\n'
    } > "$NFT_FILE"
else
    echo "    APPLY_EGRESS=0: only the IMDS drop is installed (egress allowlist skipped)."
    {
        printf 'table inet llm_egress {\n'
        printf '    chain output {\n'
        printf '        type filter hook output priority 0; policy accept;\n\n'
        printf '        # Only this UID is filtered\n'
        printf '        meta skuid != %s accept\n\n' "$LLM_UID"
        printf '        # Drop cloud metadata for this UID\n'
        printf '        ip daddr 169.254.169.254 drop\n'
        printf '    }\n'
        printf '}\n'
    } > "$NFT_FILE"
fi

# Replace any previous version of the table, then load the new one.
nft list table inet llm_egress >/dev/null 2>&1 && nft delete table inet llm_egress
nft -f "$NFT_FILE"

# Persist across reboots by including the file from /etc/nftables.conf
if [ -f /etc/nftables.conf ] && ! grep -qF "$NFT_FILE" /etc/nftables.conf; then
    {
        echo
        echo "# llm_restricted IMDS block / egress (managed by harden-host.sh)"
        echo "include \"$NFT_FILE\""
    } >> /etc/nftables.conf
fi
systemctl enable --now nftables 2>/dev/null || true
echo "    rules loaded; persisted via /etc/nftables.conf"
echo

# ── Smoke tests ──────────────────────────────────────────────────────────────
echo "==> Smoke tests (run as $LLM_USER):"
echo
echo "  IMDS block — expect timeout / connection refused:"
sudo -u "$LLM_USER" curl -s --max-time 3 -o /dev/null -w '    HTTP %{http_code}, exit %{exitcode}\n' http://169.254.169.254/latest/meta-data/ 2>&1 | sed 's/^/    /' || echo "    (curl exited non-zero — expected)"
echo
echo "  Blocked host (example.com) — expect failure:"
sudo -u "$LLM_USER" curl -s --max-time 3 -o /dev/null -w '    HTTP %{http_code}, exit %{exitcode}\n' https://example.com 2>&1 | sed 's/^/    /' || echo "    (curl exited non-zero — expected)"
echo
echo "  Allowed host (api.anthropic.com) — expect 200/4xx (a real response):"
sudo -u "$LLM_USER" curl -sI --max-time 5 https://api.anthropic.com 2>&1 | head -1 | sed 's/^/    /' || true
echo
echo "  Lingering — expect Linger=no:"
if [ -e "/var/lib/systemd/linger/$LLM_USER" ]; then
    echo "    Linger=yes (unexpected)"
else
    echo "    Linger=no"
fi
echo
echo "Re-run this script to refresh DNS-resolved IPs (consider a daily systemd timer)."

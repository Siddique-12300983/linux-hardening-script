#!/usr/bin/env bash
#
# harden.sh - baseline hardening for a fresh Debian or Ubuntu server.
#
# What it does:
#   1. Configures the UFW firewall (default deny inbound, rate-limited SSH).
#   2. Disables root SSH login and password authentication (key auth only).
#   3. Installs and configures fail2ban to ban repeated SSH failures.
#   4. Applies baseline sysctl network hardening.
#
# It is idempotent: running it twice gives the same result and does not stack
# up duplicate rules or config. Every managed file is written to a drop-in
# directory so the distro's own config is left untouched.
#
# Usage:
#   sudo ./harden.sh --dry-run     # print what would change, change nothing
#   sudo ./harden.sh               # apply
#   sudo ./harden.sh --force       # apply even if no SSH key is present
#
# Run it on the box you want to harden, not on your workstation.

set -euo pipefail

# --- settings ---------------------------------------------------------------

SSH_PORT="${SSH_PORT:-22}"            # change if your SSH runs on a custom port
SSHD_DROPIN="/etc/ssh/sshd_config.d/99-hardening.conf"
SYSCTL_DROPIN="/etc/sysctl.d/99-hardening.conf"
FAIL2BAN_JAIL="/etc/fail2ban/jail.d/sshd-hardening.conf"

DRY_RUN=0
FORCE=0

# --- small helpers ----------------------------------------------------------

c_info() { printf '\033[0;34m[*]\033[0m %s\n' "$*"; }
c_ok()   { printf '\033[0;32m[+]\033[0m %s\n' "$*"; }
c_warn() { printf '\033[0;33m[!]\033[0m %s\n' "$*"; }
c_err()  { printf '\033[0;31m[x]\033[0m %s\n' "$*" >&2; }

# run: execute a command, or just print it in dry-run mode.
run() {
    if [[ "$DRY_RUN" -eq 1 ]]; then
        printf '    would run: %s\n' "$*"
    else
        "$@"
    fi
}

# write_managed <path>: read the desired content from stdin and install it at
# <path>, but only when it differs from what is already there. Keeps a one-time
# .orig backup of any pre-existing file. Idempotent by design.
write_managed() {
    local path="$1"
    local new; new="$(cat)"

    if [[ -f "$path" ]] && [[ "$(cat "$path")" == "$new" ]]; then
        c_ok "$path already up to date"
        return 0
    fi

    if [[ "$DRY_RUN" -eq 1 ]]; then
        c_info "would write $path:"
        printf '%s\n' "$new" | sed 's/^/        | /'
        return 0
    fi

    run mkdir -p "$(dirname "$path")"
    if [[ -f "$path" && ! -f "$path.orig" ]]; then
        cp -a "$path" "$path.orig"
        c_info "backed up existing $path to $path.orig"
    fi
    printf '%s\n' "$new" > "$path"
    c_ok "wrote $path"
}

# --- checks -----------------------------------------------------------------

require_root() {
    if [[ "$DRY_RUN" -eq 0 && "${EUID:-$(id -u)}" -ne 0 ]]; then
        c_err "this script needs root to apply changes. Re-run with sudo, or use --dry-run."
        exit 1
    fi
}

detect_os() {
    if [[ ! -r /etc/os-release ]]; then
        c_err "cannot read /etc/os-release; this script targets Debian and Ubuntu."
        exit 1
    fi
    # shellcheck disable=SC1091
    . /etc/os-release
    case "${ID:-}:${ID_LIKE:-}" in
        *debian*|*ubuntu*)
            c_ok "detected ${PRETTY_NAME:-Debian/Ubuntu}"
            ;;
        *)
            c_err "this script targets Debian/Ubuntu. Found: ${PRETTY_NAME:-unknown}."
            exit 1
            ;;
    esac
}

# Disabling password auth locks out anyone without an SSH key. Check that at
# least one account has an authorized_keys file before we do it.
check_ssh_key_present() {
    local found=0 f
    for f in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do
        if [[ -s "$f" ]]; then
            found=1
            c_ok "found SSH key(s) in $f"
        fi
    done
    if [[ "$found" -eq 0 ]]; then
        if [[ "$FORCE" -eq 1 ]]; then
            c_warn "no authorized_keys found, but --force was given; continuing."
        else
            c_err "no authorized_keys found anywhere. Disabling password auth now would"
            c_err "lock you out. Add your public key first, or re-run with --force if you"
            c_err "already have another way in (console, cloud key injection)."
            exit 1
        fi
    fi
}

# --- hardening steps --------------------------------------------------------

harden_ssh() {
    c_info "Hardening SSH (drop-in: $SSHD_DROPIN)"
    write_managed "$SSHD_DROPIN" <<EOF
# Managed by harden.sh. Baseline SSH hardening.
Port ${SSH_PORT}
PermitRootLogin no
PasswordAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
KbdInteractiveAuthentication no
UsePAM yes
PubkeyAuthentication yes
X11Forwarding no
AllowAgentForwarding no
MaxAuthTries 3
MaxSessions 4
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
EOF

    # Validate config before reloading so a typo can't take sshd down.
    if [[ "$DRY_RUN" -eq 1 ]]; then
        printf '    would run: sshd -t && systemctl reload ssh\n'
    else
        if sshd -t; then
            run systemctl reload ssh 2>/dev/null || run systemctl reload sshd
            c_ok "SSH config validated and service reloaded"
        else
            c_err "sshd -t rejected the config; not reloading. Check $SSHD_DROPIN."
            return 1
        fi
    fi
}

configure_ufw() {
    c_info "Configuring UFW firewall"
    if ! command -v ufw >/dev/null 2>&1; then
        run apt-get update
        run apt-get install -y ufw
    else
        c_ok "ufw already installed"
    fi

    # These are all idempotent: ufw de-duplicates rules.
    run ufw default deny incoming
    run ufw default allow outgoing
    # limit adds a rate limit (6 connections / 30s per IP) on top of allow.
    run ufw limit "${SSH_PORT}/tcp"
    run ufw --force enable
    if [[ "$DRY_RUN" -eq 0 ]]; then
        ufw status verbose | sed 's/^/        /'
    fi
}

install_fail2ban() {
    c_info "Installing and configuring fail2ban"
    if ! command -v fail2ban-server >/dev/null 2>&1; then
        run apt-get update
        run apt-get install -y fail2ban
    else
        c_ok "fail2ban already installed"
    fi

    write_managed "$FAIL2BAN_JAIL" <<EOF
# Managed by harden.sh. Ban hosts that fail SSH auth repeatedly.
[sshd]
enabled  = true
port     = ${SSH_PORT}
backend  = systemd
maxretry = 4
findtime = 10m
bantime  = 1h
EOF

    run systemctl enable fail2ban
    run systemctl restart fail2ban
    c_ok "fail2ban enabled with an sshd jail (4 tries / 10m -> 1h ban)"
}

harden_sysctl() {
    c_info "Applying sysctl network hardening (drop-in: $SYSCTL_DROPIN)"
    write_managed "$SYSCTL_DROPIN" <<'EOF'
# Managed by harden.sh. Baseline network hardening.

# Ignore ICMP redirects; an attacker on the path can use these to reroute you.
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0

# Do not act as a router unless you mean to.
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.ip_forward = 0

# Reject source-routed packets; the source should not get to pick the path.
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0

# Reverse-path filtering: drop packets whose source could not have come from
# the interface they arrived on (anti-spoofing).
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Log packets with impossible addresses (martians).
net.ipv4.conf.all.log_martians = 1

# SYN cookies help absorb SYN-flood attempts.
net.ipv4.tcp_syncookies = 1

# Ignore ICMP echo broadcasts (Smurf amplification) and bogus error responses.
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
EOF

    if [[ "$DRY_RUN" -eq 1 ]]; then
        printf '    would run: sysctl --system\n'
    else
        run sysctl --system >/dev/null
        c_ok "sysctl settings applied"
    fi
}

# --- argument parsing -------------------------------------------------------

usage() {
    # Print the header comment block (between the shebang and the first code line).
    sed -n '3,20p' "$0" | sed 's/^# \{0,1\}//'
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --dry-run) DRY_RUN=1 ;;
            --force)   FORCE=1 ;;
            -h|--help) usage; exit 0 ;;
            *) c_err "unknown option: $1"; usage; exit 2 ;;
        esac
        shift
    done
}

# --- main -------------------------------------------------------------------

main() {
    parse_args "$@"

    if [[ "$DRY_RUN" -eq 1 ]]; then
        c_warn "DRY RUN: no changes will be made."
    fi

    require_root
    detect_os
    check_ssh_key_present

    harden_ssh
    configure_ufw
    install_fail2ban
    harden_sysctl

    echo
    if [[ "$DRY_RUN" -eq 1 ]]; then
        c_info "Dry run complete. Re-run without --dry-run to apply."
    else
        c_ok "Hardening complete."
        c_warn "Open a NEW SSH session to confirm you can still log in before closing this one."
    fi
}

main "$@"

# linux-hardening-script

A Bash script that applies a baseline set of hardening steps to a fresh Debian
or Ubuntu server: firewall, SSH lockdown, fail2ban, and sysctl network settings.
It is idempotent and has a `--dry-run` mode, so you can see every change before
anything touches the system.

I wrote this to stop hand-editing the same config on every new VM. It is a
starting baseline, not a full CIS benchmark.

## Why harden a fresh box

A default server install leaves a few things open that are worth closing on day
one: root can log in over SSH, passwords are accepted (so the box can be
brute-forced), and the kernel accepts network messages like ICMP redirects and
source routing that an attacker on the path can abuse. This script closes those
and adds a firewall and fail2ban so repeated failures get banned.

## What it does

| Step | Change | Why it matters |
|---|---|---|
| UFW firewall | Default deny inbound, allow outbound, rate-limit SSH | Only the ports you choose are reachable; `limit` slows SSH brute-forcing |
| SSH | `PermitRootLogin no`, `PasswordAuthentication no`, `MaxAuthTries 3`, no X11/agent forwarding, login grace and keepalive limits | Forces key-based auth and removes the easiest ways in |
| fail2ban | sshd jail: 4 failures in 10 minutes earns a 1 hour ban | Bans the IPs doing the brute-forcing, on top of the firewall rate limit |
| sysctl | Ignore ICMP redirects, drop source-routed packets, reverse-path filter, SYN cookies, ignore broadcast pings, log martians | Removes network tricks used for spoofing, rerouting and amplification |

Every managed file is written to a drop-in directory
(`/etc/ssh/sshd_config.d/`, `/etc/sysctl.d/`, `/etc/fail2ban/jail.d/`), so your
distribution's own config files are left alone and the changes are easy to find
and reverse.

## Safety

- **Lockout guard.** Disabling password auth locks out anyone without an SSH
  key. The script checks for an `authorized_keys` file first and refuses to run
  if it finds none, unless you pass `--force`. Add your public key before you
  run it.
- **SSH config is validated** with `sshd -t` before the service is reloaded, so
  a bad setting cannot take SSH down.
- **Idempotent.** Managed files are only rewritten when their content changes,
  and UFW de-duplicates rules, so running it twice is safe.
- After applying, open a **new** SSH session to confirm you can still log in
  before you close the current one.

## Requirements

- Debian or Ubuntu (checked from `/etc/os-release`; it refuses to run elsewhere)
- root (via `sudo`) to apply changes
- An SSH public key already installed for your user

## Usage

```bash
# See every change without applying anything
sudo ./harden.sh --dry-run

# Apply
sudo ./harden.sh

# Apply even if no SSH key is found (you have another way in)
sudo ./harden.sh --force
```

SSH runs on port 22 by default. If yours is different, set it:

```bash
sudo SSH_PORT=2222 ./harden.sh
```

## Example (dry run)

```
[!] DRY RUN: no changes will be made.
[+] detected Ubuntu 24.04.1 LTS
[+] found SSH key(s) in /root/.ssh/authorized_keys
[*] Hardening SSH (drop-in: /etc/ssh/sshd_config.d/99-hardening.conf)
[*] would write /etc/ssh/sshd_config.d/99-hardening.conf:
        | PermitRootLogin no
        | PasswordAuthentication no
        | ...
[*] Configuring UFW firewall
    would run: ufw default deny incoming
    would run: ufw limit 22/tcp
...
[*] Dry run complete. Re-run without --dry-run to apply.
```

## A note on testing

I validate this script with `bash -n` and
[shellcheck](https://www.shellcheck.net/) rather than running it on my own
machine, since its whole job is to change a system's SSH and firewall config.
The GitHub Actions workflow runs both checks on every push. To test the actual
behaviour, run it on a throwaway Debian or Ubuntu VM.

```bash
bash -n harden.sh
shellcheck harden.sh
```

## Reversing it

The changes live in named drop-in files. To undo them:

```bash
sudo rm /etc/ssh/sshd_config.d/99-hardening.conf
sudo rm /etc/sysctl.d/99-hardening.conf
sudo rm /etc/fail2ban/jail.d/sshd-hardening.conf
sudo systemctl reload ssh && sudo sysctl --system && sudo systemctl restart fail2ban
sudo ufw disable   # if you want the firewall off again
```

## License

MIT. See [LICENSE](LICENSE).

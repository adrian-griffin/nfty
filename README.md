# nfty

<!-- SHIELDS -->
[![Version][version-shield]][version-url]
[![MIT License][license-shield]][license-url]  
[![Go Reference][reference-shield]][reference-url]
[![Go Version][goversion-shield]][goversion-url]
[![Go Report Card][reportcard-shield]][reportcard-url]

<br/>

A network firewall manager for Linux, aimed at simplifying management and providing more visibility, with rollback & lockout-prevention safety features inspired by enterprise network routers, such as Arista/Juniper/Mikrotik, written in go.

- uses `nftables` under the hood
- diffing of planned changes
- lockout prevention and config rollback
- packet counters
- docker compatibility

## Why?

The NFTables user experience is obtuse, visibility is terrible, and lockout is as easy as accidentally wiping the wrong table..

***Every time*** a ruleset is applied by nfty, automatic config rollback is put on a timer, stopped only when the user approves changes with a `nfty confirm` (30s default). If you accidentally lock yourself out or kill some service functionality, changes will revert upon timer expire or user-supplied `nfty rollback`.  
The intent is to function similarly to `commit confirmed` or `safe mode` functions of enterprise-grade network equipment, and to make changes and tinkering more approachable.  
Additional details on how the rollback functionality works can be found here [Commit Confirm/Rollback](#commit-confirmrollback)

nfty uses simple `.toml` config for defining rulesets, chains, IP address lists, etc., and handles atomic ruleset application to the system.  
Config is linted for basic sanity and security, such as detecting SSH connections to prevent shell lockout, warning when a socket is open to all addresses or interfaces, etc.

Defining config is made as simple as possible. IPv6 is native and always defined, SSH attempt logging is toggleable, the `default_rules` option handles basic sanity rules (eg. `ICMP`, `Established, Related`, `Invalid`, `SLAAC`, and `DHCP (v4 & v6)`), and entries for both `[tcp, udp]` protocols can be defined in a single rule with nfty, but function as 2 individual rules on the kernel. 

Tracking changes and their effect on traffic is made easy with colourized diffs and human-readable packet counters (and eventually, maybe packet graphs), so it's easy to tinker and troubleshoot when hardening systems.

## Scope

The number one question anyone should be asking when looking at at tool like this is the scope or.. blast radius, if things go south.

nfty *only* edits and participates in its own NFTables table, and doesn't write to or touch other user-defined tables or docker tables, but nfty *does* snapshot **ALL** config for restoration. 

This means you can feel secure that nfty will never break other, existing NFTables configuration, but it will backup, store, and persist it, read-only.

## Requirements

- Linux with `nftables`
- `sudo`/`root` privileges (required for nftables interaction)
- `systemd` (for rollback timer functionality)

## Install

```bash
go install github.com/adrian-griffin/nfty/cmd/nfty@latest
```

Or build from source:

```bash
git clone https://github.com/adrian-griffin/nfty.git
cd nfty
go build -o nfty ./cmd/nfty
sudo mv nfty /usr/local/bin/
```

Requires `nft` (nftables) to be installed and available in PATH

```bash
sudo apt-get install nftables -y

sudo systemctl restart nftables  # start nft
sudo systemctl enable nftables   # nft on startup
```

## Commit Confirm/Rollback

Importantly, the rollback timer is a systemd transient unit (`systemd-run`), **NOT** a sleep in the CLI process. Rollback survives shell death, SSH disconnects, and terminal crashes. Bar the machine rebooting mid-timer, it can be relied on.

Even if it's been 30 mins after the user approves changes with a `nfty confirm`, running a `nfty rollback` will instantly revert the firewall to the previous state, in case you discover issue with new changes at any point.

## 101

```bash
# validate a nfty toml config
nfty check config.toml

# preview changes against the current, live ruleset
nfty diff config.toml

# apply with 60s rollback timer
nfty apply config.toml --commit-confirm=60

# if everything looks good, confirm
nfty confirm

# if something went wrong, rollback (or just wait for timer expire)
nfty rollback

# to view table of rules & statistics
nfty counters
```

## Config Example

```toml
[core]
  name          = "my-firewall"
  description   = "homelab node - jan-01-1970"
  table         = "nfty-default"

  docker_compat = true
  persist       = true
  default_rules = true
  icmp_limit  = "10/s"
  log_ssh_fails = true

[chains.policy]
  input   = "drop"
  forward = "drop"
  output  = "accept"

[lists.ipv4.ssh]
  comment = "SSH allowlist"
  entries = [
    "10.0.0.0/24",
    "192.168.1.5/32",
  ]

[[chains.ipv4.input]]
  comment  = "Allow SSH from trusted hosts"
  protocol = "tcp"
  dport    = [22]
  src_list = "ssh"
  action   = "accept"

[[chains.ipv4.input]]
  comment    = "Rate-limited HTTPS/HTTP"
  protocol   = "tcp"
  dport      = [443,80]
  action     = "accept"
  rate_limit = { rate = "20/second", action = "accept", burst = "40 packets" }
  over_limit = "drop"
```

## Usage

```bash
nfty version                          show version info
nfty check <config.toml>              validate config and show summary
    --list-ruleset                      show generated nftables script
nfty diff <config.toml>               diff proposed config against live ruleset
nfty apply <config.toml>              apply config with commit-confirm safety
    --commit-confirm <seconds>          set rollback timer (default: 30)
    --skip-confirm                      skip rollback timer (dangerous)
nfty confirm                          confirm pending apply
nfty rollback                         revert to previous ruleset snapshot
nfty status                           show current state and pending changes
    --list-ruleset                      show full live nftables ruleset
nfty counters                         display per-rule hit counters
```

## State Files

nfty stores state and metadata in `/var/nfty/`:

| File | Purpose |
|---|---|
| `rollback.nft` | Pre-apply ruleset snapshot for emergency restoration |
| `running.nft` | Last confirmed ruleset (for boot persistence) |
| `pending.json` | Metadata for in-flight applies awaiting confirmation |
| `last-apply.json` | Metadata from the most recent confirmed apply |

## Docker Compatibility

When `docker_compat = true`, nfty sets its chain priorities to `filter + 10`, ensuring nfty's rulesets evaluate *after* Docker's auto-generated ones. This lets Docker's networking remain operational, and inter-container or host-level forwarding be handled by nfty.


<!-- SHIELD URLS -->
[version-shield]: https://img.shields.io/github/v/release/adrian-griffin/nfty?label=version
[version-url]: https://github.com/adrian-griffin/nfty/releases

[reference-shield]: https://pkg.go.dev/badge/github.com/adrian-griffin/nfty.svg
[reference-url]: https://pkg.go.dev/github.com/adrian-griffin/nfty

[reportcard-shield]: https://goreportcard.com/badge/github.com/adrian-griffin/nfty
[reportcard-url]: https://goreportcard.com/report/github.com/adrian-griffin/nfty

[license-shield]: https://img.shields.io/github/license/adrian-griffin/nfty
[license-url]: https://github.com/adrian-griffin/nfty/blob/main/LICENSE

[goversion-shield]: https://img.shields.io/github/go-mod/go-version/adrian-griffin/nfty
[goversion-url]: https://go.dev/dl/
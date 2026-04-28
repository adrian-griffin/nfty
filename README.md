# nfty

A network firewall manager for Linux, aimed at simplifying management and changes, with rollback & lockout prevention safety features inspired by enterprise-grade network routers, such as Arista/Juniper/Mikrotik, written in go.

- uses `nftables` under the hood
- allows diffing of planned changes
- lockout prevention and config rollback
- packet counters (and eventually, rate graphs)
- docker compatibility

## Why?

NFTables' user experience is tough, visibility is shite, and lockout certainly isn't as low as you'd hope 👀

*Every time* a ruleset is applied by nfty, automatic config rollback is put on a timer, stopped only when the user approves the changes with a `nfty confirm` (30s default). If you accidentally lock yourself out or kill service functionality, changes will revert upon timer expire or user-supplied `nfty rollback`.

nfty uses simple `.toml` config for defining rulesets, chains, IP address lists, etc., and handles atomic ruleset application to the system.  
Config is linted for basic sanity and security, such as detecting SSH connections to prevent shell lockout, warning when a socket is open to all addresses or interfaces, etc.

Defining config is made as simple as possible. IPv6 is native and always defined, SSH attempt logging is toggleable, the `default_rules` option handles basic sanity rules (eg. `ICMP`, `Established, Related`, `Invalid`, and `DHCP/SLAAC (v4 & v6)`), and entries for both `[tcp, udp]` protocols can be defined in one rule. 

Tracking changes and their effect on traffic is made easy with colourized diffs and human-readable packet counters (and eventually, maybe packet graphs)

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
  icmpv4_limit  = "10/s"
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

## Requirements

- Linux with `nftables`
- `sudo`/`root` privileges (required for nftables interaction)
- `systemd` (for rollback timer functionality)

## Scope

nfty only edits or participates in its own NFTables table, and doesn't touch other user-defined tables or docker tables, but it *does* snapshot **all** config for restoration. 

This means you can feel secure that nfty will not break other, existing NFTables configuration, but will backup, store, and persist it, read-only.

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

## Commit Confirm/Rollback

The rollback timer is a systemd transient unit (`systemd-run`), **not** a sleep in the CLI process. Rollback survives shell death, SSH disconnects, and terminal crashes. Bar the machine rebooting mid-timer, it can be relied on.

Even if it's been 30 mins after a `nfty confirm`, running a `nfty rollback` will instantly revert the firewall to the previous state, in case you discover issue with new changes.

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


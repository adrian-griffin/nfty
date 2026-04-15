# CHANGELOG

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [0.2.0] - 2026-Apr-14
- systemd daemon timer for rollback logic
- reading pending.json file for restore as needed
- fleshing out `apply` logic, partway complete
    - ruleset snapshotting
    - systemd timer creation
- final rollback logic
- `-dry-run` cleanup
- flush ruleset on rollback fix
- `nfty status` output overhaul

## [0.1.1] - 2026-Apr-14
- commit.go package creation
- rollback/snapshot capture bones
- running-config & write/persistence bones
- pending config logic+tracking for `nfty confirm` groundwork

## [0.1.0] - 2026-Apr-13
- topmost-level NFT config builder, generates full NFTables ruleset from `nfty` config
- Generate/full config builder wired into `nfty check` for live machine testing of nfty → nftables configs
- input flag sorter to allow more dynamic flag user inpts
- nft `flags intervals` (cidr/subnetting) auto-merge functionality

## [0.0.9] - 2026-Apr-13
- NFTables address-list/set conversion function
- NFT config output table builder
- ratelimit rule splitter generator (1 nfty = 2 nftables)
- rulebuilder that combines all lower-level rule tools to write fully-functional NFT-syntax rule
- topmost-level NFT config builder, generates full NFTables ruleset from nfty config
- traces on logic, minor ip family naming mismatches, minor bug & verbiage cleanup

## [0.0.8] - 2026-Apr-13
- basic structure for nfty → NFTables config generation
- `default-rules` generation logic implemented (eg `established,related`, `drop: invalid`, etc)
- dport formatting function, such as for accepting port-ranges, port lists, etc.
- srcip formatting function, such as for accepint address-list names OR arrays of individual IPs
- ipv6 functionality for all of the above
- additional nfty → NFTables config generation
- chain, socket, and src-ip handling
- interface matching generation

## [0.0.7] - 2026-Apr-12
- the name is bond, james bond
- internal and minimal toml templates heavy overhauls
    - `default_rules` and other bool vars for cutting boilerplate config
    - toggle for logging blocked ssh attempts
- chain policy validations & sanitization
- allow array of protocols
- multiple config validation improvements

## [0.0.6] - 2026-Apr-12
- added chain policy .toml variables
- config apply scaffolding
    - framework for sub-option flags
    - dry run
    - skip rollback
    - commit confirm timeout
- basic `check` option logic

## [0.0.5] - 2026-Apr-12
- basic CLI flag parsing
- init main.go

## [0.0.4] - 2026-Apr-12
- loading tomlfile functionality
- validating built nft config syntax functionality
- port-value and port-range handling structs
- rule structure tweaking

## [0.0.3] - 2026-Apr-12
- init base structs for parsing toml configs
- defined basic firewall rule structure
- template tweaks

## [0.0.2] - 2026-Apr-12
- Create example/template TOML files
    - internal.toml - for internal/private network standard hosts
    - minimal.toml - for very basic or hardened setups
    - public-vps.toml - for public-facing servers, such as a VPS or cloud machine

## [0.0.1] - 2026-Apr-12
- Init of nfty
- Basic nftables json interactions and validations
- Prep for commit-confirmed/timer rollback

### Added
- Init versioning of `nfty`
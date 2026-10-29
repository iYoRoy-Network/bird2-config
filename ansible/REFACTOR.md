# Configuration Refactor

## Deployment Semantics

Full and scoped peer deployment share the BIRD and WireGuard Python helpers.
BIRD validates before reloading; failure restores and reloads the previous tree.
WireGuard stops changed interfaces using the old hooks, installs the new file,
and starts with the new addresses/MTU/hooks. Service failures trigger file and
service recovery. This can briefly interrupt a changed tunnel.
Recovery tracks active and enabled states separately. Scoped recovery restores
only the named configuration and its previous manifest. Helpers serialize
application with a lock, and each invocation uploads to an isolated directory.

These are per-component transactions, not one distributed transaction across
WireGuard and BIRD. A successful tunnel update remains applied if a subsequent
BIRD update fails. Inspect the failure before retrying. Rollback can also fail
if the host or service becomes unavailable; recovery results must be checked.

`deploy.wireguard.ignore_start_failures` may list interface names whose service
start failures should be reported but not abort a full or scoped deployment.
Their configs remain installed and enabled, and later deployments retry them.
This does not ignore validation, upload, stop, or other service failures.

Single-peer deployment modifies only its named peer, never other peer files.
It requires the current shared BIRD functions to have been deployed separately.
Production deployment is never part of the local verification workflow.
Full deployment verifies the node identity and content manifest both before
upload and again on the remote host. `--check` stops before remote mutations.
Failed deployments retain their staging directory and backups for inspection;
successful full deployments retain backups under the configured backup parent.
Successful scoped deployments remove their temporary backups.

## Configuration Ownership

`intra` is the mandatory underlay domain and its presence enables the internal
confederation. `dn42` and `iana` each have an independent `enabled` flag.
Their directories and includes are derived from that flag, so disabling one
domain leaves no files for it in the rendered artifact. `dn42.rpki.enabled`
controls its optional external RPKI client, while DN42 flap dampening tables
are always present whenever DN42 is enabled. The same `bird_modules` function
selects both generated files and includes.

The optional Flapalerted feed is configured as `intra.flapalerted`. Its target
node and BGP/RPKI ports are inherited from `intra_global.flapalerted` unless
overridden per node. It requires DN42 because it exports DN42 routes; the feed
itself remains an intra service, separate from DN42's always-on dampening
tables.

Route-domain origin ASNs live in `group_vars/all/domains.yml` under
`route_domains`. Templates emit numeric ASNs directly; the old `*_OWNAS` and
router-id macro layer is no longer part of the rendered configuration.

PoP geography belongs to `node.geo`. Peer/session geography remains independent.
`node.region` is the existing addressing/topology index, not a community region.
`node.wireguard.endpoint_host` is the tunnel endpoint hostname, independent of
SSH management inventory. It sits with the node's WireGuard public key. Public
node addresses use prefix + token exclusively.
External aggregates remain explicit in `iana.static.advertise_routes`.

## Normalized Intent

`filter_plugins/intent.py` converts input into normalized DN42 sessions and
effective intra/WireGuard lists. Templates render these records rather than
implementing legacy transport selection. Existing DN42 peer files and the
autopeer src/dst input remain supported at this boundary; new peers should use
`bgp.sessions` with explicit address families. Per-session geo overrides merge
with the peer's geo.

Automatic intra WireGuard listen ports are derived from the remote node's
confederation ASN: `10000 + (remote ASN mod 10000)`. A peer's explicit
`wireguard.listen_port` takes precedence. NAT nodes `hkg04-hk`, `tyo03-jp`, and
`cdg01-fr` are listed in `intra_global.wireguard_listen_port_manual_nodes` and
must keep explicit ports. Endpoint ports are resolved from the reciprocal
peer's effective listener, so NAT mappings and automatically derived ports
both work without duplicating endpoint values.

Each node's intra WireGuard public key is owned by `node.wireguard.public_key`.
Automatic intra peers reference that key through their node name; do not copy
the remote key into each peer entry. The separate `node.peering.publickey`
field remains part of the external peering metadata.

`wireguard.standalone_interfaces` is for transports independent of managed
peers. It remains supported and is validated alongside generated interfaces.
Duplicate names, ports, protocols, session files, missing reciprocal intra
links, and invalid policy names fail before rendering. CDG/LHR now use the same
node/domain schema and endpoint derivation as every other configured node.
Both are included in local rendering, validation, and CI; their Autopeer flags
remain disabled. Inclusion in these checks does not establish live service
status or trigger production deployment.

## Reproducible Rendering

IRR results are public, reviewable inputs in `ansible/irr/<node>.json`. Ordinary
rendering does not query IRR. Refresh explicitly when AS-SET intent or membership
changes, inspect the snapshot diff, and commit the desired results:

```sh
ansible-playbook -i ansible/inventory.yml ansible/playbooks/update-irr.yml
```

This is the only step requiring `bgpq4` and IRR network access. A snapshot whose
query mapping differs from current peer intent fails rendering. Membership
freshness is an operational choice; snapshots do not expire automatically.

Both renderers build in a temporary directory, validate there, and only then
publish. A failed build preserves the previous published artifact and cleans up
the temporary files. Publishing uses locked directory renames with recovery;
the two renames are not a zero-gap atomic exchange. Do not run render and
deployment concurrently: a racing upload will fail its remote manifest check
if it captures inconsistent contents.

Each `manifest.json` records node, component, source Git revision, source digest,
dirty state, and file digests. Source digests cover tracked and untracked Ansible
sources, excluding Git-ignored local secrets. Output file digests cover actual
rendered secrets without recording their plaintext in the manifest. A manifest
detects stale or accidentally edited contents; it is not a cryptographic
signature. Scoped updates invalidate the old full-tree live manifest.

## Local Checks

Use Python 3.10+ and `pip install -r ansible/requirements-dev.txt`. `bird` and
`birdc` are required for BIRD verification, and `wg-quick` for WireGuard syntax
checks. Missing binaries now fail render/validation instead of skipping checks.
Set `ANSIBLE_STDOUT_CALLBACK=default` when `community.general` is unavailable.
Provide the ignored local BIRD/WireGuard secret files for the normal workflow:

```sh
python3 -m unittest discover -s ansible/tests -v
ansible-playbook -i ansible/inventory.yml ansible/playbooks/render.yml
ansible-playbook -i ansible/inventory.yml ansible/playbooks/validate.yml
ansible-playbook -i ansible/inventory.yml ansible/playbooks/render-wireguard.yml
ansible-playbook -i ansible/inventory.yml ansible/playbooks/validate-wireguard.yml
```

Outputs are `.rendered/<node>` and `.rendered-wireguard/<node>`. The local
inventory excludes production connectivity, and tunnel endpoints are independent
of management addresses. GitHub Actions runs regression tests and full offline
BIRD rendering/validation using a dummy BGP password. WireGuard rendering with
real secrets remains a local check; CI never receives production secrets.

Internal public node announcements remain derived `/128` host routes. The
configured `node.public_ipv6_prefix` allocates addresses; it does not originate
that `/48`. External `/43` aggregates remain exclusively in
`iana.static.advertise_routes`. This refactor does not consolidate every link
into a global topology file or remove legacy peer input compatibility.

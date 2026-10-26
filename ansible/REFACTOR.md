# Configuration Refactor

## Deployment Semantics

Full and scoped peer deployment share the BIRD and WireGuard Python helpers.
BIRD validates before reloading; failure restores and reloads the previous tree.
WireGuard stops changed interfaces using the old hooks, installs the new file,
and starts with the new addresses/MTU/hooks. Service failures trigger file and
service recovery. This can briefly interrupt a changed tunnel.

These are per-component transactions, not one distributed transaction across
WireGuard and BIRD. A successful tunnel update remains applied if a subsequent
BIRD update fails. Inspect the failure before retrying. Rollback can also fail
if the host or service becomes unavailable; recovery results must be checked.

Single-peer deployment modifies only its named peer, never other peer files.
It requires the current shared BIRD functions to have been deployed separately.
Production deployment is never part of the local verification workflow.

## Configuration Ownership

Each domain has one `enabled` flag under `iana`, `dn42`, or `intra`. Removed
`modules.*` flags were not authoritative for IANA/DN42; migration preserves
their previous effective behavior. `dn42.rpki.enabled` controls its RPKI module.
The same `bird_modules` function selects both generated files and includes.

PoP geography belongs to `node.geo`. Peer/session geography remains independent.
`node.region` is the existing addressing/topology index, not a community region.
`node.wireguard_endpoint_host` is the tunnel endpoint hostname, independent of
SSH management inventory. Public node addresses use prefix + token exclusively.
External aggregates remain explicit in `iana.static.advertise_routes`.

## Normalized Intent

`filter_plugins/intent.py` converts input into normalized DN42 sessions and
effective intra/WireGuard lists. Templates render these records rather than
implementing legacy transport selection. Existing DN42 peer files and the
autopeer src/dst input remain supported at this boundary; new peers should use
`bgp.sessions` with explicit address families. Per-session geo overrides merge
with the peer's geo.

`wireguard.standalone_interfaces` is for transports independent of managed
peers. It remains supported and is validated alongside generated interfaces.
Duplicate names, ports, protocols, session files, missing reciprocal intra
links, and invalid policy names fail before rendering. Retired CDG/LHR host
definitions are left untouched; active peers use explicit CDG endpoints.

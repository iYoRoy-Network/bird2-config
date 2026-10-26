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

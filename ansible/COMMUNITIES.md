# Community Boundaries

The community registry is `group_vars/all/communities.yml`. IANA evaluates
AS205369 controls; DN42 evaluates AS4242422024 controls.

## External Import

`remove_internal_communities()` removes `FN_IDENTIFY` (2), `FN_GEO_SRC` (644),
and `FN_GEO_DST` (645) under each enabled own-AS namespace. External sessions
then assign their own origin and geography markers. This prevents imported
routes from supplying internal identities or another domain's geo markers.

All other communities, including peer-supplied own-AS export controls, survive
import and can travel through the confederation. Existing route validation
and internal origin requirements still apply.

## Internal Transport

Confederation and IANA iBGP sessions preserve identity, geography, and export
controls. They do not consume controls intended for external neighbors.
Existing NO_ADVERTISE restrictions still apply.

## External Export

The processing order is:

1. Apply the existing domain and origin eligibility checks.
2. Evaluate the domain's controls for the target ASN (deny/only, prepend, attach).
3. Remove confederation ASNs and internal identity/geography markers.
4. Remove implemented own-AS controls with `remove_export_control_communities()`.
5. Accept the route.

Control cleanup enumerates registry entries with the `FN_ATTACH_`, `FN_DENY_`,
`FN_ONLY_`, and `FN_PREPEND_` prefixes for enabled own ASNs. It does not delete
an entire ASN namespace. Third-party standard/large communities, ordinary
well-known communities, and unrecognized own-AS function codes pass through.
Unimplemented controls are preserved but have no local effect.

Runtime target matching uses `(own_as, function_code, peer_as) ~
bgp_large_community`. Set literals with runtime parameters parsed successfully
on BIRD 2.17.2 but failed the target-matching regression tests; constant
wildcard matching still uses sets.

## Verification

```sh
python3 -m unittest discover -s ansible/tests -v
```

The export tests execute rendered policy functions in an isolated BIRD
instance with static routes, empty ROA tables, and no kernel/BGP protocols.
They cover IANA peer/upstream/downstream policies, DN42 eBGP/IX IPv4 and IPv6,
ingress sanitation, confederation transport, and selective export cleanup.
They do not establish live BGP sessions.

Deploy the full BIRD configuration when updating these shared functions;
targeted peer deployment only updates the peer's session file.

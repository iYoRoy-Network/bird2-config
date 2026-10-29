# Community Boundaries

The community registry is `group_vars/all/communities.yml`. Intra route identity
uses AS4220240000; IANA evaluates AS205369 controls; DN42 evaluates
AS4242422024 controls.

## External Import

`remove_internal_communities()` removes `FN_IDENTIFY` (2), `FN_GEO_SRC` (644),
and `FN_GEO_DST` (645) under the intra, IANA, and DN42 namespaces, independent
of which route domains are enabled. External sessions then assign their own
origin and geography markers. This prevents imported routes from supplying
internal identities or another domain's geo markers.

All other communities, including peer-supplied own-AS export controls, survive
import and can travel through the confederation. Existing route validation
and internal origin requirements still apply.

## Internal Transport

Confederation and IANA iBGP sessions preserve identity, geography, and export
controls. Underlay loopbacks use `(4220240000, 2, 100)` independently of the
DN42 and IANA module switches. During migration, loopbacks also carry the old
DN42 and IANA identity markers so nodes can be updated without interrupting
route exchange. Internal sessions accept legacy markers only on underlay
prefixes. They do not consume controls intended for external neighbors.
Existing NO_ADVERTISE restrictions still apply.

## External Export

The processing order is:

1. Apply the existing domain and origin eligibility checks.
2. Evaluate the domain's controls for the target ASN and geography (deny/only,
   prepend, attach).
3. Remove confederation ASNs and all intra, DN42, and IANA identity/geography
   markers. These markers are internal-only and never leave an external peer.
4. Remove implemented own-AS controls with `remove_export_control_communities()`.
5. Accept the route.

Control cleanup enumerates registry entries with the `FN_ATTACH_`, `FN_DENY_`,
`FN_ONLY_`, and `FN_PREPEND_` prefixes for enabled own ASNs. It does not delete
an entire ASN namespace. Third-party standard/large communities, ordinary
well-known communities, and unrecognized own-AS function codes pass through.
Unimplemented controls are preserved but have no local effect.

### Geographic Export Controls

| Function | Argument | Behavior |
| --- | --- | --- |
| 650 | REGION | Deny export to peers in this region |
| 651 | REGION | Only export to peers in listed regions |
| 660 | COUNTRY | Deny export to peers in this country |
| 661 | COUNTRY | Only export to peers in listed countries |

The target location comes from the peer/session `geo` mapping, including DN42
per-session overrides. Missing fields default to the local PoP's location.
These checks do not use the route's 644/645 markers. Countries include the
ISO numeric +1000 offset: `205369:660:1392` denies IANA export to Japan.

Multiple values of the same `only` function form an allow list. Region,
country, and ASN constraints must all pass, and a matching deny overrides an
allow. Without a control of a given type, that type imposes no restriction.
For example, `[205369, COMM_FN_ONLY_REGION, GEO_REGION_ASIA_EAST]` together
with `[205369, COMM_FN_ONLY_COUNTRY, GEO_COUNTRY_JAPAN]` permits only peers
whose configured region is East Asia and country is Japan, subject to the
existing export eligibility checks.

### Geographic Prepending

| Function | Argument | Behavior |
| --- | --- | --- |
| 697 / 698 / 699 | REGION | Prepend own ASN 1 / 2 / 3 times to listed regions |
| 700 / 701 / 702 | REGION | Prepend own ASN 1 / 2 / 3 times outside listed regions |
| 703 / 704 / 705 | COUNTRY | Prepend own ASN 1 / 2 / 3 times to listed countries |
| 706 / 707 / 708 | COUNTRY | Prepend own ASN 1 / 2 / 3 times outside listed countries |

These controls use the same target peer/session `geo` mapping as deny/only,
not the route's 644/645 markers. Country values still include the +1000 offset.
For example, `205369:698:52` adds two AS205369 entries for East Asian peers;
`205369:708:1392` adds three for peers outside Japan. DN42 controls use the
AS4242422024 namespace and prepend AS4242422024 instead.

Multiple values of one function form a target list (or exclusion list for
`OTHERS`): the action runs at most once for that function, not once per tag.
An `OTHERS` action requires at least one tag of that function and does nothing
if the target is among its listed values. Without any prepend controls, no
extra ASN is added. Different matching prepend functions are additive,
including ASN-, region-, and country-based actions. Deny/only checks still
run first, and consumed controls are removed only on external export.
These counts are policy additions; normal eBGP AS_PATH processing still applies.

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
Geographic prepend cases cover every function's matching and non-matching
targets, multi-value lists, additive actions, and domain isolation.
They do not establish live BGP sessions.

Deploy the full BIRD configuration when updating these shared functions;
targeted peer deployment only updates the peer's session file.

# Route Geography

Both AS205369 and AS4242422024 use the same region and country registry:
`group_vars/all/geo.yml`. Regions use DN42 codes; countries use the ISO-3166-1
numeric code plus 1000, for example JAPAN = 1392.

On external BGP import, each domain replaces its own geography communities:

| Community | Meaning |
| --- | --- |
| `<own_as>:644:<region/country>` | Location of the remote end of this peering session |
| `<own_as>:645:<region/country>` | Location of the local PoP receiving the route |

These describe the peering endpoints, not the prefix registration country or
the ASN's headquarters. The tags survive internal confederation transport.
External exports strip internal identity/geography and implemented own-AS
export controls after applying the controls. Other communities pass through.
Locally originated business prefixes receive the PoP's location
for both 644 and 645; local-only `extra_routes` are not tagged automatically.

## Peer Configuration

DN42 peer files (`host_vars/<node>/dn42-peers/<asn>.yml`) have a top-level field:

```yaml
geo:
  region: ASIA_EAST
  country: JAPAN
```

Use the same `geo` field on each IANA `peers`, `upstreams4`, `upstreams6`, or
`downstreams` entry and on each DN42 `ix.sessions` entry. Existing peers on
operational nodes were initialized with their local node's location as a
starting value; update cross-region/country sessions individually.

For a DN42 peer with `bgp.sessions`, an individual session's `geo` mapping
overrides the peer's mapping field by field. Missing fields default to the
local PoP's location. Numeric region/country values are also accepted;
countries must include the +1000 offset. Unknown registry names and invalid
numeric ranges fail rendering.

## PoP Configuration

Set the shared PoP location in `node.geo.region` and `node.geo.country`,
including on IANA-only nodes. Operational configurations no longer use
`dn42.region` or `dn42.country`. Do not use `node.region` for this: it is an
internal addressing index.

## Verification

```sh
python3 -m unittest discover -s ansible/tests -v
```

The runtime test starts a temporary BIRD instance with its own control socket,
static test routes, and no BGP sessions or kernel protocol. It checks
cross-region and same-region tags, replacement of incoming geography, and
preservation of other control communities.

New per-peer configs reference new shared import functions and PoP constants.
Deploy the full BIRD configuration once before using targeted peer updates.

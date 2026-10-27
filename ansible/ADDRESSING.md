# Public Node Addresses

Each configured node declares its public address prefix in `host_vars/<node>/node.yml`:

```yaml
node:
  public_ipv6_prefix: "2a14:7583:f224::/48"
  node_token: "7d89"
```

This generates `2a14:7583:f224::7d89`. Only the final 16 bits come from
`node_token`; all other host bits are zero. The prefix must be an aligned IPv6
network from /48 through /112. More-specific bases preserve existing allocations
such as Shanghai's `2a14:7583:f22d:2000::/56`.

The prefix is an address allocation input, **not a route announcement**:

- The overlay interface receives the generated address as /128.
- `intra/static.conf` originates only that node's /128, with IANA identity
  and NO_EXPORT, for internal confederation transport.
- The kernel policy uses the same generated address as its public source address.
- Multiple nodes may share a prefix, but must have distinct resulting addresses.

No /48 route is generated from this field. External aggregate and anycast
announcements remain explicitly controlled by `iana.static.advertise_routes`.
The prefix does not change `node.region`, external aggregates, or geo communities.

Legacy nodes without `public_ipv6_prefix` retain the region-derived prefix.
`iana.own_ipv6`, `iana.own_net_v6`, and the unused /43 derivation have been removed.
DN42's `own_ipv6` remains its separately assigned node address.

Changing a prefix/token changes both the interface address and the originated
host route. Deploy network and BIRD updates together; rendering alone does not
change a running node. Both intra-confederation and IANA iBGP preserve owned
host routes with internal identity. External IANA sessions still reject routes
longer than /48 and routes carrying NO_EXPORT.

## Verification

```sh
python3 -m unittest discover -s ansible/tests -v
ansible-playbook -i ansible/inventory.yml ansible/playbooks/render.yml --limit hkg02-hk
ansible-playbook -i ansible/inventory.yml ansible/playbooks/validate.yml --limit hkg02-hk
```

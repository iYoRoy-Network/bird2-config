"""Ansible filter plugins deriving per-node addressing values.

The formulas live here in one place so templates — including ones that read a
neighbour's ``node`` metadata through ``hostvars`` — reference a filter instead
of recomputing the derivation. This keeps working under ``--limit`` renders
(where a neighbour's ``set_fact`` values would not exist).
"""

from __future__ import annotations

from ipaddress import IPv6Address, IPv6Network
import re

from ansible.errors import AnsibleFilterError


def intra_lla(node, intra_global):
    """Intra link-local address for a node's underlay interface."""
    return "%s:%d:%d:%s" % (
        intra_global["link_local_prefix"],
        node["tier"],
        node["region"],
        node["node_token"],
    )


def intra_loopback_v4(node):
    """Intra IPv4 loopback for a node."""
    return "100.64.%d.%d" % (node["tier"] * 10 + node["region"], node["node_id"])


def intra_loopback_v6(node, intra_global):
    """Intra IPv6 loopback for a node."""
    return "%s:%d:%d::%s" % (
        intra_global["loopback_v6_prefix"],
        node["tier"],
        node["region"],
        node["node_token"],
    )


def intra_as(node, intra_global):
    """Derived intra confederation ASN for a node."""
    return intra_global["confederation_as_format"] % (
        node["tier"],
        node["region"],
        node["node_id"],
    )


def public_ipv6(node):
    """Combine a node's address prefix with its final 16-bit token."""
    prefix = node.get("public_ipv6_prefix", "2a14:7583:f2%01x4::/48" % (node["region"] * 2))
    try:
        network = IPv6Network(prefix)
    except (ValueError, TypeError) as exc:
        raise AnsibleFilterError("Invalid node.public_ipv6_prefix %r: %s" % (prefix, exc)) from exc
    if not 48 <= network.prefixlen <= 112:
        raise AnsibleFilterError("node.public_ipv6_prefix must be /48 through /112, leaving 16 token bits")
    token = node["node_token"]
    if not isinstance(token, str) or re.fullmatch(r"[0-9a-fA-F]{1,4}", token) is None:
        raise AnsibleFilterError("node.node_token must be 1-4 hexadecimal digits")
    return str(IPv6Address(int(network.network_address) | int(token, 16)))


class FilterModule(object):
    def filters(self):
        return {
            "intra_lla": intra_lla,
            "intra_loopback_v4": intra_loopback_v4,
            "intra_loopback_v6": intra_loopback_v6,
            "intra_as": intra_as,
            "public_ipv6": public_ipv6,
        }

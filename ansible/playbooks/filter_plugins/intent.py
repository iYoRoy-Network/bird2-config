"""Normalize configuration intent before rendering BIRD and WireGuard."""

from copy import deepcopy
from ipaddress import ip_address
import re

from ansible.errors import AnsibleFilterError


INTRA_POLICIES = {"default", "full", "iana_full", "dn42_full", "3377confed_iana"}


def intra_session(session):
    result = deepcopy(session)
    for family in ("ipv4", "ipv6"):
        channel = result.setdefault(family, {})
        for direction in ("import", "export"):
            key = direction + "_policy"
            policy = channel.get(key, result.get(key, "default"))
            if policy not in INTRA_POLICIES:
                raise AnsibleFilterError("Unknown intra %s: %r" % (key, policy))
            channel[key] = policy
    return result


def bird_modules(domains):
    result = {name: [] for name in ("iana", "dn42", "intra")}
    for name, settings in domains.items():
        if not settings.get("enabled", False):
            continue
        if name == "iana":
            files = ["rpki.conf", "filter.conf", "static.conf"]
            for key, filename in (("peers", "peer.conf"), ("downstreams", "downstream.conf")):
                if settings.get(key):
                    files.append(filename)
            if settings.get("upstreams4") or settings.get("upstreams6"):
                files.insert(3, "upstream.conf")
            if settings.get("ibgp", {}).get("sessions"):
                files.append("ibgp.conf")
        elif name == "dn42":
            files = (["rpki.conf"] if settings.get("rpki", {}).get("enabled", True) else [])
            files += ["filter.conf", "flapalerted.conf", "static.conf"]
            if settings.get("peers"):
                files.append("ebgp.conf")
            if settings.get("ix", {}).get("sessions"):
                files.append("ix.conf")
        else:
            files = ["ibgp.conf", "static.conf"]
        result[name] = files
    return result


def dn42_sessions(peer):
    """Accept existing peer input at the boundary; expose one session schema."""
    bgp = peer.get("bgp", {})
    neighbor = peer.get("neighbor", {})
    sessions = deepcopy(bgp.get("sessions") or [])
    if not sessions:
        transport = "dst" in peer and "src" in peer
        if ("dst" in peer) != ("src" in peer):
            raise AnsibleFilterError("DN42 src and dst must be specified together")
        address = peer.get("dst") if transport else peer.get("lla", neighbor.get("address"))
        extended = bgp.get("extended_next_hop", peer.get("ipv4", {}).get("extended_next_hop", False))
        families = (["ipv4", "ipv6"] if extended else
                    ["ipv6"] if transport and ":" in address else ["ipv4"])
        sessions = [{"name": "mp-bgp", "neighbor": address,
                     "source": peer.get("src") if transport else None,
                     "interface": None if transport else neighbor.get("interface", peer.get("wireguard", {}).get("interface", "dn42_%s" % peer["asn"])),
                     "extended_next_hop": extended, "address_families": families}]
    result = []
    names = set()
    for session in sessions:
        name = session.get("name", "mp-bgp")
        if not re.fullmatch(r"[A-Za-z0-9_-]+", name) or name in names:
            raise AnsibleFilterError("Invalid or duplicate DN42 session name %r" % name)
        names.add(name)
        address = session.get("neighbor")
        try:
            ip_address(address)
        except (ValueError, TypeError) as exc:
            raise AnsibleFilterError("Invalid DN42 neighbor %r" % address) from exc
        families = session.get("address_families", [])
        if not families or set(families) - {"ipv4", "ipv6"}:
            raise AnsibleFilterError("DN42 address_families must contain ipv4 and/or ipv6")
        interface = session.get("interface")
        if session.get("transport") == "ipv6_link_local" and not interface:
            raise AnsibleFilterError("Link-local DN42 sessions require an interface")
        source = session.get("source")
        if source and ip_address(source).version != ip_address(address).version:
            raise AnsibleFilterError("DN42 source and neighbor address families differ")
        result.append({**session, "name": name,
                       "protocol": "dn42_peer_%s%s" % (peer["asn"], "" if name == "mp-bgp" else "_" + name),
                       "interface": interface, "source": source,
                       "port": session.get("port", neighbor.get("port")),
                       "extended_next_hop": session.get("extended_next_hop", False),
                       "geo": {**peer.get("geo", {}), **session.get("geo", {})}})
    return result


def unique(items, key, label):
    seen = set()
    for item in items:
        value = item[key]
        if value in seen:
            raise AnsibleFilterError("Duplicate %s: %s" % (label, value))
        seen.add(value)


def materialize_intent(config, hostvars, hostname, defaults):
    """Build transport interfaces and internal sessions without mutating input."""
    intra, dn42, wireguard = (config.get(name, {}) for name in ("intra", "dn42", "wireguard"))
    interfaces, sessions = [], []
    for peer in intra.get("auto_confed_peers", []) if intra.get("enabled", False) else []:
        remote = hostvars.get(peer["node"])
        if remote is None:
            raise AnsibleFilterError("Unknown intra node %s" % peer["node"])
        reciprocal = [entry for entry in remote.get("intra", {}).get("auto_confed_peers", [])
                      if entry["node"] == hostname]
        if len(reciprocal) != 1:
            raise AnsibleFilterError("Expected one reciprocal link %s -> %s" % (peer["node"], hostname))
        wg = {**defaults["intra"], **peer.get("wireguard", {})}
        endpoint_host = remote.get("node", {}).get("wireguard_endpoint_host")
        endpoint = wg.get("endpoint")
        if endpoint is None and not wg.get("passive", False):
            if not endpoint_host:
                raise AnsibleFilterError("Set node.wireguard_endpoint_host or explicit endpoint for %s" % peer["node"])
            if ":" in endpoint_host:
                endpoint_host = "[" + endpoint_host.strip("[]") + "]"
            endpoint = "%s:%s" % (endpoint_host, reciprocal[0]["wireguard"]["listen_port"])
        tunnel_peer = {key: wg[key] for key in ("public_key", "allowed_ips", "endpoints", "persistent_keepalive", "preshared_key_ref") if key in wg}
        if endpoint and not wg.get("passive", False):
            tunnel_peer["endpoint"] = endpoint
        interface = {key: wg[key] for key in ("address_mode", "listen_port", "table", "post_up", "fwmark", "mtu", "private_key_ref", "pre_up", "pre_down", "post_down", "address") if key in wg}
        interfaces.append({**interface, "name": peer["interface"], "peer": tunnel_peer})
        sessions.append(intra_session({**peer.get("bgp", {}),
                                       "neighbor": {"node": peer["node"], "interface": peer["interface"]}}))
    for peer in dn42.get("peers", []) if dn42.get("enabled", False) else []:
        dn42_sessions(peer)
        if "wireguard" not in peer:
            continue
        wg = {**defaults["dn42"], **peer["wireguard"]}
        tunnel_peer = {key: wg[key] for key in ("public_key", "allowed_ips", "endpoint", "endpoints", "persistent_keepalive", "preshared_key_ref") if key in wg}
        interface = {key: deepcopy(wg[key]) for key in ("address", "listen_port", "table", "post_up", "post_down", "fwmark", "mtu", "private_key_ref", "pre_up", "pre_down", "address_mode") if key in wg}
        if "dst" in peer:
            family = "-6" if ip_address(peer["dst"]).version == 6 else "-4"
            length = 128 if family == "-6" else 32
            interface.setdefault("post_up", []).append("ip %s addr add %s/%s peer %s/%s dev %%i || true" % (family, peer["src"], length, peer["dst"], length))
            interface.setdefault("post_down", []).insert(0, "ip %s addr del %s/%s dev %%i || true" % (family, peer["src"], length))
        interfaces.append({**interface, "name": wg.get("interface", "dn42_%s" % peer["asn"]), "peer": tunnel_peer})
    interfaces += deepcopy(wireguard.get("standalone_interfaces") or [])
    sessions += [intra_session(session) for session in intra.get("explicit_confed_peers", [])] if intra.get("enabled", False) else []
    unique(interfaces, "name", "WireGuard interface")
    unique(interfaces, "listen_port", "WireGuard listen port")
    unique(sessions, "protocol", "intra protocol")
    unique(sessions, "file", "intra session filename")
    for interface in interfaces:
        if not re.fullmatch(r"[A-Za-z0-9_=+.-]{1,15}", interface["name"]):
            raise AnsibleFilterError("Invalid WireGuard interface name %r" % interface["name"])
    protocols = [{"protocol": session["protocol"]} for peer in dn42.get("peers", []) for session in dn42_sessions(peer)]
    unique(protocols, "protocol", "DN42 protocol")
    return {"wireguard_interfaces": interfaces, "intra_ibgp_sessions": sessions}


class FilterModule:
    def filters(self):
        return {"intra_session": intra_session, "bird_modules": bird_modules,
                "dn42_sessions": dn42_sessions, "materialize_intent": materialize_intent}

"""Normalize configuration intent before rendering BIRD and WireGuard."""

from copy import deepcopy
from ipaddress import ip_address
import re

from ansible.errors import AnsibleFilterError


INTRA_POLICIES = {"default", "full", "iana_full", "dn42_full", "3377confed_iana"}
LEGACY_CONFED_PROTOCOL_PREFIX = "intra_ibgp_"
CONFED_PROTOCOL_PREFIX = "intra_confed_"


def _confed_protocol_for_node(node):
    """Return the stable protocol ID for an automatic intra peer."""
    return CONFED_PROTOCOL_PREFIX + _confed_node_label(node)


def _confed_node_label(node):
    if not isinstance(node, str):
        raise AnsibleFilterError("Intra peer node must be a string")
    label = node.split("-", 1)[0]
    if not re.fullmatch(r"[A-Za-z0-9_]+", label):
        raise AnsibleFilterError("Cannot derive intra peer names from node %r" % node)
    return label


def _confed_interface_for_node(node):
    return "intra_" + _confed_node_label(node)


def _confed_file_for_node(node):
    return _confed_node_label(node) + ".conf"


def _confed_protocol_for_file(filename):
    """Return a protocol ID for an explicit session when only its file is set."""
    basename = str(filename).rsplit("/", 1)[-1]
    stem = re.sub(r"\.conf$", "", basename)
    return CONFED_PROTOCOL_PREFIX + stem


def _normalize_intra_protocol(protocol, default=None):
    protocol = default if protocol is None else protocol
    if not isinstance(protocol, str) or not protocol:
        raise AnsibleFilterError("Intra session requires a protocol name")
    if protocol.startswith(LEGACY_CONFED_PROTOCOL_PREFIX):
        return CONFED_PROTOCOL_PREFIX + protocol[len(LEGACY_CONFED_PROTOCOL_PREFIX):]
    return protocol


def intra_session(session, default_protocol=None):
    result = deepcopy(session)
    protocol = result.get("protocol", default_protocol)
    if protocol is not None:
        result["protocol"] = _normalize_intra_protocol(protocol)
    for family in ("ipv4", "ipv6"):
        channel = result.setdefault(family, {})
        for direction in ("import", "export"):
            key = direction + "_policy"
            policy = channel.get(key, result.get(key, "default"))
            if policy not in INTRA_POLICIES:
                raise AnsibleFilterError("Unknown intra %s: %r" % (key, policy))
            channel[key] = policy
    return result


def validate_intra_domains(session, dn42_enabled, iana_enabled):
    policies = [session[family][direction + "_policy"]
                for family in ("ipv4", "ipv6")
                for direction in ("import", "export")]
    if "dn42_full" in policies and not dn42_enabled:
        raise AnsibleFilterError("intra session requires the DN42 domain")
    if ({"iana_full", "3377confed_iana"} & set(policies)) and not iana_enabled:
        raise AnsibleFilterError("intra session requires the IANA domain")


def bird_modules(domains):
    """Return the complete BIRD module plan for one node.

    Intra is the required underlay module.  DN42 and IANA are independent edge
    modules, while the Flapalerted client is an optional intra service.
    """
    result = {"iana": [], "dn42": [], "intra": ["ibgp.conf", "static.conf"]}
    intra = domains.get("intra", {})
    if intra.get("flapalerted", {}).get("enabled", False):
        result["intra"].append("flapalerted.conf")

    iana = domains.get("iana", {})
    if iana.get("enabled", False):
        files = ["rpki.conf", "filter.conf", "static.conf"]
        for key, filename in (("peers", "peer.conf"), ("downstreams", "downstream.conf")):
            if iana.get(key):
                files.append(filename)
        if iana.get("upstreams4") or iana.get("upstreams6"):
            files.insert(3, "upstream.conf")
        if iana.get("ibgp", {}).get("sessions"):
            files.append("ibgp.conf")
        result["iana"] = files

    dn42 = domains.get("dn42", {})
    if dn42.get("enabled", False):
        files = (["rpki.conf"] if dn42.get("rpki", {}).get("enabled", True) else [])
        files += ["filter.conf", "flap-dampening.conf", "static.conf"]
        if dn42.get("peers"):
            files.append("ebgp.conf")
        if dn42.get("ix", {}).get("sessions"):
            files.append("ix.conf")
        result["dn42"] = files
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


def _intra_confed_as(node, intra_global):
    try:
        value = int(intra_global["confederation_as_format"] % (
            int(node["tier"]), int(node["region"]), int(node["node_id"])))
        start = int(intra_global["confederation_start"])
        end = int(intra_global["confederation_end"])
    except (KeyError, TypeError, ValueError) as exc:
        raise AnsibleFilterError("Cannot derive intra confederation AS from node metadata") from exc
    if not start <= value <= end:
        raise AnsibleFilterError("Derived intra confederation AS %s is out of range" % value)
    return value


def _intra_listen_port(owner, peer, hostvars, intra_global):
    """Resolve one node's WG port for its intra peer, honoring explicit ports."""
    wireguard = peer.get("wireguard", {})
    if not isinstance(wireguard, dict):
        raise AnsibleFilterError("Invalid intra WireGuard settings for %s" % owner)
    if "listen_port" in wireguard:
        try:
            port = int(wireguard["listen_port"])
        except (TypeError, ValueError) as exc:
            raise AnsibleFilterError("Invalid intra WireGuard listen_port for %s" % owner) from exc
        if not 1 <= port <= 65535:
            raise AnsibleFilterError("Invalid intra WireGuard listen_port for %s" % owner)
        return port

    manual_nodes = intra_global.get("wireguard_listen_port_manual_nodes", [])
    if owner in manual_nodes:
        raise AnsibleFilterError(
            "Intra WireGuard node %s requires an explicit listen_port" % owner)
    target = hostvars.get(peer.get("node"), {})
    node = target.get("node")
    if not isinstance(node, dict):
        raise AnsibleFilterError("Cannot derive intra WireGuard port: missing node metadata for %s" % peer.get("node"))
    peer_as = _intra_confed_as(node, intra_global)
    return 10000 + peer_as % 10000


def irr_queries(iana):
    queries = {}
    for role, key in (("downstream", "downstreams"), ("peer", "peers")):
        for peer in iana.get(key, []):
            asn = int(peer["neighbor"]["asn"])
            value = peer.get("as_set", "none")
            if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_:.-]*", value):
                raise AnsibleFilterError("Invalid AS-SET %r" % value)
            if value.lower() == "none":
                continue
            name = "%s_%s_as_set" % (role, asn)
            if name in queries and queries[name] != value:
                raise AnsibleFilterError("Conflicting AS-SETs for %s" % name)
            queries[name] = value
    return dict(sorted(queries.items()))


def irr_defines(snapshot, queries):
    if snapshot.get("queries") != queries:
        raise AnsibleFilterError("IRR snapshot does not match peer intent; run update-irr.yml")
    sets = snapshot.get("sets", {})
    if set(sets) != set(queries):
        raise AnsibleFilterError("Incomplete IRR snapshot")
    lines = []
    for name in queries:
        values = sets[name]
        if not values or any(type(asn) is not int or not 1 <= asn <= 4294967295 for asn in values):
            raise AnsibleFilterError("Invalid/empty IRR ASN list for %s" % name)
        lines.append("define %s = [%s];" % (name, ", ".join(map(str, sorted(set(values))))))
    return "\n".join(lines) + "\n"


def materialize_intent(config, hostvars, hostname, defaults):
    """Build transport interfaces and internal sessions without mutating input."""
    intra, dn42, wireguard = (config.get(name, {}) for name in ("intra", "dn42", "wireguard"))
    intra_global = defaults.get("intra_global", {})
    interfaces, sessions, dn42_peer_sessions = [], [], []
    for peer in intra.get("auto_confed_peers", []):
        remote = hostvars.get(peer["node"])
        if remote is None:
            raise AnsibleFilterError("Unknown intra node %s" % peer["node"])
        reciprocal = [entry for entry in remote.get("intra", {}).get("auto_confed_peers", [])
                      if entry["node"] == hostname]
        if len(reciprocal) != 1:
            raise AnsibleFilterError("Expected one reciprocal link %s -> %s" % (peer["node"], hostname))
        wg = {**defaults["intra"], **peer.get("wireguard", {})}
        wg["listen_port"] = _intra_listen_port(hostname, peer, hostvars, intra_global)
        endpoint_host = remote.get("node", {}).get("wireguard_endpoint_host")
        endpoint = wg.get("endpoint")
        if endpoint is None and not wg.get("passive", False):
            if not endpoint_host:
                raise AnsibleFilterError("Set node.wireguard_endpoint_host or explicit endpoint for %s" % peer["node"])
            if ":" in endpoint_host:
                endpoint_host = "[" + endpoint_host.strip("[]") + "]"
            remote_port = _intra_listen_port(peer["node"], reciprocal[0], hostvars, intra_global)
            endpoint = "%s:%s" % (endpoint_host, remote_port)
        tunnel_peer = {key: wg[key] for key in ("public_key", "allowed_ips", "endpoints", "persistent_keepalive", "preshared_key_ref") if key in wg}
        if endpoint and not wg.get("passive", False):
            tunnel_peer["endpoint"] = endpoint
        peer_interface = _confed_interface_for_node(peer["node"])
        interface = {key: wg[key] for key in ("address_mode", "listen_port", "table", "post_up", "fwmark", "mtu", "private_key_ref", "pre_up", "pre_down", "post_down", "address") if key in wg}
        interfaces.append({**interface, "name": peer_interface, "peer": tunnel_peer})
        bgp = {**(peer.get("bgp") or {}),
               "file": _confed_file_for_node(peer["node"]),
               "protocol": _confed_protocol_for_node(peer["node"])}
        sessions.append(intra_session(
            {**bgp, "neighbor": {"node": peer["node"], "interface": peer_interface}},
        ))
        validate_intra_domains(sessions[-1], dn42.get("enabled", False),
                               config.get("iana", {}).get("enabled", False))
    for peer in dn42.get("peers", []) if dn42.get("enabled", False) else []:
        normalized_sessions = dn42_sessions(peer)
        dn42_peer_sessions.append({"peer": deepcopy(peer), "sessions": normalized_sessions})
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
    explicit_sessions = []
    for session in intra.get("explicit_confed_peers", []):
        default_protocol = (_confed_protocol_for_file(session["file"])
                            if "protocol" not in session and "file" in session else None)
        explicit_sessions.append(intra_session(session, default_protocol=default_protocol))
    for session in explicit_sessions:
        validate_intra_domains(session, dn42.get("enabled", False),
                               config.get("iana", {}).get("enabled", False))
    sessions += explicit_sessions
    unique(interfaces, "name", "WireGuard interface")
    unique(interfaces, "listen_port", "WireGuard listen port")
    unique(sessions, "protocol", "intra protocol")
    unique(sessions, "file", "intra session filename")
    for interface in interfaces:
        if not re.fullmatch(r"[A-Za-z0-9_=+.-]{1,15}", interface["name"]):
            raise AnsibleFilterError("Invalid WireGuard interface name %r" % interface["name"])
    protocols = [{"protocol": session["protocol"]}
                 for peer in dn42_peer_sessions for session in peer["sessions"]]
    unique(protocols, "protocol", "DN42 protocol")
    return {"wireguard_interfaces": interfaces, "intra_ibgp_sessions": sessions,
            "dn42_peer_sessions": dn42_peer_sessions}


class FilterModule:
    def filters(self):
        return {"intra_session": intra_session, "bird_modules": bird_modules,
                "dn42_sessions": dn42_sessions, "materialize_intent": materialize_intent,
                "irr_queries": irr_queries, "irr_defines": irr_defines}

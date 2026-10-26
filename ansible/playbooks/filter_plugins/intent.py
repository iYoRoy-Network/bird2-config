"""Normalize configuration intent before rendering BIRD and WireGuard."""

from copy import deepcopy

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


class FilterModule:
    def filters(self):
        return {"intra_session": intra_session, "bird_modules": bird_modules}

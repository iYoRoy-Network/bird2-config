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


class FilterModule:
    def filters(self):
        return {"intra_session": intra_session}

"""Resolve geo registry values to validated BIRD constants."""

from collections.abc import Mapping

from ansible.errors import AnsibleFilterError


def geo_define(value, registry, kind):
    if isinstance(value, str) and value in registry:
        return "GEO_%s_%s" % (kind.upper(), value)
    if type(value) is int and (
        (kind == "region" and 41 <= value <= 70)
        or (kind == "country" and 1001 <= value <= 1999)
    ):
        return str(value)
    raise AnsibleFilterError(
        "Invalid geo %s %r: use a registry name or %s"
        % (kind, value, "41-70" if kind == "region" else "ISO numeric + 1000")
    )


def geo_args(geo, regions, countries):
    if not isinstance(geo, Mapping) or set(geo) - {"region", "country"}:
        raise AnsibleFilterError("Peer geo must be a mapping with region/country keys")
    return ", ".join(
        geo_define(geo[kind], registry, kind) if kind in geo else fallback
        for kind, registry, fallback in (
            ("region", regions, "POP_REGION"),
            ("country", countries, "POP_COUNTRY"),
        )
    )


class FilterModule:
    def filters(self):
        return {"geo_define": geo_define, "geo_args": geo_args}

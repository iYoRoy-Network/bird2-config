"""Run with python3 -m unittest discover -s ansible/tests -v."""

import importlib.util
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest

from ansible.errors import AnsibleFilterError
from jinja2 import ChainableUndefined, Environment, FileSystemLoader
import yaml


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "geo", ROOT / "ansible/playbooks/filter_plugins/geo.py"
)
GEO = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GEO)
SPEC_INTENT = importlib.util.spec_from_file_location("intent", ROOT / "ansible/playbooks/filter_plugins/intent.py")
INTENT = importlib.util.module_from_spec(SPEC_INTENT)
SPEC_INTENT.loader.exec_module(INTENT)


def variables():
    result = {}
    for name in ("communities", "domains", "geo"):
        result.update(yaml.safe_load((ROOT / f"ansible/group_vars/all/{name}.yml").read_text()))
    return result


def render(name, **values):
    env = Environment(
        loader=FileSystemLoader(ROOT / "ansible/templates"),
        undefined=ChainableUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters.update(GEO.FilterModule().filters())
    env.filters.update(INTENT.FilterModule().filters())
    env.filters["combine"] = lambda left, right: {**left, **right}
    return env.get_template(f"bird/{name}.j2").render(**(variables() | values))


class GeoRenderingTests(unittest.TestCase):
    def test_names_numeric_and_defaults(self):
        values = variables()
        regions, countries = values["geo_region"], values["geo_country"]
        self.assertEqual(GEO.geo_args({}, regions, countries), "POP_REGION, POP_COUNTRY")
        self.assertEqual(
            GEO.geo_args({"region": "ASIA_EAST", "country": "JAPAN"}, regions, countries),
            "GEO_REGION_ASIA_EAST, GEO_COUNTRY_JAPAN",
        )
        self.assertEqual(GEO.geo_args({"region": 52, "country": 1392}, regions, countries), "52, 1392")
        for value, kind in ((392, "country"), (True, "region"), ("TYPO", "region")):
            with self.subTest(value=value), self.assertRaises(AnsibleFilterError):
                GEO.geo_define(value, regions if kind == "region" else countries, kind)

    def test_iana_only_pop(self):
        output = render(
            "bird.conf", node={"geo": {"region": "NA_WEST", "country": "UNITED_STATES"}},
            iana={"enabled": True, "router_id": "192.0.2.1"},
            bird={}, modules={}, derived_intra_loopback_v4="100.64.1.1",
        )
        self.assertIn("define POP_REGION = GEO_REGION_NA_WEST;", output)
        self.assertIn("define POP_COUNTRY = GEO_COUNTRY_UNITED_STATES;", output)
        self.assertNotIn("define DN42_OWNAS", output)

    def test_dn42_session_geo_override_and_disabled_af(self):
        peer = {
            "asn": 65000, "geo": {"region": "NA_WEST", "country": "UNITED_STATES"},
            "bgp": {"sessions": [{
                "name": "v6", "transport": "ipv6_link_local", "neighbor": "fe80::2",
                "interface": "test0", "address_families": ["ipv6"],
                "geo": {"region": "ASIA_EAST", "country": "JAPAN"},
            }]},
        }
        output = render("dn42/peer.conf", peer=peer)
        self.assertIn("dn42_ebgp_import_v6(GEO_REGION_ASIA_EAST, GEO_COUNTRY_JAPAN)", output)
        self.assertIn("dn42_ebgp_export_v6(65000, GEO_REGION_ASIA_EAST, GEO_COUNTRY_JAPAN)", output)
        self.assertNotIn("dn42_ebgp_import_v4", output)
        self.assertIn("import none;", output)

    def test_all_external_peers_have_valid_explicit_geo(self):
        values = variables()
        count = 0
        for directory in (ROOT / "ansible/host_vars").iterdir():
            if not directory.is_dir():
                continue
            dn42 = yaml.safe_load((directory / "dn42.yml").read_text())["dn42"]
            iana = yaml.safe_load((directory / "iana.yml").read_text().replace("\t", " "))["iana"]
            peers = [yaml.safe_load(path.read_text()) for path in (directory / "dn42-peers").glob("*.yml")]
            peers += dn42.get("peers", []) + dn42.get("ix", {}).get("sessions", [])
            for key in ("peers", "upstreams4", "upstreams6", "downstreams"):
                peers += iana.get(key) or []
            for peer in peers:
                with self.subTest(node=directory.name, peer=peer.get("asn", peer.get("protocol"))):
                    for kind in ("region", "country"):
                        GEO.geo_define(peer["geo"][kind], values[f"geo_{kind}"], kind)
                count += 1
        self.assertGreater(count, 0)

    def test_external_export_uses_peer_geo(self):
        session = {
            "protocol": "test_session", "local": "2001:db8::1",
            "neighbor": {"asn": 65000, "address": "2001:db8::2"},
            "geo": {"region": "ASIA_EAST", "country": "JAPAN"},
        }
        for template, key, function in (
            ("iana/peer.conf", "peers", "iana_peer_export_default"),
            ("iana/downstream.conf", "downstreams", "iana_downstream_export_default"),
            ("iana/upstream.conf", "upstreams4", "iana_upstream_export_default"),
            ("iana/upstream.conf", "upstreams6", "iana_upstream_export_default"),
        ):
            with self.subTest(template=template, key=key):
                output = render(template, iana={key: [session]})
                self.assertIn(f"{function}(65000, GEO_REGION_ASIA_EAST, GEO_COUNTRY_JAPAN)", output)
        output = render("dn42/ix.conf", dn42={"ix": {"sessions": [session]}}, derived_intra_loopback_v4="100.64.1.1")
        for af in ("v4", "v6"):
            self.assertIn(f"dn42_ix_export_{af}(65000, GEO_REGION_ASIA_EAST, GEO_COUNTRY_JAPAN)", output)
        legacy = {"asn": 65000, "neighbor": {"address": "fe80::2"}, "bgp": {"extended_next_hop": True}}
        output = render("dn42/peer.conf", peer=legacy)
        for af in ("v4", "v6"):
            self.assertIn(f"dn42_ebgp_export_{af}(65000, POP_REGION, POP_COUNTRY)", output)


@unittest.skipUnless(shutil.which("bird") and shutil.which("birdc"), "BIRD binaries required")
class GeoRuntimeTests(unittest.TestCase):
    def test_cross_region_same_region_retag_and_preserve_controls(self):
        values = variables()
        defines = "\n".join(f"define COMM_{key} = {value};" for key, value in values["bgp_community"].items())
        functions = render(
            "filter.conf", bird_own_as_defines=["IANA_OWNAS", "DN42_OWNAS"],
            iana={"enabled": True}, dn42={"enabled": True},
        )
        config = f"""
router id 192.0.2.1;
define IANA_OWNAS = 205369;
define DN42_OWNAS = 4242422024;
define INTRA_CONFEDERATION_START = 4220240000;
define INTRA_CONFEDERATION_END = 4220249999;
define POP_REGION = 44;
define POP_COUNTRY = 1840;
{defines}
{functions}
protocol static geo_test {{
    ipv4 {{ import all; }};
    route 192.0.2.1/32 reject {{
        bgp_large_community.add((205369, 644, 41));
        bgp_large_community.add((205369, 645, 1276));
        bgp_large_community.add((205369, 670, 6939));
        bgp_large_community.add((4242422024, 644, 41));
        iana_add_geo(52, 1392);
    }};
    route 192.0.2.2/32 reject {{ dn42_add_geo(POP_REGION, POP_COUNTRY); }};
}}
"""
        with tempfile.TemporaryDirectory(prefix="bird-geo-test-") as directory:
            path = Path(directory)
            conf, sock = path / "bird.conf", path / "bird.ctl"
            conf.write_text(config)
            subprocess.run(["bird", "-p", "-c", str(conf)], check=True, capture_output=True, text=True)
            with (path / "bird.log").open("w+") as log:
                process = subprocess.Popen(
                    ["bird", "-f", "-c", str(conf), "-s", str(sock), "-P", str(path / "bird.pid")],
                    stdout=log, stderr=log,
                )
                try:
                    for _ in range(100):
                        if sock.exists() or process.poll() is not None:
                            break
                        time.sleep(0.02)
                    def route(prefix):
                        return subprocess.run(
                            ["birdc", "-s", str(sock), "show", "route", "for", prefix, "all"],
                            check=True, capture_output=True, text=True,
                        ).stdout
                    cross = route("192.0.2.1/32")
                    for community in ("(205369, 644, 52)", "(205369, 644, 1392)", "(205369, 645, 44)",
                                      "(205369, 645, 1840)", "(205369, 670, 6939)", "(4242422024, 644, 41)"):
                        self.assertIn(community, cross)
                    self.assertNotIn("(205369, 644, 41)", cross)
                    self.assertNotIn("(205369, 645, 1276)", cross)
                    same = route("192.0.2.2/32")
                    for fn in (644, 645):
                        for code in (44, 1840):
                            self.assertIn(f"(4242422024, {fn}, {code})", same)
                finally:
                    process.terminate()
                    process.wait(timeout=5)


if __name__ == "__main__":
    unittest.main()

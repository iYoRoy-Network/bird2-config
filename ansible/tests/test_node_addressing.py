"""Check configurable public address prefixes and host-only announcements."""

import importlib.util
from ipaddress import IPv6Address, IPv6Network
import re
import unittest

from ansible.errors import AnsibleFilterError
from jinja2 import Environment, FileSystemLoader, StrictUndefined
import yaml

from test_geo import ROOT, render, variables


SPEC = importlib.util.spec_from_file_location(
    "node_addressing", ROOT / "ansible/playbooks/filter_plugins/node_addressing.py"
)
ADDRESSING = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ADDRESSING)


class NodeAddressingTests(unittest.TestCase):
    def test_prefix_and_token(self):
        node = {"region": 1, "node_token": "7d89"}
        self.assertEqual(ADDRESSING.public_ipv6(node), "2a14:7583:f224::7d89")
        for prefix, expected in (
            ("2a14:7583:f228::/48", "2a14:7583:f228::7d89"),
            ("2a14:7583:f22d:2000::/56", "2a14:7583:f22d:2000::7d89"),
            ("2001:db8:abcd:1:2:3:4:0/112", "2001:db8:abcd:1:2:3:4:7d89"),
        ):
            with self.subTest(prefix=prefix):
                self.assertEqual(ADDRESSING.public_ipv6({**node, "public_ipv6_prefix": prefix}), expected)
        self.assertEqual(
            ADDRESSING.public_ipv6({**node, "node_token": "0001"}), "2a14:7583:f224::1"
        )

    def test_invalid_prefix_and_token(self):
        node = {"region": 1, "node_token": "7d89", "public_ipv6_prefix": "2001:db8:1::/48"}
        for prefix in (None, "typo", "192.0.2.0/24", "2001:db8::/32",
                       "2001:db8::/113", "2001:db8::/128", "2001:db8:1::1/48"):
            with self.subTest(prefix=prefix), self.assertRaises(AnsibleFilterError):
                ADDRESSING.public_ipv6({**node, "public_ipv6_prefix": prefix})
        for token in (None, True, 1234, "", "10000", "xyz", "::1", "-1"):
            with self.subTest(token=token), self.assertRaises(AnsibleFilterError):
                ADDRESSING.public_ipv6({**node, "node_token": token})

    def test_inventory_preserves_addresses(self):
        expected = {
            "hkg01-hk": "2a14:7583:f224::d576", "hkg02-hk": "2a14:7583:f224::7d89",
            "hkg03-hk": "2a14:7583:f224::872c", "hkg04-hk": "2a14:7583:f224::c75a",
            "tyo01-jp": "2a14:7583:f228::63f4", "tyo02-jp": "2a14:7583:f228::31c8",
            "tyo03-jp": "2a14:7583:f228::6f78", "pvg01-cn": "2a14:7583:f22d:2000::5fac",
            "fra01-de": "2a14:7583:f244::3b06", "fra02-de": "2a14:7583:f244::d131",
            "lax01-us": "2a14:7583:f284::de75",
        }
        addresses = set()
        for host, address in expected.items():
            with self.subTest(host=host):
                directory = ROOT / "ansible/host_vars" / host
                node = yaml.safe_load((directory / "node.yml").read_text())["node"]
                iana = yaml.safe_load((directory / "iana.yml").read_text().replace("\t", " "))["iana"]
                self.assertIn("public_ipv6_prefix", node)
                self.assertNotIn("own_ipv6", iana)
                derived = ADDRESSING.public_ipv6(node)
                self.assertEqual(derived, address)
                self.assertNotIn(derived, addresses)
                addresses.add(derived)

    def test_consumers_use_host_address_without_announcing_prefix(self):
        env = Environment(
            loader=FileSystemLoader(ROOT / "ansible/templates"), undefined=StrictUndefined,
            trim_blocks=True, lstrip_blocks=True,
        )
        env.filters["regex_replace"] = lambda value, pattern, replacement: re.sub(pattern, replacement, value)
        for prefix in ("2a14:7583:f224::/48", "2a14:7583:f228::/48", "2a14:7583:f22d:2000::/56"):
            with self.subTest(prefix=prefix):
                node = {"region": 1, "node_token": "7d89", "public_ipv6_prefix": prefix}
                address = ADDRESSING.public_ipv6(node)
                context = {
                    "iana": {"enabled": True}, "intra": {}, "node": node,
                    "bird_own_as_defines": ["IANA_OWNAS"],
                    "derived_public_ipv6": address,
                    "derived_intra_loopback_v4": "100.64.11.3",
                    "derived_intra_loopback_v6": "fd18:3e15:61d0:ffff:1:1::7d89",
                }
                static = render("intra/static.conf", **context)
                self.assertIn(f"route {address}/128 reject", static)
                routes = re.findall(r"route (\S+)", static)
                self.assertTrue(all(IPv6Network(route).prefixlen == 128 for route in routes if ":" in route))
                self.assertNotIn(f"route {prefix} ", static)
                self.assertIn("COMM_WK_NO_EXPORT", static)
                self.assertIn("IANA_OWNAS,COMM_FN_IDENTIFY", static)
                self.assertIn(f"krt_prefsrc = {address};", render("kernel.conf", **context))
                overlay = env.get_template("network/overlay.j2").render(**(variables() | context))
                self.assertIn(f"address {address}/128", overlay)
                self.assertEqual(IPv6Address(address).packed[-2:].hex(), "7d89")


if __name__ == "__main__":
    unittest.main()

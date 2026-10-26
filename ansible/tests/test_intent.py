import importlib.util
import unittest

from ansible.errors import AnsibleFilterError
from test_geo import ROOT
import yaml


def plugin(name, directory="playbooks/filter_plugins"):
    spec = importlib.util.spec_from_file_location(name, ROOT / "ansible" / directory / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


INTENT = plugin("intent")


class IntentTests(unittest.TestCase):
    def test_legacy_transport_normalization_and_explicit_families(self):
        legacy = {"asn": 65000, "src": "192.0.2.1", "dst": "192.0.2.2",
                  "geo": {"region": "ASIA_EAST"}, "bgp": {"extended_next_hop": True}}
        session = INTENT.dn42_sessions(legacy)[0]
        self.assertEqual(session["address_families"], ["ipv4", "ipv6"])
        self.assertEqual(session["source"], "192.0.2.1")
        self.assertIsNone(session["interface"])
        explicit = {"asn": 65000, "geo": {"region": "ASIA_EAST"}, "bgp": {"sessions": [
            {"name": "v6", "neighbor": "fe80::2", "interface": "wg0", "transport": "ipv6_link_local",
             "address_families": ["ipv6"], "geo": {"country": "JAPAN"}}]}}
        self.assertEqual(INTENT.dn42_sessions(explicit)[0]["geo"], {"region": "ASIA_EAST", "country": "JAPAN"})
        with self.assertRaises(AnsibleFilterError):
            INTENT.dn42_sessions({"asn": 65000, "src": "192.0.2.1"})

    def test_topology_is_independent_of_management_inventory(self):
        def load(host, name):
            return yaml.safe_load((ROOT / "ansible/host_vars" / host / (name + ".yml")).read_text())
        hosts = {path.name: {**load(path.name, "node"), **load(path.name, "intra")}
                 for path in (ROOT / "ansible/host_vars").iterdir() if (path / "node.yml").exists()}
        hosts["cdg01-fr"] = {**yaml.safe_load((ROOT / "ansible/host_vars/cdg01-fr/main.yml").read_text()),
                             **load("cdg01-fr", "intra")}
        defaults = yaml.safe_load((ROOT / "ansible/group_vars/all/wireguard.yml").read_text())
        defaults = {"intra": defaults["intra_wireguard_defaults"], "dn42": defaults["dn42_wireguard_defaults"]}
        config = {**load("hkg02-hk", "intra"), "dn42": {"enabled": False}}
        first = INTENT.materialize_intent(config, hosts, "hkg02-hk", defaults)
        hosts["tyo01-jp"]["ansible_host"] = "different-management-address"
        self.assertEqual(first, INTENT.materialize_intent(config, hosts, "hkg02-hk", defaults))
        config["wireguard"] = {"standalone_interfaces": [first["wireguard_interfaces"][0]]}
        with self.assertRaisesRegex(AnsibleFilterError, "Duplicate"):
            INTENT.materialize_intent(config, hosts, "hkg02-hk", defaults)

    def test_domain_enable_and_file_selection(self):
        self.assertEqual(INTENT.bird_modules({"dn42": {"enabled": False, "peers": [{}]}})["dn42"], [])
        self.assertEqual(INTENT.bird_modules({"dn42": {"enabled": True, "rpki": {"enabled": False}}})["dn42"],
                         ["filter.conf", "flapalerted.conf", "static.conf"])
        files = INTENT.bird_modules({"iana": {"enabled": True, "upstreams6": [{}], "peers": [{}]}})
        self.assertEqual(files["iana"], ["rpki.conf", "filter.conf", "static.conf", "upstream.conf", "peer.conf"])

    def test_independent_direction_and_family_inheritance(self):
        source = {"import_policy": "iana_full", "export_policy": "full",
                  "ipv4": {"export_policy": "dn42_full"}, "ipv6": {"import_policy": "default"}}
        result = INTENT.intra_session(source)
        self.assertEqual(result["ipv4"], {"import_policy": "iana_full", "export_policy": "dn42_full"})
        self.assertEqual(result["ipv6"], {"import_policy": "default", "export_policy": "full"})
        self.assertEqual(source["ipv4"], {"export_policy": "dn42_full"})
        with self.assertRaises(AnsibleFilterError):
            INTENT.intra_session({"export_policy": "typo"})

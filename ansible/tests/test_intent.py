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


def host_config(host):
    result = {}
    for path in sorted((ROOT / "ansible/host_vars" / host).glob("*.yml")):
        result.update(yaml.safe_load(path.read_text().replace("\t", " ")))
    return result


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
        hosts = {path.name: host_config(path.name)
                 for path in (ROOT / "ansible/host_vars").iterdir() if (path / "node.yml").exists()}
        defaults = yaml.safe_load((ROOT / "ansible/group_vars/all/wireguard.yml").read_text())
        defaults = {"intra": defaults["intra_wireguard_defaults"], "dn42": defaults["dn42_wireguard_defaults"]}
        config = {"intra": hosts["hkg02-hk"]["intra"],
                  "dn42": {"enabled": True}, "iana": {"enabled": True}}
        first = INTENT.materialize_intent(config, hosts, "hkg02-hk", defaults)
        hosts["tyo01-jp"]["ansible_host"] = "different-management-address"
        self.assertEqual(first, INTENT.materialize_intent(config, hosts, "hkg02-hk", defaults))
        config["wireguard"] = {"standalone_interfaces": [first["wireguard_interfaces"][0]]}
        with self.assertRaisesRegex(AnsibleFilterError, "Duplicate"):
            INTENT.materialize_intent(config, hosts, "hkg02-hk", defaults)

    def test_cdg_lhr_preserve_transport_and_policy_intent(self):
        hosts = {path.name: host_config(path.name)
                 for path in (ROOT / "ansible/host_vars").iterdir() if (path / "node.yml").exists()}
        values = yaml.safe_load((ROOT / "ansible/group_vars/all/wireguard.yml").read_text())
        defaults = {"intra": values["intra_wireguard_defaults"], "dn42": values["dn42_wireguard_defaults"]}
        expected = {
            "cdg01-fr": [("fra01", "full", 50225), ("hkg02", "default", 50226),
                         ("lax01", "dn42_full", 50227), ("tyo01", "default", 50228),
                         ("lhr01", "full", 50229)],
            "lhr01-uk": [("cdg01", "full", 10123)],
        }
        for host, links in expected.items():
            with self.subTest(host=host):
                config = hosts[host]
                self.assertFalse(config["node"]["peering"]["enabled"])
                for domain in ("iana", "dn42"):
                    self.assertTrue(config[domain]["enabled"])
                self.assertIn("intra", config)
                self.assertEqual(
                    config["iana"]["static"]["advertise_routes"],
                    [
                        {
                            "prefix": "2a14:7583:f240::/43",
                            "communities": "{{ iana_global.export_to_continent_communities.EUROPE }}",
                        },
                        "{{ iana_global.anycast_net_v6 }}",
                    ],
                )
                intent = INTENT.materialize_intent(config, hosts, host, defaults)
                self.assertEqual(len(intent["wireguard_interfaces"]), len(links))
                self.assertEqual(len(intent["intra_ibgp_sessions"]), len(links))
                for session, interface, (remote, policy, port) in zip(
                        intent["intra_ibgp_sessions"], intent["wireguard_interfaces"], links):
                    self.assertEqual(session["protocol"], "intra_confed_" + remote)
                    self.assertEqual(interface["name"], "intra_" + remote)
                    self.assertEqual(interface["listen_port"], port)
                    endpoint_host = hosts[session["neighbor"]["node"]]["node"]["wireguard_endpoint_host"]
                    endpoint_port = 50229 if host == "lhr01-uk" else 10123
                    self.assertEqual(interface["peer"]["endpoint"], "%s:%s" % (endpoint_host, endpoint_port))
                    for family in ("ipv4", "ipv6"):
                        self.assertEqual(session[family], {"import_policy": policy, "export_policy": policy})
                self.assertEqual(INTENT.irr_queries(config["iana"]), {})

    def test_confederation_protocol_names_are_derived_and_migrated(self):
        self.assertEqual(
            INTENT.intra_session({"protocol": "intra_ibgp_hkg02"})["protocol"],
            "intra_confed_hkg02",
        )
        self.assertEqual(
            INTENT.intra_session({}, default_protocol="intra_confed_hkg02")["protocol"],
            "intra_confed_hkg02",
        )
        self.assertEqual(
            INTENT.intra_session({"protocol": "custom_confed_link"})["protocol"],
            "custom_confed_link",
        )

        hosts = {
            "fra01-de": {
                "node": {"wireguard_endpoint_host": "fra01.example"},
                "intra": {"auto_confed_peers": [{
                    "node": "fra03-de", "wireguard": {"listen_port": 10325},
                }]},
            },
            "fra03-de": {
                "node": {"wireguard_endpoint_host": "fra03.example"},
                "intra": {"auto_confed_peers": [{
                    "node": "fra01-de", "interface": "intra_fra01",
                    "wireguard": {"public_key": "test-key", "listen_port": 50225},
                    "bgp": {"file": "fra01.conf"},
                }]},
            },
        }
        intent = INTENT.materialize_intent(
            hosts["fra03-de"], hosts, "fra03-de", {"intra": {}, "dn42": {}}
        )
        self.assertEqual(intent["intra_ibgp_sessions"][0]["protocol"], "intra_confed_fra01")

    def test_regional_aggregates_use_continent_export_communities(self):
        domains = yaml.safe_load((ROOT / "ansible/group_vars/all/domains.yml").read_text())
        communities = domains["iana_global"]["export_to_continent_communities"]
        expected_asia_regions = {
            "GEO_REGION_ASIA_SOUTH",
            "GEO_REGION_ASIA_SOUTHEAST",
            "GEO_REGION_ASIA_EAST",
            "GEO_REGION_ASIA_NORTH",
            "GEO_REGION_ASIA_WEST",
            "GEO_REGION_ASIA_CENTRAL",
        }
        self.assertEqual(
            {entry[2] for entry in communities["ASIA"] if entry[1] == "COMM_FN_ONLY_REGION"},
            expected_asia_regions,
        )
        self.assertIn([205369, "COMM_FN_DENY_AS", 6939], communities["ASIA"])
        self.assertEqual(
            communities["EUROPE"],
            [
                [205369, "COMM_FN_ONLY_REGION", "GEO_REGION_EUROPE"],
                [205369, "COMM_FN_DENY_AS", 6939],
            ],
        )

        tagged_prefixes = {
            "2a14:7583:f220::/43": ("ASIA", 0),
            "2a14:7583:f240::/43": ("EUROPE", 0),
        }
        for directory in (ROOT / "ansible/host_vars").iterdir():
            iana_path = directory / "iana.yml"
            if not iana_path.exists():
                continue
            iana = yaml.safe_load(iana_path.read_text().replace("\t", " "))["iana"]
            for route in iana.get("static", {}).get("advertise_routes", []):
                if not isinstance(route, dict) or route.get("prefix") not in tagged_prefixes:
                    continue
                prefix = route["prefix"]
                continent, count = tagged_prefixes[prefix]
                self.assertEqual(
                    route.get("communities"),
                    "{{ iana_global.export_to_continent_communities.%s }}" % continent,
                    "%s in %s must use the %s export policy" % (prefix, directory.name, continent),
                )
                tagged_prefixes[prefix] = (continent, count + 1)

        self.assertGreater(tagged_prefixes["2a14:7583:f220::/43"][1], 0)
        self.assertGreater(tagged_prefixes["2a14:7583:f240::/43"][1], 0)

    def test_irr_queries_ignore_peers_without_as_set(self):
        iana = {
            "peers": [{"neighbor": {"asn": 218418}, "as_set": "none"}],
            "downstreams": [],
        }
        self.assertEqual(INTENT.irr_queries(iana), {})

    def test_domain_enable_and_file_selection(self):
        self.assertEqual(INTENT.bird_modules({"dn42": {"enabled": False, "peers": [{}]}})["dn42"], [])
        self.assertEqual(INTENT.bird_modules({"dn42": {"enabled": True, "rpki": {"enabled": False}}})["dn42"],
                         ["filter.conf", "flap-dampening.conf", "static.conf"])
        modules = INTENT.bird_modules({
            "intra": {"flapalerted": {"enabled": True}},
            "dn42": {"enabled": False},
            "iana": {"enabled": False},
        })
        self.assertEqual(modules["intra"], ["ibgp.conf", "static.conf", "flapalerted.conf"])
        self.assertEqual(modules["dn42"], [])
        self.assertEqual(modules["iana"], [])
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

    def test_intra_policy_cannot_reference_disabled_domain(self):
        config = {
            "intra": {"explicit_confed_peers": [{
                "file": "iana.conf", "protocol": "intra_iana",
                "ipv4": {"import_policy": "iana_full", "export_policy": "iana_full"},
            }]},
            "dn42": {"enabled": False},
            "iana": {"enabled": False},
        }
        with self.assertRaisesRegex(AnsibleFilterError, "requires the IANA domain"):
            INTENT.materialize_intent(config, {}, "node", {"intra": {}, "dn42": {}})

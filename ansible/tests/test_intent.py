import importlib.util
import unittest

from ansible.errors import AnsibleFilterError
from test_geo import ROOT


def plugin(name, directory="playbooks/filter_plugins"):
    spec = importlib.util.spec_from_file_location(name, ROOT / "ansible" / directory / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


INTENT = plugin("intent")


class IntentTests(unittest.TestCase):
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

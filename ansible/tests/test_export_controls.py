"""Exercise rendered policy functions in an isolated BIRD routing table."""

from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest

from test_geo import render, variables


@unittest.skipUnless(shutil.which("bird") and shutil.which("birdc"), "BIRD binaries required")
class ExportControlTests(unittest.TestCase):
    def test_import_internal_transport_and_external_export(self):
        context = {
            "bird_own_as_defines": ["IANA_OWNAS", "DN42_OWNAS"],
            "iana": {
                "enabled": True,
                "downstreams": [{"export_policy": policy} for policy in ("default", "own_only", "reject")],
            },
            "dn42": {"enabled": True},
            "intra": {},
            "derived_intra_loopback_v4": "100.64.1.1",
        }
        defines = "\n".join(
            f"define COMM_{key} = {value};" for key, value in variables()["bgp_community"].items()
        )
        functions = render("filter.conf", **context)
        for name in ("iana/filter.conf", "iana/peer.conf", "iana/upstream.conf",
                     "iana/downstream.conf", "dn42/filter.conf", "dn42/ebgp.conf", "dn42/ix.conf"):
            functions += "\n" + render(name, **context).partition("template bgp")[0]

        cases = []

        def add_case(label, body, action, accepted=True, present=(), absent=(), prefix=None):
            index = len(cases) + 1
            cases.append({
                "label": label, "prefix": prefix or f"2a14:7583:{0xf200 + index:x}::/48",
                "body": body, "action": action, "accepted": accepted,
                "present": present, "absent": absent,
            })

        for policy in ("iana_peer_export_default", "iana_upstream_export_default",
                       "iana_downstream_export_default", "iana_downstream_export_own_only",
                       "dn42_ebgp_export_v4", "dn42_ix_export_v4",
                       "dn42_ebgp_export_v6", "dn42_ix_export_v6"):
            own = 4242422024 if policy.startswith("dn42") else 205369
            base = f"bgp_path.prepend(65001); bgp_large_community.add(({own}, 2, 100));"
            policy_start = len(cases)
            # Empty ROA tables yield UNKNOWN; all prefixes satisfy the domain policy.
            def case(label, body, accepted=True, present=(), absent=()):
                # IANA requires <= /48; reserve the owned /40 for own_only cases.
                subnet = (0xf200 + len(cases) - policy_start if policy.endswith("own_only")
                          else 0xe000 + len(cases))
                prefix = f"2a14:7583:{subnet:x}::/48"
                if own == 4242422024:
                    prefix = (f"10.{100 + len(cases) // 256}.{len(cases) % 256}.0/24" if policy.endswith("v4")
                              else f"fdab:{len(cases) + 1:x}::/48")
                add_case(
                    f"{policy}: {label}", base + body,
                    f"if !{policy}(6939, 52, 1392) then reject; accept;", accepted, present, absent, prefix,
                )

            def tags(*entries):
                return "".join(f"bgp_large_community.add(({own}, {fn}, {value}));" for fn, value in entries)

            def as_path(count):
                return "BGP.as_path: " + " ".join([str(own)] * count + ["65001"])

            for deny, only, target, elsewhere in ((650, 651, 52, 44), (660, 661, 1392, 1840)):
                case(f"deny geo {deny}", tags((deny, target)), False)
                case(f"deny other geo {deny}", tags((deny, elsewhere)))
                case(f"only geo {only}", tags((only, target)), absent=(f"({own}, {only}, {target})",))
                case(f"only other geo {only}", tags((only, elsewhere)), False)
                case(f"multiple allowed geo {only}", tags((only, elsewhere), (only, target)))
                case(f"deny wins {deny}", tags((only, target), (deny, target)), False)
                other = 205369 if own == 4242422024 else 4242422024
                case(f"other domain geo {deny}", f"bgp_large_community.add(({other}, {deny}, {target}));")
            case("combined geo allowed", tags((651, 52), (661, 1392)))
            case("combined country mismatch", tags((651, 52), (661, 1840)), False)
            case("combined region mismatch", tags((651, 44), (661, 1392)), False)
            case("combined ASN mismatch", tags((651, 52), (661, 1392), (671, 65002)), False)
            case("combined ASN allowed", tags((651, 52), (661, 1392), (671, 6939)))
            case("route geo does not override peer", tags((644, 44), (645, 1840), (650, 44), (660, 1840)))
            case("deny target", f"bgp_large_community.add(({own}, 670, 6939));", False)
            case("only another AS", f"bgp_large_community.add(({own}, 671, 65002));", False)
            case("only target", f"bgp_large_community.add(({own}, 671, 6939));")
            case("deny another AS", f"bgp_large_community.add(({own}, 670, 65002));")
            other = 205369 if own == 4242422024 else 4242422024
            case("other domain does not control this export", f"bgp_large_community.add(({other}, 670, 6939));")
            for fn, count in ((691, 1), (692, 2), (693, 3), (694, 1), (695, 2), (696, 3)):
                target = 65002 if fn >= 694 else 6939
                case(
                    f"prepend {fn}", f"bgp_large_community.add(({own}, {fn}, {target}));",
                    present=("BGP.as_path: " + " ".join([str(own)] * count + ["65001"]),),
                    absent=(f"({own}, {fn}, {target})",),
                )
                non_target = 6939 if fn >= 694 else 65002
                case(
                    f"do not prepend {fn}", f"bgp_large_community.add(({own}, {fn}, {non_target}));",
                    present=("BGP.as_path: 65001",),
                )
            case("no prepend controls", "", present=(as_path(0),))
            for first, target, elsewhere, third in ((697, 52, 44, 41), (703, 1392, 1840, 1826)):
                for offset in range(6):
                    fn = first + offset
                    count = offset % 3 + 1
                    inverted = offset >= 3
                    match, miss = (elsewhere, target) if inverted else (target, elsewhere)
                    case(
                        f"geographic prepend {fn}", tags((fn, match)),
                        present=(as_path(count),), absent=(f"({own}, {fn}, {match})",),
                    )
                    case(
                        f"no geographic prepend {fn}", tags((fn, miss)),
                        present=(as_path(0),), absent=(f"({own}, {fn}, {miss})",),
                    )
                    case(
                        f"multiple geographic targets {fn}", tags((fn, target), (fn, elsewhere)),
                        present=(as_path(0 if inverted else count),),
                        absent=(f"({own}, {fn}, {target})", f"({own}, {fn}, {elsewhere})"),
                    )
                    case(
                        f"multiple nonmatching geographic targets {fn}", tags((fn, elsewhere), (fn, third)),
                        present=(as_path(count if inverted else 0),),
                    )
                    case(
                        f"other domain geographic prepend {fn}",
                        f"bgp_large_community.add(({other}, {fn}, {match}));",
                        present=(as_path(0),), absent=(f"({other}, {fn}, {match})",),
                    )
                    case(
                        f"third-party geographic prepend {fn}",
                        f"bgp_large_community.add((65002, {fn}, {match}));",
                        present=(as_path(0), f"(65002, {fn}, {match})"),
                    )
                    case(
                        f"deny before geographic prepend {fn}", tags((650, 52), (fn, match)), False,
                    )
            case(
                "geographic prepend uses peer rather than route geo",
                tags((644, 44), (644, 1840), (645, 44), (645, 1840),
                     (697, 52), (703, 1392), (698, 44), (704, 1840)),
                present=(as_path(2),),
            )
            case(
                "ASN region and country prepends are additive",
                tags((691, 6939), (697, 52), (698, 52), (699, 52), (704, 1392), (708, 1840)),
                present=(as_path(12),),
            )
            case(
                "specified and non-specified geographic prepends are additive",
                tags((697, 52), (701, 44), (703, 1392), (707, 1840)),
                present=(as_path(6),),
            )
            for fn, wellknown in ((100666, 666), (165281, 65281), (165282, 65282),
                                  (200666, 666), (265281, 65281), (265282, 65282)):
                target = 65002 if fn in (200666, 265281, 265282) else 6939
                case(
                    f"attach {fn}", f"bgp_large_community.add(({own}, {fn}, {target}));",
                    present=(f"(65535,{wellknown})",), absent=(f"({own}, {fn}, {target})",),
                )
                non_target = 6939 if fn in (200666, 265281, 265282) else 65002
                case(
                    f"do not attach {fn}", f"bgp_large_community.add(({own}, {fn}, {non_target}));",
                    absent=(f"(65535,{wellknown})",),
                )
                if fn in (100666, 165281, 165282):
                    case(
                        f"attach {fn} to all", f"bgp_large_community.add(({own}, {fn}, 0));",
                        present=(f"(65535,{wellknown})",),
                    )
            case(
                "selective cleanup",
                f"""
                bgp_large_community.add(({own}, 644, 52));
                bgp_large_community.add(({own}, 645, 1392));
                bgp_large_community.add(({own}, 999, 123));
                bgp_large_community.add((65002, 670, 6939));
                bgp_community.add((65002, 100));
                """,
                present=(f"({own}, 999, 123)", "(65002, 670, 6939)", "(65002,100)"),
                absent=(f"({own}, 2, 100)", f"({own}, 644, 52)", f"({own}, 645, 1392)"),
            )
            case("existing no-export", "bgp_community.add((65535, 65281));", False)
            case("existing no-advertise", "bgp_community.add((65535, 65282));", False)

        # External import strips forged markers from both domains, then retags
        # the receiving domain. It must leave controls for later egress intact.
        add_case(
            "external ingress",
            """
            bgp_path.prepend(65001);
            bgp_large_community.add((205369, 2, 100));
            bgp_large_community.add((4242422024, 2, 100));
            bgp_large_community.add((4242422024, 644, 41));
            bgp_large_community.add((205369, 670, 6939));
            bgp_large_community.add((205369, 650, 44));
            bgp_large_community.add((205369, 661, 1392));
            bgp_large_community.add((4242422024, 691, 65002));
            bgp_large_community.add((205369, 697, 52));
            bgp_large_community.add((4242422024, 708, 1392));
            bgp_large_community.add((65002, 670, 6939));
            """,
            "iana_peer_import_default(52, 1392);",
            present=("(205369, 2, 101)", "(205369, 644, 52)", "(205369, 645, 44)",
                     "(205369, 670, 6939)", "(205369, 650, 44)", "(205369, 661, 1392)",
                     "(4242422024, 691, 65002)", "(65002, 670, 6939)",
                     "(205369, 697, 52)", "(4242422024, 708, 1392)", "BGP.as_path: 65001"),
            absent=("(205369, 2, 100)", "(4242422024, 2, 100)", "(4242422024, 644, 41)"),
        )

        internal = {**context, "effective_intra_ibgp_sessions": [{"import_policy": "full", "export_policy": "full"}]}
        functions += "\n" + render("intra/ibgp.conf", **internal).partition("template bgp")[0]
        add_case(
            "confederation export preserves ingress and controls",
            """
            bgp_large_community.add((205369, 2, 100));
            bgp_large_community.add((205369, 644, 52));
            bgp_large_community.add((205369, 645, 44));
            bgp_large_community.add((205369, 670, 6939));
            bgp_large_community.add((205369, 651, 52));
            bgp_large_community.add((205369, 660, 1840));
            bgp_path.prepend(65001);
            bgp_large_community.add((205369, 697, 52));
            bgp_large_community.add((4242422024, 708, 1392));
            """,
            "@intra_ibgp_export_full",
            present=("(205369, 2, 100)", "(205369, 644, 52)", "(205369, 645, 44)", "(205369, 670, 6939)",
                     "(205369, 651, 52)", "(205369, 660, 1840)",
                     "(205369, 697, 52)", "(4242422024, 708, 1392)", "BGP.as_path: 65001"),
        )
        ibgp = render("iana/ibgp.conf", **context)
        functions += "\n" + ibgp.partition("template bgp")[0]
        ibgp_export = ibgp.split("export filter {", 1)[1].split("};", 1)[0]
        add_case(
            "IANA iBGP preserves ingress and controls",
            """
            bgp_large_community.add((205369, 2, 100));
            bgp_large_community.add((205369, 644, 52));
            bgp_large_community.add((205369, 645, 44));
            bgp_large_community.add((205369, 670, 6939));
            bgp_path.prepend(65001);
            bgp_large_community.add((205369, 697, 52));
            bgp_large_community.add((4242422024, 708, 1392));
            """,
            ibgp_export,
            present=("(205369, 2, 100)", "(205369, 644, 52)", "(205369, 645, 44)", "(205369, 670, 6939)",
                     "(205369, 697, 52)", "(4242422024, 708, 1392)", "BGP.as_path: 65001"),
        )
        add_case(
            "downstream reject policy",
            "bgp_large_community.add((205369, 2, 100));",
            "if !iana_downstream_export_reject(6939, 52, 1392) then reject; accept;", False,
        )
        for action, accepted in ((ibgp_export, True),
                                 ("if !iana_peer_export_default(6939, 52, 1392) then reject; accept;", False)):
            add_case(
                "owned host route internal versus external",
                "bgp_large_community.add((205369, 2, 100)); bgp_community.add((65535, 65281));",
                action, accepted, prefix=f"2a14:7583:f224::{len(cases) + 1:x}/128",
                present=("(205369, 2, 100)", "(65535,65281)"),
            )

        for case in cases:
            action = case["action"]
            case["import_filter"] = action[1:] if action.startswith("@") else "{ " + action + " }"
        protocols = "\n".join(
            f"""protocol static case_{index} {{
                {'ipv6' if ':' in case['prefix'] else 'ipv4'} {{ import filter {case['import_filter']}; }};
                route {case['prefix']} reject {{ {case['body']} }};
            }}""" for index, case in enumerate(cases)
        )
        config = f"""
router id 192.0.2.1;
define IANA_OWNAS = 205369;
define DN42_OWNAS = 4242422024;
define INTRA_CONFEDERATION_START = 4220240000;
define INTRA_CONFEDERATION_END = 4220249999;
define GEO_COMM_AS = 64511;
define POP_REGION = 44;
define POP_COUNTRY = 1840;
define DN42_REGION = POP_REGION;
define DN42_COUNTRY = POP_COUNTRY;
{defines}
roa6 table iana_roa_v6;
roa4 table dn42_roa;
roa6 table dn42_roa_v6;
roa4 table dn42_roa_flap_v4;
roa6 table dn42_roa_flap_v6;
{functions}
{protocols}
"""
        with tempfile.TemporaryDirectory(prefix="bird-export-test-") as directory:
            path = Path(directory)
            conf, sock = path / "bird.conf", path / "bird.ctl"
            conf.write_text(config)
            parsed = subprocess.run(["bird", "-p", "-c", str(conf)], capture_output=True, text=True)
            self.assertEqual(parsed.returncode, 0, parsed.stderr)
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
                    for case in cases:
                        with self.subTest(case=case["label"]):
                            output = subprocess.run(
                                ["birdc", "-s", str(sock), "show", "route", case["prefix"], "all"],
                                capture_output=True, text=True,
                            ).stdout
                            if not case["accepted"]:
                                self.assertIn("Network not found", output)
                                continue
                            self.assertIn(case["prefix"], output)
                            for value in case["present"]:
                                if value.startswith("BGP.as_path:"):
                                    self.assertIn(value, [line.strip() for line in output.splitlines()])
                                else:
                                    self.assertIn(value, output)
                            for value in case["absent"]:
                                self.assertNotIn(value, output)
                finally:
                    process.terminate()
                    process.wait(timeout=5)


if __name__ == "__main__":
    unittest.main()

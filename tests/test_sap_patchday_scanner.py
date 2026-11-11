"""Tests for sap_patchday_scanner.py.

All expected grades come from the Onapsis ICM2SHELL and PROXYGATE
advisories of 10 November 2026, cross-checked against The Hacker News
and RedRays. The mock HTTP server and the fake disp+work install are
local fixtures only; the scanner never touches a real SAP system in
these tests.
"""

import json
import os
import subprocess
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sap_patchday_scanner import (  # noqa: E402
    grade_gateway,
    grade_hana,
    grade_icm,
    grade_saml2,
    grade_shield,
    grade_system,
    grade_xs_advanced,
    main,
    overall_grade,
    parse_hana_revision,
    parse_kernel,
    parse_prxyinfo,
)

METADATA_XML = """<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
 entityID="https://sap.example/saml2">
<md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
</md:SPSSODescriptor>
</md:EntityDescriptor>
"""


class MetadataHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/sap/saml2/sp/metadata"):
            body = METADATA_XML.encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/xml")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, *args):
        pass


def run_server():
    server = HTTPServer(("127.0.0.1", 0), MetadataHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


class TestParseKernel(unittest.TestCase):
    def test_plain(self):
        self.assertEqual(parse_kernel("7.93"), ("7.93", None))

    def test_with_patch(self):
        self.assertEqual(parse_kernel("7.93 PL 419"), ("7.93", 419))

    def test_dispwork_style(self):
        self.assertEqual(parse_kernel("793 patch 419"), ("7.93", 419))

    def test_unparseable(self):
        self.assertEqual(parse_kernel("banana"), (None, None))


class TestGradeIcm(unittest.TestCase):
    def test_below_fixed_is_vulnerable(self):
        result = grade_icm("7.53", 1615)
        self.assertEqual(result["grade"], "VULNERABLE")

    def test_at_fixed_is_patched(self):
        self.assertEqual(grade_icm("7.53", 1616)["grade"], "PATCHED")
        self.assertEqual(grade_icm("7.54", 710)["grade"], "PATCHED")
        self.assertEqual(grade_icm("7.77", 914)["grade"], "PATCHED")
        self.assertEqual(grade_icm("9.16", 111)["grade"], "PATCHED")
        self.assertEqual(grade_icm("9.18", 37)["grade"], "PATCHED")

    def test_793_stack_kernel_401_is_patched(self):
        self.assertEqual(grade_icm("7.93", 401)["grade"], "PATCHED")

    def test_793_402_is_patched(self):
        self.assertEqual(grade_icm("7.93", 402)["grade"], "PATCHED")

    def test_793_419_trap_is_vulnerable(self):
        result = grade_icm("7.93", 419)
        self.assertEqual(result["grade"], "VULNERABLE")
        self.assertIn("420", result["note"])

    def test_793_gap_is_vulnerable(self):
        self.assertEqual(grade_icm("7.93", 403)["grade"], "VULNERABLE")
        self.assertEqual(grade_icm("7.93", 410)["grade"], "VULNERABLE")

    def test_793_420_is_patched(self):
        self.assertEqual(grade_icm("7.93", 420)["grade"], "PATCHED")
        self.assertEqual(grade_icm("7.93", 421)["grade"], "PATCHED")

    def test_793_below_401_is_vulnerable(self):
        self.assertEqual(grade_icm("7.93", 400)["grade"], "VULNERABLE")

    def test_920_stack_11_patched(self):
        self.assertEqual(grade_icm("9.20", 11)["grade"], "PATCHED")

    def test_920_12_is_unknown_not_clean(self):
        result = grade_icm("9.20", 12)
        self.assertEqual(result["grade"], "UNKNOWN")
        self.assertIn("3778788", result["note"])

    def test_920_13_patched(self):
        self.assertEqual(grade_icm("9.20", 13)["grade"], "PATCHED")

    def test_920_below_11_vulnerable(self):
        self.assertEqual(grade_icm("9.20", 10)["grade"], "VULNERABLE")

    def test_722_not_affected(self):
        result = grade_icm("7.22", 1612)
        self.assertEqual(result["grade"], "NOT-AFFECTED")

    def test_out_of_maintenance_no_fix(self):
        for release in ("7.40", "7.49", "7.73", "7.89"):
            self.assertEqual(grade_icm(release, 999)["grade"], "NO-FIX")

    def test_unknown_release_is_unknown(self):
        self.assertEqual(grade_icm("8.88", 1)["grade"], "UNKNOWN")

    def test_missing_patch_is_unknown(self):
        self.assertEqual(grade_icm("7.93", None)["grade"], "UNKNOWN")


class TestGradeHanaAndXs(unittest.TestCase):
    def test_hana_fixed_revisions(self):
        self.assertEqual(grade_hana("2.00.079.11")["grade"], "PATCHED")
        self.assertEqual(grade_hana("2.00.089.05")["grade"], "PATCHED")
        self.assertEqual(grade_hana("089.05")["grade"], "PATCHED")

    def test_hana_below_fixed_is_vulnerable(self):
        self.assertEqual(grade_hana("2.00.079.10")["grade"], "VULNERABLE")
        self.assertEqual(grade_hana("2.00.089.04")["grade"], "VULNERABLE")

    def test_hana_unknown_sps(self):
        self.assertEqual(grade_hana("2.00.090.01")["grade"], "UNKNOWN")

    def test_hana_unparseable(self):
        self.assertEqual(grade_hana("banana")["grade"], "UNKNOWN")

    def test_xs_advanced(self):
        self.assertEqual(grade_xs_advanced("05", 4)["grade"], "PATCHED")
        self.assertEqual(grade_xs_advanced("05", 5)["grade"], "PATCHED")
        self.assertEqual(grade_xs_advanced("05", 3)["grade"], "VULNERABLE")
        self.assertEqual(grade_xs_advanced("04", 9)["grade"], "UNKNOWN")


class TestGradeShield(unittest.TestCase):
    def test_shield_levels(self):
        self.assertEqual(grade_shield("7.53", 1629)["grade"], "SHIELDED")
        self.assertEqual(grade_shield("7.53", 1628)["grade"], "VULNERABLE")
        self.assertEqual(grade_shield("7.93", 430)["grade"], "SHIELDED")
        self.assertEqual(grade_shield("9.16", 200)["grade"], "SHIELDED")

    def test_router_voids_shield(self):
        result = grade_shield("7.53", 1629, router=True)
        self.assertEqual(result["grade"], "NOT-EXPOSED")
        self.assertIn("ROUTER", result["note"])

    def test_unknown_release(self):
        self.assertEqual(grade_shield("8.04", 244)["grade"], "UNKNOWN")


class TestParsePrxyinfo(unittest.TestCase):
    def test_wildcard_is_permissive(self):
        state, _ = parse_prxyinfo("P SOURCE=* DEST=*\n")
        self.assertEqual(state, "permissive")

    def test_broad_cidr_is_permissive(self):
        state, _ = parse_prxyinfo("P SOURCE=10.0.0.0/8 DEST=internal\n")
        self.assertEqual(state, "permissive")

    def test_restrictive_hosts(self):
        state, _ = parse_prxyinfo(
            "P SOURCE=app01.corp.example,app02.corp.example DEST=*\n")
        self.assertEqual(state, "restrictive")

    def test_restrictive_narrow_cidr(self):
        state, _ = parse_prxyinfo("P SOURCE=10.1.2.0/24 DEST=*\n")
        self.assertEqual(state, "restrictive")

    def test_comments_ignored(self):
        state, _ = parse_prxyinfo(
            "# P SOURCE=* DEST=*\nP SOURCE=localhost DEST=*\n")
        self.assertEqual(state, "restrictive")

    def test_no_rules_is_missing(self):
        state, _ = parse_prxyinfo("# nothing here\n")
        self.assertEqual(state, "missing")

    def test_one_permissive_rule_taints_the_file(self):
        state, _ = parse_prxyinfo(
            "P SOURCE=localhost DEST=*\nP SOURCE=* DEST=*\n")
        self.assertEqual(state, "permissive")


class TestGradeGateway(unittest.TestCase):
    def test_permissive_prxyinfo_overrides_patched_kernel(self):
        result = grade_gateway("7.53", 1700, "permissive", 1)
        self.assertEqual(result["grade"], "VULNERABLE")
        self.assertIn("any kernel patch level", result["note"])

    def test_restrictive_prxyinfo_is_not_exposed(self):
        result = grade_gateway("7.53", 100, "restrictive", 0)
        self.assertEqual(result["grade"], "NOT-EXPOSED")

    def test_cross_cve_trap_753_1616(self):
        # 7.53 PL 1616 fixes ICM2SHELL but PROXYGATE needs PL 1625.
        self.assertEqual(grade_icm("7.53", 1616)["grade"], "PATCHED")
        result = grade_gateway("7.53", 1616, "missing", 1)
        self.assertEqual(result["grade"], "VULNERABLE")

    def test_753_1625_with_param_is_patched(self):
        result = grade_gateway("7.53", 1625, "missing", 1)
        self.assertEqual(result["grade"], "PATCHED")

    def test_753_1625_param_zero_is_vulnerable(self):
        result = grade_gateway("7.53", 1625, "missing", 0)
        self.assertEqual(result["grade"], "VULNERABLE")
        self.assertIn("patch alone", result["note"])

    def test_753_1625_param_unknown_is_unknown(self):
        result = grade_gateway("7.53", 1625, "missing", None)
        self.assertEqual(result["grade"], "UNKNOWN")

    def test_793_param_only(self):
        self.assertEqual(
            grade_gateway("7.93", 419, "missing", 1)["grade"], "PATCHED")
        self.assertEqual(
            grade_gateway("7.93", 419, "missing", 0)["grade"], "VULNERABLE")
        self.assertEqual(
            grade_gateway("7.93", 419, "missing", None)["grade"], "UNKNOWN")

    def test_920_patch_only(self):
        self.assertEqual(
            grade_gateway("9.20", 16, "missing", None)["grade"], "PATCHED")
        self.assertEqual(
            grade_gateway("9.20", 15, "missing", None)["grade"], "VULNERABLE")

    def test_722_gateway_needs_patch(self):
        self.assertEqual(
            grade_gateway("7.22", 1611, "missing", 1)["grade"], "VULNERABLE")
        self.assertEqual(
            grade_gateway("7.22", 1612, "missing", 1)["grade"], "PATCHED")

    def test_out_of_maintenance_no_fix(self):
        result = grade_gateway("7.40", 1, "missing", 0)
        self.assertEqual(result["grade"], "NO-FIX")

    def test_unknown_release(self):
        self.assertEqual(
            grade_gateway("8.88", 1, "missing", 1)["grade"], "UNKNOWN")


class TestGradeSaml2(unittest.TestCase):
    def test_in_scope_when_in_use(self):
        result = grade_saml2(750, True)
        self.assertEqual(result["grade"], "IN-SCOPE")
        self.assertIn("3849308", result["note"])

    def test_not_exposed_when_not_in_use(self):
        self.assertEqual(grade_saml2(750, False)["grade"], "NOT-EXPOSED")

    def test_unknown_use_is_in_scope(self):
        self.assertEqual(grade_saml2(750, None)["grade"], "IN-SCOPE")

    def test_basis_not_in_list(self):
        self.assertEqual(grade_saml2(700, True)["grade"], "NOT-AFFECTED")

    def test_no_basis_is_not_checked(self):
        self.assertEqual(grade_saml2(None, True)["grade"], "NOT-CHECKED")


class TestGradeSystem(unittest.TestCase):
    def test_793_419_system(self):
        checks = grade_system({"kernel": "7.93", "patch": 419})
        by_cve = {c["cve"]: c for c in checks}
        self.assertEqual(by_cve["CVE-2026-76964"]["grade"], "VULNERABLE")
        self.assertEqual(by_cve["CVE-2026-89126"]["grade"], "VULNERABLE")
        # Gateway: no prxyinfo or parameter supplied, kernel 7.93 is
        # param-only, so it grades UNKNOWN, not clean.
        self.assertEqual(by_cve["CVE-2026-89103"]["grade"], "UNKNOWN")
        self.assertEqual(overall_grade(checks), "VULNERABLE")

    def test_fully_patched_system(self):
        checks = grade_system({
            "kernel": "7.53", "patch": 1625,
            "prxyinfo": "restrictive", "gw_acl_mode_proxy": 1,
            "basis": 750, "saml2": False,
        })
        self.assertEqual(overall_grade(checks), "NOT-EXPOSED")

    def test_hana_only_entry(self):
        checks = grade_system({"hana": "2.00.089.04"})
        self.assertEqual(len(checks), 1)
        self.assertEqual(checks[0]["grade"], "VULNERABLE")

    def test_url_probe_enables_saml2(self):
        server = run_server()
        try:
            port = server.server_address[1]
            checks = grade_system({
                "basis": 750,
                "url": f"http://127.0.0.1:{port}",
            })
            saml2 = [c for c in checks
                     if c["cve"] == "CVE-2026-120017"
                     and c["component"] == "SAML2 service provider"]
            self.assertEqual(len(saml2), 1)
            self.assertEqual(saml2[0]["grade"], "IN-SCOPE")
        finally:
            server.shutdown()

    def test_url_probe_unreachable_is_unknown(self):
        checks = grade_system({"basis": 750, "url": "http://127.0.0.1:1"})
        probe = [c for c in checks if c["component"] == "SAML2 metadata probe"]
        self.assertEqual(len(probe), 1)
        self.assertEqual(probe[0]["grade"], "UNKNOWN")


class TestCli(unittest.TestCase):
    def test_list(self):
        self.assertEqual(main(["--list"]), 0)

    def test_vulnerable_exit_code(self):
        self.assertEqual(main(["--kernel", "7.93", "--patch", "419"]), 2)

    def test_patched_exit_code(self):
        self.assertEqual(
            main(["--kernel", "7.53", "--patch", "1625",
                  "--prxyinfo-state", "restrictive",
                  "--gw-acl-mode-proxy", "1"]), 0)

    def test_json_output(self):
        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(["--kernel", "7.93", "--patch", "419", "--json"])
        self.assertEqual(code, 2)
        data = json.loads(buf.getvalue())
        self.assertEqual(data["overall"], "VULNERABLE")
        self.assertTrue(any(c["cve"] == "CVE-2026-76964"
                            for c in data["checks"]))

    def test_kernel_version_flag(self):
        self.assertEqual(main(["--kernel-version", "7.93 PL 419"]), 2)

    def test_inventory_json(self):
        import io
        import tempfile
        from contextlib import redirect_stdout
        inventory = [
            {"label": "prod", "kernel": "7.93", "patch": 420,
             "prxyinfo": "missing", "gw_acl_mode_proxy": 1},
            {"label": "old", "kernel": "7.53", "patch": 1616,
             "prxyinfo": "missing", "gw_acl_mode_proxy": 1},
        ]
        with tempfile.NamedTemporaryFile("w", suffix=".json",
                                        delete=False) as handle:
            json.dump(inventory, handle)
            path = handle.name
        try:
            buf = io.StringIO()
            with redirect_stdout(buf):
                code = main(["--inventory-json", path])
            # prod is clean; old is VULNERABLE on the Gateway (1616 < 1625)
            self.assertEqual(code, 2)
            self.assertIn("old", buf.getvalue())
        finally:
            os.unlink(path)

    def test_local_fixture(self):
        import io
        import tempfile
        from contextlib import redirect_stdout
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "exe").mkdir()
            dispwork = root / "exe" / "disp+work"
            dispwork.write_text(
                "#!/bin/sh\n"
                "echo 'kernel release 7.93, patch level 419'\n")
            dispwork.chmod(0o755)
            (root / "profile").mkdir()
            (root / "profile" / "DEFAULT.PFL").write_text(
                "gw/acl_mode_proxy = 0\n"
                "icm/HTTP/support_websocket_upgrade = TRUE\n")
            (root / "prxyinfo").write_text("P SOURCE=* DEST=*\n")
            buf = io.StringIO()
            with redirect_stdout(buf):
                code = main(["--local", str(root)])
            self.assertEqual(code, 2)
            output = buf.getvalue()
            self.assertIn("VULNERABLE", output)

    def test_missing_args_errors(self):
        with self.assertRaises(SystemExit) as caught:
            main([])
        self.assertEqual(caught.exception.code, 2)


class TestMainEndToEnd(unittest.TestCase):
    def test_script_runs(self):
        here = Path(__file__).resolve().parent.parent
        proc = subprocess.run(
            [sys.executable, str(here / "sap_patchday_scanner.py"),
             "--kernel", "7.54", "--patch", "718",
             "--prxyinfo-state", "missing", "--gw-acl-mode-proxy", "1"],
            capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0)
        self.assertIn("PATCHED", proc.stdout)


if __name__ == "__main__":
    unittest.main()

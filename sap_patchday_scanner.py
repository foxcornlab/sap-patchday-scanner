#!/usr/bin/env python3
"""Detection-only local triage for the SAP November 2026 Patch Day batch.

Four flaws, each rated CVSS 10.0, were fixed on 10 November 2026, and
none of them needs an attacker to log in first:

- CVE-2026-76964 (ICM2SHELL, ICM) and CVE-2026-89126 (ICM2SHELL, Web
  Dispatcher): a heap out-of-bounds write in the SAP kernel code that
  reassembles fragmented WebSocket messages. An unauthenticated
  attacker with network access to the HTTP/HTTPS port runs operating
  system commands as <sid>adm. Onapsis, which found and reported the
  flaw, gave SAP a working exploit. WebSocket support is on by
  default, so a system is exposed even if nothing uses it.
- CVE-2026-89103 (PROXYGATE, SAP Gateway): broken access control in
  the gateway's proxy list. An unauthenticated attacker is treated as
  one of the system's own application servers and can run operating
  system commands as <sid>adm. Onapsis demonstrated it end to end in
  a proof of concept shared with SAP.
- CVE-2026-120017 (SAML2 service provider): the service provider did
  not check signatures on incoming assertions in some configurations,
  so an unauthenticated attacker can forge a response and log on as
  any ABAP user, including privileged ones.

This tool sends no exploit traffic and probes no vulnerable path. It
only compares kernel patch levels, gateway configuration, and SAP_BASIS
releases you supply, or values it reads from a local install, against
the fixed levels published by Onapsis. Its one network read is an
optional plain GET of the public SAML2 metadata document, which only
establishes whether SAML2 is enabled on a client.

The traps this tool exists for:

- Kernel 7.93 patch level 419 is still vulnerable to ICM2SHELL. Only
  the updated PL 401 Stack Kernel, PL 402 once released, and PL 420 or
  later carry the fix. A higher patch level is not always a fixed one.
- The ICM fix level and the Gateway fix level are different numbers
  for the same kernel. Kernel 7.53 PL 1616 fixes ICM2SHELL, but
  PROXYGATE needs PL 1625. Patching to the ICM level does not close
  the Gateway flaw. The same gap exists on 7.54 (710 vs 718), 7.77
  (914 vs 915), and 9.20 (13 vs 16).
- A kernel patch alone does not protect the Gateway. PROXYGATE needs
  a restrictive prxyinfo file or gw/acl_mode_proxy set to 1 as well,
  and a permissive prxyinfo leaves the system vulnerable at any patch
  level, patched or not.
- Kernel 7.22 is not affected by ICM2SHELL, but it is affected by
  PROXYGATE. Checking one flaw does not clear the other.
- For SAML2 there is no public fixed support-package table: SAP note
  3849308 sits behind SAP for Me sign-in. This tool grades a system
  IN-SCOPE when its SAP_BASIS release is listed and SAML2 logon is in
  use; it does not claim a patched state it cannot verify.

Usage:
    python3 sap_patchday_scanner.py --kernel 7.93 --patch 419
    python3 sap_patchday_scanner.py --kernel 7.53 --patch 1625 --prxyinfo prxyinfo --gw-acl-mode-proxy 1
    python3 sap_patchday_scanner.py --kernel 7.93 --patch 420 --basis 750 --saml2
    python3 sap_patchday_scanner.py --hana-revision 2.00.089.05
    python3 sap_patchday_scanner.py --local
    python3 sap_patchday_scanner.py --inventory-json sites.json
    python3 sap_patchday_scanner.py --list

Exit codes: 0 = nothing vulnerable found, 2 = vulnerable finding
(VULNERABLE or NO-FIX), 1 = scan error (missing argument, bad input).
UNKNOWN and IN-SCOPE do not change the exit code, but they are not
clean: a version that has not been graded, or a flaw whose patch state
cannot be verified from public sources, has simply not been cleared.
"""

import argparse
import json
import re
import shutil
import socket
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

CVES = {
    "ICM": "CVE-2026-76964",
    "WD": "CVE-2026-89126",
    "GW": "CVE-2026-89103",
    "SAML2": "CVE-2026-120017",
}

# Fixed patch levels for ICM2SHELL (CVE-2026-76964 / CVE-2026-89126),
# per the Onapsis ICM2SHELL advisory of 10 November 2026. A patch level
# at or above the listed minimum carries the fix, except for the two
# releases with an explicit gap, handled in grade_icm.
ICM_FIXED_MIN = {
    "7.53": 1616,
    "7.54": 710,
    "7.77": 914,
    "9.16": 111,
    "9.18": 37,
}
# Kernels out of maintenance: affected, and they may never get a fix.
ICM_NO_FIX = {"7.40", "7.41", "7.42", "7.45", "7.49", "7.73", "7.81",
              "7.85", "7.89"}
# Kernel 7.22 is not affected by ICM2SHELL at all, per Onapsis.
ICM_NOT_AFFECTED = {"7.22"}

# Fixed patch levels for PROXYGATE (CVE-2026-89103), per the Onapsis
# PROXYGATE advisory of 10 November 2026. These are the minimum patch
# levels that gain the gw/acl_mode_proxy parameter (or, for 9.20/9.21,
# the kernel patch that is the whole fix). They are higher than the
# ICM2SHELL levels for the same release: that gap is a trap, not a typo.
GW_FIXED_MIN = {
    "7.22": 1612,
    "7.53": 1625,
    "7.54": 718,
    "7.77": 915,
    "8.04": 244,
    "9.20": 16,
    "9.21": 4,
}
# On these releases the parameter already exists, so the fix is setting
# gw/acl_mode_proxy to 1; no new kernel is required.
GW_PARAM_ONLY = {"7.93", "9.16"}
# On 9.20/9.21 SAP lists no manual activity beyond applying the kernel
# patch, so the patch level alone decides the grade there.
GW_PATCH_ONLY = {"9.20", "9.21"}
GW_NO_FIX = {"7.20", "7.21", "7.40", "7.41", "7.42", "7.45", "7.49",
             "7.73", "7.81", "7.85", "7.89"}

# A Web Dispatcher on these levels or higher can shield the backends
# behind it, per SAP note 3778788 FAQ 14 as quoted by Onapsis. The
# shield only covers backends reached exclusively through that WD, and
# it does not work if the WD is configured as a router (PROT=ROUTER).
SHIELD_MIN = {
    "7.53": 1629,
    "7.54": 723,
    "7.93": 430,
    "9.16": 200,
}

# SAP HANA Database 2.0 revisions carrying the ICM2SHELL fix for the
# Web Dispatcher embedded in XS Classic: (SPS, revision).
HANA_FIXED = {("079", 11), ("089", 5)}
# SAP Extended Application Services 1.0 (XS Advanced): SP05 Patch 4.
XS_ADV_FIXED = ("05", 4)

# SAP_BASIS releases listed in SAP note 3849308 for CVE-2026-120017,
# per The Hacker News table of 10 November 2026, corroborated by the
# Circuitry summary. RedRays' rendering of the same note also names
# 804 and 918; those two are treated as a source disagreement and are
# not graded as affected here, they are flagged in the note instead.
SAML2_BASIS = {702, 731, 740, 750, 751, 752, 753, 754, 755, 756, 757,
               758, 816, 920, 921, 922}

GRADE_ORDER = ["VULNERABLE", "NO-FIX", "IN-SCOPE", "UNKNOWN",
               "NOT-EXPOSED", "SHIELDED", "NOT-AFFECTED", "PATCHED",
               "NOT-CHECKED"]

_KERNEL_RE = re.compile(r"(\d+)\.(\d+)")
_PATCH_RE = re.compile(r"(\d+)")
# disp+work -v prints the kernel release and patch level; the exact
# wording varies by release, so both numbers are matched tolerantly
# and the raw output is kept for the note when parsing fails.
_DISPWORK_RELEASE_RE = re.compile(
    r"kernel[^0-9]*?(\d)[\.\s]?(\d\d)\b", re.IGNORECASE)
_DISPWORK_PATCH_RE = re.compile(
    r"patch(?:\s*level)?\s*[:=]?\s*(\d+)", re.IGNORECASE)


def parse_kernel(text):
    """Return (release, patch) from a kernel string, or (None, None).

    Accepts `7.93`, `7.93 PL 419`, `793 patch 419`, and a bare patch
    number on its own is not enough: the release is required.
    """
    if not isinstance(text, str):
        return None, None
    match = _KERNEL_RE.search(text)
    if match:
        release = f"{match.group(1)}.{match.group(2)}"
        rest = text[match.end():]
    else:
        # Compact form as printed by disp+work, e.g. `793 patch 419`.
        compact = re.match(r"\s*(\d)(\d\d)\b", text)
        if not compact:
            return None, None
        release = f"{compact.group(1)}.{compact.group(2)}"
        rest = text[compact.end():]
    patch_match = _PATCH_RE.search(rest)
    patch = int(patch_match.group(1)) if patch_match else None
    return release, patch


def parse_hana_revision(text):
    """Return (sps, revision) from a HANA revision string, or None.

    Accepts `2.00.089.05`, `089.05`, and `2.00.079.11`.
    """
    if not isinstance(text, str):
        return None
    parts = text.strip().split(".")
    if len(parts) == 4 and parts[0] == "2" and parts[1] == "00":
        return parts[2], int(parts[3])
    if len(parts) == 2:
        return parts[0], int(parts[1])
    return None


def grade_icm(release, patch):
    """Grade one kernel release + patch level against ICM2SHELL.

    Covers both CVE-2026-76964 (ICM) and CVE-2026-89126 (Web
    Dispatcher): the two share the kernel code and the fixed levels.
    Returns a dict with grade, fixed, and note keys.
    """
    if release is None or patch is None:
        return {"grade": "UNKNOWN", "fixed": None,
                "note": "kernel release and patch level are both needed "
                        "to grade ICM2SHELL; supply --kernel and --patch"}
    if release in ICM_NOT_AFFECTED:
        return {"grade": "NOT-AFFECTED", "fixed": None,
                "note": f"kernel {release} is not affected by ICM2SHELL "
                        f"({CVES['ICM']} / {CVES['WD']}), per Onapsis; "
                        "it is still affected by PROXYGATE, check the "
                        "Gateway grade separately"}
    if release in ICM_NO_FIX:
        return {"grade": "NO-FIX", "fixed": None,
                "note": f"kernel {release} is out of maintenance, "
                        f"affected by ICM2SHELL ({CVES['ICM']} / "
                        f"{CVES['WD']}), and may never get a fix; upgrade "
                        "to a supported downward-compatible kernel (SAP "
                        "note 3778788 FAQ 4)"}
    if release == "7.93":
        # The 419 trap: a higher patch level is not always a fixed one.
        if patch == 401:
            return {"grade": "PATCHED", "fixed": "7.93 PL 401 (Stack "
                    "Kernel) / PL 402 / PL 420+",
                    "note": "PL 401 carries the fix only as the updated "
                            "PL 401 Stack Kernel; confirm it is the "
                            "re-released stack kernel build, not the "
                            "original 401 (SAP note 3778788 FAQ 6)"}
        if patch == 402:
            return {"grade": "PATCHED", "fixed": "7.93 PL 401 (Stack "
                    "Kernel) / PL 402 / PL 420+",
                    "note": "PL 402 carries the fix once released (SAP "
                            "note 3778788 FAQ 6)"}
        if 403 <= patch <= 419:
            return {"grade": "VULNERABLE", "fixed": "7.93 PL 401 (Stack "
                    "Kernel) / PL 402 / PL 420+",
                    "note": f"7.93 PL {patch} is still vulnerable to "
                            f"ICM2SHELL; PL 419 is confirmed affected and "
                            "the fix lands at PL 420, so patch to PL 420 "
                            "or later (SAP note 3778788 FAQ 6)"}
        if patch >= 420:
            return {"grade": "PATCHED", "fixed": "7.93 PL 401 (Stack "
                    "Kernel) / PL 402 / PL 420+",
                    "note": f"7.93 PL {patch} is at or above the fixed "
                            "PL 420"}
        return {"grade": "VULNERABLE", "fixed": "7.93 PL 401 (Stack "
                "Kernel) / PL 402 / PL 420+",
                "note": f"7.93 PL {patch} is below every fixed patch "
                        "level for ICM2SHELL"}
    if release == "9.20":
        # Onapsis lists 11 and 13 as the fixed levels; 12 sits in the
        # gap between the two channels and is not listed as fixed.
        if patch == 11:
            return {"grade": "PATCHED", "fixed": "9.20 PL 11 / PL 13+",
                    "note": "PL 11 carries the fix as the stack kernel "
                            "build (SAP note 3778788)"}
        if patch == 12:
            return {"grade": "UNKNOWN", "fixed": "9.20 PL 11 / PL 13+",
                    "note": "9.20 PL 12 is not listed by Onapsis as a "
                            "fixed level for ICM2SHELL: the listed levels "
                            "are 11 and 13. It has not been cleared, only "
                            "left ungraded; verify it against SAP note "
                            "3778788 before treating it as safe"}
        if patch >= 13:
            return {"grade": "PATCHED", "fixed": "9.20 PL 11 / PL 13+",
                    "note": f"9.20 PL {patch} is at or above the fixed "
                            "PL 13"}
        return {"grade": "VULNERABLE", "fixed": "9.20 PL 11 / PL 13+",
                "note": f"9.20 PL {patch} is below the fixed patch level "
                        "for ICM2SHELL"}
    if release in ICM_FIXED_MIN:
        fixed = ICM_FIXED_MIN[release]
        if patch >= fixed:
            return {"grade": "PATCHED", "fixed": f"{release} PL {fixed}+",
                    "note": f"{release} PL {patch} is at or above the "
                            f"fixed PL {fixed} for ICM2SHELL"}
        return {"grade": "VULNERABLE", "fixed": f"{release} PL {fixed}+",
                "note": f"{release} PL {patch} is below the fixed PL "
                        f"{fixed} for ICM2SHELL; the ICM and every Web "
                        "Dispatcher on this kernel are open to "
                        "unauthenticated remote code execution"}
    return {"grade": "UNKNOWN", "fixed": None,
            "note": f"kernel {release} is not in the published "
                    "ICM2SHELL table (7.53, 7.54, 7.77, 7.93, 9.16, "
                    "9.18, 9.20, plus out-of-maintenance lines); it has "
                    "not been cleared, only left ungraded; check it "
                    "against SAP notes 3778530 / 3778556"}


def grade_hana(revision_text):
    """Grade a HANA 2.0 revision against ICM2SHELL (XS Classic WD)."""
    parsed = parse_hana_revision(revision_text)
    if parsed is None:
        return {"grade": "UNKNOWN", "fixed": None,
                "note": f"HANA revision {revision_text!r} does not parse "
                        "as 2.00.079.11 or 2.00.089.05"}
    sps, revision = parsed
    fixed = dict(HANA_FIXED).get(sps)
    if fixed is None:
        return {"grade": "UNKNOWN", "fixed": None,
                "note": f"HANA SPS {sps} is not in the published fix "
                        "table (SPS 079 revision 11, SPS 089 revision 5); "
                        "it has not been cleared, only left ungraded"}
    if revision >= fixed:
        return {"grade": "PATCHED", "fixed": f"2.00.{sps}.{fixed:02d}",
                "note": f"HANA 2.00.{sps}.{revision:02d} is at or above "
                        f"the fixed revision 2.00.{sps}.{fixed:02d}"}
    return {"grade": "VULNERABLE", "fixed": f"2.00.{sps}.{fixed:02d}",
            "note": f"HANA 2.00.{sps}.{revision:02d} is below the fixed "
                    f"revision 2.00.{sps}.{fixed:02d} for ICM2SHELL in "
                    "the XS Classic Web Dispatcher"}


def grade_xs_advanced(sp, patch):
    """Grade an XS Advanced SP + patch against ICM2SHELL."""
    if sp is None or patch is None:
        return {"grade": "UNKNOWN", "fixed": None,
                "note": "XS Advanced needs both a support package and a "
                        "patch number to grade"}
    fixed_sp, fixed_patch = XS_ADV_FIXED
    if sp != fixed_sp:
        return {"grade": "UNKNOWN", "fixed": None,
                "note": f"XS Advanced SP{sp} is not in the published fix "
                        f"table (SP{fixed_sp} Patch {fixed_patch}); it has "
                        "not been cleared, only left ungraded"}
    if patch >= fixed_patch:
        return {"grade": "PATCHED", "fixed": f"SP{fixed_sp} Patch "
                f"{fixed_patch}",
                "note": f"XS Advanced SP{sp} Patch {patch} is at or above "
                        f"the fixed Patch {fixed_patch}"}
    return {"grade": "VULNERABLE", "fixed": f"SP{fixed_sp} Patch "
            f"{fixed_patch}",
            "note": f"XS Advanced SP{sp} Patch {patch} is below the fixed "
                    f"Patch {fixed_patch} for ICM2SHELL"}


def grade_shield(release, patch, router=False):
    """Grade a Web Dispatcher as a shield for the backends behind it.

    Per SAP note 3778788 FAQ 14: a WD on the shield levels can protect
    backends reached exclusively through it. A WD configured as a
    router (PROT=ROUTER) cannot.
    """
    if release is None or patch is None:
        return {"grade": "UNKNOWN", "fixed": None,
                "note": "a Web Dispatcher release and patch level are "
                        "needed to grade the shield"}
    if router:
        return {"grade": "NOT-EXPOSED", "fixed": None,
                "note": "the shield does not work on a Web Dispatcher "
                        "configured as a router (PROT=ROUTER); backends "
                        "behind it are not protected by it"}
    fixed = SHIELD_MIN.get(release)
    if fixed is None:
        return {"grade": "UNKNOWN", "fixed": None,
                "note": f"no published shield level for Web Dispatcher "
                        f"{release} (shield levels exist for 7.53, 7.54, "
                        "7.93, 9.16); it has not been cleared, only left "
                        "ungraded"}
    if patch >= fixed:
        return {"grade": "SHIELDED", "fixed": f"{release} PL {fixed}+",
                "note": f"Web Dispatcher {release} PL {patch} is at or "
                        f"above the shield level PL {fixed}; it protects "
                        "backends reached exclusively through it, and "
                        "only those. Patch the backends too: the shield "
                        "is a workaround, not a fix"}
    return {"grade": "VULNERABLE", "fixed": f"{release} PL {fixed}+",
            "note": f"Web Dispatcher {release} PL {patch} is below the "
                    f"shield level PL {fixed}; it does not shield the "
                    "backends behind it"}


def parse_prxyinfo(text):
    """Grade a prxyinfo file's contents.

    Returns ("permissive" | "restrictive" | "missing", note). A rule is
    permissive when its SOURCE is a wildcard or a broad network: an
    attacker sitting in that source range can use the gateway as a
    proxy. SOURCE is what decides exposure; DEST alone does not.
    """
    rules = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if not line.startswith("P "):
            continue
        source = None
        for token in line.split()[1:]:
            if token.upper().startswith("SOURCE="):
                source = token.split("=", 1)[1]
                break
        rules.append(source)
    if not rules:
        return "missing", ("no P rules found in the prxyinfo file, so the "
                            "gateway falls back to its default proxy "
                            "policy; check gw/acl_mode_proxy next")
    permissive = []
    for source in rules:
        if source is None:
            continue
        if "*" in source:
            permissive.append(source)
            continue
        if "/" in source:
            try:
                prefix = int(source.rsplit("/", 1)[1])
            except ValueError:
                continue
            if prefix <= 16:
                permissive.append(source)
    if permissive:
        return "permissive", ("prxyinfo allows proxy connections from "
                              f"{', '.join(sorted(set(permissive)))}: a "
                              "broad source range or wildcard. A "
                              "permissive prxyinfo leaves the gateway "
                              "vulnerable to PROXYGATE at any patch level; "
                              "restrict it first, starting with gateways "
                              "reachable from the internet")
    return "restrictive", ("prxyinfo restricts proxy connections to "
                            "trusted sources only, so the gateway is not "
                            "exploitable from untrusted networks; apply "
                            "the kernel fix anyway, because if the file is "
                            "ever removed the gateway falls back to its "
                            "default proxy policy")


def grade_gateway(release, patch, prxyinfo, param):
    """Grade one system against PROXYGATE (CVE-2026-89103).

    prxyinfo is "permissive", "restrictive", "missing", or None when
    its state was not supplied. param is the gw/acl_mode_proxy value
    (0, 1, or None when not supplied). A permissive prxyinfo overrides
    everything: patch level cannot save it.
    """
    if prxyinfo == "permissive":
        return {"grade": "VULNERABLE", "fixed": None,
                "note": "permissive prxyinfo: the gateway is vulnerable "
                        f"to {CVES['GW']} at any kernel patch level, "
                        "patched or not. Restrict the proxy list first; "
                        "the kernel fix alone does not close this"}
    if prxyinfo == "restrictive":
        return {"grade": "NOT-EXPOSED", "fixed": None,
                "note": "restrictive prxyinfo: the gateway is not "
                        "exploitable from untrusted networks. Apply the "
                        "kernel fix anyway (note 3798345), so the system "
                        "stays protected if the file is ever removed"}
    if release is None:
        return {"grade": "UNKNOWN", "fixed": None,
                "note": "a kernel release is needed to grade PROXYGATE; "
                        "supply --kernel (and --prxyinfo / "
                        "--gw-acl-mode-proxy for the config half)"}
    if release in GW_NO_FIX and prxyinfo == "missing":
        return {"grade": "NO-FIX", "fixed": None,
                "note": f"kernel {release} is out of maintenance, "
                        f"affected by {CVES['GW']}, and may never get a "
                        "fix; upgrade to a supported downward-compatible "
                        "kernel (SAP note 3810197). A restrictive "
                        "prxyinfo file would still reduce exposure in the "
                        "meantime"}
    if release in GW_NO_FIX:
        return {"grade": "UNKNOWN", "fixed": None,
                "note": f"kernel {release} is out of maintenance and "
                        f"affected by {CVES['GW']}, and the prxyinfo "
                        "state was not supplied; it has not been cleared, "
                        "only left ungraded"}
    if release in GW_PARAM_ONLY:
        # 7.93 and 9.16 already support the parameter: no kernel patch.
        if param == 1:
            return {"grade": "PATCHED", "fixed": "gw/acl_mode_proxy = 1",
                    "note": f"kernel {release} already supports "
                            "gw/acl_mode_proxy, and it is set to 1; no new "
                            "kernel is required for PROXYGATE"}
        if param == 0:
            return {"grade": "VULNERABLE", "fixed": "gw/acl_mode_proxy = 1",
                    "note": f"kernel {release} already supports "
                            "gw/acl_mode_proxy, but it is set to 0 (allow "
                            "all); set it to 1"}
        return {"grade": "UNKNOWN", "fixed": "gw/acl_mode_proxy = 1",
                "note": f"kernel {release} already supports "
                        "gw/acl_mode_proxy, but its value was not "
                        "supplied; the fix on this release is setting it "
                        "to 1, so this has not been cleared"}
    if release in GW_PATCH_ONLY:
        # 9.20/9.21: SAP lists no manual activity beyond the patch.
        fixed = GW_FIXED_MIN[release]
        if patch is None:
            return {"grade": "UNKNOWN", "fixed": f"{release} PL {fixed}+",
                    "note": f"kernel {release} needs a patch level to "
                            "grade PROXYGATE"}
        if patch >= fixed:
            return {"grade": "PATCHED", "fixed": f"{release} PL {fixed}+",
                    "note": f"{release} PL {patch} is at or above the "
                            f"fixed PL {fixed} for PROXYGATE; SAP lists no "
                            "manual activity beyond applying the patch, "
                            "but confirm gw/acl_mode_proxy = 1 in the "
                            "profile anyway"}
        return {"grade": "VULNERABLE", "fixed": f"{release} PL {fixed}+",
                "note": f"{release} PL {patch} is below the fixed PL "
                        f"{fixed} for PROXYGATE"}
    if release in GW_FIXED_MIN:
        fixed = GW_FIXED_MIN[release]
        if patch is None:
            return {"grade": "UNKNOWN", "fixed": f"{release} PL {fixed}+",
                    "note": f"kernel {release} needs a patch level to "
                            "grade PROXYGATE"}
        if patch < fixed:
            return {"grade": "VULNERABLE", "fixed": f"{release} PL "
                    f"{fixed}+ and gw/acl_mode_proxy = 1",
                    "note": f"{release} PL {patch} is below the fixed PL "
                            f"{fixed}; the kernel does not even have the "
                            "gw/acl_mode_proxy parameter yet, so the "
                            "gateway permits every proxy connection"}
        if param == 1:
            return {"grade": "PATCHED", "fixed": f"{release} PL {fixed}+ "
                    "and gw/acl_mode_proxy = 1",
                    "note": f"{release} PL {patch} carries the fix and "
                            "gw/acl_mode_proxy is set to 1"}
        if param == 0:
            return {"grade": "VULNERABLE", "fixed": f"{release} PL "
                    f"{fixed}+ and gw/acl_mode_proxy = 1",
                    "note": f"{release} PL {patch} carries the fix, but "
                            "gw/acl_mode_proxy is set to 0 (allow all); "
                            "the kernel patch alone does not protect the "
                            "gateway, set the parameter to 1"}
        return {"grade": "UNKNOWN", "fixed": f"{release} PL {fixed}+ and "
                "gw/acl_mode_proxy = 1",
                "note": f"{release} PL {patch} carries the fix, but the "
                        "gw/acl_mode_proxy value was not supplied; the "
                        "patch alone does not protect the gateway, so "
                        "this has not been cleared"}
    return {"grade": "UNKNOWN", "fixed": None,
            "note": f"kernel {release} is not in the published PROXYGATE "
                    "table (7.22, 7.53, 7.54, 7.77, 7.93, 8.04, 9.16, "
                    "9.20, 9.21, plus out-of-maintenance lines); it has "
                    "not been cleared, only left ungraded; check it "
                    "against SAP note 3798345"}


def grade_saml2(basis, saml2):
    """Grade one SAP_BASIS release against CVE-2026-120017.

    saml2 is True (SAML2 browser logon in use), False (not in use), or
    None (unknown). There is no public fixed support-package table for
    this flaw, so an in-scope system grades IN-SCOPE, never PATCHED.
    """
    if basis is None:
        return {"grade": "NOT-CHECKED", "fixed": None,
                "note": "no SAP_BASIS release supplied, so the SAML2 "
                        "check was not run; pass --basis to grade it"}
    if basis not in SAML2_BASIS:
        return {"grade": "NOT-AFFECTED", "fixed": None,
                "note": f"SAP_BASIS {basis} is not in the affected list "
                        f"for {CVES['SAML2']} (702, 731, 740, 750-758, "
                        "816, 920-922); note that RedRays' rendering of "
                        "the same note also names 804 and 918, which this "
                        "tool does not grade as affected"}
    if saml2 is False:
        return {"grade": "NOT-EXPOSED", "fixed": None,
                "note": f"SAP_BASIS {basis} is in the affected list, but "
                        "SAML2 browser logon is not in use on this "
                        "system, so the flaw is not reachable here; apply "
                        "note 3849308 anyway if SAML2 is ever enabled"}
    if saml2 is True:
        return {"grade": "IN-SCOPE", "fixed": "SAP note 3849308",
                "note": f"SAP_BASIS {basis} is affected and SAML2 browser "
                        f"logon is in use: the system is in scope for "
                        f"{CVES['SAML2']}. No public fixed support-package "
                        "table exists (note 3849308 is behind SAP for Me "
                        "sign-in), so the patch state cannot be graded "
                        "from public sources; apply the correction "
                        "instructions or the listed support package, "
                        "review every trusted identity provider in "
                        "transaction SAML2, and check audit logs for SAML "
                        "logons by privileged users from unexpected "
                        "sources"}
    return {"grade": "IN-SCOPE", "fixed": "SAP note 3849308",
            "note": f"SAP_BASIS {basis} is affected and whether SAML2 "
                    "browser logon is in use was not supplied; treat the "
                    "system as in scope until shown otherwise, and "
                    "confirm it with --saml2 or --no-saml2"}


def probe_saml2_metadata(base_url, client="000", timeout=10):
    """Check whether SAML2 is enabled on a client, detection-only.

    Fetches the public SP metadata document, the same GET a browser
    makes. Returns True when the response is SAML metadata XML, False
    when the endpoint answers without metadata, and None on any
    network or HTTP error: an unreachable endpoint has not been graded.
    """
    url = base_url.rstrip("/") + "/sap/saml2/sp/metadata?sap-client=" + client
    request = urllib.request.Request(url, headers={"User-Agent": "sap-patchday-scanner/1.0"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read().decode("utf-8", errors="replace")
    except (urllib.error.URLError, urllib.error.HTTPError, socket.timeout,
            OSError, ValueError):
        return None
    if "EntityDescriptor" in body and "SPSSODescriptor" in body:
        return True
    return False


def parse_dispwork_output(text):
    """Parse `disp+work -v` output into (release, patch) or (None, None)."""
    if not text:
        return None, None
    release_match = _DISPWORK_RELEASE_RE.search(text)
    patch_match = _DISPWORK_PATCH_RE.search(text)
    if not release_match or not patch_match:
        return None, None
    release = f"{release_match.group(1)}.{release_match.group(2)}"
    return release, int(patch_match.group(1))


def _read_profile_params(profile_dir):
    """Read gw/acl_mode_proxy and the WebSocket flag from .pfl files.

    Returns (param, websocket_disabled, files_read). The last setting
    in file order wins, matching how SAP resolves profiles.
    """
    param = None
    websocket_disabled = None
    files_read = []
    if profile_dir is None:
        return param, websocket_disabled, files_read
    profiles = sorted(Path(profile_dir).glob("*.pfl"))
    for profile in profiles:
        try:
            text = profile.read_text(errors="replace")
        except OSError:
            continue
        files_read.append(str(profile))
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("#") or "=" not in stripped:
                continue
            key, _, value = stripped.partition("=")
            key = key.strip().lower()
            value = value.strip()
            if key == "gw/acl_mode_proxy":
                try:
                    param = int(value)
                except ValueError:
                    pass
            if key == "icm/http/support_websocket_upgrade":
                websocket_disabled = value.upper() == "FALSE"
    return param, websocket_disabled, files_read


def _find_prxyinfo(root):
    """Locate a prxyinfo file under root, or None."""
    if root is None:
        return None
    root = Path(root)
    for candidate in (root / "prxyinfo", root / "data" / "prxyinfo"):
        if candidate.is_file():
            return candidate
    for found in root.rglob("prxyinfo"):
        if found.is_file():
            return found
    return None


def detect_local(root=None, dispwork_bin="disp+work"):
    """Detect kernel, gateway config, and WebSocket flag on this host.

    Runs `disp+work -v` (from <root>/exe first, then PATH) for the
    kernel release and patch level, reads *.pfl profiles under
    <root>/profile for gw/acl_mode_proxy and the WebSocket flag, and
    looks for a prxyinfo file under <root>. Returns a dict of findings.
    Raises ValueError when nothing usable is found: an undetected
    install has not been graded.
    """
    findings = {}
    tried = []
    dispwork = None
    if root is not None:
        candidate = Path(root) / "exe" / "disp+work"
        if candidate.is_file():
            dispwork = str(candidate)
    if dispwork is None:
        dispwork = shutil.which(dispwork_bin)
    if dispwork is not None:
        try:
            proc = subprocess.run([dispwork, "-v"], capture_output=True,
                                  text=True, timeout=15)
            output = proc.stdout + proc.stderr
        except (OSError, subprocess.SubprocessError):
            output = ""
        release, patch = parse_dispwork_output(output)
        if release is not None:
            findings["kernel"] = release
            findings["patch"] = patch
            findings["kernel_source"] = f"{dispwork} -v"
        else:
            tried.append(f"{dispwork} -v (output did not parse)")
    else:
        tried.append("disp+work -v (not found)")
    profile_dir = None
    if root is not None:
        candidate = Path(root) / "profile"
        if candidate.is_dir():
            profile_dir = candidate
    if profile_dir is None:
        for candidate in Path("/sapmnt").glob("*/profile"):
            if candidate.is_dir():
                profile_dir = candidate
                break
    param, websocket_disabled, files = _read_profile_params(profile_dir)
    if param is not None:
        findings["gw_acl_mode_proxy"] = param
    if websocket_disabled is not None:
        findings["websocket_disabled"] = websocket_disabled
    if files:
        findings["profile_source"] = ", ".join(files)
    prxyinfo_path = _find_prxyinfo(root)
    if prxyinfo_path is not None:
        try:
            text = prxyinfo_path.read_text(errors="replace")
        except OSError:
            text = None
        if text is not None:
            state, _note = parse_prxyinfo(text)
            findings["prxyinfo"] = state
            findings["prxyinfo_source"] = str(prxyinfo_path)
    if not findings:
        raise ValueError(
            "no SAP install detected; checked " + "; ".join(tried) +
            ". This tool grades the host it runs on, or values you "
            "supply with --kernel, --patch, --prxyinfo, and "
            "--gw-acl-mode-proxy"
        )
    return findings


def grade_system(entry):
    """Grade one system entry and return a list of check dicts.

    Entry keys: label, kernel, patch, webdisp, webdisp_patch, hana,
    xs_advanced_sp, xs_advanced_patch, prxyinfo, prxyinfo_file,
    gw_acl_mode_proxy, basis, saml2, websocket_disabled, router, url,
    client. Each check carries cve, component, grade, fixed, note.
    """
    checks = []
    kernel = entry.get("kernel")
    patch = entry.get("patch")
    if kernel is not None and patch is None and isinstance(kernel, str):
        kernel, patch = parse_kernel(kernel)
    if kernel is not None or patch is not None:
        icm = grade_icm(kernel, patch)
        checks.append({"cve": CVES["ICM"], "component": "ICM",
                       **icm})
        checks.append({"cve": CVES["WD"], "component": "Web Dispatcher "
                       "(kernel ICM path)", **icm})
        webdisp = entry.get("webdisp", kernel)
        webdisp_patch = entry.get("webdisp_patch", patch)
        assumed = entry.get("webdisp") is None
        wd = {"cve": CVES["WD"],
              "component": "Web Dispatcher (standalone)",
              **grade_icm(webdisp, webdisp_patch)}
        if assumed:
            wd["note"] = ("Web Dispatcher assumed to run the same kernel "
                          "as the ICM; pass --webdisp / --webdisp-patch "
                          "to grade it separately. ") + wd["note"]
        checks.append(wd)
        gateway = grade_gateway(kernel, patch, entry.get("prxyinfo"),
                                entry.get("gw_acl_mode_proxy"))
        checks.append({"cve": CVES["GW"], "component": "SAP Gateway",
                       **gateway})
        if entry.get("shield"):
            shield = grade_shield(webdisp, webdisp_patch,
                                  router=bool(entry.get("router")))
            checks.append({"cve": CVES["WD"], "component": "Web "
                           "Dispatcher shield", **shield})
    if entry.get("hana") is not None:
        checks.append({"cve": CVES["WD"], "component": "HANA XS Classic "
                       "Web Dispatcher", **grade_hana(entry["hana"])})
    if entry.get("xs_advanced_sp") is not None:
        checks.append({"cve": CVES["WD"], "component": "XS Advanced Web "
                       "Dispatcher",
                       **grade_xs_advanced(entry["xs_advanced_sp"],
                                           entry.get("xs_advanced_patch"))})
    if entry.get("basis") is not None or entry.get("url") is not None:
        saml2 = entry.get("saml2")
        if entry.get("url") is not None:
            probed = probe_saml2_metadata(entry["url"],
                                          entry.get("client", "000"))
            if probed is None:
                checks.append({"cve": CVES["SAML2"], "component": "SAML2 "
                               "metadata probe", "grade": "UNKNOWN",
                               "fixed": None,
                               "note": f"could not reach "
                                       f"{entry['url']}/sap/saml2/sp/"
                                       "metadata; the endpoint has not been "
                                       "graded, only left ungraded"})
            elif probed:
                saml2 = True
            else:
                saml2 = False
        checks.append({"cve": CVES["SAML2"], "component": "SAML2 service "
                       "provider", **grade_saml2(entry.get("basis"), saml2)})
    return checks


def overall_grade(checks):
    """Worst grade across checks, by GRADE_ORDER."""
    worst = "NOT-CHECKED"
    worst_rank = len(GRADE_ORDER)
    for check in checks:
        grade = check["grade"]
        if grade in GRADE_ORDER and GRADE_ORDER.index(grade) < worst_rank:
            worst = grade
            worst_rank = GRADE_ORDER.index(grade)
    return worst


def render(checks, label=None):
    lines = []
    if label:
        lines.append(f"[{label}]")
    for check in checks:
        lines.append(f"{check['cve']}  {check['component']}: "
                     f"{check['grade']}")
        if check["fixed"]:
            lines.append(f"  fixed in: {check['fixed']}")
        lines.append(f"  note: {check['note']}")
    lines.append(f"overall: {overall_grade(checks)}")
    return "\n".join(lines)


def load_inventory(path):
    try:
        data = json.loads(Path(path).read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read inventory {path}: {exc}") from exc
    if not isinstance(data, list):
        raise ValueError("inventory JSON must be a list of entries")
    for entry in data:
        if not isinstance(entry, dict):
            raise ValueError("each inventory entry must be an object")
    return data


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Detection-only triage for the SAP November 2026 "
                    "Patch Day batch: CVE-2026-76964, CVE-2026-89126, "
                    "CVE-2026-89103, CVE-2026-120017 (all CVSS 10.0)."
    )
    parser.add_argument("--kernel", help="SAP kernel release, e.g. 7.93")
    parser.add_argument("--patch", type=int,
                        help="SAP kernel patch level, e.g. 419")
    parser.add_argument("--kernel-version",
                        help="combined kernel version, e.g. '7.93 PL 419'")
    parser.add_argument("--webdisp", help="standalone Web Dispatcher "
                        "kernel release (defaults to --kernel)")
    parser.add_argument("--webdisp-patch", type=int,
                        help="standalone Web Dispatcher patch level "
                        "(defaults to --patch)")
    parser.add_argument("--hana-revision",
                        help="HANA 2.0 revision, e.g. 2.00.089.05")
    parser.add_argument("--xs-advanced-sp",
                        help="XS Advanced support package, e.g. 05")
    parser.add_argument("--xs-advanced-patch", type=int,
                        help="XS Advanced patch number, e.g. 4")
    parser.add_argument("--prxyinfo",
                        help="path to a prxyinfo file to parse")
    parser.add_argument("--prxyinfo-state",
                        choices=["permissive", "restrictive", "missing"],
                        help="prxyinfo state, when no file is supplied")
    parser.add_argument("--gw-acl-mode-proxy", type=int, choices=[0, 1],
                        help="gw/acl_mode_proxy profile value")
    parser.add_argument("--basis", type=int,
                        help="SAP_BASIS release, e.g. 750")
    parser.add_argument("--saml2", action="store_true",
                        help="SAML2 browser logon is in use")
    parser.add_argument("--no-saml2", action="store_true",
                        help="SAML2 browser logon is not in use")
    parser.add_argument("--url",
                        help="base URL to probe for SAML2 metadata, e.g. "
                        "https://host:44300")
    parser.add_argument("--client", default="000",
                        help="SAP client for the metadata probe "
                        "(default 000)")
    parser.add_argument("--websocket-disabled", action="store_true",
                        help="icm/HTTP/support_websocket_upgrade is FALSE")
    parser.add_argument("--shield", action="store_true",
                        help="also grade the Web Dispatcher as a shield "
                        "for backends behind it")
    parser.add_argument("--router", action="store_true",
                        help="the Web Dispatcher is configured as a "
                        "router (PROT=ROUTER), which voids the shield")
    parser.add_argument("--local", nargs="?", const="",
                        help="detect the install on this host (optional "
                        "SAP root, e.g. /sapmnt/SID)")
    parser.add_argument("--inventory-json",
                        help="JSON list of system entries")
    parser.add_argument("--json", action="store_true",
                        help="machine-readable output")
    parser.add_argument("--list", action="store_true",
                        help="print the advisory table")
    args = parser.parse_args(argv)

    if args.list:
        print("SAP November 2026 Patch Day, published 10 November 2026; "
              "all four CVSS 10.0, all unauthenticated")
        print(f"  {CVES['ICM']}  ICM2SHELL ICM: kernel 7.53 PL 1616+, "
              "7.54 PL 710+, 7.77 PL 914+, 7.93 PL 401 Stack / 402 / 420+, "
              "9.16 PL 111+, 9.18 PL 37+, 9.20 PL 11 / 13+; 7.93 PL 403-419 "
              "still vulnerable; 7.22 not affected; 7.40-7.89 no fix")
        print(f"  {CVES['WD']}  ICM2SHELL Web Dispatcher: same kernel "
              "levels; HANA 2.00.079.11 / 2.00.089.05; XS Advanced SP05 "
              "Patch 4; shield levels 7.53 PL 1629, 7.54 PL 723, 7.93 PL "
              "430, 9.16 PL 200")
        print(f"  {CVES['GW']}  PROXYGATE Gateway: kernel 7.22 PL 1612+, "
              "7.53 PL 1625+, 7.54 PL 718+, 7.77 PL 915+, 8.04 PL 244+, "
              "9.20 PL 16+, 9.21 PL 4+; 7.93 and 9.16 need "
              "gw/acl_mode_proxy = 1, no kernel patch; a permissive "
              "prxyinfo is vulnerable at any patch level")
        print(f"  {CVES['SAML2']}  SAML2 service provider: SAP_BASIS 702, "
              "731, 740, 750-758, 816, 920-922; no public fixed-SP table, "
              "graded IN-SCOPE, apply note 3849308")
        print("No exploitation observed in the wild as of 10 November "
              "2026 (Onapsis); working exploits exist in researchers' "
              "hands for ICM2SHELL and PROXYGATE")
        return 0

    if args.inventory_json:
        try:
            entries = load_inventory(args.inventory_json)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        results = []
        vulnerable = False
        for entry in entries:
            entry = dict(entry)
            if "prxyinfo_file" in entry:
                try:
                    text = Path(entry["prxyinfo_file"]).read_text(
                        errors="replace")
                except OSError as exc:
                    print(f"error: cannot read prxyinfo file "
                          f"{entry['prxyinfo_file']}: {exc}",
                          file=sys.stderr)
                    return 1
                entry["prxyinfo"], _ = parse_prxyinfo(text)
            checks = grade_system(entry)
            grade = overall_grade(checks)
            if grade in ("VULNERABLE", "NO-FIX"):
                vulnerable = True
            results.append({"label": entry.get("label"),
                            "overall": grade, "checks": checks})
        if args.json:
            print(json.dumps(results, indent=2))
        else:
            for result in results:
                print(render(result["checks"], label=result["label"]))
                print()
        return 2 if vulnerable else 0

    entry = {}
    if args.kernel_version:
        release, patch = parse_kernel(args.kernel_version)
        if release is None:
            print(f"error: cannot parse kernel version "
                  f"{args.kernel_version!r}", file=sys.stderr)
            return 1
        entry["kernel"] = release
        entry["patch"] = patch
    if args.kernel:
        entry["kernel"] = args.kernel
    if args.patch is not None:
        entry["patch"] = args.patch
    if args.webdisp:
        entry["webdisp"] = args.webdisp
    if args.webdisp_patch is not None:
        entry["webdisp_patch"] = args.webdisp_patch
    if args.hana_revision:
        entry["hana"] = args.hana_revision
    if args.xs_advanced_sp:
        entry["xs_advanced_sp"] = args.xs_advanced_sp
    if args.xs_advanced_patch is not None:
        entry["xs_advanced_patch"] = args.xs_advanced_patch
    if args.prxyinfo:
        try:
            text = Path(args.prxyinfo).read_text(errors="replace")
        except OSError as exc:
            print(f"error: cannot read prxyinfo file {args.prxyinfo}: "
                  f"{exc}", file=sys.stderr)
            return 1
        state, _note = parse_prxyinfo(text)
        entry["prxyinfo"] = state
        entry["prxyinfo_source"] = args.prxyinfo
    elif args.prxyinfo_state:
        entry["prxyinfo"] = args.prxyinfo_state
    if args.gw_acl_mode_proxy is not None:
        entry["gw_acl_mode_proxy"] = args.gw_acl_mode_proxy
    if args.basis is not None:
        entry["basis"] = args.basis
    if args.saml2:
        entry["saml2"] = True
    if args.no_saml2:
        entry["saml2"] = False
    if args.url:
        entry["url"] = args.url
        entry["client"] = args.client
    if args.websocket_disabled:
        entry["websocket_disabled"] = True
    if args.shield:
        entry["shield"] = True
    if args.router:
        entry["router"] = True
    if args.local is not None:
        try:
            findings = detect_local(args.local or None)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        for key in ("kernel", "patch", "gw_acl_mode_proxy", "prxyinfo",
                    "websocket_disabled"):
            if key in findings:
                entry[key] = findings[key]
        entry.setdefault("label", "local")

    if not entry:
        parser.error("supply --kernel/--patch, --hana-revision, "
                     "--xs-advanced-sp, --basis, --url, or --local "
                     "(or --inventory-json / --list)")

    # WebSocket disabled removes the ICM2SHELL exposure on the ICM and
    # the Web Dispatcher; it does not touch the Gateway or SAML2.
    checks = grade_system(entry)
    if entry.get("websocket_disabled"):
        for check in checks:
            if check["cve"] in (CVES["ICM"], CVES["WD"]) and \
                    check["grade"] in ("VULNERABLE", "UNKNOWN", "NO-FIX"):
                check["grade"] = "NOT-EXPOSED"
                check["note"] = ("icm/HTTP/support_websocket_upgrade is "
                                 "FALSE, so WebSocket support is off and "
                                 "the flaw is not reachable on this "
                                 "component. Disabling WebSocket breaks "
                                 "features that depend on it (ABAP Push "
                                 "Channels, some Fiori scenarios), and it "
                                 "is a workaround, not a patch: " +
                                 check["note"])
    grade = overall_grade(checks)
    if args.json:
        print(json.dumps({"label": entry.get("label"), "overall": grade,
                          "checks": checks}, indent=2))
    else:
        print(render(checks, label=entry.get("label")))
    return 2 if grade in ("VULNERABLE", "NO-FIX") else 0


if __name__ == "__main__":
    raise SystemExit(main())

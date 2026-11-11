# `sap-patchday-scanner`

Local triage for the `SAP November 2026 Patch Day` batch: four flaws, each rated `CVSS 10.0`, none of them needing an attacker to log in first. Give it a kernel patch level you own, a `prxyinfo` file, or the install root on the host, and it tells you which of the four is still open. It never sends exploit traffic, never probes a vulnerable path, and its one network read is a plain `GET` of the public `SAML2` metadata document.

## `The flaws`

`SAP` published the batch on `10 November 2026` as part of its monthly `Security Patch Day`: `35` new notes, `four` of them `HotNews` at the maximum score. `Onapsis Research Labs` found three of the four and gave `SAP` a working exploit for `ICM2SHELL` and an end-to-end proof of concept for `PROXYGATE`. No exploitation in the wild had been observed as of `10 November 2026`, and none of the four is in `CISA KEV`. That is not a reason to wait: the exploits exist, the flaws are pre-authentication, and the components they hit face the network by design.

- `CVE-2026-76964` (`ICM2SHELL`, `ICM`) and `CVE-2026-89126` (`ICM2SHELL`, `Web Dispatcher`): a heap out-of-bounds write in the kernel code that reassembles fragmented `WebSocket` messages. An unauthenticated attacker with network access to the `HTTP/HTTPS` port runs operating system commands as `<sid>adm`. `WebSocket` support is on by default, so a system is exposed even if nothing uses it, and the same flaw reliably crashes the `ICM` or `Web Dispatcher` with a single connection.
- `CVE-2026-89103` (`PROXYGATE`, `SAP Gateway`): broken access control in the gateway's proxy list. An unauthenticated attacker is treated as one of the system's own application servers and can run operating system commands as `<sid>adm`. It does not depend on a weak `secinfo` or `reginfo`: those two lists play no part in stopping it. The one list that matters is `prxyinfo`.
- `CVE-2026-120017` (`SAML2` service provider): the service provider did not check signatures on incoming assertions in some configurations, so an unauthenticated attacker can forge a response and log on as any `ABAP` user, including privileged ones. No workaround, patching is the only fix.

## `The traps`

| `Signal` | `Grade` | `Why` |
| --- | --- | --- |
| Kernel `7.93 PL 419` | `VULNERABLE` | **The 419 trap.** A higher patch level is not always a fixed one. `PL 419` is confirmed affected; only the updated `PL 401 Stack Kernel`, `PL 402` once released, and `PL 420` or later carry the `ICM2SHELL` fix. |
| Kernel `9.20 PL 12` | `UNKNOWN` | `Onapsis` lists `11` and `13` as the fixed levels for `ICM2SHELL`. `12` sits in the gap between the two channels and is not listed as fixed. This tool refuses to clear it; verify it against `SAP` note `3778788` before treating it as safe. |
| Kernel `7.53 PL 1616` | `ICM PATCHED`, `Gateway VULNERABLE` | **The cross-flaw gap.** `PL 1616` fixes `ICM2SHELL`, but `PROXYGATE` needs `PL 1625`. Patching to the `ICM` level does not close the `Gateway` flaw. The same gap exists on `7.54` (`710` vs `718`), `7.77` (`914` vs `915`), and `9.20` (`13` vs `16`). |
| A kernel patch, on its own, for `PROXYGATE` | `VULNERABLE` or `UNKNOWN` | The kernel patch alone does not protect the `Gateway`. `PROXYGATE` needs a restrictive `prxyinfo` file or `gw/acl_mode_proxy` set to `1` as well. On `7.93` and `9.16` the parameter already exists, so setting it to `1` is the whole fix and no new kernel is required. |
| A permissive `prxyinfo` (`P SOURCE=* DEST=*`, or a broad source range) | `VULNERABLE` | **At any patch level.** A permissive proxy list leaves the gateway vulnerable to `PROXYGATE` whether the kernel is patched or not. Restrict it first, starting with gateways reachable from the internet. |
| Kernel `7.22` | `ICM NOT-AFFECTED`, `Gateway VULNERABLE` | `7.22` is not affected by `ICM2SHELL` at all, but it is affected by `PROXYGATE` (fixed at `PL 1612`). Checking one flaw does not clear the other. |
| A `Web Dispatcher` on the shield levels (`7.53 PL 1629`, `7.54 PL 723`, `7.93 PL 430`, `9.16 PL 200`) | `SHIELDED` | It protects backends reached exclusively through it, and only those. It does not work if the `WD` is configured as a router (`PROT=ROUTER`), and it is a workaround, not a fix: patch the backends too. Note the shield levels are higher than the fix levels. |
| An out-of-maintenance kernel (`7.40` to `7.89`, plus `7.20`/`7.21` for the `Gateway`) | `NO-FIX` | Affected, and it may never get a fix. Upgrade to a supported downward-compatible kernel. A restrictive `prxyinfo` still reduces exposure in the meantime. |
| `SAP_BASIS 750` with `SAML2` in use | `IN-SCOPE` | **There is no public fixed support-package table for `CVE-2026-120017`.** `SAP` note `3849308` sits behind `SAP for Me` sign-in, so this tool grades an in-scope system `IN-SCOPE`, never `PATCHED`. Apply the correction instructions or the listed support package, review every trusted identity provider in transaction `SAML2`, and check audit logs for `SAML` logons by privileged users from unexpected sources. |
| `SAP_BASIS 804` or `918` | `NOT-AFFECTED` (with a flag) | `RedRays`' rendering of note `3849308` also names `804` and `918`; `The Hacker News` table and the `Circuitry` summary do not. This tool follows the two agreeing sources and flags the disagreement in the grade note. |

## `What it checks`

- `One system` (`--kernel 7.93 --patch 419`): grades the `ICM`, the `Web Dispatcher`, and the `Gateway` against their own tables, each with its own traps
- `The gateway config` (`--prxyinfo prxyinfo --gw-acl-mode-proxy 1`): parses the proxy list and the profile parameter, because the patch level alone cannot grade `PROXYGATE`
- `HANA XS Classic` (`--hana-revision 2.00.089.05`): grades the `Web Dispatcher` embedded in `XS Classic` against revisions `2.00.079.11` and `2.00.089.05`
- `XS Advanced` (`--xs-advanced-sp 05 --xs-advanced-patch 4`): grades `SP05 Patch 4`
- `SAML2` (`--basis 750 --saml2`, or `--url https://host:44300`): grades the `BASIS` release in scope, or probes the public metadata document to establish whether `SAML2` is enabled on a client
- `The host it runs on` (`--local`): runs `disp+work -v` for the kernel release and patch level, reads `*.pfl` profiles for `gw/acl_mode_proxy` and the `WebSocket` flag, and looks for a `prxyinfo` file
- `A fleet, offline` (`--inventory-json sites.json`): a `JSON` list of system entries
- `The full table` (`--list`): fixed levels, shield levels, and the `SAML2` scope
- `Machine output` (`--json`): the same grades as `JSON`

```sh
python3 sap_patchday_scanner.py --kernel 7.93 --patch 419
python3 sap_patchday_scanner.py --kernel 7.53 --patch 1625 --prxyinfo prxyinfo --gw-acl-mode-proxy 1
python3 sap_patchday_scanner.py --kernel 7.93 --patch 420 --basis 750 --saml2
python3 sap_patchday_scanner.py --hana-revision 2.00.089.05
python3 sap_patchday_scanner.py --url https://sap.example:44300 --basis 750
python3 sap_patchday_scanner.py --local
python3 sap_patchday_scanner.py --inventory-json sites.json
```

```json
[
  {"label": "prod-erp", "kernel": "7.93", "patch": 420, "prxyinfo": "missing", "gw_acl_mode_proxy": 1, "basis": 750, "saml2": true},
  {"label": "old-bw", "kernel": "7.53", "patch": 1616, "prxyinfo": "missing", "gw_acl_mode_proxy": 1}
]
```

Inventory entries take `kernel` + `patch` (or a combined `kernel` string like `"7.93 PL 419"`), `webdisp` + `webdisp_patch`, `hana`, `xs_advanced_sp` + `xs_advanced_patch`, `prxyinfo` as `permissive` / `restrictive` / `missing` (or `prxyinfo_file` with a path to parse), `gw_acl_mode_proxy` as `0` or `1`, `basis`, `saml2`, `websocket_disabled`, `shield`, and `router`.

Exit codes: `0` nothing vulnerable found, `2` vulnerable finding (`VULNERABLE` or `NO-FIX`), `1` scan error. `UNKNOWN` and `IN-SCOPE` do not change the exit code, but they are not clean.

Find your kernel patch level in transaction `SM51`, from `disp+work -v` on the host, or from the `SAP` kernel directory. Find `gw/acl_mode_proxy` in the instance profile and `prxyinfo` in the instance directory. Find your `SAP_BASIS` release in `System > Status`. This tool reads values you supply or files on the host; it does not log in to a server to fetch them, except for the optional public `SAML2` metadata document.

## `The table`

| `CVE` | `Score` | `Auth` | `Affected` | `Fixed in` |
| --- | --- | --- | --- | --- |
| `CVE-2026-76964` | `10.0` | None | `SAP` kernel `7.40+` (`ICM`) | `7.53 PL 1616+`, `7.54 PL 710+`, `7.77 PL 914+`, `7.93 PL 401 Stack / 402 / 420+`, `9.16 PL 111+`, `9.18 PL 37+`, `9.20 PL 11 / 13+` |
| `CVE-2026-89126` | `10.0` | None | `Web Dispatcher`, incl. `HANA XS` | Same kernel levels; `HANA 2.00.079.11` / `2.00.089.05`; `XS Advanced SP05 Patch 4` |
| `CVE-2026-89103` | `10.0` | None | `SAP Gateway` (any stack) | `7.22 PL 1612+`, `7.53 PL 1625+`, `7.54 PL 718+`, `7.77 PL 915+`, `8.04 PL 244+`, `9.20 PL 16+`, `9.21 PL 4+`, plus `gw/acl_mode_proxy = 1` (or a restrictive `prxyinfo`); `7.93` / `9.16` need the parameter only |
| `CVE-2026-120017` | `10.0` | None | `SAP_BASIS 702, 731, 740, 750-758, 816, 920-922` (`SAML2` in use) | `SAP` note `3849308` (correction or support package; no public fixed-SP table) |

## `What this tool does not do`

- It does not send `WebSocket` frames, `RFC` calls, or `SAML` assertions. Probing the `ICM2SHELL` path would be the attack itself, and probing the `Gateway` path would be the attack itself. Version and configuration grading is the detection here.
- It does not grade a system `PATCHED` on a claim it cannot verify. A `9.20 PL 12` kernel, an unlisted kernel release, and a `SAML2` patch state all grade `UNKNOWN` or `IN-SCOPE`, not clean.
- It does not check whether a system was already compromised. If compromise is suspected, preserve evidence and audit `<sid>adm` activity, `RFC` destinations, and privileged `SAML` logons before patching, because a patch alone does not undo a created account or a stolen credential.
- It does not replace `SAP`'s own notes. The notes (`3778530`, `3778556`, `3778788`, `3798345`, `3810197`, `3849308`, `3849602`) sit behind `SAP for Me` sign-in and change after release; check the current version before you plan.

## `Sources`

- `Onapsis`, `ICM2SHELL` advisory (`CVE-2026-76964` / `CVE-2026-89126`), `10 November 2026`: fixed patch levels, the `7.93 PL 419` trap, shield levels, out-of-maintenance kernels, no exploitation observed
- `Onapsis`, `PROXYGATE` advisory (`CVE-2026-89103`), `10 November 2026`: fixed patch levels, `prxyinfo` and `gw/acl_mode_proxy` checks, no exploitation observed
- `The Hacker News`, `SAP Patches Four CVSS 10.0 Flaws`, `10 November 2026`: the four notes, affected versions, `SAML2` scope
- `RedRays`, `Patch Day November 2026` and the per-note analyses (`3778530`, `3798345`, `3849308`), `10 November 2026`: note contents reviewed in `SAP for Me`, `SAML2` checks
- `BleepingComputer`, `SAP patches ICM2SHELL and PROXYGATE maximum severity flaws`, `10 November 2026`

## `Thanks to`

- `Onapsis Research Labs` for finding and reporting three of the four flaws, and for publishing the fixed patch levels and the `7.93` trap in the open instead of leaving them behind a login wall
- `SAP Product Security Response Team` for the fixes, and `RedRays` for reviewing the login-walled notes in public

## `Disclaimer`

Educational and defensive use only. This tool grades patch levels and configuration you supply against public advisories; it does not exploit anything, and a `PATCHED` grade is not a guarantee that a system is safe or was never attacked.

> Research by `Vineeth Kumar` (`foxcornlab`). Found a bug or want a feature, open an `issue`.

<!--
Copyright (C) 2026 Leif Davisson <leifdavisson@gmail.com>
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Net-Docu-Crawler Zero-Blast-Radius Command Allowlist & Fortinet Paging Ruling

Author: `safety-reviewer` (Role 6 — Veto Authority), Swarm Board `#15` (2026-11-24 20:16:03)

Phase 1 Safety & Zero-Blast-Radius Audit complete (read-only; verified against codebase + `netmiko==4.8.0` / `paramiko==4.0.0` installed source; zero live device connections; `credentials.json` untouched).

---

## 1. Fortinet Read-Only Paging Ruling (P0 ZERO-BLAST-RADIUS VETO)

**RULING: VETO / REJECT current `FortinetDriver` (`device_type="fortinet"` / Netmiko `FortinetSSH`) as a P0 Zero-Blast-Radius violation.**

### Confirmed Violation
Inspecting installed `netmiko==4.8.0` (`netmiko.fortinet.fortinet_ssh.FortinetSSH`) confirms:
- `FortinetSSH.session_preparation()` runs `disable_paging()`, which — on any FortiGate with default `output more` — enters configuration mode and commits persistent global CMDB changes:
  `[config global] -> config system console -> set output standard -> end -> [end]`
- `FortinetSSH.cleanup()` re-enters configuration mode on disconnect and commits:
  `[config global] -> config system console -> set output more -> end -> [end]`
- `net_docu_crawler/drivers/fortinet.py:42` also declares `paging_cmd = "config system console\nset output standard\nend"`, and `docs/drivers/fortinet.md:30-36` & `docs/drivers/overview.md:45` document this write.
- **Impact**: Mutates live global firewall config on every crawl; triggers SIEM/FortiManager/HA config-change events; permanently drifts firewall config if disconnected mid-crawl; breaks least-privilege `ReadOnlyAuditor` (`sysgrp read`) accounts; and `FortinetSSH.__init__` also strips modern KEX (`curve25519-sha256`, `diffie-hellman-group14-sha256`) whenever `disabled_algorithms` lacks `"kex"`.

### Approved Strictly Read-Only Architecture (MANDATED)
**Adopt Option A: Custom `ReadOnlyFortinetSSH(FortinetSSH)` Netmiko subclass (or dedicated read-only interactive connection) + bounded `--More--` pager drainer.**
1. **Override `__init__`**: Do NOT strip modern KEX algorithms (`super(FortinetSSH, self).__init__(...)`); let `ssh_compat.py`'s 3-stage ladder manage KEX.
2. **Override `session_preparation()`**: Accept post-login banner (`"to accept"` -> `"a\r"`) and call `set_base_prompt()` ONLY. **Never** call `_vdoms_enabled()`, `_determine_os_version()`, `_get_output_mode()`, `_config_global()`, `_exit_config_global()`, or `disable_paging()`.
3. **Override `disable_paging()` -> no-op (`return ""`)** and **override `cleanup(command="exit")`** to send ONLY `exit\n` (no `config global`, no `config system console`, no `set output more`, no `end`).
4. **Hard-block write APIs**: Override `config_mode()`, `send_config_set()`, `send_config_from_file()`, and `save_config()` on `ReadOnlyFortinetSSH` to raise `RuntimeError("Zero-Blast-Radius violation: config/write operations forbidden")`.
5. **Bounded Read-Only `--More--` Pager Drainer** in `send_command()`:
   - Read chunks until either device prompt (`rf"(?m)^{re.escape(self.base_prompt)}(?:\s*\([^)]+\))?\s*[#$]\s*$"`) or pager prompt (`r"--More--\s*$"`).
   - On `--More--`: send single space `" "` (non-mutating scroll key only) and continue, bounded by per-page `read_timeout`, total command deadline, and `max_pages` safety cap (e.g. `2000` for `show full-configuration`, lower default for short commands) to guarantee zero VTY hangs.
   - Strip FortiOS pager overwrite artifacts (`--More--`, `\r\s+\r`, `\x08+`, `\x1b\[K`), echoed command, and trailing prompt.
6. **Clean up code & docs**: Set `FortinetDriver.paging_cmd = ""`, remove `config system console` from `docs/drivers/fortinet.md` and `docs/drivers/overview.md`, and add offline mock regression tests asserting (a) zero `config`/`set`/`end` bytes ever written on `connect()`/`crawl()`/`disconnect()`, and (b) multi-page `--More--` output drains cleanly and terminates on timeout/`max_pages`.

### Trade-Offs vs Option B (Paramiko `exec_command`)
- **Option B (`exec_command`)** suppresses PTY pagination on some FortiOS builds, **but** opens a fresh SSH channel/audit event per command, has known incompatibilities across FortiOS 6.x/7.x with `set post-login-banner enable`, VDOM contexts, and certain `diagnose` commands, and is unverified on live hardware here.
- **Verdict**: Option A is mandated as primary (single SSH VTY, works across FortiOS 6.x–7.x + post-login banners + read-only `accprofile`, fully mock-testable offline). Option B may only be evaluated later as opt-in after live verification.

### `NEEDS-DEVICE-DATA` Verification Items (Fortinet)
1. Exact `--More--` erasure/ANSI byte sequences on FortiOS 6.4 / 7.0 / 7.2 / 7.4 when draining `show full-configuration`.
2. Behavior of read-only `accprofile` on multi-VDOM FortiGates (`Virtual domain configuration: enable|split-task`) without entering `config global`.
3. Whether Paramiko non-interactive `exec_command` succeeds on FortiOS 7.x with `set post-login-banner enable` and read-only `accprofile`.

---

## 2. Complete Per-Driver Command Allowlist (For `SWARM/command_allowlist.md`)

Codebase-wide grep confirmed **zero** calls to `send_config_set`, `send_config_from_file`, `save_config`, `edit_config`, `commit`, `reload`, `clear`, `delete`, `uci set`, `uci commit`, `opkg`, `/system reset`, or SNMP `SetRequest` (`0xA3`) in production modules. (`scratch/` lab bootstrap scripts are untracked and gitignored; Phase 4 gate will block any attempt to commit or import them.)

| Driver | Command | Context / Implicit? | Read-Only Justification | Verdict |
| :--- | :--- | :--- | :--- | :--- |
| `CiscoDriver` (`cisco_ios` / `_telnet`) | `terminal width 511` | Implicit (`CiscoIosBase.session_preparation`) | VTY session-only line width; non-persistent | SESSION-SCOPED |
| `CiscoDriver` (`cisco_ios` / `_telnet`) | `terminal length 0` | Implicit (`CiscoIosBase.disable_paging`) | VTY session-only pagination disable; non-persistent | SESSION-SCOPED |
| `CiscoDriver` (`cisco_ios` / `_telnet`) | `enable` | Explicit (`connect` if `secret`; `crawl` Arista delegation) | Exec privilege elevation for `show running-config`; never enters config mode | SESSION-SCOPED |
| `CiscoDriver` (`cisco_ios` / `_telnet`) | `exit` | Implicit (`CiscoBaseConnection.cleanup`) | Graceful VTY session close | SESSION-SCOPED |
| `CiscoDriver` | `show version`, `show inventory`, `show ip interface brief`, `show interfaces`, `show cdp neighbors detail`, `show lldp neighbors detail`, `show lldp neighbors`, `show spanning-tree`, `show ip route`, `show ip arp`, `show power inline`, `show mac address-table`, `show mac-address-table` *(fallback)*, `show interfaces transceiver`, `show running-config`, `show interfaces trunk`, `show etherchannel summary`, `show port-channel summary` *(NX-OS)* | Explicit (`cisco.py`) | Strictly read-only IOS/IOS-XE/NX-OS operational/config display commands | ALLOW |
| `CiscoXRDriver` (`cisco_xr` / `_telnet`) | `terminal width 511`, `terminal length 0`, `exit` | Implicit (`CiscoXrBase.session_preparation` / `cleanup`) | Session-only terminal width/paging and VTY close (`NoEnable`) | SESSION-SCOPED |
| `CiscoXRDriver` | `show version`, `show inventory`, `show ipv4 interface brief`, `show interfaces`, `show lldp neighbors detail`, `show cdp neighbors detail`, `show route`, `show arp`, `show hsrp brief`, `show vrrp brief`, `show hsrp summary`, `show vrrp summary`, `show bundle`, `show bgp all all summary`, `show bgp vrf all summary`, `show ospf neighbor`, `show isis neighbors`, `show vrf all detail`, `show mpls ldp neighbor brief`, `show mpls ldp interface`, `show mpls forwarding-table`, `show running-config` | Explicit (`cisco_xr.py`) | Strictly read-only IOS-XR operational/config queries | ALLOW |
| `CiscoXRDriver` (optional) | NETCONF `<get>` (`xpath`), gNMI `Get()` (`json_ietf`) | Explicit (`fetch_netconf_operational`, `fetch_gnmi_operational`) | Strictly read-only RPC Get operations (no `<edit-config>`/`Set()`) | ALLOW |
| `CiscoSMBDriver` (`cisco_s300` / `_telnet`) | `terminal width 511`, `terminal datadump`, `enable`, `exit` | Implicit (`CiscoS300Base`) + explicit (`connect`: `enable`) | Session-only width/paging, exec elevation, VTY close; non-persistent | SESSION-SCOPED |
| `CiscoSMBDriver` | `show system`, `show system id`, `show version`, `show ip interface`, `show interfaces status`, `show lldp neighbors`, `show ip route`, `show arp`, `show spanning-tree`, `show power inline`, `show mac address-table`, `show fiber-ports optical-transceiver`, `show running-config`, `show interfaces switchport`, `show interfaces port-channel` | Explicit (`ciscosmb.py`) | Strictly read-only Cisco SMB operational/config queries | ALLOW |
| `JuniperDriver` (`juniper_junos` / `_telnet`) | `cli` (only if BSD shell), `set cli screen-width 511`, `set cli complete-on-space off`, `set cli screen-length 0`, `exit` | Implicit (`JuniperBase.session_preparation` / `cleanup`) | Operational-mode session-only CLI terminal preferences (never enters `configure`, never commits) | SESSION-SCOPED |
| `JuniperDriver` | `show version [\| display json]`, `show chassis hardware [\| display json]`, `show chassis mac-addresses`, `show interfaces terse [\| display json]`, `show interfaces`, `show lldp neighbors detail [\| display json]`, `show lldp neighbors [\| display json]`, `show spanning-tree bridge [\| display json]`, `show route \| display json`, `show route table inet.0`, `show arp no-resolve [\| display json]`, `show poe controller [\| display json]`, `show poe interface [\| display json]`, `show ethernet-switching table [\| display json]`, `show interfaces diagnostics optics [\| display json]`, `show configuration [\| display set]`, `show ethernet-switching interface [\| display json]` *(ELS)*, `show ethernet-switching interfaces [\| display json]` *(pre-ELS fallback)*, `show lacp interfaces \| display json`, `show spanning-tree interface \| display json`, `show dot1x interface \| display json` | Explicit (`juniper.py`) | Strictly read-only Junos operational & config display queries | ALLOW |
| `AristaDriver` (`arista_eos` / `_telnet`) | `terminal width 511`, `terminal length 0`, `enable`, `exit` | Implicit (`AristaBase`) + explicit (`connect`: `enable`) | Session-only width/paging, exec elevation, VTY close; non-persistent | SESSION-SCOPED |
| `AristaDriver` | `show version [\| json]`, `show hostname \| json`, `show running-config`, `show ip interface \| json`, `show interfaces [\| json]`, `show ip interface brief`, `show lldp neighbors detail [\| json]`, `show spanning-tree [\| json]`, `show ip route [\| json]`, `show ip arp [\| json]`, `show power inline [\| json]`, `show mac address-table [\| json]`, `show interfaces transceiver [\| json]`, `show interfaces trunk [\| json]`, `show port-channel [\| json]`, `show port-channel summary [\| json]` | Explicit (`arista.py`) | Strictly read-only EOS operational/config queries | ALLOW |
| `ArubaDriver` (`aruba_os`) | `enable`, `no paging`, `no page` (AOS-CX & delegated ProCurve), `exit` | Implicit (`ArubaOsSSH.session_preparation` / `cleanup`) + explicit (`no page`) | Session-only exec elevation, paging disable, VTY close (`SF-07` resolved) | SESSION-SCOPED |
| `ArubaDriver` | `show version`, `show system`, `show aps`, `show ip interface brief`, `show interface brief`, `show lldp neighbor-info detail`, `show ap debug lldp info`, `show ip route`, `show arp`, `show clients`, `show spanning-tree`, `show mac-address-table`, `show power-over-ethernet brief`, `show interface transceiver`, `show running-config`, `show configuration`, `show run`, `show interface trunk`, `show lacp interfaces` | Explicit (`aruba.py`) | Strictly read-only Aruba IAP / AOS-CX operational/config queries | ALLOW |
| `HPProCurveDriver` (`hp_procurve` / `_telnet`) | `<CR>` (press-any-key banner), `enable`, `terminal width 511`, `no page`, `logout` (+ `y` confirm logout, `n` decline save) | Implicit (`HPProcurveBase.session_preparation` / `cleanup`) | Session-only banner dismiss, exec elevation, width/paging, graceful logout explicitly declining config save | SESSION-SCOPED |
| `HPProCurveDriver` | `show system`, `show version`, `show modules`, `show ip`, `show name`, `show interfaces brief`, `show lldp info remote-device`, `show lldp info remote-device detail`, `show lldp info remote-device all`, `show cdp neighbor detail`, `show ip route`, `show arp`, `show mac-address`, `show spanning-tree`, `show running-config`, `show config`, `show power-over-ethernet brief`, `show power-over-ethernet`, `show interfaces transceiver`, `show trunks`, `show lacp`, `show vlans ports all`, `show vlans ports all detail`, `show spanning-tree detail`, `show port-access authenticator` | Explicit (`hpprocurve.py`) | Strictly read-only Provision / ArubaOS-S operational/config queries | ALLOW |
| `PaloAltoDriver` (`paloalto_panos` / `_telnet`) | `set cli scripting-mode on`, `set cli terminal width 500`, `set cli pager off`, `show system info`, `exit` | Implicit (`PaloAltoPanosBase.session_preparation` / `cleanup`) + explicit (`connect`: `set cli pager off`) | Operational-mode session-only CLI settings (non-persistent; never enters `configure` or `commit`) | SESSION-SCOPED |
| `PaloAltoDriver` | `show system info`, `show high-availability state`, `show interface all`, `show lldp neighbors all`, `show routing route`, `show arp all`, `show config running` | Explicit (`paloalto.py`) | Strictly read-only PAN-OS operational/config queries | ALLOW |
| `FortinetDriver` (`fortinet` — REMOVED IN WAVE 1) | `config system console` / `set output standard` / `end` | ~~Implicit (`FortinetSSH.disable_paging`)~~ **REMOVED** (`f041ba4`) | **PERSISTENT GLOBAL CMDB CONFIG WRITE — REJECTED & REMOVED** | **REJECT** |
| `FortinetDriver` (`fortinet` — REMOVED IN WAVE 1) | `config system console` / `set output more` / `end` | ~~Implicit (`FortinetSSH.cleanup`)~~ **REMOVED** (`f041ba4`) | **PERSISTENT GLOBAL CMDB CONFIG WRITE — REJECTED & REMOVED** | **REJECT** |
| `FortinetDriver` (`fortinet` — REMOVED IN WAVE 1) | `config global` / `end` | ~~Implicit (`FortinetSSH._config_global` / `_exit_config_global`)~~ **REMOVED** (`f041ba4`) | Enters global config scope solely to toggle paging — **REJECTED & REMOVED** | **REJECT** |
| `FortinetDriver` (`ReadOnlyFortinetSSH` — ACTIVE) | `a\r` (post-login banner accept), `" "` (space on `--More--`), `"q"` (bounded cap quit), `exit` | Implicit (`ReadOnlyFortinetSSH` banner/pager/cleanup, `f041ba4`) | Strictly non-mutating interactive login/scroll/exit; zero config mode; all write APIs hard-blocked | SESSION-SCOPED |
| `FortinetDriver` | `get system status`, `get system interface`, `get system interface physical`, `show system interface`, `diagnose lldprx neighbor details`, `diagnose lldprx neighbor summary`, `diagnose switch-controller switch-info lldp neighbors-detail`, `diagnose snmp sysinfo lldp neighbor`, `diagnose lldp neighbor list`, `get switch lldp neighbors-summary`, `get router info routing-table all`, `get system arp`, `get system interface transceiver`, `show full-configuration` | Explicit (`fortinet.py`) | Strictly read-only FortiOS `get`/`show`/`diagnose` telemetry queries | ALLOW |
| `MikroTikDriver` (`mikrotik_routeros`) | username `+ct511w4098h` suffix; banner `<CR>` / `n` / `\x03`; `quit` | Implicit (`MikrotikBase._modify_connection_params`, `special_login_handler`, `cleanup`) | Session-only terminal dimensions/color suppression; never sends `r` to reset default config | SESSION-SCOPED |
| `MikroTikDriver` | `/system identity print`, `/system resource print`, `/system routerboard print`, `/interface print detail [without-paging]`, `/interface ethernet print detail [without-paging]`, `/ip address print detail [without-paging]`, `/ip neighbor print detail [without-paging]`, `/ip route print detail [without-paging]`, `/ip arp print detail [without-paging]`, `/interface ethernet monitor [find where name~"sfp"] once`, `/export compact` | Explicit (`mikrotik.py`) | Strictly read-only RouterOS `print [without-paging]`/`monitor once`/`/export` queries | ALLOW |
| `FRRDriver` (`linux`) | `exit` (Note: `LinuxSSH.enable()` / `sudo -s` is NOT called and remains forbidden) | Implicit (`LinuxSSH.cleanup`) | Graceful shell logout; zero paging cmd | SESSION-SCOPED |
| `FRRDriver` | `vtysh -c 'show version'`, `hostname -s`, `cat /etc/os-release`, `ip -s -j link show`, `ip -j link show` *(fallback)*, `ip -j -4 addr show`, `vtysh -c 'show interface vrf all json'`, `vtysh -c 'show interface json'`, `lldpcli show neighbors -f json`, `command -v lldpcli >/dev/null 2>&1 \|\| echo __NO_LLDPD__`, `ip -j route show`, `vtysh -c 'show ip route vrf all json'`, `vtysh -c 'show ip route json'`, `vtysh -c 'show bgp vrf all summary json'`, `vtysh -c 'show bgp summary json'`, `vtysh -c 'show ip ospf vrf all neighbor json'`, `vtysh -c 'show ip ospf neighbor json'`, `vtysh -c 'show vrf json'`, `ip -j neigh show`, `vtysh -c 'show running-config'` | Explicit (`frr.py`) | Strictly read-only Linux/vtysh operational & config queries | ALLOW |
| `OPNsenseDriver` (Paramiko `exec_command`) | `hostname`, `opnsense-version`, `kenv smbios.system.product 2>/dev/null`, `kenv smbios.system.serial 2>/dev/null`, `ifconfig -a`, `lldpctl -f json 2>/dev/null`, `command -v lldpctl >/dev/null 2>&1 \|\| echo __NO_LLDPD__`, `netstat -rnW -f inet`, `netstat -rn -f inet`, `arp -an`, `cat /conf/config.xml` | Explicit (`opnsense.py`) | Strictly read-only FreeBSD/OPNsense non-interactive exec queries (no PTY menu trap) | ALLOW |
| `OpenWrtDriver` (`linux`) | `exit` | Implicit (`LinuxSSH.cleanup`) | Graceful shell logout; zero paging cmd | SESSION-SCOPED |
| `OpenWrtDriver` | `ubus call system board 2>/dev/null`, `cat /proc/sys/kernel/hostname 2>/dev/null \|\| hostname`, `cat /etc/openwrt_release 2>/dev/null`, `cat /proc/cpuinfo 2>/dev/null`, `ubus call network.interface dump 2>/dev/null`, `ip -d address show 2>/dev/null \|\| ip address show 2>/dev/null`, `lldpcli show neighbors -f json 2>/dev/null`, `command -v lldpcli >/dev/null 2>&1 \|\| echo __NO_LLDPD__`, `ubus call hostapd.* get_clients 2>/dev/null`, `ip route show 2>/dev/null \|\| route -n 2>/dev/null`, `cat /proc/net/arp 2>/dev/null`, `uci export 2>/dev/null`, `head -n 1000 /etc/config/* 2>/dev/null` | Explicit (`openwrt.py`) | Strictly read-only OpenWrt `ubus`/`uci export`/POSIX queries | ALLOW |
| `detector.py` & `snmp_collector.py` | TCP connect probe; SSH banner read; Telnet IAC WONT (`\xff\xfc\x18\xff\xfc\x1f\r\n`); HTTP/HTTPS `GET / HTTP/1.0`; SNMPv2c `GetRequest` (`0xA0`) & `GetBulkRequest` (`0xA5`) on IF-MIB/LLDP-MIB/sysDescr/sysName; local `/proc/net/arp` / `arp -n` / `arp -a` | Explicit (`detector.py`, `snmp_collector.py`) | Strictly read-only pre-auth probes and SNMP GET/GETBULK (zero SNMP Set) | ALLOW |

---

---

### Phase 4 Veto Gate Criteria (Enforced on Every Fix Branch Before Merge)
I will VETO any Phase 3/4 diff that:
1. Retains or introduces any write/config/commit/clear/reload/reboot/state-mutating command (explicit or via Netmiko `session_preparation`/`disable_paging`/`cleanup`).
2. Weakens any connect/auth/banner/read timeout or leaves a socket/VTY unclosed on exception paths.
3. Allows >1 authentication attempt per username per target IP (across drivers or SSH/Telnet ports) or adds credential retries.
4. Logs, prints, or persists unredacted passwords, enable secrets, private keys, or SNMP communities (including in `LazySessionLog` or `tests/fixtures/`).
5. Imports or commits `scratch/` provisioning scripts or `credentials.json`.

Standing by for Phase 4 diff reviews.

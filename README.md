# Powershell-Ops-IR-Toolkit
A small suite of powershell tools. Endpoint triage, incident response, and day-to-day system maintenance.  Built with a consistent house style, structured param blocks, color coded console output, a quiet mode that emits a ServiceNow pasteable output and Json support for every run.

Built while supporting enterprise Tier 2 technical operations in a healthcare IT environment, and extended through home-lab detection engineering work.

## Contents

All scripts are PowerShell 5.1+ compatible and ship with full comment-based help (`Get-Help .\<script>.ps1 -Full`).

---

## Invoke-LiveResponse.ps1

Live-response artifact collector for first-responder triage. **Read-only** — it inspects host state and never remediates or changes anything. Intended for authorized defensive/IR use on systems you're permitted to examine.

**Collectors (14):** host context, processes (hash + Authenticode + parent lineage), network connections mapped to owning process, autoruns/persistence (Run keys, Winlogon, AppInit_DLLs, IFEO debuggers), scheduled tasks, services, WMI event subscriptions, startup folders, local accounts + Administrators membership, recently-written executables, prefetch, PowerShell console history, Defender + firewall posture, and high-signal Security/System events.

Findings are scored **High / Medium / Info** and surfaced at the top, so a box is triage-ready instead of a raw data dump.

```powershell
# Standard run
.\Invoke-LiveResponse.ps1

# Custom output location + wider recent-file window
.\Invoke-LiveResponse.ps1 -OutputPath C:\IR -RecentFileHours 72

# Quiet mode — copies the ServiceNow-pasteable summary straight to clipboard
.\Invoke-LiveResponse.ps1 -Quiet | clip
```

**Sample summary output:**

```
====================================================
  LIVE RESPONSE  -  DESKTOP-7JQ2KD
====================================================
Collected : 2026-10-11T14:02:09Z UTC
By        : CORP\jparker  (Elevated: True)
OS        : Microsoft Windows 11 Enterprise  (Build 26100)  Uptime 3.2h

VERDICT   : 2 item(s) to review

-- FINDINGS --
  [Medi] Autorun        HKCU:\...\Run\UpdaterTask = C:\Users\jparker\AppData\Local\Temp\upd.exe
  [Info] Accounts       3 member(s) in local Administrators - verify all are expected

-- COUNTS --
  Processes            : 118 (flagged 0)
  External connections : 4
  Listeners            : 9
  ...
```

| Parameter | Default | Notes |
|---|---|---|
| `-OutputPath` | `%TEMP%\LiveResponse` | Root folder; a `<HOST>_<timestamp>` subfolder is created |
| `-Quiet` | off | Console prints only the pasteable summary (files still written) |
| `-SkipHashes` | off | Skip SHA256 hashing for speed |
| `-SkipEventLogs` | off | Skip Security/System log collection |
| `-RecentFileHours` | 24 | Look-back window for recently-written executables |
| `-MaxEvents` | 200 | Cap on events pulled per log |

---

## Invoke-NetTriage.ps1

Interactive, read-only endpoint triage for "my computer is slow" and "the network is down" tickets. One run produces a color-coded console dashboard **and** a plain-text summary ready to paste into a ticket.

**Covers:** system baseline + pending-reboot detection, performance snapshot (CPU/memory/disk free + disk latency + top processes by real-time CPU%), network config (adapters, IPv4/IPv6, gateway, DNS), VPN detection (Cisco Secure Client + Zscaler, read per-user via SID hive so it works from a PAM/admin context), proxy config (WinHTTP + per-user IE/WinInet), latency/quality (RTT + packet loss to gateway/DNS, DNS resolve time), core-infrastructure reachability (target list overridable via a local `CoreInfrastructure.json`), an optional single-target diagnostic (DNS + ping + multi-port TCP), and egress IP.

```powershell
# Full interactive dashboard
.\Invoke-NetTriage.ps1

# Ticket-ready summary, auto-copied to clipboard
.\Invoke-NetTriage.ps1 -TargetDestination intranet.example.com -Quiet

# Test a file/RDP server on specific ports
.\Invoke-NetTriage.ps1 -TargetDestination fileserver01 -TargetPorts 445,139,3389
```

**Sample KEY FINDINGS block:**

```
KEY FINDINGS:
  - [WARN] Uptime 9.4 days - consider reboot
  - [WARN] Weak Wi-Fi signal 54% on 'CORP-GUEST'
  - [FAIL] Cannot reach Identity Federation (SSO) (sso.corp.example.com:443)
```

| Parameter | Default | Notes |
|---|---|---|
| `-TargetDestination` | prompted | Hostname/IP to run the single-target diagnostic against |
| `-TargetPorts` | `443,80,445,3389` | Alias `-TargetPort` |
| `-ExportPath` | `%LOCALAPPDATA%\NetTriage\Triage_<timestamp>.json` | Per-user, not a shared path |
| `-RetainCount` | 20 | Older export pairs pruned after a successful run |
| `-Quiet` | off | Plain-text summary only; auto-copies to clipboard |
| `-SkipExternalIP` | off | Skip the egress-IP lookup |

Version 2.2. Fully read-only — makes no configuration changes.

---

## Invoke-EndpointTuneUp.ps1

Network-stack reset/repair plus disk cleanup and optimization, designed to run in an elevated remote-support session. Three phases: **Network** (DNS flush/re-register, ARP/NetBIOS purge, TCP autotuning reset, disable NIC power-saving, Winsock/TCP-IP stack reset, adapter restart, DHCP release/renew), **Cleanup** (temp files across all profiles, optional Recycle Bin, optional DISM/SFC), **Optimize** (volume TRIM/defrag, `gpupdate /force`, SCCM/MECM client policy + inventory triggers).

Deliberately **excludes**, for compliance and managed-endpoint safety: clearing event logs, resetting firewall policy, clearing prefetch, resetting the WinHTTP proxy, and clearing the Windows Update/Delivery Optimization/WER caches.

```powershell
# Standard run
powershell.exe -ExecutionPolicy Bypass -File .\Invoke-EndpointTuneUp.ps1

# Deep clean + auto-reboot when done
powershell.exe -ExecutionPolicy Bypass -File .\Invoke-EndpointTuneUp.ps1 -DeepClean -Reboot

# Fragile connection: keep the session alive, skip reboot-dependent resets
powershell.exe -ExecutionPolicy Bypass -File .\Invoke-EndpointTuneUp.ps1 -SkipAdapterRestart -SkipStackReset
```

| Parameter | Default | Notes |
|---|---|---|
| `-SkipStackReset` | off | Skip Winsock/TCP-IP reset — use on static-IP machines |
| `-SkipAdapterRestart` | off | Skip the two steps that briefly drop the remote session |
| `-ClearRecycleBin` | off | Off by default — confirm with the user first |
| `-DeepClean` | off | Adds DISM + SFC (+15–45 min) |
| `-Reboot` | off | Auto-restart with a countdown warning |
| `-RebootDelaySeconds` | 60 | Countdown before auto-reboot |

Full transcript written to `C:\ProgramData\EndpointTuneUp\Logs`.

---

## Update-System.ps1

Scans for and applies driver/firmware/BIOS updates on Windows 11. Pulls driver + firmware updates through the built-in Windows Update Agent COM API (no module dependency), then routes BIOS/firmware to the correct OEM tool — Dell Command | Update, Lenovo System Update, HP Image Assistant, Surface (via Windows Update), MyASUS, MSI Center, or a manual path for whitebox builds.

**Safety note:** this script never flashes the BIOS itself. OEM tools include AC/battery checks and recovery paths, so the actual flash is deliberately delegated to them.

```powershell
# Interactive menu
powershell -ExecutionPolicy Bypass -File .\Update-System.ps1

# Non-interactive: install everything, including app upgrades via winget
powershell -ExecutionPolicy Bypass -File .\Update-System.ps1 -AutoInstall -IncludeApps
```

| Parameter | Notes |
|---|---|
| `-AutoInstall` | Apply driver/firmware updates without an interactive prompt |
| `-IncludeApps` | Also run `winget upgrade --all` |

Requires an elevated session (`#Requires -RunAsAdministrator`). Log written to `%ProgramData%\SystemUpdateToolkit\`.

---

## License

MIT — see [`LICENSE`](./LICENSE).


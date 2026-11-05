# Powershell-Ops-IR-Toolkit
A small suite of powershell tools. Endpoint triage, incident response, and day-to-day system maintenance.  Built with a consistent house style, structured param blocks, color coded console output, a quiet mode that emits a ServiceNow pasteable output and Json support for every run.

Built while supporting enterprise Tier 2 technical operations in a healthcare IT environment, and extended through home-lab detection engineering work.

## Contents

All scripts are PowerShell 5.1+ compatible and ship with full comment-based help (`Get-Help .\<script>.ps1 -Full`).

---

## Invoke-LiveResponse.ps1

For ongoing live-response development, see [LiveResponse NG](https://github.com/jp101216/LiveResponse-NG).

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

**Covers:** system baseline + pending-reboot detection, performance snapshot (CPU/memory/disk free + disk latency + top processes by real-time CPU%), network config (adapters, IPv4/IPv6, gateway, DNS), VPN indicators (Cisco Secure Client + Zscaler processes, services, and tunnel adapters), proxy config (WinHTTP + per-user IE/WinInet), latency/quality (RTT + packet loss to gateway/DNS, DNS resolve time), TCP reachability for configured infrastructure, an optional single-target diagnostic (DNS + ping + multi-port TCP), and egress IP.

```powershell
# Full interactive dashboard
.\Invoke-NetTriage.ps1

# Ticket-ready summary, auto-copied to clipboard
.\Invoke-NetTriage.ps1 -TargetDestination intranet.example.com -Quiet

# Test a file/RDP server on specific ports
.\Invoke-NetTriage.ps1 -TargetDestination fileserver01 -TargetPorts 445,139,3389

# Internal DNS and branch-office TCP checks without the built-in public probes
.\Invoke-NetTriage.ps1 -NonInteractive -SkipPublicProbes -DnsProbeName intranet.example.com -CoreInfrastructurePath .\BranchOffice.json
```

**Sample KEY FINDINGS block:**

```
KEY FINDINGS:
  - [WARN] Uptime 9.4 days - consider reboot
  - [WARN] Weak Wi-Fi signal 54% on 'CORP-GUEST'
  - [FAIL] Cannot reach Branch file server (fileserver01:445)
```

| Parameter | Default | Notes |
|---|---|---|
| `-TargetDestination` | prompted | Hostname/IP to run the single-target diagnostic against |
| `-TargetPorts` | `443,80,445,3389` | Alias `-TargetPort` |
| `-ExportPath` | `%LOCALAPPDATA%\NetTriage\Triage_<timestamp>.json` | Per-user, not a shared path |
| `-RetainCount` | 20 | Keep this many timestamped export pairs. Use 0 to disable pruning. |
| `-CoreInfrastructurePath` | `CoreInfrastructure.json` beside the script, if present | JSON array of `Name`, `Host`, and `Port` entries |
| `-DnsProbeName` | `www.microsoft.com` | DNS name to time. An explicit name also works with `-SkipPublicProbes`. |
| `-SkipPublicProbes` | off | Skip the built-in public TCP and DNS checks and the egress-IP lookup. Configured targets still run. |
| `-NonInteractive` | off | Skip the optional target prompt |
| `-Quiet` | off | Plain-text summary only; auto-copies to clipboard |
| `-SkipExternalIP` | off | Skip the egress-IP lookup |

Without a config file, the built-in TCP probe checks `8.8.8.8:53`. Use an empty array to disable the infrastructure list. A branch-office config might look like this.

```json
[
  {"Name": "Branch file server", "Host": "fileserver01", "Port": 445},
  {"Name": "Intranet", "Host": "intranet.example.com", "Port": 443}
]
```

The JSON export includes the same findings shown in the ticket summary.

---

## Invoke-EndpointTuneUp.ps1

Network-stack reset/repair plus disk cleanup and optimization, designed to run in an elevated remote-support session. Three phases: **Network** (DNS flush/re-register, ARP/NetBIOS purge, TCP autotuning reset, disable NIC power-saving, Winsock/TCP-IP stack reset, adapter restart, DHCP release/renew), **Cleanup** (temp files across all profiles, optional Recycle Bin, optional DISM/SFC), **Optimize** (volume TRIM/defrag, `gpupdate /force`, SCCM/MECM client policy + inventory triggers).

Deliberately **excludes**, for compliance and managed-endpoint safety: clearing event logs, resetting firewall policy, clearing prefetch, resetting the WinHTTP proxy, and clearing the Windows Update/Delivery Optimization/WER caches.

```powershell
# Standard run
powershell.exe -File .\Invoke-EndpointTuneUp.ps1

# Deep clean + auto-reboot when done
powershell.exe -File .\Invoke-EndpointTuneUp.ps1 -DeepClean -Reboot

# Fragile connection: keep the session alive, skip reboot-dependent resets
powershell.exe -File .\Invoke-EndpointTuneUp.ps1 -SkipAdapterRestart -SkipStackReset

# Preview component-store cleanup and SFC
powershell.exe -File .\Invoke-EndpointTuneUp.ps1 -Phase Cleanup -DeepClean -SkipTempCleanup -WhatIf
```

| Parameter | Default | Notes |
|---|---|---|
| `-Phase` | Network, Cleanup, Optimize | Select one or more maintenance phases |
| `-SkipTempCleanup` | off | Skip deletion of temporary files |
| `-WhatIf` | off | Preview maintenance steps without writing logs or changing the clipboard |
| `-SkipStackReset` | off | Skip Winsock/TCP-IP reset — use on static-IP machines |
| `-SkipAdapterRestart` | off | Skip the two steps that briefly drop the remote session |
| `-ClearRecycleBin` | off | Off by default — confirm with the user first |
| `-DeepClean` | off | Adds DISM + SFC (+15–45 min) |
| `-Reboot` | off | Auto-restart with a countdown warning |
| `-RebootDelaySeconds` | 60 | Countdown before auto-reboot |

The transcript and JSON step report default to `C:\ProgramData\EndpointTuneUp\Logs`.

---

## Invoke-UpdateSystem.ps1

Scans for and applies driver/firmware/BIOS updates on Windows 11. Queries the configured Windows Update source through the built-in Windows Update Agent COM API, then routes BIOS/firmware to the appropriate OEM tool — Dell Command | Update, Lenovo System Update, HP Image Assistant, Surface (via Windows Update), MyASUS, MSI Center, or a manual path for whitebox builds.

**Safety note:** this script never flashes the BIOS itself. OEM tools include AC/battery checks and recovery paths, so the actual flash is deliberately delegated to them.

```powershell
# Interactive menu
powershell -File .\Invoke-UpdateSystem.ps1

# Scan and report available updates
powershell -File .\Invoke-UpdateSystem.ps1 -ScanOnly

# Unattended driver and firmware installation
powershell -File .\Invoke-UpdateSystem.ps1 -AutoInstall -NonInteractive
```

| Parameter | Notes |
|---|---|
| `-ScanOnly` | Report available updates and the OEM recommendation |
| `-UpdateId` | Limit the scan or installation to the exact update IDs recorded in a prior JSON report |
| `-WhatIf` | Preview update actions without creating a transcript or JSON report |
| `-AutoInstall` | Apply driver/firmware updates without an interactive prompt |
| `-IncludeApps` | Also offer app upgrades via winget. Use `-Force` to approve app and OEM-tool installs in unattended runs. |

Requires an elevated session (`#Requires -RunAsAdministrator`). The transcript and JSON report default to `%ProgramData%\SystemUpdateToolkit\`. The report records scan status, each update’s download and installation results, and whether a reboot is required.

---

## License

MIT — see [`LICENSE`](./LICENSE).


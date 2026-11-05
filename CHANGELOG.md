# Changelog

## 3.0.0

### Diagnostics and support

- Add offline before-and-after comparison of NetTriage exports with JSON and ticket summaries.
- Report VPN client activity and active tunnel-interface evidence.
- Select destination routes and interface DNS configuration through Windows networking APIs.
- Support IPv4 and IPv6 TCP probing with address fallback.
- Add RemoteSafe maintenance and preflight protection for manually configured IP addresses.

### Reliability

- Report partial batch failures and per-adapter or per-schedule outcomes.
- Use supported NIC sleep controls with verification and deferred adapter restart.
- Keep unavailable diagnostic measurements as null in JSON and display Unknown.
- Restrict temporary-file cleanup by creation and modification age, skip reparse-point paths, and report deletion and skip counts.
- Write JSON atomically and restore the preceding NetTriage report pair if publication fails.
- Add documented process exit codes and version fields.
- Add exact update-ID selection, scan-only mode, and per-update download and installation results.

### Compatibility

- Automation should accept exit code 3010 as completed work requiring a reboot.
- Exit code 2 identifies incomplete collection or partially successful maintenance.
- NetTriage consumers should handle null measurements and inspect CollectionErrors.
- The release ZIP contains the four maintained operations commands, documentation, and an example infrastructure configuration.
- Windows PowerShell 5.1 and PowerShell 7 are covered by Windows CI, with native Windows 11 ARM coverage.

## 2.0.0

- Modernize the original scripts for PowerShell 5.1 and PowerShell 7.

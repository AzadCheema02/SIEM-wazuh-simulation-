# Incident Report: INC-002 (Advanced LotL Credential Theft)

**Date of Activity:** September 18, 2026
**Target System:** Windows-Target (10.10.10.10) - Windows 11
**SIEM Platform:** SentinelForge Lab (Wazuh / Sysmon)
**Analyst:** Azadvir Singh

## Executive Summary
A multi-stage adversary simulation was executed against a Windows 11 endpoint to validate custom detection engineering capabilities. The simulated threat actor utilized "Living off the Land" (LotL) techniques to bypass standard static defenses. The attack chain consisted of defense evasion via `MSBuild.exe`, credential theft via Volume Shadow Copies using WMI/CIM, and data exfiltration via a renamed `rclone` binary. All stages were successfully detected and logged by custom Wazuh rules analyzing Sysmon telemetry.

## Detection Rule Matrix

| Rule ID | Level | Data Source | MITRE Technique(s) | Trigger Condition |
| :--- | :--- | :--- | :--- | :--- |
| **100020** | 12 | Sysmon (EID 1) | T1127.001 | `MSBuild.exe` spawning command shell |
| **100021** | 10 | Sysmon (EID 1) | T1003.002, T1047 | Command line containing `Win32_ShadowCopy` |
| **100022** | 12 | Sysmon (EID 1) | T1567.002 | `originalFileName` matches `rclone.exe` |
| **100023** | 12 | Sysmon (EID 3) | T1567.002 | `backup_service.exe` outbound to port 8080 |

## Threat Hunting & Correlation
The attack was successfully correlated using Sysmon Event ID 1 (Process Creation) and Event ID 3 (Network Connection). The detection engineering explicitly ignored the renamed binary (`backup_service.exe`) and instead triggered on the internal `originalFileName` metadata (`rclone.exe`) to catch the exfiltration attempt.

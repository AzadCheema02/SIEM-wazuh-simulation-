# Incident Report: INC-003

## Executive Summary
* **Incident ID:** INC-003
* **Detection Engineering Case:** DET-003
* **Target System:** Windows 11 Enterprise (`Windows-Target` / ID: 001)
* **SIEM Platform:** Wazuh Server / OpenSearch Dashboards (`10.10.10.50`)
* **Severity:** Critical (Level 12)
* **Status:** Resolved / Post-Incident Review Complete

During automated adversary simulation, host-based telemetry on endpoint `Windows-Target` triggered two custom high-severity detection rules. The telemetry captures a multi-stage ransomware execution model: defense evasion via system recovery disabling and log clearing, followed by rapid bulk file encryption across a monitored corporate directory (`C:\Finance_Data`).

---

## MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Target / Command Executed |
| :--- | :--- | :--- | :--- |
| **Defense Evasion** | T1490 | Inhibit System Recovery | `vssadmin delete shadows /all /quiet`, `bcdedit /set {default} recoveryenabled No` |
| **Defense Evasion** | T1070 | Indicator Removal | `wevtutil cl Application`, `wevtutil cl System` |
| **Impact** | T1486 | Data Encrypted for Impact | Bulk modification of `.txt` files to `.crypt` in `C:\Finance_Data` |

---

## Technical Detection & Rule Configuration

To mitigate alert fatigue and elevate high-confidence adversary behavior, two dedicated Level 12 rules were deployed within the Wazuh manager's `/var/ossec/etc/rules/local_rules.xml`.

```xml
<group name="ransomware_simulation,">
    <!-- Phase 1: Inhibit System Recovery & Log Destruction -->
    <rule id="100030" level="12">
        <if_group>sysmon_process-creation</if_group>
        <field name="win.eventdata.commandLine" type="pcre2">(?i)(vssadmin.*delete\s+shadows|bcdedit.*recoveryenabled\s+no|wevtutil.*cl\s+(application|security|system))</field>
        <description>Custom Detection: Defense Impairment and Recovery Invalidation (T1490/T1070)</description>
        <mitre>
            <id>T1490</id>
            <id>T1070</id>
        </mitre>
    </rule>

    <!-- Phase 2: Rapid Data Encryption (FIM Trigger) -->
    <rule id="100031" level="12">
        <if_group>syscheck</if_group>
        <match>.crypt</match>
        <description>Custom Detection: Ransomware File Extension (.crypt) Detected in Monitored Directory (T1486)</description>
        <mitre>
            <id>T1486</id>
        </mitre>
    </rule>
</group>
```
## Incident Timeline & Investigation

**Initial Access & Execution:**
* Script execution initiated via an administrative PowerShell process (`powershell.exe -ExecutionPolicy Bypass -File C:\Temp\ransomware_sim.ps1`).

**Defense Evasion Triggers (Rule 100030):**
* Exactly 4 high-severity events were ingested via the `Microsoft-Windows-Sysmon/Operational` event channel.
* Telemetry logged process spawning of `vssadmin.exe` with arguments removing Volume Shadow Copies, `bcdedit.exe` disabling boot recovery options, and `wevtutil.exe` attempting log destruction.

**Data Impact Triggers (Rule 100031):**
* Wazuh File Integrity Monitoring (`syscheck`) identified real-time changes within `C:\Finance_Data`.
* Multiple file modification events generated corresponding alerts as `.txt` files were modified and appended with the `.crypt` extension.

**Correlation & Telemetry Health:**
* Endpoint connectivity confirmed healthy on target port `1514/tcp` following service stabilization.

---

## Dashboard Visualizations

*(Insert your saved OpenSearch dashboard screenshots here)*

* **Figure 1.1: Ransomware Rule Distribution (Pie Chart):** Captures the proportional breakdown of the 4 Defense Evasion commands versus the bulk File Encryption alerts (`rule.id: 100030` vs `rule.id: 100031`).
* **Figure 1.2: Encrypted File Ledger (Data Table):** Itemizes compromised artifacts (`Payroll_Record_*.crypt`) using the `syscheck.path` field.
* **Figure 1.3: Defense Evasion Activity (Saved Search):** Forensic command-line evidence extracted from `win.eventdata.commandLine`.

---

## Root Cause Analysis & Engineering Lessons Learned

* **FIM Real-Time Hooks & Directory Re-creation:** When monitored directories are deleted and recreated at runtime, directory monitor hooks must be refreshed. Restarting `WazuhSvc` re-initializes `syscheck` watchers and completes baseline generation before adversary execution occurs.
* **Rule Engine Match Logic:** Standardizing field parsing using substring pattern matching (`<match>`) avoids schema inconsistencies between UI display fields (`syscheck.path`) and decoder representations (`file`), ensuring zero dropped alerts during bulk operations.

---

## Remediation & Hardening Recommendations

1. **Active Response Deployment:** Deploy an automated Active Response block to immediately terminate parent PowerShell processes when `100030` is detected, stopping encryption prior to phase two.
2. **Access Control Hardening:** Restrict execution privileges for `vssadmin.exe`, `bcdedit.exe`, and `wevtutil.exe` to high-privilege administrative service accounts, removing general user access.
3. **Immutable Backups:** Transition critical enterprise shares to write-once-read-many (WORM) storage to invalidate the impact of shadow copy and local backup purges.

## Threat Hunting & Proactive Scoping

**Hypothesis:** If an adversary successfully evades our `vssadmin` or FIM alerting (Rules 100030 and 100031), residual telemetry regarding mass file modification velocity and alternative recovery subversion techniques will still be present in the environment.

The following OpenSearch (Lucene/KQL) queries can be utilized to retroactively scope the blast radius of a ransomware infection or hunt for alternative execution methods.

### 1. Alternate Shadow Copy Deletion (WMI)
Adversaries often pivot to WMI if `vssadmin.exe` is heavily monitored. This query hunts for alternative volume shadow copy destruction methods.
* **Query:** 
  `rule.groups: "sysmon" AND data.win.eventdata.commandLine: (*wmic* AND *shadowcopy* AND *delete*)`
* **Purpose:** Identifies adversaries bypassing `vssadmin` restrictions via Windows Management Instrumentation.

### 2. Event Log Clearance Anomalies (Event ID 1102 & 104)
Instead of hunting for the `wevtutil` process execution, this query hunts for the actual systemic result of an event log being cleared.
* **Query:**
  `data.win.system.eventID: ("1102" OR "104")`
* **Purpose:** Detects the operational success of an adversary clearing the Windows Security (1102) or System/Application (104) logs, regardless of the tool used to do it.

### 3. File Modification Velocity (Spike Detection)
If an adversary uses a novel ransomware extension (e.g., `.unknown`) that bypasses the `.crypt` rule, you can hunt for a high velocity of file modifications.
* **Query:**
  `rule.group: "syscheck" AND syscheck.event: ("added" OR "modified" OR "deleted")`
* **Purpose:** When visualized over a 15-minute time aggregation, a massive, unnatural spike in this query's results isolates the exact moment bulk encryption commenced, even if the file extension is unrecognized.

### 4. Bypassed Execution Policies
Ransomware scripts often require execution policy bypasses to run unattended.
* **Query:**
  `data.win.eventdata.commandLine: (*ExecutionPolicy* AND *Bypass*) OR data.win.eventdata.commandLine: (*-ep* AND *bypass*)`
* **Purpose:** Identifies the precursor staging activity where an adversary lowers PowerShell constraints to execute their payload.

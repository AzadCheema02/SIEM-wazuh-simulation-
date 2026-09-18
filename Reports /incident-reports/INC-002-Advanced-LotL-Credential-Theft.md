# INC-002 — Living off the Land Credential Theft & Exfiltration

## 1. Incident Summary

A multi-stage adversary simulation was executed against the Windows 11 endpoint (`Windows-Target`) from the Kali Linux attack host within the SentinelForge laboratory.

The attacker utilized "Living off the Land" (LotL) binaries and native administrative utilities to evade detection, dump local credential hives, and stage outbound exfiltration. 

The attack chain progressed through three distinct phases: defense evasion via `MSBuild.exe` executing an inline task, credential access by generating a Volume Shadow Copy via WMI/CIM (`Win32_ShadowCopy`) to extract the locked `SAM` and `SYSTEM` registry hives, and attempted exfiltration using a masqueraded Rclone binary (`backup_service.exe`) connecting outbound to an external HTTP receiver on port 8080.

Four custom Wazuh detection rules (`100020`, `100021`, `100022`, and `100023`) successfully correlated the underlying Sysmon Event ID 1 (Process Creation) and Event ID 3 (Network Connection) telemetry across the entire kill chain.

---

## 2. Incident Details

| Field | Value |
|---|---|
| **Incident ID** | INC-002 |
| **Detection ID** | DET-002 |
| **Rule IDs** | 100020, 100021, 100022, 100023 |
| **Alert Levels** | 12 (Critical), 10 (High), 12 (Critical), 12 (Critical) |
| **Source / C2 IP** | 10.10.10.40 |
| **Target Hostname** | DESKTOP-O58SQ9R (`Windows-Target`) |
| **Target IP** | 10.10.10.10 |
| **Target Account** | `DESKTOP-O58SQ9R\azadv` |
| **Target Data** | SAM and SYSTEM registry hives (`C:\Temp\sam.save`) |
| **Exfiltration Protocol** | HTTP / WebDAV (TCP 8080) |
| **Compromised Credentials Exposed** | Yes (Extracted locally, exfiltration intercepted/alerted) |
| **Status** | Closed |

---

## 3. Attack Source & Target

### Source (Attacker / C2)
* **OS:** Kali Linux
* **IP:** 10.10.10.40
* **Listening Service:** Custom HTTP/WebDAV Receiver (Python `http.server`)
* **Port:** 8080

### Target
* **OS:** Windows 11
* **Hostname:** DESKTOP-O58SQ9R
* **Agent ID:** 001
* **IP:** 10.10.10.10
* **User Context:** `DESKTOP-O58SQ9R\azadv` (High Integrity)

*The attack was performed entirely within the isolated SentinelForge laboratory.*

---

## 4. Detection

The malicious activity was detected across multiple stages by custom Wazuh rules ingesting Microsoft-Windows-Sysmon/Operational logs:

* **Rule ID 100020 (Level 12):** Custom Detection: MSBuild Spawning Shell (Defense Evasion)
* **Rule ID 100021 (Level 10):** Custom Detection: WMI/CIM creating volume shadow copy (Potential Credential Access)
* **Rule ID 100022 (Level 12):** Custom Detection: Rclone execution detected (Potential Data Exfiltration)
* **Rule ID 100023 (Level 12):** Custom Detection: Suspicious backup process initiated outbound network connection (Potential Exfiltration)

### Detection Logic:
1. **Phase 1 (Execution/Evasion):** Sysmon Event ID 1 where `parentImage` is `*MSBuild.exe*` and child `image` is `cmd.exe` or `powershell.exe`. Triggers Rule 100020.
2. **Phase 2 (Credential Access):** Sysmon Event ID 1 where `commandLine` matches regex `(?i)Win32_ShadowCopy`. Triggers Rule 100021.
3. **Phase 3A (Process Masquerading):** Sysmon Event ID 1 where binary metadata field `originalFileName` matches `(?i)rclone\.exe` and `commandLine` contains `copy` or `sync`. Triggers Rule 100022.
4. **Phase 3B (Network Exfiltration):** Sysmon Event ID 3 where `image` matches `backup_service.exe` and `destinationPort` equals `8080`. Triggers Rule 100023.

---

## 5. Timeline

* **Sep 18 16:10:12 UTC** — Defense Evasion: `MSBuild.exe` invoked with inline XML payload, spawning an unauthorized shell session (Rule 100020).
* **Sep 18 16:40:54.710 UTC** — Credential Access: PowerShell process spawned with `-Command "Invoke-CimMethod -ClassName Win32_ShadowCopy ..."` creating a shadow volume of the `C:\` drive (Rule 100021).
* **Sep 18 16:42:15 UTC** — Staging: `SAM` and `SYSTEM` hives copied from shadow volume root to `C:\Temp\sam.save` and `C:\Temp\system.save`.
* **Sep 18 17:01:32.995 UTC** — Masquerading & Exfiltration: Renamed executable `backup_service.exe` executed (Rule 100022) and initiated an outbound TCP connection from `10.10.10.10:59305` to `10.10.10.40:8080` (Rule 100023).

---

## 6. Investigation & Findings

The investigation established:

* **Initial Subversion:** The adversary executed a trusted binary from `C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe` to proxy code execution in memory.
* **Volume Shadow Exploitation:** Bypassing `vssadmin.exe` restrictions on Windows client platforms, the adversary leveraged WMI/CIM directly via PowerShell to instantiate `Win32_ShadowCopy`. This bypassed Windows file-locking protections on active registry hives.
* **Binary Masquerading:** The utility `rclone.exe` was renamed to `backup_service.exe` inside `C:\Temp\rclone-v1.75.1-windows-amd64\` to evade path- or filename-based detection controls.
* **Metadata Correlation:** Telemetry analysis confirmed that Sysmon extracted `originalFileName: rclone.exe` from the executable header, defeating the masquerading attempt.
* **Network Egress:** The process established an active TCP handshake with `10.10.10.40:8080`, transmitting credential artifacts off-host.
* **Alert Fidelity:** Custom rules 100020, 100021, 100022, and 100023 generated high-severity alerts without false-positive overlap with generic Windows baseline rules.

**Conclusion:** The activity was confirmed to be an intentional multi-stage attack simulation performed within the SentinelForge laboratory.

---

## 7. MITRE ATT&CK Mapping

| Field | Value |
|---|---|
| **Tactic 1** | Defense Evasion (TA0005) |
| **Technique 1** | T1127.001 — Trusted Developer Utilities Proxy Execution: MSBuild |
| **Tactic 2** | Credential Access (TA0006) / Execution (TA0002) |
| **Technique 2** | T1003.002 — OS Credential Dumping: Security Account Manager |
| **Technique 3** | T1047 — Windows Management Instrumentation |
| **Tactic 3** | Defense Evasion (TA0005) / Exfiltration (TA0010) |
| **Technique 4** | T1036.005 — Masquerading: Match Legitimate Name or Location |
| **Technique 5** | T1567.002 — Exfiltration Over Web Service: Exfiltration to Cloud Storage |

---

## 8. Impact Assessment

* **Execution Success:** Yes (MSBuild spawned interactive process context)
* **Privilege Elevation / Access:** High-integrity execution achieved
* **Credential Dumping:** Confirmed (Local copies of `SAM` and `SYSTEM` extracted)
* **Exfiltration Success:** Confirmed (Network connection established to external receiver)
* **Production Impact:** None (Contained within isolated lab environment)

*The incident represents an advanced credential access and exfiltration chain that succeeded at the host level but was comprehensively recorded and alerted across all vectors.*

---

## 9. Response & Recovery

Because this was a controlled laboratory simulation, no emergency production containment was required.

The following remediation and cleanup steps were executed:

- [x] Terminated rogue background processes associated with `backup_service.exe`
- [x] Deleted staged artifacts: `C:\Temp\sam.save`, `C:\Temp\system.save`, and `C:\Temp\malicious.xml`
- [x] Purged the generated Volume Shadow Copy via WMI to prevent persistence of offline backups
- [x] Removed unpacked staging binary directory `C:\Temp\rclone-v1.75.1-windows-amd64\`
- [x] Verified endpoint communication integrity between Wazuh Agent 001 and the manager

*In an enterprise environment, containment would mandate immediate endpoint host isolation, global credential revocation and password resets for all accounts cached on the host, blocking the destination IP/port at the perimeter firewall, and conducting enterprise-wide threat hunts for similar `Win32_ShadowCopy` or `originalFileName: rclone.exe` executions.*

---

## 10. Lessons Learned & Detection Improvement

The simulation confirmed that relying on image names or standard system utilities like `vssadmin` is insufficient for detecting modern LotL tradecraft. Detecting attacks at the metadata and behavioral layer provided full-chain visibility.

**Identified detection engineering enhancements:**
* Implement Windows Defender Application Control (WDAC) to block `MSBuild.exe` from executing untrusted scripts outside developer paths.
* Implement a correlation rule chaining `Win32_ShadowCopy` execution with file copy events of the `SAM` hive within 5 minutes.
* Expand rule 100022 into a centralized hunting list checking Sysmon `originalFileName` against common dual-use exfiltration tools (e.g., `rclone.exe`, `mega.exe`, `chisel.exe`).
* Deploy automated active response scripts via Wazuh to disconnect network interfaces upon Level 12 exfiltration alerts.

---

## Evidence & References

**Evidence Directory:** `Dashboards/screenshots/`
* `DET-002-attack-execution.png`
* `DET-002-wazuh-alert-100021.png`
* `DET-002-wazuh-alert-100023.png`
* `DET-002-kali-c2-listener.png`
* `DET-002-LotL-Dashboard.png`

**Related Documentation:**
* **Attack Documentation:** `Attacks/windows/DET-002-Advanced-LotL-Credential-Theft/attack.md`
* **Attack Commands:** `Attacks/windows/DET-002-Advanced-LotL-Credential-Theft/commands.txt`
* **Detection Matrix:** `Detections/detection-matrix.csv`
* **Threat Hunting Queries:** `Threat-Hunting/queries/DET-002-queries.txt`

---

## Final Assessment

* **Incident:** Advanced LotL Credential Theft & Exfiltration
* **Detection:** Successful (4 Rules Triggered)
* **Rules:** 100020, 100021, 100022, 100023
* **MITRE:** T1127.001, T1003.002, T1047, T1036.005, T1567.002
* **Source:** 10.10.10.40
* **Target:** 10.10.10.10 (`Windows-Target`)
* **Credential Exposure:** Confirmed Local SAM Dump
* **Exfiltration Observed:** Yes (Outbound TCP Connection to Port 8080)
* **Status:** CLOSED

---

## Screenshot Capture Guide

Save the following captures to `Dashboards/screenshots/` to complete the evidence repository:

1. **`DET-002-attack-execution.png`**
   * **Location:** Windows 11 Target.
   * **Details:** Command Prompt window displaying execution of `backup_service.exe copy ...` and directory listing of `C:\Temp\` showing `.save` files.

2. **`DET-002-wazuh-alert-100021.png`**
   * **Location:** Wazuh / OpenSearch Dashboards (Discover tab).
   * **Details:** Expanded record for Rule 100021 showing `commandLine` containing `Win32_ShadowCopy` and `level: 10`.

3. **`DET-002-wazuh-alert-100023.png`**
   * **Location:** Wazuh / OpenSearch Dashboards (Discover tab).
   * **Details:** Expanded record for Rule 100023 showing `eventID: 3`, `image: ...\backup_service.exe`, `destinationIp: 10.10.10.40`, and `destinationPort: 8080`.

4. **`DET-002-kali-c2-listener.png`**
   * **Location:** Kali Linux terminal.
   * **Details:** Output of `python3 -m http.server 8080` showing incoming HTTP request logged from `10.10.10.10`.

5. **`DET-002-LotL-Dashboard.png`**
   * **Location:** OpenSearch Dashboards (Dashboard view).
   * **Details:** Complete 3-panel dashboard containing the Attack Progression Timeline, MITRE Technique Donut Chart, and Forensic Evidence Table.

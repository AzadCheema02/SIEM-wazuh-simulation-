# DET-001 — SSH Brute Force Detection

## 1. Detection Overview

| Field | Value |
|---|---|
| Detection ID | DET-001 |
| Detection Name | SSH Brute Force - High Frequency Password Guessing |
| Platform | Ubuntu Linux |
| Data Source | SSH Authentication Logs |
| SIEM | Wazuh |
| Detection Type | Custom Wazuh Rule |
| Rule ID | 100010 |
| Severity | High |
| MITRE ATT&CK | T1110.001 - Password Guessing |
| Status | Validated |

---

## 2. Detection Objective

Detect repeated failed SSH authentication attempts originating from the same source IP within a short period of time.

The objective is to identify potential SSH password-guessing or brute-force activity against the Linux system.

---

## 3. Attack Scenario

A controlled SSH brute-force simulation was performed from the Kali Linux attacker machine against the Ubuntu target inside the isolated SentinelForge lab.

### Attacker

```text
Host: Kali Linux
IP: 10.10.10.40 
```

## 4.Target
```text
Host: Ubuntu Linux
IP: 10.10.10.30
Service: SSH
Port: 22
Username: root
```

## 5.Attack Tool

Hydra was used to generate repeated SSH authentication attempts using a locally created lab-only password list.

Command Used
```bash
hydra -l root -P /tmp/lab-passwords.txt ssh://10.10.10.30 -t 4
```

## 6. Telemetry Flow
```text
Kali Linux
    |
    | SSH authentication attempts
    v
Ubuntu Linux
    |
    | SSH authentication logs
    v
Wazuh Agent
    |
    | Log forwarding
    v
Wazuh Server
    |
    | Decoder + Rule Analysis
    v
Base Rule 5760
    |
    | Repeated matching events
    v
Custom Rule 100010
    |
    v
Wazuh Alert
    |
    v
SOC Analyst
```
## 7.Detection Logic

The custom rule correlates repeated SSH authentication failure events.

Detection conditions:
```text
5 matching authentication events
        +
Within 120 seconds
        +
Same source IP
        =
SSH Brute Force Alert
```
The detection uses Wazuh rule ```5760 ``` as the matching base event.

## 8.Custom Wazuh Rule
```xml
<group name="linux, ssh, authentication_failed, attacks,">
    <rule id="100010" level="12" frequency="5" timeframe="120">
        <if_matched_sid>5760</if_matched_sid>
        <same_source_ip />
        <description>Custom Detection: SSH Brute Force - High frequency password guessing</description>
        <mitre>
            <id>T1110.001</id>
        </mitre>
    </rule>
</group>
```
Rule Configuration
| Parameter | Value |
|---|---|
| Rule ID | 100010 |
| Level | 12 |
| Frequency | 5 events |
| Timeframe | 120 seconds |
| Base Rule | 5760 |
| Correlation | Same source IP |
| MITRE | T1110.001 |

## 9. Detection Validation & Evidence

The detection was validated using two independent tests.
### 7.1 Live Attack Validation

A controlled SSH brute-force simulation was executed from the Kali attacker against the Ubuntu target.
```text
Rule ID: 100010
Rule Level: 12
Description: Custom Detection: SSH Brute Force - High frequency password guessing
MITRE ATT&CK: T1110.001 - Password Guessing

Source IP: 10.10.10.40
Destination IP: 10.10.10.30
Username: root

Failed Authentication Attempts: 5
Successful Authentication: NO
```
### 7.2Wazuh Logtest Validation

The underlying SSH authentication event was tested using Wazuh's rule-testing utility:
```bash
sudo /var/ossec/bin/wazuh-logtest
```
The actual SSH event generated during the attack was used:
```text
Sep 14 11:56:36 cheema sshd-session[2886]: Failed password for root from 10.10.10.40 port 53578 ssh2
```
Phase 1 — Pre-decoding

Wazuh successfully extracted:
```text
hostname: cheema
program_name: sshd-session
timestamp: Sep 14 11:56:36
```

Phase 2 — Decoding

The SSH decoder successfully extracted:
```text
decoder: sshd
dstuser: root
srcip: 10.10.10.40
srcport: 53578
```
Phase 3 — Rule Matching

The individual event matched the expected base rule:
```text
Rule ID: 5760
Description: sshd: authentication failed.
```
Five matching SSH authentication-failure events from the same source IP were then supplied within the same logtest session.

The custom correlation rule successfully triggered:
```text 
Rule ID: 100010
Rule Level: 12
Description: Custom Detection: SSH Brute Force - High frequency password guessing
```
Validatio Result
```text
Raw SSH Event
      ↓
Pre-decoding ✓
      ↓
SSH Decoder ✓
      ↓
Base Rule 5760 ✓
      ↓
5 matching events
      ↓
Same source IP ✓
      ↓
Custom Rule 100010 ✓
      ↓
Level 12 Detection ✓
```
The detection logic was therefore validated both against live attack telemetry and through Wazuh's rule-testing engine.
Evidence screenshot:
* `Dashboards/screenshots/DET-001-wazuh-alert.png`

## 10. MITRE ATT&CK Mapping
Technique
```text
T1110 — Brute Force
```
Sub-technique
```text
T1110.001 — Password Guessing
```
Tactic
```text
Credential Access
```
Rationale

The simulated attack repeatedly attempted SSH authentication using different passwords against the target account.

This behavior maps to``` MITRE ATT&CK T1110.001 - Password Guessing```.

## 11. SOC Triage & Response

When this alert is generated, a SOC analyst should investigate:

Source
```text
- Identify the source IP.
- Determine whether the source is authorized.
- Check for additional activity from the source.
```
Target
```twxt
- Identify the targeted host.
- Determine whether SSH access is expected.
- Identify the targeted account.
```
Authentication
```text
- Confirm the number of failed attempts.
- Check whether authentication eventually succeeded.
- Check whether additional accounts were targeted.
```
Response

If the activity is confirmed as malicious:
```text
1. Investigate the source IP.
2. Check for successful authentication.
3. Search for related activity on other systems.
4. Block or restrict the source if appropriate.
5. Review the targeted account.
6. Escalate if compromise is suspected.
10. Detection Improvement
```
## 12.Detection Improvement
Future improvements to DET-001 could include:
```text
- Detect successful login after repeated failures.
- Detect one source attacking multiple hosts.
- Detect attacks against multiple usernames.
- Detect distributed brute-force attempts.
- Add trusted-source allowlisting.
- Correlate SSH activity with firewall/network telemetry.
- Automate containment for confirmed malicious sources.
```
A higher-confidence future detection could correlate:
```text
Multiple SSH failures
        +
Successful authentication
        =
Potential Account Compromise
```
Detection Status
```text
DET-001 — SSH Brute Force

Attack:        Hydra SSH brute-force simulation
Source:        10.10.10.40
Target:        10.10.10.30
Rule:          100010
Severity:      High
Failures:      5
Successful Login: NO
MITRE:         T1110.001
Status:        VALIDATED
```

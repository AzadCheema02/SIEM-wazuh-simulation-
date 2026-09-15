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

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
| Rule Level | 12 |
| Severity | High |
| MITRE ATT&CK | T1110.001 - Password Guessing |
| Status | Validated |

---

## 2. Detection Objective

Detect repeated failed SSH authentication attempts originating from the same source IP within a short period of time.

The purpose of this detection is to identify potential SSH password-guessing or brute-force activity against Linux systems.

The detection should generate a high-severity Wazuh alert when multiple failed SSH authentication events are observed from the same source IP.

---

## 3. Attack Scenario

The detection was validated using a controlled brute-force simulation inside the isolated SentinelForge lab.

### Attacker

- Host: Kali Linux
- IP Address: `10.10.10.40`

### Target

- Host: Ubuntu Linux
- IP Address: `10.10.10.30`
- Service: SSH
- Port: `22`
- Target Username: `root`

### Attack Tool

Hydra was used to generate repeated SSH authentication failures.

The password list used for the simulation was a locally created lab-only password list.

### Attack Command

```bash
hydra -l root -P /tmp/lab-passwords.txt ssh://10.10.10.30 -t 4

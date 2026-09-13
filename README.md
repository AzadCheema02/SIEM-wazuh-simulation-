# Endpoint Security & SIEM Portfolio

## 📖 Overview
This repository documents a custom-built Security Operations Center (SOC) home lab environment. It demonstrates the ability to generate malicious telemetry, ingest logs into a SIEM, and write custom detection rules to catch advanced attacker techniques.

## 🏗️ Architecture
*   **SIEM:** Wazuh (Elastic Stack)
*   **Endpoints:** 
    *   Windows 10 / 11 (Sysmon with SwiftOnSecurity configuration)
    *   Ubuntu Linux (Auditd)
*   **Attack Infrastructure:** Kali Linux

## 🗺️ Lab Architecture Diagram
<img width="5359" height="1340" alt="image" src="https://github.com/user-attachments/assets/7a1e9774-055c-40c1-8c8b-17441820845b" />
## SOC Capabilities Demonstrated

- SIEM deployment and administration
- Windows security monitoring
- Linux security monitoring
- Sysmon telemetry
- Network intrusion detection
- Detection engineering
- Custom Wazuh rules
- Sigma rules
- Log analysis
- Threat hunting
- MITRE ATT&CK mapping
- IOC enrichment
- Incident triage
- Incident response
- Security automation
- Python scripting


## ⚔️ Detection Scenarios
### Windows
*   [Scenario 1: Fileless PowerShell Stager & Policy Bypass](Scenario-1-PowerShell.md)

### Linux
*   *Coming soon...*

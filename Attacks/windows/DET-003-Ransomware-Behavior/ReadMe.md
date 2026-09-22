# README.md

# DET-003: Ransomware Behavior Simulation

## Overview
This repository contains the detection engineering documentation and artifacts for **DET-003**, a multi-stage ransomware behavior simulation. The objective of this lab is to detect and alert on the sequential execution phases typical of modern ransomware strains, specifically focusing on defense impairment and rapid mass file encryption.

## Environment
* **Target System:** Windows 11 Enterprise (`Windows-Target`)
* **SIEM / XDR:** Wazuh Server (`10.10.10.50`) & OpenSearch Dashboards
* **Log Sources:** Sysmon (`Microsoft-Windows-Sysmon/Operational`), Wazuh File Integrity Monitoring (`syscheck`)

## Detection Objectives
1. **Phase 1 (Defense Evasion):** Detect administrative commands designed to inhibit system recovery (e.g., volume shadow copy deletion, disabled boot recovery) and clear event logs.
2. **Phase 2 (Impact):** Detect rapid file extension modifications (specifically `.crypt` extensions) within high-value corporate directories using File Integrity Monitoring (FIM).

## Artifacts Included
* `attack.md`: Detailed breakdown of the adversary methodology and MITRE ATT&CK mapping.
* `commands.md`: The exact PowerShell and CMD commands utilized to simulate the ransomware behavior.
* `INC-003_Ransomware_Behavior.md`: The finalized incident report and post-incident review (located in the primary reporting directory).

# MITRE ATT&CK Coverage

SentinelForge maps individual security detections and investigations to the MITRE ATT&CK framework.

The purpose of this document is to track which attacker behaviors have been simulated, detected, investigated, and validated within the laboratory.

## Current Coverage

| Detection | Technique | Sub-Technique | Tactic | Platform | Status |
|---|---|---|---|---|---|
| DET-001 | T1110 — Brute Force | T1110.001 — Password Guessing | Credential Access | Ubuntu | Validated |

## DET-001 Evidence

The SSH brute-force scenario generated repeated failed authentication attempts against the Ubuntu SSH service.

The activity was detected using custom Wazuh Rule `100010`.

Supporting documentation:

```text
Attacks/linux/DET-001-SSH-Brute-Force/
```
```text
Detections/wazuh/DET-001-SSH-Brute-Force.md
```
```text
Reports/incident-reports/INC-001-SSH-Brute-Force.md
```

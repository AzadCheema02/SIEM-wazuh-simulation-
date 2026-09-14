# DET-001 — SSH Brute Force Attack

## Detection ID

DET-001

## Scenario

SSH Brute Force Detection and Investigation

## Objective

Simulate an SSH brute-force attack against the Ubuntu monitored endpoint and validate the SentinelForge SOC detection and investigation workflow.

The scenario demonstrates the complete process from attack simulation to security telemetry collection, detection, alert triage, investigation, MITRE ATT&CK mapping, response, and detection improvement.

---

# 1. Scenario Overview

An attacker attempts to gain unauthorized access to the Ubuntu endpoint by repeatedly submitting SSH authentication attempts using invalid credentials.

The SentinelForge SOC should detect the abnormal authentication activity, identify the source of the attempts, determine the targeted account and service, assess the severity of the activity, and perform appropriate response actions.

## Attack Flow

```text
Kali Linux
    |
    | SSH authentication attempts
    v
Ubuntu Target
    |
    | Authentication telemetry
    v
Wazuh Agent
    |
    v
Wazuh Server
    |
    v
Detection Engine
    |
    v
SOC Alert
    |
    v
Triage
    |
    v
Investigation
    |
    v
MITRE ATT&CK Mapping
    |
    v
Incident Response
    |
    v
Detection Tuning
```

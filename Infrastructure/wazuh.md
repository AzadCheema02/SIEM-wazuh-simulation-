# 🛡️ Wazuh SOC Server

> **Purpose:** Provides centralized security monitoring, log analysis, alert generation, and endpoint visibility for the **SentinelForge laboratory**.

## 🏗️ Architecture

    Wazuh Server
        │
        ├── Windows Agent
        └── Ubuntu Agent

## 💻 Monitored Endpoints

| Endpoint | OS | Telemetry |
| :--- | :--- | :--- |
| **SF-Windows** | Windows 11 | Sysmon + Windows Events |
| **SF-Ubuntu** | Ubuntu | Auditd + Linux logs |

## 🎯 Core Responsibilities

- Receive endpoint telemetry
- Decode events
- Apply detection rules
- Generate security alerts
- Provide centralized investigation
- Support threat hunting

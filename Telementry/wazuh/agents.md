# 🏗️ Wazuh Agent Architecture

> **Monitoring Objective:** Centralize endpoint telemetry and provide a single platform for security monitoring, detection, investigation, and response.

## 🧠 Central Manager

**Wazuh Server**

## 🕵️‍♂️ Active Agents

| Operating System | Telemetry Sources | Status |
| :--- | :--- | :--- |
| **Windows 11** | Sysmon + Windows Event Logs | 🟢 Active |
| **Ubuntu** | Auditd + Linux Logs | 🟢 Active |

## 🔄 Data Flow

    Windows ────────┐
                    │
                    ▼
                 Wazuh
                 Server
                    ▲
                    │
    Ubuntu ─────────┘

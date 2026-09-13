# 🐧 Ubuntu Linux Endpoint

> **Purpose:** Acts as the primary Linux endpoint within the **SentinelForge SOC laboratory** environment.

## 🕸️ Network Configuration

| Attribute | Details |
| :--- | :--- |
| **IP Address** | `10.10.10.30` |
| **Network** | `10.10.10.0/24` |

## 🛡️ Security Telemetry

This endpoint generates and monitors critical security events using the following sources:

- **Auditd**
- **Linux Authentication Logs**
- **System Logs**
- **Wazuh Agent**

## 📡 Monitoring & Forwarding

**Auditd** provides comprehensive host-level security auditing, while the **Wazuh Agent** collects and forwards all relevant telemetry to the centralized Wazuh server for analysis.

# 🪟 Windows 11 Endpoint

> **Purpose:** Acts as the primary Windows endpoint monitored by the **SentinelForge** laboratory.

## 🕸️ Network Configuration

| Attribute | Details |
| :--- | :--- |
| **IP Address** | `10.10.10.20` |
| **Network** | `10.10.10.0/24` |

## 🛡️ Security Telemetry

- **Windows Event Logs**
- **Sysmon**
- **Wazuh Agent**

## 📡 Monitoring & Forwarding

**Sysmon** provides detailed endpoint telemetry, including process creation, network activity, and other critical system events. 

The **Wazuh Agent** securely collects and forwards this security telemetry to the centralized Wazuh server for analysis and alert generation.

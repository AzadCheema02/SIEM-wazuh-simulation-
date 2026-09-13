# 🔍 Linux Auditd Telemetry

> **Purpose:** Auditd provides host-level security auditing for the Ubuntu endpoint.

## 🗄️ Data Source

`Linux Audit Framework`

## ⚡ Key Telemetry

- User activity
- Command execution
- Privilege changes
- Authentication activity
- File access
- System configuration changes

## 🔄 Collection Pipeline

    Ubuntu
       ↓
    Auditd
       ↓
    Wazuh Agent
       ↓
    Wazuh Server
       ↓
    Detection Engine
       ↓
    Alert

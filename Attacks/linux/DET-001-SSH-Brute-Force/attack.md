# DET-001 — SSH Brute Force

## Objective

Simulate an SSH brute-force attack against the Ubuntu endpoint using a custom password list created specifically for the SentinelForge laboratory.

The purpose of this simulation is to generate realistic authentication telemetry and validate the SOC detection and investigation workflow.

## Attack Source

- Platform: Kali Linux
- Role: Attack simulation host
- Tool: Hydra
- Password list: `lab-passwords.txt`

## Target

- Platform: Ubuntu Linux
- Service: SSH
- Port: 22
- IP: `<10.10.10.30>`

## Attack Method

A custom password list named `lab-passwords.txt` was created for this controlled laboratory simulation.

The password list was supplied to Hydra to generate multiple SSH authentication attempts against the Ubuntu test account.

## Command Used

```bash
hydra -l root -P /tmp/lab-passwords.txt ssh://10.10.10.30 -t 4

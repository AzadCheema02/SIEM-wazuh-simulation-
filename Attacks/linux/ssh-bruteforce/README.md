# Scenario: SSH Brute Force (T1110.001)

## Overview
This attack simulates an adversary attempting to gain initial access by performing a high-speed dictionary attack against the exposed SSH service on the Ubuntu endpoint.

## Execution Details
* **Attacker System:** Kali Linux
* **Target System:** Ubuntu Linux 
* **Target Service:** SSH (Port 22)
* **Tool Used:** Hydra

## Execution Command
A custom wordlist (`lab-passwords.txt`) containing 10 dummy passwords was generated to trigger the specific detection threshold.

```bash
hydra -l root -P /tmp/lab-passwords.txt ssh://10.10.10.30 -t 4

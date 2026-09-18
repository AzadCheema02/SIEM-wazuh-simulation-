# INC-001 — SSH Brute Force Attempt

## 1. Incident Summary

A controlled SSH brute-force attack was simulated from the Kali Linux attack host against the Ubuntu endpoint in the SentinelForge laboratory. 

The attacker targeted the `root` account using a custom laboratory password list. 

Five failed authentication attempts were detected from the same source IP, triggering the custom Wazuh detection rule `100010`. 

No successful authentication was observed.

---

## 2. Incident Details

| Field | Value |
|---|---|
| **Incident ID** | INC-001 |
| **Detection ID** | DET-001 |
| **Rule ID** | 100010 |
| **Alert Level** | 12 |
| **Source IP** | 10.10.10.40 |
| **Target IP** | 10.10.10.30 |
| **Target Service** | SSH |
| **Target Account** | root |
| **Failed Attempts** | 5 |
| **Successful Authentication** | No |
| **Status** | Closed |

---

## 3. Attack Source & Target

### Source
* **OS:** Kali Linux
* **IP:** 10.10.10.40

### Target
* **OS:** Ubuntu Linux
* **IP:** 10.10.10.30
* **Service:** SSH
* **Port:** 22
* **Account:** root

*The attack was performed entirely within the isolated SentinelForge laboratory.*

---

## 4. Detection

The activity was detected by the custom Wazuh rule:

* **Rule ID:** 100010
* **Level:** 12
* **Description:** Custom Detection: SSH Brute Force - High frequency password guessing

### Detection Logic:
1. 5 authentication failures
2. From the same source IP
3. Within 120 seconds
4. **Triggers:** Rule 100010 (Level 12 Alert)

---

## 5. Timeline

* **Sep 14 11:56:32** — First Relevant Event: Five failed SSH authentication attempts were observed.
* **Sep 14 17:26:37.915** — Detection Alert: Wazuh generated the custom Rule 100010 alert.

*(Note: The timestamp formats/display times should be verified against the underlying Ubuntu and Wazuh timezone configuration before using them for precise MTTD measurements.)*

---

## 6. Investigation & Findings

The investigation established:

* The authentication attempts originated from `10.10.10.40`.
* The targeted endpoint was `10.10.10.30`.
* The targeted account was `root`.
* Five failed SSH authentication attempts were observed.
* The custom Wazuh detection successfully identified the activity.
* No successful authentication was observed.
* No evidence of account compromise was identified.

**Conclusion:** The activity was confirmed to be an intentional security test performed within the SentinelForge laboratory.

---

## 7. MITRE ATT&CK Mapping

| Field | Value |
|---|---|
| **Tactic** | Credential Access |
| **Technique** | T1110 — Brute Force |
| **Sub-technique** | T1110.001 — Password Guessing |

*The repeated authentication attempts against the SSH service are consistent with password-guessing behavior.*

---

## 8. Impact Assessment

* **Authentication Success:** No
* **Account Compromise:** Not observed
* **Unauthorized Access:** Not observed
* **Production Impact:** None

*The incident represents an attempted credential attack with no confirmed compromise.*

---

## 9. Response & Recovery

Because this was a controlled laboratory simulation, no production containment was required. 

The following checks were performed (or should be performed) after the simulation:

- [x] SSH service remains operational
- [x] Wazuh Agent remains connected
- [x] No successful unauthorized login occurred
- [x] No unexpected account changes occurred
- [x] No unexpected persistence was identified

*In a real production environment, possible containment actions would include blocking the source IP, restricting SSH access, reviewing authentication activity, and investigating any successful login following the brute-force attempts.*

---

## 10. Lessons Learned & Detection Improvement

The scenario demonstrated that repeated SSH authentication failures can be correlated into a higher-confidence detection. The custom rule successfully detected the 5 failed attempts from the same IP within a 120-second window.

**Potential future improvements include:**
* Detecting failed attempts followed by successful authentication.
* Detecting attacks against multiple accounts (password spraying).
* Increasing severity when privileged accounts are targeted.
* Enriching source IP information.
* Adding automated response through the Wazuh API.
* Correlating authentication activity with post-login process activity.

---

## Evidence & References

**Evidence Directory:** `Dashboards/screenshots/`
* `DET-001-attack.png`
* `DET-001-authentication-events.png`
* `DET-001-wazuh-alert.png`
* `DET-001-logtest-validation.png`

**Related Documentation:**
* **Attack:** `Attacks/linux/DET-001-SSH-Brute-Force/`
* **Detection:** `Detections/wazuh/DET-001-SSH-Brute-Force.md`
  

---

## Final Assessment

* **Incident:** SSH Brute Force Attempt
* **Detection:** Successful
* **Rule:** 100010
* **MITRE:** T1110.001
* **Source:** 10.10.10.40
* **Target:** 10.10.10.30
* **Failed Attempts:** 5
* **Successful Authentication:** NO
* **Confirmed Compromise:** NO
* **Status:** CLOSED

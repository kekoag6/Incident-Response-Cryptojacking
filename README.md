# Incident Response: Cryptojacking via Spoofed Vendor Update

An end-to-end incident response investigation: three helpdesk tickets about a slow application
turned out to be an unauthorized cryptocurrency miner on an engineering file server, installed
through a software update that came from an address impersonating the vendor.

The case is a good one to work because the initial symptom was a performance complaint, not a
security alert. Nothing fired. The path from "the CAD application is slow" to "we have an
attacker-controlled process beaconing out on port 3333" ran through the helpdesk, the
applications team, and the SIEM — which is how a meaningful share of real incidents actually
surface.

## Tools used

| Tool | Role |
|---|---|
| Wazuh | SIEM — dashboard, alert correlation, host telemetry |
| Windows Task Manager / Resource Monitor | Process and resource attribution |
| Windows Security (Defender Antivirus) | Detection and remediation |
| Windows Defender Firewall | Egress control |
| Windows Server 2019 | Affected platform |
| MITRE ATT&CK | Technique classification |

## Incident summary

| | |
|---|---|
| **Affected system** | `WIN-6JNN6RLT6IL` — Windows Server 2019, engineering file server |
| **Function** | Hosts CAD model files for the Pro/ENGINEER application |
| **Users affected** | 3 directly; all engineering staff dependent on the application |
| **Incident date** | 13 December |
| **Detection to containment** | 10:00 first ticket → 17:00 egress blocked |
| **Classification** | Compromised system · Social engineering · Malware |
| **Functional impact** | High |
| **Priority** | High |

---

## 1. Correlate the tickets

Three tickets arrived over five hours reporting that Pro/ENGINEER was slow or timing out:
10:00, 15:14, and 15:20. Individually, three people complaining about a slow application is a
performance problem. Together — same application, same server, same day, different users — it is
a single systemic fault, and the right question shifts from "what's wrong with their
workstations" to "what changed on the server."

Operations had already rebooted the file server at 15:30 under standard procedure. The symptoms
returned immediately.

**That reboot is the first real finding.** A performance problem that survives a restart is not a
runaway process or a memory leak — something is re-establishing the load. At that point the
incident should have been escalated as a suspected compromise rather than retried as a
performance issue.

## 2. Establish what changed

At 15:35 the applications engineering group confirmed that updates had recently been installed
on the affected server. Interviewing the administrator who applied them produced the root cause:

> Vendor updates arrive by email. The administrator did not verify the sender before downloading.
> The address appeared to be the expected vendor contact; on review, it was a personal account
> spoofing the vendor's domain.

By 15:50 the incident was reclassified from performance degradation to suspected compromise via
social engineering. The update package was the delivery mechanism.

## 3. Confirm with telemetry

With a hypothesis, the SIEM gets a specific question instead of a fishing expedition.

**16:00 — resource utilization.** Wazuh showed sustained abnormal CPU and GPU utilization on the
engineering application server, **continuing outside office hours.** The after-hours profile is
the discriminator: legitimate CAD workloads track the working day. A load that holds steady at
02:00, when no one is logged in, is not user-driven.

**16:10 — network.** The Wazuh dashboard confirmed an established remote connection between the
server and an unrecognized external address, correlated to the same window as the CPU load.

**16:15 — port.** Narrowing to that connection identified **TCP 3333** as the channel the process
was using to maintain communication. Port 3333 is a Stratum mining-pool convention, which
independently corroborated the resource evidence.

Three independent sources — host resource telemetry, network connection data, and port
convention — agreeing on the same conclusion. Any one alone would have been suggestive; together
they are conclusive.

## 4. Identify the process

Resource attribution on the host identified the process consuming CPU and GPU as **XMRig**, an
open-source Monero miner.

Monero is the standard choice for cryptojacking because it is CPU-mineable and privacy-oriented,
so proceeds are not traceable the way Bitcoin's are. XMRig itself is legitimate open-source
software — which is the point. It is not malware by signature, so signature-only detection
frequently misses it, and its presence has to be judged by context: nobody authorized a miner on
a production file server.

## 5. Remediate

**16:30 — restore endpoint protection.** Windows Defender Antivirus had been **disabled via Group
Policy** on the affected server. That is not a side effect of a miner; it is a deliberate
defense-evasion step taken by whoever installed it, and it explains why nothing alerted at
install time.

```
Group Policy → Computer Configuration → Administrative Templates
  → Windows Components → Microsoft Defender Antivirus
  → "Turn off Microsoft Defender Antivirus" = Disabled / Not Configured
```

```powershell
gpupdate /force
Get-MpComputerStatus | Select-Object AntivirusEnabled, RealTimeProtectionEnabled
```

Re-enabled real-time protection through Windows Security, ran a quick scan, which detected the
miner, reviewed the detections, and applied Start actions to remove it.

```powershell
Start-MpScan -ScanType QuickScan
Get-MpThreatDetection | Select-Object ThreatID, ActionSuccess, InitialDetectionTime
```

**17:00 — block the egress channel.** From the administrative workstation, added an outbound
firewall rule blocking unauthorized TCP traffic on port 3333.

```powershell
New-NetFirewallRule -DisplayName "Block Outbound TCP 3333 (Mining Pool)" `
  -Direction Outbound -Protocol TCP -RemotePort 3333 -Action Block
```

Removing the miner and blocking the channel are both required. Removal alone leaves the path open
for the next payload; blocking alone leaves the miner running against a different port.

---

## Results

| Time | Action |
|---|---|
| 10:00 | First ticket (user 1) |
| 15:14 / 15:20 | Tickets 2 and 3 — pattern emerges |
| 15:30 | Server rebooted per SOP; symptoms return |
| 15:35 | Applications team confirms recent update installation |
| 15:50 | Spoofed vendor email identified — reclassified as compromise |
| 16:00 | SIEM confirms abnormal after-hours CPU/GPU load |
| 16:10 | Unrecognized external connection confirmed |
| 16:15 | TCP 3333 identified as the C2/pool channel |
| 16:30 | Defender re-enabled; miner detected and removed |
| 17:00 | Outbound TCP 3333 blocked |

Seven hours from first ticket to containment; two hours from correct classification to
containment. The five-hour gap is the finding worth acting on — nothing in the process escalated
three related tickets, and the reboot-that-didn't-help was treated as a failed fix rather than as
evidence.

### Preventative recommendations

| # | Action | Risk addressed |
|---|---|---|
| 1 | Enforce vendor update verification; centralize patch approval through a managed process rather than email attachments | Removes the delivery path entirely — updates arriving by email are never installed directly |
| 2 | Alert on Defender/Group Policy tamper events | The miner ran undetected only because AV was disabled first; that disablement should itself page someone |
| 3 | Baseline and alert on after-hours resource utilization on servers | Sustained load with no logged-on users is a high-signal, low-false-positive detection |
| 4 | Default-deny egress on servers; allowlist required destinations | Miners, C2, and exfiltration all require outbound connectivity |
| 5 | Phishing and vendor-impersonation training for privileged administrators | The compromise required exactly one administrator to skip sender verification |
| 6 | Escalation rule: 3+ related tickets on one system triggers security review | Would have cut five hours off detection |

## Lessons learned

**A reboot that doesn't fix it is evidence.** Standard procedure correctly tried a restart. When
the symptoms returned unchanged, that result should have reclassified the ticket immediately.
Persistence across a reboot means something is deliberately re-establishing, and treating it as
"the fix didn't work" cost most of the response window.

**The helpdesk is a detection source.** Nothing alerted. No signature fired, no threshold
tripped — because AV had been disabled before the payload landed. Three correlated tickets were
the actual detection, and the ticketing system had no mechanism to surface that correlation.

**Defense evasion precedes payload.** Defender was disabled via Group Policy before the miner was
installed. Tamper events deserve alerting in their own right; by the time the payload is running,
the control that should have caught it is already gone.

**After-hours load is high-signal.** The single most useful discriminator was not the process
name or the port — it was that utilization did not fall when the office emptied. That detection
is cheap to build and generalizes well beyond cryptomining.

**Legitimate tools used illegitimately need context-based detection.** XMRig is open-source
software with real uses. Detection had to rest on where it was running and whether anyone
authorized it, not on whether it was "malware."

**Interview the humans.** Root cause came from asking the administrator how updates arrive, not
from a log. The SIEM confirmed the compromise; the conversation explained it.

## MITRE ATT&CK mapping

| Tactic | Technique | ID | Evidence |
|---|---|---|---|
| Initial Access | Phishing: Spearphishing Attachment | [T1566.001](https://attack.mitre.org/techniques/T1566/001/) | Update package from an address spoofing the vendor |
| Execution | User Execution: Malicious File | [T1204.002](https://attack.mitre.org/techniques/T1204/002/) | Administrator installed the update without verifying the sender |
| Defense Evasion | Impair Defenses: Disable or Modify Tools | [T1562.001](https://attack.mitre.org/techniques/T1562/001/) | Defender Antivirus disabled via Group Policy prior to install |
| Command and Control | Non-Standard Port | [T1571](https://attack.mitre.org/techniques/T1571/) | Persistent outbound TCP 3333 to the mining pool |
| Impact | Resource Hijacking | [T1496](https://attack.mitre.org/techniques/T1496/) | XMRig consuming CPU and GPU continuously, including after hours |
| Impact | Service Stop / Degradation | [T1489](https://attack.mitre.org/techniques/T1489/) | Pro/ENGINEER timeouts and loss of availability for engineering staff |

---

*Completed as a virtual lab exercise for D483 Security Operations at Western Governors University.
The organization, systems, and users in this scenario are fictional; the tooling, analysis, and
remediation steps are real.*

#  SOC Analyst Portfolio 
## ➡️ Continuous Learning & Operations

<!-- TECH STACK BANNER -->
<p align="left">
  <!-- Role & Core SIEM -->
  <img src="https://img.shields.io/badge/Role-SOC_Analyst-1E90FF?style=flat-square&logo=shield&logoColor=white" alt="SOC Analyst">
  <img src="https://img.shields.io/badge/SIEM-Microsoft_Sentinel-0A2342?style=flat-square&logo=microsoft&logoColor=white" alt="Microsoft Sentinel">
  <img src="https://img.shields.io/badge/SIEM-Wazuh-7B68EE?style=flat-square&logo=wazuh&logoColor=white" alt="Wazuh SIEM">
  <img src="https://img.shields.io/badge/Cloud-Entra_ID-00BFFF?style=flat-square&logo=microsoftazure&logoColor=white" alt="Azure Entra ID">
  <br>
  <!-- Telemetry & Queries -->
  <img src="https://img.shields.io/badge/Telemetry-Sysmon-663399?style=flat-square&logo=windows&logoColor=white" alt="Sysmon">
  <img src="https://img.shields.io/badge/OS_Logs-Windows_Events-9370DB?style=flat-square&logo=windows&logoColor=white" alt="Windows Events">
  <img src="https://img.shields.io/badge/Language-KQL-C9A0DC?style=flat-square&logo=azuredataexplorer&logoColor=white" alt="KQL">
  <img src="https://img.shields.io/badge/Detection-Sigma_Rules-9370DB?style=flat-square" alt="Sigma Rules">
  <img src="https://img.shields.io/badge/Network-Wireshark-DA70D6?style=flat-square&logo=wireshark&logoColor=white" alt="Wireshark">
  <br>
  <!-- Scripting & Emulation -->
  <img src="https://img.shields.io/badge/Scripting-PowerShell-191970?style=flat-square&logo=powershell&logoColor=white" alt="PowerShell">
  <img src="https://img.shields.io/badge/Emulation-Kali_Linux-4B0082?style=flat-square&logo=kali-linux&logoColor=white" alt="Kali Linux">
  <img src="https://img.shields.io/badge/Payloads-Python-0A2342?style=flat-square&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/Recon-Nmap_%26_Ncrack-D5006D?style=flat-square" alt="Nmap & Ncrack">
</p>

**Translating real-world logistics investigations into Blue Team and SOC practices.**
This portfolio brings together my hands-on SOC training and the investigative skills I developed in a high-volume logistics environment. 

The same methodology I used to analyse perpetual inventory discrepancies, validate multi-source data, and reconstruct supply chain timelines now underpins my approach to detection engineering, log analysis, and structured SOC investigations.

> ⚠️ **Recruiters & Hiring Managers:** Looking for an executive summary of my best work? 

Please visit my curated ➡️ **[Blue Team & SOC Analyst Showcase](https://github.com/magda-uk/soc-analyst-showcase)**.

---

## 🟣 Operational Readiness & Core Domains

<table>
  <tr>
    <td width="50%" valign="top">

###  [Detection Engineering](./1.detections/README.md)

*Focus:* Sigma & KQL Rule Creation

*Role:* Detection Engineer

*Objective:* Proactive threat hunting playbooks and custom detection logic strictly mapped to MITRE ATT&CK.

`#kql` `#sigma` `#rule-creation`

</td>
    <td width="50%" valign="top">

###  [Investigations](/2.investigations/README.md)

*Focus:* Threat Triage & False Positive Tuning

*Role:* SOC Analyst L1/L2

*Objective:* Deep-dive telemetry triage, false-positive baselining, and active incident response workflows.

`#incident-response` `#triage` `#tuning`

</td>
  </tr>
</table>

<table>
  <tr>
    <td width="50%" valign="top">

###  [Log Analysis](./3.log-analysis/README.md)

*Focus:* Sysmon, PowerShell & Entra ID

*Role:* Telemetry Analyst

*Objective:* Granular forensic analysis, event correlation, and raw telemetry triage across endpoint and cloud.

`#sysmon` `#entra-id` `#powershell`

</td>
    <td width="50%" valign="top">

###  [Threat Hunting](./4.hunting/README.md)

*Focus:* Credential & Cloud Identity Abuse

*Role:* Threat Hunter

*Objective:* Proactive hunting playbooks targeting OS credential dumping and cloud identity abuse.

`#playbooks` `#proactive-hunting` `#identity`

</td>
  </tr>
</table>

<table>
  <tr>
    <td width="50%" valign="top">

###  [Security Architecture & Labs](./5.projects/README.md)

*Focus:* Wazuh SIEM, FIM & Elastic Architecture

*Role:* Blue Team Operator

*Objective:* End-to-end SIEM deployment generating real-world logs via active adversary emulation. Includes [Foundation Labs](./7.hands-on/README.md).

`#wazuh` `#homelab` `#emulation`

</td>
    <td width="50%" valign="top">

###  [SOC Documentation](./6.documents/2.incident-response-workflow.md)

*Focus:* IR Workflows & Methodologies

*Role:* First Responder

*Objective:* Standard Operating Procedures (SOPs), IR checklists, and structured investigative methodologies.

`#sop` `#governance` `#checklists`

</td>
  </tr>
</table>

---

## 🟣 Featured Enterprise Lab & Investigations

<table>
  <tr>
    <td width="50%" valign="top">

### ➡️ [Wazuh SIEM & Sysmon Operations](/5.projects/wazuh-lab/README.md)

*Type:* Enterprise Architecture Lab

*Executed Scenarios:* NLA Evasion & RDP Brute Force, Ransomware Emulation, FIM (Syscheck).

`#wazuh` `#siem` `#emulation`

</td>
    <td width="50%" valign="top">

### ➡️ [OS Credential Dumping (T1003/T1048)](./2.investigations/06-true-positive-procdump-exfiltration.md)

*Type:* Incident Analysis & Triage

*Objective:* Deep-dive telemetry triage of LSASS/Explorer dumping via Procdump and Data Exfiltration.

`#credential-dumping` `#kql` `#true-positive`

</td>
  </tr>
</table>

<table>
  <tr>
    <td width="50%" valign="top">

### ➡️ [LSASS Access via Mimikatz (Event 10)](./3.log-analysis/sysmon/id10-lsass-access/evtx-mimikatz-lsass-access.md)

*Type:* Core Log Analysis

*Objective:* Process Access (Event ID 10) telemetry breakdown targeting the Local Security Authority Subsystem Service.

`#mimikatz` `#lsass` `#event10`

</td>
    <td width="50%" valign="top">

### ➡️ [Cloud Identity: Impossible Travel](./3.log-analysis/entra-id/EntraID-Impossible-Travel.md)

*Type:* Incident Analysis & Triage

*Objective:* Investigation of Entra ID sign-in logs focusing on MFA anomalies and geographic impossible travel alerts.

`#entra-id` `#impossible-travel` `#cloud`

</td>
  </tr>
</table>

<table>
  <tr>
    <td width="50%" valign="top">

### ➡️ [Suspicious PS Encoded Command](./2.investigations/02-threat-hunt-powershell.md)

*Type:* Incident Analysis & Triage

*Objective:* De-obfuscation and execution timeline analysis of Base64 encoded PowerShell payloads (T1059.001).

`#powershell` `#obfuscation` `#t1059`

</td>
    <td width="50%" valign="top">

### ➡️ [EDR Interception vs. OS Blindspot](./2.investigations/01-sysmon-edr-blindspot.md)

*Type:* Incident Analysis & Triage

*Objective:* Analysis of a Sysmon blindspot where EDR interception prevented OS-level process creation telemetry.

`#edr` `#blindspots` `#telemetry`

</td>
  </tr>
</table>

<table>
  <tr>
    <td width="50%" valign="top">

### ➡️ [Special Privileges Assigned (Event 4672)](./3.log-analysis/windows-events/4672-privilege-special-assigned.md)

*Type:* Detection Engineering & Alert Tuning

*Objective:* Normalization and analysis of administrative privilege escalation in Windows environments.

`#event4672` `#privilege-escalation` `#windows`

</td>
    <td width="50%" valign="top">

### ➡️ [High-Velocity Group Enumeration (4798)](./2.investigations/04-false-positive-event4798.md)

*Type:* Detection Engineering & Alert Tuning

*Objective:* False positive investigation of rapid local group enumeration activities to reduce alert fatigue.

`#event4798` `#enumeration` `#false-positive`

</td>
  </tr>
</table>

<table>
  <tr>
    <td width="50%" valign="top">

### ➡️ [False Positive Tuning: Lenovo Vantage](./2.investigations/03-tuning-lenovo-vantage.md)

*Type:* Detection Engineering & Alert Tuning

*Objective:* Analysis of OEM telemetry (Lenovo Vantage) to build robust false-positive exclusions in Sentinel.

`#alert-tuning` `#kql` `#oem-telemetry`

</td>
    <td width="50%" valign="top">

### ➡️ [Registry Modification & Persistence (13)](/3.log-analysis/sysmon/id13-registry-modification/multi-event-analysis.md)

*Type:* Detection Engineering & Alert Tuning

*Objective:* Forensic correlation of registry modifications (Event ID 13) used for establishing system persistence.

`#persistence` `#registry` `#event13`

</td>
  </tr>
</table>

---

## ➡️ Connect with me   

**Magda Dominguez**    
Blue Team operations 🔻 SOC investigations 🔻 Logistics-to-SOC analytical mindset 

[![Magda Dominguez LinkedIn](https://img.shields.io/badge/LinkedIn-Magda_Dominguez-9370DB?style=flat-square&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/magda-d-infosec)




> I'm actively seeking a Cyber Security / SOC role where I can bring my structured troubleshooting, log analysis, and secure architecture skills to a dedicated security team.
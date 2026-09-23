# SOC Lab Investigation: RDP Brute Force & NLA Evasion (T1110.001)

**Objective:** To simulate, detect, and analyse an unauthorised Remote Desktop Protocol (RDP) access attempt. The simulation demonstrates pivoting from standard brute-force tools blocked by Network Level Authentication (NLA) to native RDP clients, and the subsequent detection of Event ID 4625 using Wazuh SIEM.

## Red Team: Reconnaissance & Simulation
The investigation began with active reconnaissance against the target endpoint to identify open services, specifically checking for RDP availability.

* Executed a stealth TCP SYN scan using `nmap` while bypassing ICMP blocks (`-Pn`).
* Identified port 3389 (ms-wbt-server) as open and actively listening.

![nmap results](/5.projects/project3.wazuh-lab/screenshots/nmap-1.png)


Initial brute-force attempts using `ncrack` failed to negotiate the connection because the target enforced Network Level Authentication (NLA). To successfully generate authentication traffic and bypass this restriction, a native RDP client (`xfreerdp`) was utilised to simulate a targeted credential attack.

* Executed the authentication attempt bypassing NLA restrictions.
* Forced a deliberate logon failure to trigger the security telemetry.

<!-- PLACEHOLDER 2: Insert Kali terminal xfreerdp screenshot here -->
![xfreerdp command execution and authentication failure](/5.projects/project3.wazuh-lab/screenshots/Ncrack.png)

## Blue Team: Detection & Telemetry Analysis
The endpoint's Wazuh agent successfully captured the authentication failure and forwarded the telemetry to the SIEM, triggering a high-severity alert.

* **Rule Triggered:** Windows: Logon Failure
* **Event ID:** 4625 (An account failed to log on)
* **Target Account:** Administrator
* **Source IP Address:** 192.168.1.8 (Kali Linux Attacker)


![Wazuh SIEM dashboard displaying Event ID 4625 details](/5.projects/project3.wazuh-lab/screenshots/wazuh-0.png)

![Wazuh SIEM dashboard displaying Event ID 4625 details](/5.projects/project3.wazuh-lab/screenshots/wazuh-1.png)

![Wazuh SIEM dashboard displaying Event ID 4625 details](/5.projects/project3.wazuh-lab/screenshots/wazuh-2.png)

## Triage & Incident Response Recommendations
Upon verifying this alert in a live production environment, the following immediate containment and remediation actions are recommended:

1. **Verify Post-Incident Activity:** Query the SIEM for Event ID 4624 (Successful Logon) associated with the attacker's IP address to ensure the brute-force attempt did not ultimately succeed.
2. **Network Containment:** Block the malicious source IP address (`192.168.1.8`) at the perimeter firewall.
3. **Hardening:** Ensure account lockout policies are strictly enforced via Active Directory Group Policy to mitigate sustained brute-force campaigns.
4. **Access Control:** Restrict RDP access to VPN users or dedicated management subnets only.

##  Author
**Magda Dominguez**  
*Security Operations 🔸 Detection Engineering 🔸 Blue Team*
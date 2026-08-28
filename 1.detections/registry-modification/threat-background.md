# Threat Background — Suspicious Registry Modification (T1112, T1547, T1031, T1050)

## Threat Summary
Adversaries frequently modify the Windows Registry to achieve persistence, escalate privileges, hijack legitimate services, or manipulate system behaviour. Registry changes are stealthy, blend easily with normal system activity, and often leave artefacts that can be correlated with process execution, service configuration, or user interaction.

This threat focuses on detecting abnormal or high-risk registry modifications, especially those performed by SYSTEM-level processes or involving keys commonly abused for persistence and execution.

---

## Why Registry Modification Matters
Registry changes are a core technique in post-exploitation. Attackers rely on them because they:
* Do not necessarily require dropping new files to disk (fileless persistence)
* Blend in with legitimate operating system and software behaviour
* Persist across system reboots and user logoffs
* Can hijack execution flows or elevate privileges indirectly
* Are rarely monitored thoroughly by default Windows event logging configurations

**Sysmon Event ID 13 (RegistryEvent - Value Set)** provides essential visibility into these changes, allowing SOC analysts to identify suspicious activity early in the attack chain.

---

## Common Malicious Uses of Registry Modification

### 1. Persistence via Shell Extensions (T1547)
Attackers add malicious commands under shell execution paths to trigger payloads when users interact with the GUI (e.g., right-clicking files or folders in Windows Explorer). Malware families such as Qbot, Emotet, and various info-stealers frequently use shell extension handlers to achieve user-triggered persistence.

### 2. Service Hijacking and Privilege Escalation (T1031, T1050)
Modifying existing service configuration paths (such as `ImagePath`) allows attackers to replace legitimate executable paths with malicious commands, run code with `NT AUTHORITY\SYSTEM` privileges, persist across reboots, and escalate privileges silently. This technique is widely leveraged by APT groups, ransomware operators, and post-exploitation frameworks.

### 3. AppCompatFlags Manipulation (T1112)
`AppCompatFlags` registry keys store application compatibility decisions and execution shims. Attackers modify these keys to disable security mitigations, suppress warnings, force insecure execution modes, or bypass application whitelisting and controls.

---

## Threat Impact
Suspicious registry modification can lead to:
* Persistent host access without dropping new binaries
* Execution flow hijacking via services or shell extensions
* Privilege escalation to administrative or SYSTEM levels
* Evasion of baseline security controls and monitoring
* Stealthy post-exploitation activity
* Long-term compromise that survives reboots and patch cycles

Because legitimate software installations and administrative tools also produce similar registry events, robust detection tuning, baselining, and structured triage workflows are essential.

---

## Detection Rationale
This detection monitors for:
* Registry modifications performed by SYSTEM-level or unexpected parent processes
* Changes to high-risk registry paths (e.g., Run keys, Services, Shell Extensions)
* Creation or alteration of shell extension command subkeys
* Changes to service `ImagePath` or startup configurations
* Updates to `AppCompatFlags` metadata and shim databases
* Unexpected registry writes targeting system-wide hives (`HKLM`) from user-space applications

By correlating **Sysmon Event ID 13** with process identity, command lines, target registry paths, and assigned values, SOC analysts can identify suspicious behaviour early and reduce adversary dwell time.

---

## MITRE ATT&CK Mapping
* **T1112** — Modify Registry
* **T1547** — Boot or Logon Autostart Execution (Registry)
* **T1031** — Modify Existing Service
* **T1050** — New Service

---

## Conclusion
Registry modification is a versatile and stealthy technique used across multiple stages of an attack. Monitoring **Sysmon Event ID 13** provides critical visibility into persistence, service hijacking, and defense evasion behaviours that would otherwise remain undetected. This threat background supports the detection logic and evidence collected for registry-modification triage.